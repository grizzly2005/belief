# Isolated Web Validation Worker

## Purpose

BELIEF can execute a canonical `ValidationPlan` against eight transparent
Flask and FastAPI fixtures in a separate local process. The worker gathers
deterministic path-traversal and IDOR/BOLA evidence without starting a server,
opening a port, or loading caller-selected code.

This is an **isolated process with Python-level controls**, not a secure
sandbox. Only reviewed first-party registered fixtures are supported.

## Data flow

```text
ValidationPlan + exact registered fixture ID
  -> canonical request JSON bytes (maximum 16 KiB)
  -> parent-owned container with a fixed child root
  -> spawn-only worker
  -> sanitized environment + network/process policy
  -> allowlisted fixed adapter/framework imports
  -> resource limits
  -> filesystem-confined fixture preparation and execution
  -> Flask test_client or direct in-memory ASGI execution
  -> canonical response JSON bytes (maximum 256 KiB)
  -> binding plus evidence/attestation/response digest verification
  -> ValidationExecutionSummary
  -> existing ValidationResult
```

The transport uses two one-way `multiprocessing.Connection` pipes and only
`send_bytes`/`recv_bytes`. Caller data is never accepted through a Python
object-unpickling transport.

The parent always requests the `spawn` start method, including on POSIX.

## Request contract

Schema: `belief.validation_worker_request.v2`

The request contains exactly:

| Field | Contract |
| --- | --- |
| `schema_version` | Exact v2 request schema |
| `fixture_id` | Exact lowercase ID from the closed registry |
| `validation_plan_id` | Canonical `vp_` identifier |
| `validation_plan_digest` | Lowercase SHA-256 of the canonical plan |
| `source_revision` | Bounded revision label, never a path |
| `test_parameters` | Empty or `{"include_symlink": boolean}` |
| `timeout_ms` | Integer, not boolean, from 100 through 30,000 |
| `correlation_id` | Bounded routing label |

There is no module, callable, expression, command, URL, host, port, adapter,
source-code, or fixture-path field.

The decoder requires canonical UTF-8 JSON and rejects unknown/missing fields,
duplicate keys, non-finite numbers, malformed Unicode, extra/trailing values,
oversize or deeply nested structures, invalid identifiers, and malformed
digests before fixture execution.

## Response and attestation

Schemas:

```text
belief.validation_worker_response.v3
belief.validation_worker_attestation.v3
belief.validation_worker_diagnostics.v1
```

The response binds its envelope and attestation to the request, registered
fixture source, and complete registry. It contains tri-state baseline evidence,
bounded observations with explicit oracle roles, oracle counts, normalized
errors and limitations, and runtime-only diagnostics.

Three digests have separate meanings:

- `evidence_digest` covers only the plan-bound observations, baseline, outcome
  inputs, limitations, and normalized errors. It excludes platform, Python and
  framework versions, resource limits, cleanup, correlation, duration, child
  exit code, output, cancellation text, and temporary paths;
- `attestation_digest` covers environment, platform, framework, installed
  policies, resource-limit state, and cleanup;
- `response_digest` covers the complete response envelope except itself.

`semantic_digest` is retained only as a deprecated compatibility alias for
`evidence_digest`. The reader verifies and migrates canonical v2 responses in
memory; new responses are always v3.

The fixed protocol error taxonomy is:

```text
invalid_request
unsupported_protocol
unknown_fixture
binding_mismatch
dependency_unavailable
timeout
cancelled
child_crash
malformed_response
response_too_large
policy_violation
internal_error
```

Crash, timeout, cancellation, malformed output, missing dependency, unknown
fixture, and policy violation always project to an inconclusive BELIEF result.

## Registered fixtures

The public registry contains eight opaque IDs:

| Fixture ID | Framework | Vertical |
| --- | --- | --- |
| `fx_01d7c2_v1` | Flask | Path traversal |
| `fx_18a4e9_v1` | Flask | Path traversal |
| `fx_2f6b10_v1` | Flask | IDOR/BOLA |
| `fx_3c8d57_v1` | Flask | IDOR/BOLA |
| `fx_47e1a3_v1` | FastAPI | Path traversal |
| `fx_5b9c20_v1` | FastAPI | Path traversal |
| `fx_6d04f8_v1` | FastAPI | IDOR/BOLA |
| `fx_7a2e61_v1` | FastAPI | IDOR/BOLA |

Each ID maps to a separate fixed application module. There is no runtime
posture switch, and expected outcomes exist only in evaluator-side benchmark
metadata. They are not passed to static analysis, the worker, MCP, or plan
generation.

The scanner and worker consume the same fixture application module and shared
helper/protocol sources. The fixture-source digest commits to those exact
normalized documents; the registry digest commits to the closed mapping. The
two application variants for a framework and vertical therefore have distinct
source digests.

## Oracles

Path traversal checks a legitimate file, parent escape, absolute controlled
sentinel path, normalized equivalent, optional symlink boundary, and final file
state. The application considers `allowed/` its authorized root; the worker
policy permits only the larger private worker root. No host file is used as a
sentinel.

IDOR/BOLA checks owner read/update baselines, same-tenant foreign-owner
read/update, cross-tenant read/update, returned ownership/tenant evidence, and
final state for protected resources. Authentication is represented separately
from owner and tenant authorization.

## Isolation controls

Before framework or fixture import, the inert standard-library bootstrap:

- enters the parent-created private root;
- redirects HOME/profile/app-data/XDG/cache/temp locations below it;
- replaces the environment with a small allowlist;
- redirects native stdout/stderr to the null device;
- installs bounded Python output capture;
- installs network and process policy;
- resolves one exact hardcoded registry entry.

After fixed adapter/framework import, resource limits are applied. The
filesystem policy then surrounds both fixture preparation and fixture
execution. Flask metadata required for lazy test-client initialization is
preloaded before that policy; the application itself is created under policy.

Network policy denies IPv4/IPv6, connect, bind, listen, UDP send, DNS, asyncio,
urllib, `http.client`, Requests, and non-local HTTPX dispatch. Flask uses only
`test_client()` and FastAPI uses BELIEF's direct in-memory ASGI transport.

Process policy denies subprocess/shell helpers, spawn/exec/fork APIs, nested
multiprocessing, process pools, and `pty.spawn`. POSIX additionally attempts
CPU, descriptor, file-size, and child-count limits; Windows reports those
controls as unavailable.

Filesystem policy guards ordinary opens and `Path` reads/writes as well as
path resolution, rename, replace, remove, unlink, directory creation/removal,
symlink, hardlink, enumeration, stat/lstat, readlink, truncate, chmod, and
reviewed `shutil` copy/move/rmtree operations. Paths and both ends of two-path
operations must remain below the fixed child root. Internal ancestor probes
needed to resolve an allowed path do not make parent metadata directly
available. This remains a Python-level policy and does not mediate native
direct system calls.

Full threat-model details and residual limitations are in
`docs/ISOLATED_WEB_VALIDATION_SECURITY_REVIEW.md`.

## Lifecycle and cancellation

`WorkerRunHandle` supports cancellation before start and during execution.
The parent owns an outer container, its fixed `child` root, and all handles.
Timeout or cancellation first sets a cooperative event, then uses
terminate/join and kill/join fallback.
Every terminal path closes all four pipe endpoints, closes the process handle,
removes the complete outer container, and attests cleanup success only when
that container is gone. Renaming or deleting the child root cannot redirect or
defeat parent cleanup.

Child stdout/stderr is bounded to 4 KiB per stream, sanitized, redacted, and
kept in runtime diagnostics only. It cannot write a JSON-RPC line to an MCP
server's stdout.

## Python API

```python
from belief.validation.worker import run_isolated_web_validation_plan

result = run_isolated_web_validation_plan(
    plan,
    fixture_id="fx_18a4e9_v1",
    source_revision="fixture-source-v3",
    timeout_ms=5_000,
)
```

The returned value remains the existing `ValidationResult`. Deterministic
worker status, evidence/attestation/response digests, and attestation are under
`result.metadata["isolated_worker"]`. Runtime diagnostics are available only
from the lower-level `run_worker_request` response.

## Optional dependencies

```bash
python -m pip install -e ".[web-validation]"
```

Supported ranges:

- `Flask>=3.0,<4`;
- `fastapi>=0.115,<1`.

An absent or unsupported framework produces `dependency_unavailable` and an
explicit abstention.

## Verification

Targeted worker and adversarial coverage:

```bash
python -m pytest -q \
  tests/test_isolated_web_worker_contracts.py \
  tests/test_isolated_web_worker_safety.py \
  tests/test_isolated_web_worker_adversarial.py \
  tests/test_isolated_web_validation.py
```

Repository gates:

```bash
python -m pytest -q -m security
python -m pytest -q -m "not slow and not external and not llm"
python -m ruff check belief tests
python -m pip check
python -m compileall -q belief
git diff --check
```

The repository contains legacy Python 2 Z3 samples under
`belief/tools_bundled/z3_playground`. They are data excluded from first-party
lint and are not Python 3 compile targets; use a first-party scoped compile in
addition to recording the exact repository-wide `compileall` result.

## MCP boundary

Dynamic MCP execution requires an exact trusted binding to the fixture registry
digest, fixture source digest, plan digest, case type, source revision, run, and
case. Matching only by case type is forbidden because it would misattribute
fixture evidence to a scanned target. MCP v0.2 implements that binding for
registered transparent fixtures only. See
[`MCP_DYNAMIC_VALIDATION_SECURITY.md`](MCP_DYNAMIC_VALIDATION_SECURITY.md).
