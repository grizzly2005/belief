# Isolated Web Validation Worker

## Purpose

BELIEF can execute a canonical `ValidationPlan` against eight transparent,
deterministic Flask and FastAPI applications in a separate local process. The
worker is intended to gather reproducible path-traversal and IDOR/BOLA evidence
without starting a server, opening a port, or extending the MCP surface.

The worker reuses BELIEF's existing contracts:

- `ValidationPlan`;
- `ValidationExecutionContext`;
- `ValidationObservation`;
- `ValidationExecutionSummary`;
- `ValidationResult`;
- `run_validation_plan`.

`IsolatedWebValidationExecutor` converts the child response into the existing
`ValidationExecutionSummary`. The existing runner then creates the normal
`ValidationResult`; there is no parallel verdict pipeline.

## Architecture

```text
parent / existing runner
    |
    | strict bounded JSON over multiprocessing.Connection.send_bytes()
    v
spawn-only child process
    |
    +-- strict request decoder
    +-- minimal environment and temporary working directory
    +-- ordinary network, listener, subprocess, and shell API guards
    +-- immutable closed fixture registry
    +-- Flask test_client() or direct local ASGI transport
    |
    v
strict versioned JSON response
    |
    v
ValidationExecutionSummary -> ValidationResult
```

The implementation is split across:

```text
belief/validation/worker/contracts.py
belief/validation/worker/registry.py
belief/validation/worker/process.py
belief/validation/worker/entrypoint.py
belief/validation/web/_shared.py
belief/validation/web/flask_adapter.py
belief/validation/web/fastapi_adapter.py
```

The parent always requests a `multiprocessing` context with the `spawn` start
method, including on Linux. The caller-controlled message is sent with
`send_bytes`; no caller object is unpickled by the child.

## Request Protocol

Schema: `belief.validation_worker_request.v1`

The JSON object must contain exactly these fields:

| Field | Contract |
| --- | --- |
| `schema_version` | Exact protocol version |
| `fixture_id` | Stable lowercase ID from the closed registry |
| `validation_plan_id` | Canonical `vp_` identifier |
| `validation_plan_digest` | Lowercase SHA-256 of the canonical plan |
| `source_revision` | Bounded revision label, not a path |
| `test_parameters` | Empty or `{"include_symlink": boolean}` |
| `timeout_ms` | Integer from 1 through 30,000 |
| `correlation_id` | Bounded correlation label |

The complete request is limited to 16 KiB. Missing fields, extra fields,
non-canonical values, non-finite JSON numbers, and invalid UTF-8 are rejected.

There is no request field for a module, import, callable, expression, command,
URL, port, network configuration, or fixture path. The child cannot use the
request to discover another fixture.

The complete plan is deliberately not copied into the child. The parent runner
is authoritative for canonical plan parsing, plan identity, digest binding,
case type, and safety policy. The child echoes the exact ID and digest so the
parent can reject a mismatched response.

## Response Protocol

Schema: `belief.validation_worker_response.v1`

The response is limited to 256 KiB and contains:

- correlation, fixture, plan ID, and plan digest bindings;
- `worker_status`;
- bounded observations;
- tri-state functional baseline (`true`, `false`, or `null`);
- evaluated, passed, failed, and unevaluated oracle counts;
- stable limitations;
- normalized error codes and messages;
- elapsed milliseconds;
- a capability attestation;
- a deterministic evidence digest.

The evidence digest excludes elapsed time. Runtime duration may vary, while
the observations, execution summary, and `ValidationResult` remain
semantically deterministic.

The possible worker statuses are:

- `completed`;
- `inconclusive`;
- `unsupported`;
- `invalid_request`;
- `crashed`;
- `timed_out`.

A timeout, crash, invalid response, missing optional dependency, or unknown
fixture always maps to an `inconclusive` BELIEF result. It cannot become
`bypassed`, `enforced`, or `false_positive`.

## Closed Fixture Registry

The public registry snapshot contains metadata only and is returned as a
defensive copy. Internal entries are frozen and include fixed trusted
entrypoints.

| Fixture ID | Framework | Vertical | Posture |
| --- | --- | --- | --- |
| `flask_path_traversal_vulnerable_v1` | Flask | Path traversal | Vulnerable |
| `flask_path_traversal_protected_v1` | Flask | Path traversal | Protected |
| `flask_idor_vulnerable_v1` | Flask | IDOR/BOLA | Vulnerable |
| `flask_idor_protected_v1` | Flask | IDOR/BOLA | Protected |
| `fastapi_path_traversal_vulnerable_v1` | FastAPI | Path traversal | Vulnerable |
| `fastapi_path_traversal_protected_v1` | FastAPI | Path traversal | Protected |
| `fastapi_idor_vulnerable_v1` | FastAPI | IDOR/BOLA | Vulnerable |
| `fastapi_idor_protected_v1` | FastAPI | IDOR/BOLA | Protected |

Flask applications are called only with `test_client()`. FastAPI applications
are called through a bounded direct ASGI transport. The ASGI transport drives
only immediately local request/response operations and rejects an attempt to
wait on an external asynchronous operation. Neither adapter calls `run()`,
Uvicorn, Hypercorn, a socket client, or a listening socket.

## Path-Traversal Oracles

Each path fixture creates only controlled public and sentinel files below its
worker-owned temporary directory. It checks:

- a legitimate relative path;
- a parent segment (`../`);
- an absolute path to the controlled sentinel;
- a normalized equivalent path;
- a symlink boundary when supported;
- final public and sentinel file state.

The vulnerable route joins and resolves the path without enforcing the allowed
root. The protected route requires the resolved path to remain below that
root. An outer fixture boundary prevents even the intentionally vulnerable
route from reading outside the worker-owned temporary fixture.

The symlink oracle is unevaluated with an explicit `symlink_unavailable` or
`symlink_disabled_by_test_parameters` limitation when it cannot run.

## IDOR/BOLA Oracles

Each authorization fixture creates:

- `user_a` and `user_b`;
- `tenant_a` and `tenant_b`;
- two same-tenant resources with different owners;
- one resource owned by `user_a` in the other tenant.

It checks:

- legitimate owner read;
- legitimate owner modification;
- foreign-owner read and modification;
- cross-tenant read and modification;
- final state for the foreign-owner and cross-tenant resources;
- returned owner and tenant evidence.

All requests contain an authenticated user. The vulnerable fixture checks only
authentication; the protected fixture separately enforces owner and tenant
authorization. This prevents an authentication success from being
misrepresented as an authorization decision.

## Isolation Boundary

The worker provides process separation and a narrow application protocol. It
does not claim to be a complete operating-system sandbox.

The worker enforces:

- `spawn` process creation;
- a daemon child that cannot create another multiprocessing child;
- hard timeout, terminate, and kill fallback;
- strict request and response sizes and schemas;
- a minimal environment containing temporary-directory settings, Python
  runtime flags, a worker marker, and Windows system-root values when needed;
- a worker-owned temporary directory and working directory;
- a closed registry with no caller-controlled import or path;
- guards on ordinary socket connect/bind/listen/send, DNS lookup, subprocess,
  asyncio subprocess, `os.system`, and `os.popen` APIs;
- normalized errors without exception text or tracebacks in the protocol.

The worker still runs as the invoking operating-system user. Trusted BELIEF
fixture code could theoretically bypass Python-level guards through native
code, direct system calls, or an unguarded API. The worker does not use OS
containers, seccomp, AppContainer, namespaces, a restricted token, or a
separate account. Consequently, only reviewed built-in fixtures belong in the
registry; arbitrary target code must never be added through this interface.

Capability attestation reports the Python-level guards and local client
actually used. For a crash or hard timeout, child-side attestation is
unavailable rather than guessed.

## Timeout and Crash Behavior

The timeout includes process startup, optional framework import, fixture
execution, serialization, and response receipt. At the deadline the parent:

1. terminates the worker;
2. waits for shutdown;
3. uses `kill()` as a fallback when available;
4. returns a normalized `timed_out` response.

A non-zero exit or missing response returns a normalized `crashed` response.
An invalid or mismatched response returns `inconclusive`. All three retain
baseline `null` and contain no security verdict.

## Windows and Linux

- Both platforms use `spawn`; the implementation does not depend on `fork`.
- Windows may require Developer Mode or suitable privileges for symlink
  creation. Failure is an explicit limitation, not a failed security oracle.
- The child leaves its temporary working directory before cleanup so Windows
  can remove it deterministically.
- FastAPI uses the direct ASGI transport on both platforms. This avoids the
  loopback socketpair that an asyncio test client may create on Windows.
- Path labels in evidence are logical POSIX-style fixture labels, not host
  absolute paths.

## Optional Dependencies

Flask and FastAPI are optional:

```bash
python -m pip install -e ".[web-validation]"
```

The extra installs:

- `Flask>=3.0,<4`;
- `fastapi>=0.115,<1`.

If the selected framework is absent or outside the supported version range,
the worker returns `unsupported` with an
`optional_dependency_unavailable` error. The existing runner converts that
to an explicit abstention (`inconclusive`), never a false security failure.

## Python Integration

Given an existing canonical plan:

```python
from belief.validation.worker import run_isolated_web_validation_plan

result = run_isolated_web_validation_plan(
    plan,
    fixture_id="flask_path_traversal_protected_v1",
    source_revision="fixture-source-v1",
    timeout_ms=5_000,
)
```

The returned object is the normal `ValidationResult`. Its
`metadata["execution"]` is the normal versioned `ValidationExecutionSummary`.
The meanings of `bypassed`, `enforced`, `inconclusive`, tri-state baseline, and
metrics v2 are unchanged.

## Verification

Run the targeted worker coverage:

```bash
python -m pytest -q \
  tests/test_isolated_web_worker_contracts.py \
  tests/test_isolated_web_worker_safety.py \
  tests/test_isolated_web_validation.py
```

Run the complete required gates:

```bash
python -m pytest -q -m security
python -m pytest -q -m "not slow and not external and not llm"
python -m ruff check belief tests
python -m pip check
git diff --check
```

When an optional framework is absent, framework-specific tests skip and the
runtime produces an explicit abstention.

## Limitations

- Only the eight registered miniature applications are supported.
- No arbitrary project application or untrusted application code is loaded.
- The worker does not prove exploitability outside its transparent fixtures.
- Python-level capability guards are not a system sandbox.
- Hard termination cannot recover child-side capability attestation.
- Timing is observational and is excluded from deterministic security evidence.
- The worker has no CLI artifact bundle yet; the current integration is a
  Python runner API.

## Why MCP Is Unchanged

The current MCP is intentionally read-first and does not expose dynamic
validation. Adding `belief_validate_plan` would change its capability and
threat model. That change should be a separate review that defines:

- an explicit MCP opt-in;
- exact fixture and timeout allowlists;
- user-visible execution confirmation;
- worker-result retention and resource contracts;
- cancellation and concurrency limits;
- capability and abstention presentation;
- tests proving that arbitrary targets, paths, URLs, adapters, and imports
  remain unreachable.

Until those contracts are reviewed, MCP can build and explain plans but cannot
start this worker.
