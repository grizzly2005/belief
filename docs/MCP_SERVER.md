# BELIEF local MCP server

## Status

BELIEF includes an experimental MCP v0.2 facade for local Codex dogfooding:

```powershell
python -m belief.mcp.server
```

The server uses newline-delimited JSON-RPC over standard input/output. It has no
dependency on an MCP SDK, so the repository's offline installation contract is
unchanged. Domain operations delegate to BELIEF's existing static-analysis,
validation-planning, transparent-benchmark, and isolated-worker services.

This is a local, fixture-bound integration surface with one separately
authorized, static-only real-project pilot. It is not a public remote MCP
service. Static findings and registered-fixture observations are not confirmed
vulnerabilities.

## Codex configuration

Use an absolute interpreter and checkout path in the Codex configuration. On
Windows, a repository-local virtual environment can be configured as follows:

```toml
[mcp_servers.belief]
command = "C:/absolute/path/to/belief/.venv/Scripts/python.exe"
args = ["-m", "belief.mcp.server"]
cwd = "C:/absolute/path/to/belief"
enabled = true
env = { BELIEF_MCP_WORKSPACE_ROOT = "C:/absolute/path/to/trusted/workspace" }
```

`BELIEF_MCP_WORKSPACE_ROOT` is optional. When omitted, the server confines scans
to its current working directory. Relative `workspace` arguments are resolved
under this fixed root; resolved paths outside it are rejected.

Codex loads MCP configuration at startup. Restart the Codex session after
adding or changing the server entry.

The flask-jwt-extended pilot additionally requires the two exact,
project-specific startup authorization variables documented in
[`AUTHORIZED_PROJECT_PILOT.md`](AUTHORIZED_PROJECT_PILOT.md). The pilot tool
does not accept a workspace path and cannot broaden the configured root.

## Tools

The v0.2 surface is closed:

| Tool | Operation |
| --- | --- |
| `belief_status` | Return versions, schemas, supported verticals, and boundaries. |
| `belief_scan` | Run the existing local static pipeline in audit mode. |
| `belief_get_case` | Return one complete `AuditCase` from an in-memory run. |
| `belief_explain_case` | Project candidate evidence into deterministic explanation fields. |
| `belief_build_validation_plan` | Build an unbound canonical plan without executing it. |
| `belief_prepare_validation_fixture` | Scan one exact registered fixture source and create a trusted bound plan. |
| `belief_prepare_authorized_project_pilot` | Verify and statically analyze the exact separately authorized flask-jwt-extended snapshot, then abstain from execution. |
| `belief_validate_plan` | Execute only a previously bound plan in the hardened local worker. |
| `belief_compare_runs` | Compare audit cases from two runs of the same resolved target. |
| `belief_run_local_benchmark` | Run only the transparent `local_validation_v2` corpus. |

All tools except `belief_validate_plan` are annotated read-only,
non-destructive, idempotent, and closed-world. Validation starts a local worker
and consumes CPU, so its `readOnlyHint` is false. It remains non-destructive,
idempotent, and closed-world. Background MCP tasks are not exposed.

Tool results include structured content and an equivalent JSON text block for
client compatibility.

### Static scans

`belief_scan` accepts only:

```json
{
  "workspace": "./target",
  "audit_mode": true,
  "reportability": true,
  "max_files": 200
}
```

`audit_mode` cannot be disabled through MCP. `max_files` is bounded from 1 to
200. A plan created from this scan is deliberately unbound and cannot be passed
to the dynamic validator.

### Registered-fixture preparation

`belief_prepare_validation_fixture` accepts exactly:

```json
{
  "fixture_id": "fx_01d7c2_v1"
}
```

It resolves that ID through the immutable first-party registry, copies the
registry's inspectable source documents into a private temporary directory,
and statically scans exactly those documents. Actual findings and `AuditCase`
objects from the authoritative pipeline are preserved.

An explicit `ValidationContractSeed` is stored separately from `audit_cases`
and may generate a canonical plan when no matching static case exists. Such a
plan has `static_support = false` and maturity `contract_prepared`; it cannot
become `statically_supported`. The preparation attaches
`belief.registered_fixture_binding.v2`.

It accepts no source, path, module, callable, URL, expression, adapter, plan
JSON, host, or port.

### Authorized real-project pilot

`belief_prepare_authorized_project_pilot` is bound in code to exactly:

```text
project = github.com/vimalloc/flask-jwt-extended
revision = 1910726f152016c3e48d61792983eebe11f54ac2
source_digest = 4e42c82b7d0a210350cc99fcc698e478f1b62b76785a413d40525b0555b70c52
```

It requires a separate startup grant, the same authorization ID in the tool
request, the exact revision and digest, and a literal access acknowledgement.
The grant is an explicit local-operator opt-in, not cryptographic authorization
or proof of project authority. The adapter reads and attests every source byte,
creates a private immutable snapshot from those bytes, verifies the snapshot,
analyzes the snapshot instead of the live workspace, and re-attests the live
workspace afterward. It creates
`belief.authorized_project_binding.v1` bindings with
`dynamic_execution_authorized = false`.

It accepts no path, module, callable, source, command, URL, host, port, or
adapter implementation. It never imports or executes the project. Every pilot
projection is `inconclusive` with `execution_status = abstained`. See
[`AUTHORIZED_PROJECT_PILOT.md`](AUTHORIZED_PROJECT_PILOT.md).

### Bound local validation

`belief_validate_plan` accepts exactly:

```json
{
  "run_id": "run_...",
  "plan_id": "vp_...",
  "fixture_id": "fx_01d7c2_v1",
  "timeout_ms": 5000,
  "acknowledge_local_execution": true
}
```

The acknowledgement must be the literal JSON boolean `true`. `timeout_ms` must
be an integer from 100 through 10,000. Before the worker starts, BELIEF
recomputes and compares:

- run and audit-case identity;
- plan ID and canonical plan digest;
- fixture ID and case type;
- fixture-registry digest;
- fixture-source digest;
- source-target digest;
- source revision;
- binding creator and execution scope.

A case-type match alone is never sufficient. The tool delegates execution to
the existing hardened worker; it does not implement a second execution path.

## Resources and storage

Static resources:

```text
belief://status
belief://capabilities
belief://schemas/audit-case
belief://schemas/validation-plan
belief://schemas/validation-result
belief://schemas/registered-fixture-binding
belief://schemas/authorized-project-binding
```

Resources created for each run:

```text
belief://runs/{run_id}
belief://runs/{run_id}/audit-cases
belief://runs/{run_id}/validation-plans
belief://runs/{run_id}/validation-results
```

Collection resources are paginated:

```text
belief://runs/{run_id}/audit-cases?cursor=0&limit=32
```

`cursor` is a zero-based integer and `limit` is at most 32. Responses include
`next_cursor` and `next_uri` when another page exists.

The process-memory store retains defensive copies of summaries, normalized
audit cases, generated plans, trusted fixture bindings, non-executable
authorized-project bindings, and projected validation results. It does not
retain fixture source text, the complete static analysis, the complete
environment, raw child output, tracebacks, or temporary paths.

Reviewed maxima are:

- 32 stored runs;
- 32 validation results per run;
- 128 validation results across the server;
- 512 cases per run;
- 64 KiB of canonical serialized data per case;
- 4 MiB of canonical serialized data per run;
- 16 MiB of canonical serialized store data;
- 64 MiB of accounted deep Python store memory;
- 32 collection entries per resource page;
- 512 KiB per MCP response;
- one concurrent local validation;
- four in-flight JSON-RPC requests;
- no unbounded execution queue.

Constructor configuration may lower storage limits. `belief_status` and
`belief://capabilities` publish the effective values rather than only global
maxima.

Repeated semantically identical validation produces the same content-derived
result ID and replaces the existing entry. Validation results use deterministic
insertion-order eviction; runs use deterministic least-recently-accessed
eviction.

At the JSON-RPC boundary, each input line is limited to 1 MiB in both
characters and UTF-8 bytes. JSON is rejected above depth 12, 4,096 nodes, 128
items per collection, 4,096 characters per string, or 256 characters for a
string request ID. Duplicate keys, non-finite numbers, malformed Unicode,
excess recursion, and oversized responses are rejected.

## Concurrency and cancellation

The stdio reader is separate from tool execution. A bounded executor handles
requests, a lock serializes complete JSON-RPC response lines, and duplicate
active request IDs are rejected.

`notifications/cancelled` maps its `requestId` to an active execution. For
`belief_validate_plan`, a valid cancellation marks the request, cancels the
worker handle, releases pipes and temporary state through the worker lifecycle,
stores no normal result, and suppresses the normal response. Unknown,
malformed, completed, or late cancellations are ignored. `initialize` is
handled synchronously and cannot be cancelled. Server shutdown cancels every
remaining active worker and waits for cleanup.

The active cancellation scope is `dynamic_validation_only`. For non-worker
tools, cancellation suppresses the eventual response but may not stop internal
computation. It does not implement the MCP tasks extension.

## Evidence boundary

Every dynamic result states:

```text
evidence_scope = registered_transparent_fixture_only
target_vulnerability_confirmed = false
human_confirmation_required = true
```

Fixture results use `contract_prepared`, `candidate`,
`statically_supported`, and `locally_evaluated`. BELIEF never promotes an MCP
result to `human_confirmed`, `report_ready`, or
`confirmed_vulnerability`.

`statically_supported` requires a real matching `AuditCase` produced by the
authoritative pipeline; a synthetic contract seed is insufficient.
`locally_evaluated` requires a completed built-in fixture, a passing required
functional baseline, and at least one evaluated primary security oracle.
Required unevaluated security evidence forces abstention. It says nothing about
whether an arbitrary Flask or FastAPI project has the same behavior. See
[`MCP_DYNAMIC_VALIDATION_SECURITY.md`](MCP_DYNAMIC_VALIDATION_SECURITY.md) for
the threat model and lifecycle.

Timeout, missing dependency, policy violation, child crash, and malformed child
response are stored as `inconclusive` abstentions with worker status and error
codes. Explicit cancellation, binding errors, and malformed caller requests do
not store a normal result.

The real-project pilot has a different, non-executable evidence scope:

```text
evidence_scope = authorized_real_project_static_only
outcome = inconclusive
execution_status = abstained
target_vulnerability_confirmed = false
human_confirmation_required = true
```

Its plans cannot enter the hardened worker. The ordinary fixture-only dynamic
scope remains unchanged.

## Enforced exclusions

MCP v0.2 does not expose:

- external network access;
- shell commands or arbitrary subprocesses;
- Docker;
- arbitrary Python imports, modules, callables, or adapters;
- target-file writes;
- target-server startup;
- arbitrary-plan execution;
- arbitrary fixture definitions;
- SusVibes holdout access;
- a confirmed-vulnerability verdict.

Capability resources state the actual behavior explicitly:

```text
worker_process_spawn = true
target_process_spawn = false
allowlisted_framework_imports = true
caller_controlled_imports = false
temporary_fixture_writes = true
target_workspace_writes = false
live_network_target_allowed = false
```

Directories named `benchmark_susvibes` are excluded by the common Python parser
and rejected as direct scan targets. The benchmark tool binds to the
repository's exact `benchmark_validation/cases.json` and accepts no path
argument. Fixture preparation reads only hardcoded first-party source
documents.

The one real-project pilot is a hardcoded first-party adapter, not a custom
adapter surface. It checks the exact revision and complete source digest twice,
uses no Git subprocess, and never grants dynamic execution.

An `AuditCase` remains candidate evidence. A case reported as resolved by
`belief_compare_runs` is absent from the later static case set; that alone does
not prove that a vulnerability was fixed.

Protocol references:

- [MCP standard input/output transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)
