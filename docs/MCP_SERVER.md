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

This is a local, fixture-bound integration surface. It is not a public remote
MCP service. Static findings and registered-fixture observations are not
confirmed vulnerabilities.

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
  "fixture_id": "flask_path_traversal_vulnerable_v1"
}
```

It resolves that ID through the immutable first-party registry, copies the
registry's inspectable source documents into a private temporary directory,
statically scans exactly those documents, generates a matching `AuditCase`,
builds a canonical `ValidationPlan`, and attaches
`belief.registered_fixture_binding.v1`.

It accepts no source, path, module, callable, URL, expression, adapter, plan
JSON, host, or port.

### Bound local validation

`belief_validate_plan` accepts exactly:

```json
{
  "run_id": "run_...",
  "plan_id": "vp_...",
  "fixture_id": "flask_path_traversal_vulnerable_v1",
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
```

Resources created for each run:

```text
belief://runs/{run_id}
belief://runs/{run_id}/audit-cases
belief://runs/{run_id}/validation-plans
belief://runs/{run_id}/validation-results
```

The process-memory store retains defensive copies of summaries, normalized
audit cases, generated plans, trusted bindings, and projected validation
results. It does not retain fixture source text, the complete static analysis,
the complete environment, raw child output, tracebacks, or temporary paths.

Limits are fixed:

- 32 stored runs;
- 32 validation results per run;
- 128 validation results across the server;
- one concurrent local validation;
- four in-flight JSON-RPC requests;
- no unbounded execution queue.

Repeated semantically identical validation produces the same content-derived
result ID and replaces the existing entry. Validation results use deterministic
insertion-order eviction; runs use deterministic least-recently-accessed
eviction.

## Concurrency and cancellation

The stdio reader is separate from tool execution. A bounded executor handles
requests, a lock serializes complete JSON-RPC response lines, and duplicate
active request IDs are rejected.

`notifications/cancelled` maps its `requestId` to an active execution. A valid
cancellation marks the request, cancels the worker handle, releases pipes and
temporary state through the worker lifecycle, stores no normal result, and
suppresses the normal response. Unknown, malformed, completed, or late
cancellations are ignored. `initialize` is handled synchronously and cannot be
cancelled. Server shutdown cancels every remaining active worker and waits for
cleanup.

Cancellation is best effort at the JSON-RPC boundary. It does not implement the
MCP tasks extension.

## Evidence boundary

Every dynamic result states:

```text
evidence_scope = registered_transparent_fixture_only
target_vulnerability_confirmed = false
human_confirmation_required = true
```

Allowed maturity values are `candidate`, `statically_supported`, and
`locally_reproduced_on_registered_fixture`. BELIEF never promotes an MCP result
to `human_confirmed`, `report_ready`, or `confirmed_vulnerability`.

`locally_reproduced_on_registered_fixture` means the built-in fixture completed
with a valid functional baseline and evaluated local security oracles. It says
nothing about whether an arbitrary Flask or FastAPI project has the same
behavior. See
[`MCP_DYNAMIC_VALIDATION_SECURITY.md`](MCP_DYNAMIC_VALIDATION_SECURITY.md) for
the threat model and lifecycle.

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

Directories named `benchmark_susvibes` are excluded by the common Python parser
and rejected as direct scan targets. The benchmark tool binds to the
repository's exact `benchmark_validation/cases.json` and accepts no path
argument. Fixture preparation reads only hardcoded first-party source
documents.

An `AuditCase` remains candidate evidence. A case reported as resolved by
`belief_compare_runs` is absent from the later static case set; that alone does
not prove that a vulnerability was fixed.

Protocol references:

- [MCP standard input/output transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)
