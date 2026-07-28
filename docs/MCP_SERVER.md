# BELIEF local MCP server

## Status

BELIEF includes an experimental MCP v0.1 facade for local Codex dogfooding:

```powershell
python -m belief.mcp.server
```

The server uses newline-delimited JSON-RPC over standard input/output. It has no
dependency on an MCP SDK, so the repository's offline installation contract is
unchanged. Domain operations delegate to BELIEF's existing static-analysis,
validation-planning, and transparent-benchmark services.

This is a local, read-first integration surface. It is not a public remote MCP
service and does not make static findings equivalent to confirmed
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
to its current working directory. Relative `workspace` tool arguments are
resolved under this fixed root; resolved paths outside it are rejected.

Codex loads MCP configuration at startup. Restart the Codex session after
adding or changing the server entry.

## Tools

The v0.1 surface is deliberately closed:

| Tool | Operation |
| --- | --- |
| `belief_status` | Return versions, schemas, supported verticals, and boundaries. |
| `belief_scan` | Run the existing local static pipeline in audit mode. |
| `belief_get_case` | Return one complete `AuditCase` from an in-memory run. |
| `belief_explain_case` | Project candidate evidence into deterministic explanation fields. |
| `belief_build_validation_plan` | Build the canonical plan without executing it. |
| `belief_compare_runs` | Compare audit cases from two runs of the same resolved target. |
| `belief_run_local_benchmark` | Run only the transparent `local_validation_v2` corpus. |

All tools are annotated as read-only, non-destructive, idempotent, closed-world
operations. Tool results include both structured content and an equivalent JSON
text block for client compatibility.

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
200. Scan runs and generated plans are kept in process memory; the oldest run
is evicted after 32 stored runs. The store retains run summaries, normalized
audit cases, and explicitly generated plans, not source text or the complete
analysis payload.

## Resources

Static resources:

```text
belief://status
belief://capabilities
belief://schemas/audit-case
belief://schemas/validation-plan
belief://schemas/validation-result
```

Resources created for each scan:

```text
belief://runs/{run_id}
belief://runs/{run_id}/audit-cases
belief://runs/{run_id}/validation-plans
belief://runs/{run_id}/validation-results
```

The validation-results resource is intentionally empty in v0.1 because MCP
does not expose dynamic plan execution.

## Enforced boundary

MCP v0.1 does not expose:

- network access;
- subprocesses or shell commands;
- Docker;
- arbitrary Python imports or adapters;
- target-file writes;
- server startup for a target;
- validation-plan execution;
- arbitrary file reads;
- SusVibes holdout access;
- a `confirmed_vulnerability` verdict.

Directories named `benchmark_susvibes` are excluded by the common Python parser
and rejected as direct MCP scan targets. The benchmark tool binds to the
repository's exact `benchmark_validation/cases.json` file and accepts no path
argument.

An `AuditCase` remains candidate evidence. A case reported as resolved by
`belief_compare_runs` is absent from the later static case set; that alone does
not prove that a vulnerability was fixed.

## Deferred surface

`belief_validate_plan`, report export, and feedback writes remain deferred until
an isolated worker and an allowlisted fixture registry have a separately
reviewed boundary. Generic execution, patching, merging, remote MCP transport,
and ChatGPT publication are outside v0.1.

Protocol references:

- [MCP standard input/output transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)
