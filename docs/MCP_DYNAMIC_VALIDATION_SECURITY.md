# MCP dynamic validation security model

## Scope

BELIEF MCP v0.2 exposes dynamic evidence only for transparent, first-party
fixtures in the immutable web-validation registry. The mechanism is an
isolated process with Python-level controls. It is not a secure sandbox,
arbitrary hostile-code containment, or complete operating-system isolation.

The evidence scope is exactly:

```text
registered_transparent_fixture_only
```

The feature does not dynamically validate an arbitrary Flask or FastAPI
project.

The separate flask-jwt-extended pilot is outside this dynamic execution scope.
It performs exact-source static preparation only and always abstains from
target execution. Its binding cannot be consumed by `belief_validate_plan`.

## Trusted components

- BELIEF first-party MCP and validation-worker code;
- the immutable fixture registry;
- the transparent Flask and FastAPI fixture sources;
- canonical `AuditCase`, `ValidationPlan`, and `ValidationResult` models;
- the local user who installed and started BELIEF.

Potentially malformed inputs include all JSON-RPC messages, request IDs,
cancellation reasons, MCP arguments, run/plan/fixture identifiers, timeouts,
stored in-memory state, child responses, and framework exceptions.

Out of scope are hostile native code, a compromised Python interpreter,
kernel-level isolation, malicious third-party wheels, and a complete OS
sandbox.

## Why ordinary scan plans cannot execute

`belief_scan` accepts a confined project path and produces candidate static
evidence. `belief_build_validation_plan` can build a canonical plan from that
evidence, but it does not attach an executable binding.

Running such a plan against a built-in fixture merely because both have the
same `case_type` would produce evidence about the fixture and falsely attribute
it to the scanned target. MCP therefore rejects every unbound plan.

Only `belief_prepare_validation_fixture` can create an executable binding. It
accepts one `fixture_id` and no source, path, module, callable, expression, URL,
adapter, host, port, or arbitrary plan.

## Trusted binding

The versioned binding is:

```text
belief.registered_fixture_binding.v1
```

It contains:

- binding kind;
- content-derived run ID and audit-case ID;
- exact fixture ID and case type;
- fixture-registry digest;
- fixture-source digest;
- canonical plan ID and digest;
- source revision;
- exact logical source-target digest;
- fixed creator `belief_prepare_validation_fixture`;
- fixed execution scope `registered_transparent_fixture_only`.

Preparation reads the hardcoded source-document manifest, computes the exact
digests, writes those documents only to a private temporary directory, runs the
existing static analyzer on that directory, generates a deterministic matching
case, and builds the canonical plan. Source text is not retained in the MCP run
store.

Execution reconstructs the canonical plan and recomputes every binding field
from the current registry. Any run, plan, case, fixture, registry, source,
revision, digest, creator, or scope mismatch stops before a normal result is
stored. Case-type-only matching is forbidden.

The worker independently attests its fixture registry, fixture source, plan,
and source revision. MCP compares that child attestation with the trusted
binding before projecting evidence.

## Local execution acknowledgement

The execution tool requires:

```json
"acknowledge_local_execution": true
```

Missing, false, numeric, string, or null values are rejected. This acknowledgement
remains required even when an MCP host has its own confirmation UI. BELIEF does
not use elicitation to request credentials or secrets.

The reviewed timeout range is 100 through 10,000 milliseconds. Boolean,
negative, fractional, string, and out-of-range values are rejected.

## Process and capability boundary

The tool invokes the hardened isolated web-validation worker. It does not
reimplement fixture execution.

The worker:

- resolves only a hardcoded registry entry;
- uses canonical bounded JSON bytes over one-way pipes;
- sanitizes the child environment;
- confines fixture filesystem access to a parent-owned temporary root;
- blocks network, shell, subprocess, and nested-process APIs;
- captures and sanitizes bounded stdout/stderr;
- enforces a hard timeout and best-effort optional POSIX resource limits;
- terminates, joins, closes, and removes parent-owned temporary state on every
  terminal path.

Exact controls and platform limitations are recorded in
[`ISOLATED_WEB_VALIDATION_SECURITY_REVIEW.md`](ISOLATED_WEB_VALIDATION_SECURITY_REVIEW.md).

## Concurrency and rate limits

Process-local bounds are:

- one concurrent validation worker;
- four in-flight JSON-RPC requests;
- 32 stored runs;
- 32 validation results per run;
- 128 validation results in total.

The executor queue cannot grow beyond the in-flight request bound. A second
validation while the capacity is occupied receives an actionable busy tool
error. It is not silently queued.

The run store holds deep copies. Repeated identical results replace the same
content-derived ID. Per-run and global insertion order define deterministic
eviction.

## Cancellation lifecycle

The stdio reader remains active while tool work runs in a bounded thread pool.
Active JSON-RPC request IDs map to thread-safe execution contexts and, once
created, to the worker handle.

A valid `notifications/cancelled` notification:

1. marks the active request cancelled;
2. cancels the current worker handle, or immediately cancels a handle registered
   after an early notification;
3. lets the worker lifecycle terminate/join the process and release its pipes
   and temporary root;
4. prevents a normal validation result from being stored;
5. suppresses the cancelled request's normal response.

Unknown, malformed, duplicate, completed, and late cancellation notifications
are ignored. `initialize` runs outside the cancellable executor. Completion and
cancellation are serialized so only one wins. On EOF or shutdown, the server
cancels all remaining execution contexts and waits for worker cleanup.

The transport serializes stdout writes with one lock and emits one complete
JSON object per line. Fixture output is captured in the child and never written
to MCP stdout. Duplicate active request IDs are rejected. Protocol errors remain
JSON-RPC errors; fixture, binding, busy, dependency, timeout, and policy failures
remain safe tool errors.

## Stored result boundary

The public MCP result contains only projected semantic evidence:

- result, run, case, plan, and fixture identifiers;
- trusted binding and plan/source digests;
- worker semantic digest;
- outcome and functional baseline;
- bounded observation projections;
- bounded limitations;
- fixed and attested execution boundaries;
- fixture-only evidence scope;
- maturity and human-confirmation boundary.

It does not retain source code, a complete environment, unrestricted
tracebacks, raw secrets, raw child output, or temporary paths.

Every result sets:

```text
target_vulnerability_confirmed = false
human_confirmation_required = true
human_confirmed = false
report_ready = false
confirmed_vulnerability = false
```

Allowed maturity is limited to:

- `candidate`;
- `statically_supported`;
- `locally_reproduced_on_registered_fixture`.

`locally_reproduced_on_registered_fixture` means that the registered fixture
ran with a valid functional baseline and evaluated local oracles. A `bypassed`
outcome describes that fixture's behavior only. An `enforced` outcome also
describes only that fixture. Neither establishes the behavior, reachability,
impact, deployment state, or reportability of an arbitrary target.

Target confirmation remains deferred to an explicitly authorized,
target-specific workflow and a human reviewer.

The first authorized-project pilot now provides the static half of that
workflow for one exact flask-jwt-extended revision. It requires an independent
startup grant and binds its plans to the complete source digest, but it
deliberately does not add a target execution harness. See
[`AUTHORIZED_PROJECT_PILOT.md`](AUTHORIZED_PROJECT_PILOT.md).

## Holdout and external-world exclusions

Fixture preparation reads only the fixed first-party registry documents.
SusVibes paths are neither accepted nor traversed. The feature opens no network
connection, arbitrary subprocess, shell, Docker session, public RPC, custom
adapter, or target server. It does not write target files. The one built-in
authorized-project pilot accepts no path, module, callable, or adapter
implementation and does not alter these dynamic-worker exclusions.
