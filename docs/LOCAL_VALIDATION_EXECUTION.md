# Local validation execution

## Status and scope

BELIEF now provides an experimental, deterministic execution layer for exactly
two audit-case families:

- `path_traversal_possible`;
- `idor_bola_possible`.

The data flow is:

```text
AuditCase
  -> belief.validation_plan.v1
  -> LocalValidationExecutor
  -> belief.validation_result.v1
  -> belief.validation_metrics.v1
```

This layer does not import or exploit an arbitrary application. It evaluates
trusted, explicitly registered Python fixtures with harmless local sentinels.
All other case types remain unexecuted and return `inconclusive`.

## Threat model

The engine assumes that:

1. the validation-plan bundle was produced from an authorized, pinned source;
2. the fixture definition is reviewable and contains no production data;
3. any process-local custom callable was explicitly registered by trusted
   benchmark or test code;
4. the operating system and Python runtime are trusted.

The engine defends against accidental scope expansion by enforcing these
boundaries:

- no import path is accepted from JSON;
- no dynamic module discovery is performed;
- no server is started;
- no socket, HTTP client, subprocess, shell, or Docker API is called;
- no target repository is imported into the BELIEF process;
- outputs and fixture bundles are create-only;
- path reads are limited to the temporary sandbox created by the executor;
- IDOR/BOLA state contains fixed synthetic users and resources only;
- plan identity, canonical content, fixture identity, source revision, and
  SHA-256 digests are retained in every result.

A custom callable supplied directly through
`ValidationExecutionContext.adapter_registry` runs in the current Python
process and is therefore a trusted extension point. JSON artifacts cannot
populate that registry. Untrusted repositories require a future isolated
adapter, not this interface.

## Execution contracts

The public execution objects are versioned:

| Contract | Schema |
|---|---|
| `ValidationExecutionContext` | `belief.validation_execution_context.v1` |
| `ValidationObservation` | `belief.validation_observation.v1` |
| `ValidationExecutionSummary` | `belief.validation_execution_summary.v1` |
| fixture bundle | `belief.validation_fixture_bundle.v1` |
| result bundle | `belief.validation_result_bundle.v1` |
| metrics | `belief.validation_metrics.v1` |

The existing `belief.validation_result.v1` schema remains unchanged. Execution
provenance is stored in `ValidationResult.metadata`, including:

- `validation_plan_id` and full plan digest;
- original `subject_id`;
- validation type and strategy;
- source revision or fingerprint;
- fixture identifier and digest;
- functional baseline verdict;
- attempted and evaluated counterexamples;
- evaluated oracle count and observation identifiers;
- limitations;
- deterministic cost in local operations;
- the complete execution summary.

Real elapsed time is intentionally excluded from semantic artifacts. The local
operation count is stable across identical executions and therefore supports
reproducible cost comparisons.

## Path traversal fixture

The executor creates only:

```text
sandbox/
├── allowed/
│   ├── nested/
│   └── public.txt
└── outside/
    └── sentinel.txt
```

It then evaluates:

1. `public.txt`;
2. `../outside/sentinel.txt`;
3. `nested/../../outside/sentinel.txt`;
4. the absolute temporary sentinel path;
5. `allowed/linked-sentinel.txt` when the platform permits symlinks.

The functional oracle requires `allowed/public.txt` to remain readable. The
security oracle fails when a controlled input resolves to or reads the
temporary outside sentinel. Before any read, the executor verifies that the
candidate remains inside the temporary sandbox; a custom adapter returning a
real external path is blocked by the engine and produces `inconclusive`.

`path_resolve_enforced` demonstrates an enforced boundary.
`path_join_unchecked`, `path_guard_after_sink`, and
`path_sanitizer_result_unused` are transparent negative controls. The latter
two prove that a late guard or an ignored sanitizer result cannot turn a
dynamic bypass into an enforced result.

## IDOR/BOLA fixture

The executor keeps the authenticated identity fixed as `user_a` in
`tenant_a`. It recreates an in-memory store for every scenario:

- `resource_a`: owned by `user_a` in `tenant_a`;
- `resource_b`: owned by `user_b` in `tenant_a`;
- `resource_c`: owned by `user_a` in `tenant_b`.

It evaluates:

1. read own resource;
2. update own resource;
3. read another user's resource;
4. update another user's resource;
5. delete another user's resource;
6. read an own-identity resource from another tenant;
7. update an own-identity resource from another tenant.

The functional oracle requires the owner to retain expected access. The
authorization oracle requires every foreign operation to be denied before
disclosure or mutation. Write and delete attempts also receive a separate
state oracle. A `403` returned after mutation therefore remains a bypass.

The negative-control adapters cover authentication without authorization,
tenant-only checks, owner-only checks, an owner check on the wrong resource,
and a guard evaluated after the operation.

## Outcome semantics

`validated_candidate` is existing generic BELIEF evidence. It may represent
human review or another source, but it is not emitted by these local executors.

`bypassed` means all of the following are true:

1. the trusted local entrypoint was called;
2. the functional baseline passed;
3. at least one security oracle was evaluated;
4. that oracle observed the harmless outside sentinel, unauthorized
   disclosure, or unauthorized state transition.

The `ValidationExecutionSummary` constructor rejects a `bypassed` record that
does not satisfy these invariants. `bypassed` is still a locally validated
candidate, not a confirmed vulnerability in a real application. The result
sets `human_confirmation_required: true`.

`enforced` means the baseline passed and every evaluated mandatory security
oracle passed. `false_positive` additionally requires that the source
`AuditCase` was explicitly `false_positive_likely`; a sanitizer name or static
guard alone is never sufficient.

Human confirmation is a separate decision outside this engine. It requires
authorized reproduction against the intended revision, human review of the
entrypoint and oracle, and validation that the controlled fixture faithfully
models the real behavior.

## Accepting or rejecting a result

Accept a local result as reproducible evidence only when:

- the plan bundle digest and canonical plan pass verification;
- `validation_plan_id`, case type, fixture digest, and expected plan
  digest all match;
- the recorded source revision is the intended revision;
- the plan safety contract forbids network, production data, destructive
  actions, and scope expansion;
- the baseline is functional for `enforced`, `false_positive`, or `bypassed`;
- every claim is backed by an evaluated observation;
- no limitation invalidates the relevant oracle;
- repeated execution produces identical semantic JSON.

Return or retain `inconclusive` when:

- the case type has no registered executor;
- the fixture adapter is not explicitly registered;
- the entrypoint cannot be called reliably;
- a custom adapter returns an invalid result;
- the baseline fails;
- a mandatory counterexample cannot be evaluated;
- a candidate path leaves the temporary fixture root before a safe oracle can
  inspect it.

Symlink unavailability is recorded as a limitation. It does not invalidate the
other three mandatory path-boundary counterexamples.

## Reproducible CLI procedure

Build the non-executing plan bundle:

```bash
python scripts/build_validation_plans.py \
  --audit out/belief-audit.json \
  --output out/validation-plans.json
```

Create an explicit fixture bundle from reviewed plans:

```python
from belief.validation import (
    ValidationExecutionContext,
    load_validation_plan_bundle,
    write_validation_fixture_bundle,
)

_, plans = load_validation_plan_bundle("out/validation-plans.json")
contexts = [
    ValidationExecutionContext.for_plan(
        plan,
        fixture_id=f"reviewed-{plan.subject_id}",
        adapter=(
            "path_resolve_enforced"
            if plan.case_type == "path_traversal_possible"
            else "idor_owner_tenant_enforced"
        ),
        source_revision="sha256:REVIEWED_LOCAL_FIXTURE",
    )
    for plan in plans
]
write_validation_fixture_bundle(
    "out/validation-fixtures.json",
    contexts,
)
```

Run the exact plan/fixture pair:

```bash
belief validate-plan \
  --plan out/validation-plans.json \
  --fixture out/validation-fixtures.json \
  --output out/validation-results.json
```

The command returns zero even when a local bypass is observed. CI can opt into
failure with `--fail-on-bypass`. Contract errors and attempted overwrites
return exit code 2. The command never guesses an adapter.

## Metrics

The deterministic bundle summary defines:

- `plan_count`: all input plans;
- `supported_plan_count`: plans with a registered vertical executor;
- `executed_plan_count`: fixtures whose adapter was invoked;
- outcome counts for `enforced`, `bypassed`, `inconclusive`, and
  `false_positive`;
- `baseline_pass_count` and `baseline_failure_count`;
- `oracle_evaluated_count`: plans with at least one evaluated oracle;
- `evidence_gap_resolution_rate`: executed plans with at least one original
  evidence gap resolved by a verifiable observation, divided by executed
  plans;
- `protected_regression_count`: statically protected or likely-false-positive
  plans whose local security oracle was bypassed;
- `deterministic_cost_units`: total local fixture operations.

These metrics are not `SecPass`, do not use hidden benchmark tests, and cannot
support a Fable, Kimi, or leaderboard comparison.

## Local experimental benchmark

The transparent corpus at `benchmark_validation/cases.json` contains exactly
the requested vulnerable, protected, ambiguous, and trap fixture for both
verticals. Run:

```bash
python scripts/benchmark_local_validation.py \
  --output out/local-validation-benchmark.json
```

The current deterministic result is:

| Stage | Precision | Recall | Protected false positives | Abstention |
|---|---:|---:|---:|---:|
| static only | 0.500 | 1.000 | 2 | 0.000 |
| after `ValidationPlan` | 0.000 | 0.000 | 0 | 0.750 |
| after `ValidationResult` | 1.000 | 1.000 | 0 | 0.250 |

The plan stage abstains instead of presenting planned experiments as
confirmation. The result stage resolves evidence gaps for 6/8 cases (0.75);
the two intentionally unavailable entrypoints remain inconclusive. Functional
regressions are zero, and two identical executions produce the same semantic
digest.

## Limits and future boundary

- Built-in fixtures model behavior; they do not prove that a real application
  uses the same adapter.
- Flask and FastAPI test-client adapters are not auto-discovered in this
  version.
- Untrusted target code is never imported into the main process.
- Platform-dependent symlink support remains visible in limitations.
- No timing or performance claim is derived from deterministic operation
  counts.
- A future isolated worker may add reviewed Flask/FastAPI adapters, but it must
  preserve create-only artifacts, explicit registration, network denial, and
  the same oracle invariants.

See
[`examples/local_validation_chain.json`](examples/local_validation_chain.json)
for a complete `AuditCase -> ValidationPlan -> ValidationResult` artifact.
