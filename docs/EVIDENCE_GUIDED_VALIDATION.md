# Evidence-guided validation plans

## Status

This document describes the experimental `belief.validation_plan.v1` sidecar.
The planner is deterministic, offline, and non-executing. It does not confirm a
vulnerability and does not replace human validation, a purpose-built local
harness, or end-to-end security tests.

## Problem

BELIEF already produces structured audit cases with source/sink evidence,
route context, defensive guarantees, reportability blockers, and human next
steps. The remaining gap is operational: downstream systems receive prose such
as "confirm whether the object identifier is attacker-controlled", but not a
machine-readable plan that states:

- which evidence is missing;
- which benign counterfactual inputs should be considered;
- which invariant or test oracle separates safe behavior from a bypass;
- which evidence must be captured;
- when validation should stop;
- which safety boundaries cannot be relaxed.

This patch introduces that missing contract without modifying the current audit
case schema or the frozen SusVibes benchmark artifacts.

## Research lineage

The design borrows four ideas from projects associated with the researchers
identified during BELIEF's outreach research:

1. **HyLLfuzz**: turn a reachability roadblock into a bounded target and input
   modification problem. BELIEF exports source, sink, ordered nodes, guard
   applicability, and truncation/rejection hints instead of immediately asking
   an LLM to invent a payload.
2. **SQLancer**: make the oracle explicit. A validation plan must define an
   expected invariant and a concrete failure signal; input generation alone is
   not evidence of a bug.
3. **BaxBench**: distinguish functional success from security success. Plans
   include baseline behavior and security counterfactuals so a future executor
   can require both functional non-regression and policy enforcement.
4. **SecPI**: preserve structured security reasoning. Plans and later
   `ValidationResult` records can become auditable training/evaluation traces
   without flattening the reasoning into an unstructured label.

The patch is an engineering interpretation of these ideas, not an
implementation or reproduction of any one research system.

### Technique deliberately deferred

FP-Predictor-style learned false-positive classification is valuable as an
experimental baseline, but it should not be the first integration. BELIEF does
not yet have enough independently validated runtime labels to train or assess a
classifier without learning its current heuristic errors. The validation-plan
and result loop creates those labels first; a learned prioritizer can then be
compared against the explicit evidence model in an ablation study.

## Data flow

```text
BELIEF audit JSON
    |
    v
build_validation_plans.py
    |
    v
belief.validation_plan_bundle.v1
    |
    +--> human validation
    +--> future pytest/local HTTP adapter
    +--> future mocked transport/database adapter
    +--> future bounded fuzzing or concolic adapter
    |
    v
belief.validation_result.v1
```

## Why a sidecar

The first version intentionally does not add `validation_plan` to `AuditCase`.
The public JSON contract is also captured in
`schemas/belief.validation-plan-bundle.v1.schema.json`. A sidecar provides three
advantages:

- existing JSON consumers and benchmark digests remain unchanged;
- plan quality can be evaluated independently from static detection quality;
- a failed or incomplete planner cannot accidentally upgrade an audit verdict.

After the schema and metrics are stable, the CLI can expose the same service as
an opt-in `belief validation plan` command or attach plan identifiers to audit
cases.

## Command

```bash
python scripts/build_validation_plans.py \
  --audit out/belief-audit.json \
  --output out/validation-plans.json
```

Outputs are create-only by default. Use `--overwrite` only for disposable local
artifacts.

## Plan contract

Each `belief.validation_plan.v1` record contains:

| Field | Meaning |
|---|---|
| `plan_id` | Stable content-derived identifier |
| `subject_id` | Original BELIEF `case_id` |
| `case_type` / `case_status` | Static classification being resolved |
| `strategy` | Validation family selected for the case |
| `objective` | Narrow question the plan is allowed to answer |
| `target` | File, line, source, sink, rule, CWE, and route context |
| `evidence_gaps` | Missing guarantees, dynamic evidence, or reportability blockers |
| `prerequisites` | Isolation, fixture, authorization, and baseline requirements |
| `stimuli` | Benign baseline and counterfactual input families |
| `oracles` | Expected invariant, failure signal, and evidence to capture |
| `reachability_hints` | Bounded typed source/sink, ordered nodes/edges, guards, and roadblocks |
| `stop_conditions` | Bounded termination rules |
| `safety` | Non-negotiable execution constraints |
| `result_contract` | Expected `belief.validation_result.v1` linkage to the original audit case, with `validation_plan_id` required in result metadata |

A validation result keeps the original audit-case identity in `subject_id`.
The stable `plan_id` is required in `ValidationResult.metadata.validation_plan_id`,
which preserves exact-case feedback compatibility while retaining plan provenance.

## Strategy families

### Path traversal

`property_guided_path_boundary` compares a valid in-bound path with benign
normalization and boundary counterfactuals. The primary oracle is whether every
accepted resolved path remains under a temporary allowed root.

### IDOR/BOLA

`stateful_authorization_differential` keeps the authenticated principal fixed
and changes only resource or tenant identity. It requires both a response
oracle and a state-invariant oracle so a hidden unauthorized update is not
missed.

### Command injection

`argument_boundary_differential` uses a recording process stub. The oracle
checks executable, argument vector, shell mode, and side-effect attempts rather
than launching a real command.

### SSRF

`mocked_network_policy_differential` requires fake DNS and HTTP transports. The
planner never authorizes a live request. The oracle is evaluated after parsing,
resolution, and redirects because pre-resolution string checks are
insufficient.

### SQL injection

`query_parameterization_differential` records the query template and bound
parameter vector. A mutation fails when it changes statement or operator
structure instead of remaining data.

### XSS

`contextual_output_encoding` parses an isolated rendered fragment and checks
whether an inert marker remains data in its actual output context.

### Unsafe deserialization

`safe_deserialization_policy` combines signature/type-policy observations with
stubbed file, process, and network side effects.

### Hardcoded secret

`secret_provenance_verification` performs only local provenance analysis using
redacted fingerprints. It explicitly forbids testing a value against an
external service.

### Protected and likely false-positive cases

`defensive_regression` verifies that a mined guarantee dominates the same sink,
checks the same value/resource, and preserves valid baseline behavior. A
static `protected` verdict is therefore treated as a hypothesis to regress, not
as permanent ground truth.

## Safety boundary

Every generated plan requires:

- explicit authorization;
- an isolated fixture and pinned revision;
- benign markers only;
- no production data;
- no real secrets;
- no destructive actions;
- no automatic scope expansion;
- network forbidden, or replaced by recording fakes for SSRF.

The planner itself reads JSON and writes JSON. It does not import an application,
start a server, execute a process, connect a socket, or mutate the target.

## Evaluation plan

The next experiment should measure the planner separately from the detector.
Suggested metrics:

1. **Plan coverage**: fraction of audit cases receiving a non-manual strategy.
2. **Oracle completeness**: fraction with at least one independently checkable
   functional or security invariant.
3. **Evidence-gap resolution**: fraction of gaps resolved by a returned
   `ValidationResult`.
4. **Validation precision**: confirmed bypasses divided by tested bypass claims.
5. **Protected-case regression rate**: proportion of static protected verdicts
   whose guard is not enforced at runtime.
6. **Inconclusive rate**: cases that cannot be reproduced without guessing.
7. **Cost**: wall time, executions, model calls, and human review time per case.
8. **Generalization**: freeze planner behavior on a development cohort and
   evaluate the reserved SusVibes holdout without tuning.

## Continuity roadmap

### Phase 1 - introduced by this patch

- versioned plans and bundle;
- deterministic IDs and digest verification;
- case-specific stimuli and oracles;
- create-only sidecar writer;
- explicit `ValidationResult` linkage with audit-case identity preserved;
- source-case and bundle digests for revision-aware provenance;
- a published Draft 2020-12 JSON Schema;
- unit, safety, tamper, and CLI tests.

### Phase 2 - local adapters

Implement opt-in executors that consume a plan and produce
`ValidationResult`. Executors should call
`validation_result_from_plan()` so the result remains attached to the original
`AuditCase` and records `validation_plan_id` in metadata:

- pytest function adapter;
- Flask/FastAPI test-client adapter;
- recording subprocess adapter;
- mocked HTTP/DNS adapter;
- SQLite/recording DB-API adapter.

Executors must be separate from planning and must enforce scope, budgets,
timeouts, and safety contracts.

### Phase 3 - evidence-guided reachability

Use ordered dataflow nodes and guard applicability to identify a specific
unreached branch. A local execution trace can then expose a bounded mutation
request to a solver or model, following the HyLLfuzz idea without allowing an
unbounded autonomous exploit loop.

### Phase 4 - oracle synthesis and metamorphic relations

Add versioned oracle templates and counterfactual transformations. Human or
LLM-generated oracles must be validated against negative controls to prevent
hallucinated invariants from becoming false vulnerability reports.

### Phase 5 - benchmark integration

On a frozen development/test split, compare:

- scanner alone;
- scanner plus reportability;
- scanner plus validation plans;
- scanner plus plans and local executors;
- agent repair with and without BELIEF feedback.

A leaderboard claim remains disallowed until the official benchmark harness,
functional tests, and end-to-end security exploits are executed under the same
protocol as the comparator.

## Primary research references

- Ruijie Meng, Gregory J. Duck, and Abhik Roychoudhury, *Large Language Model
  assisted Hybrid Fuzzing* (HyLLfuzz): https://arxiv.org/abs/2412.15931
- Manuel Rigger and the SQLancer contributors, SQLancer test generators and
  explicit test oracles: https://github.com/sqlancer/sqlancer
- Mark Vero et al., *BaxBench: Can LLMs Generate Correct and Secure
  Backends?*: https://arxiv.org/abs/2502.11844
- Hao Wang et al., *SecPI: Secure Code Generation with Reasoning Models via
  Security Reasoning Internalization*: https://arxiv.org/abs/2604.03587
- Tom Ohlmer, Michael Schlichtig, and Eric Bodden, *FP-Predictor - False
  Positive Prediction for Static Analysis Reports*:
  https://arxiv.org/abs/2603.10558

These works motivate reachability targets, explicit oracles, independent
functional/security evaluation, structured reasoning traces, and false-positive
triage respectively. BELIEF's sidecar is a new integration layer; it does not
claim to reproduce any of those systems.
