# BELIEF generalization protocol

Protocol version: 1

Preregistered: 2026-07-25, before reviewer implementation changes

Status: development authorized; reserved test sealed

This protocol governs the next BELIEF reviewer experiment. It is intentionally
stricter than the existing benchmark runner. A result that violates this
protocol is an engineering observation, not a score-bearing result.

## Frozen starting point

| Item | Frozen value |
|---|---|
| Authoritative checkout | `C:\Users\tatam\Desktop\projects\belief-v4` |
| Branch at registration | `main` |
| Reviewer starting commit | `c0263023d65cfef4ac577da4a85a72a3aeda462b` |
| `origin/main` at registration | `c0263023d65cfef4ac577da4a85a72a3aeda462b` |
| Research-only commit | `02f7436919b649ab66396f3443fc8ae7653bd375` |
| Baseline BELIEF Python files | 836 |
| Baseline reviewer source SHA-256 | `16eace68f2753bb11b64e5cd0f57cd9dd1ea9eabf4afa3290286dd38da2a6d2b` |
| Source normalization | relative POSIX path, NUL, SHA-256 of LF-normalized bytes |
| Python | CPython 3.12.10 in repository `.venv` |
| Z3 | `z3-solver` 4.16.0.0 / Z3 4.16.0 |
| Test runner | pytest 9.0.2 |
| Linter | Ruff 0.15.16 |
| Operating system | Windows 11, build family 26200 |

The documentation commit does not change the baseline reviewer source digest.
All implementation comparisons use `c026302...` as architecture variant A,
not the documentation commit.

## Baseline verification

The following checks were run before reviewer implementation:

| Check | Result | Status |
|---|---:|---|
| Dependency consistency (`pip check`) | no broken requirements | PASS |
| Full local pytest | 755 passed, 31 skipped | PASS |
| Security-marked pytest | 301 passed, 485 deselected | PASS |
| CI-equivalent local pytest filter | 755 passed, 31 skipped | PASS |
| Ruff on `belief`, `scripts`, `tests` | all checks passed | PASS |
| First-party Python compile | successful | PASS |
| Broad repository compile | legacy/vendored Python 2 and example files fail on Python 3 | EXPECTED / NOT A FIRST-PARTY PASS |
| GitHub Actions at starting commit | 300 security tests passed, one nested-split test failed on Linux Python 3.11 | FAIL |

The GitHub failure is
`test_nested_split_is_deterministic_and_cwe_balanced`: one side of a synthetic
split covered four primary CWE strata while the test required five. This is a
known baseline defect. It must be corrected with a deterministic,
platform-independent allocation invariant and regression test; it must not be
hidden by deleting the assertion or weakening the intended split contract.

## Dataset and split seal

The evaluator-side inputs are:

| Item | Frozen value |
|---|---|
| SusVibes upstream commit | `66d305a7a8541f4faa245171b359a6b0d141941e` |
| Dataset records / projects / CWE labels | 186 / 101 / 81 |
| Dataset SHA-256 | `be9a4ca573559544c3f28146b3b3811e5565f0a8b4053ff4cc8f4aab6c6742f7` |
| Nested manifest | `belief-susvibes-v1-nested-dev-test-20260725-01.json` |
| Nested manifest file SHA-256 | `74d916df62428882ae89cc46d10b9d14c01831a6e60826b317cbb77e3ae6631b` |
| Nested manifest semantic digest | `668b247f6bbe811ece6ae5db07213bab62dadf52c6c0931ea4f5ab6b054a878b` |
| Development cohort | 49 cases |
| Development ordered-ID SHA-256 | `a047a3218e878f504cbaf3c583012269d2e646581d5f77bf2b1977b6f6501307` |
| Reserved test cohort | 49 cases |
| Reserved ordered-ID SHA-256 | `0de4d776ee5b957a37dab6e14bf4f41d18762eaac23c30c4b1c7f89abd938db4` |
| Parent baseline artifact SHA-256 | `e61cb04ad782adff20432d29438d16f4be308f0af356d06e3115ed4acd27884a` |
| Parent baseline semantic digest | `3ff42acf6fdc5480a3fc150c990f09b59866a28f5668080ce7925095fae3f5d4` |

The individual 49 reserved IDs, source files, functions, patches, labels,
warnings, and results are forbidden inputs until formal unsealing. Only the
count and cryptographic digests above may be used during development.

The 49 development cases may be reconstructed and inspected solely through the
evaluator. Development diagnosis may use evaluator-side metadata, but
production reviewer code may not.

## Reviewer/evaluator boundary

The reviewer may receive:

- one candidate worktree;
- the candidate's ordinary Git diff;
- reviewer configuration and explicit resource limits;
- optional external-tool evidence generated from that same candidate, with
  provenance and no benchmark metadata.

The reviewer must never receive:

- `golden_patch`, `security_patch`, `test_patch`, or `mask_patch`;
- hidden functional or security tests or their results;
- benchmark CWE/CVE labels, task names, project names, or instance IDs;
- the upstream repository's history beyond the candidate worktree;
- prior benchmark run results;
- corrected source as an oracle;
- a path whose name reveals a result, cohort outcome, or reference fix.

The evaluator may use the frozen dataset and manifest to reconstruct
candidates, localize scoring, and compute metrics. Evaluator-only data must not
be imported by or serialized into reviewer models.

Production rules and summaries must pass a contamination scan rejecting:

- SusVibes instance-ID shapes and literal IDs;
- benchmark project/repository names;
- CVE identifiers and task-specific CWE labels;
- exact reference-patch fragments;
- local dataset, cache, manifest, and result paths;
- known output digests when they are used as decision rules.

Marked benchmark adapters, fixtures, and documentation may contain provenance
needed to reproduce an experiment. The scan must distinguish those from
production analysis code.

## Development question

Can a benchmark-independent semantic layer raise oracle-free paired
discrimination on the 49-case development cohort to at least 30%, while
retaining vulnerable-candidate warning recall of at least 30%, secure-candidate
false positives at or below 25%, deterministic output, bounded analysis, and no
regression in existing causal tests?

The hypothesis is that most missed pairs arise from a small number of
transversal semantic gaps—especially wrapper/interprocedural flow,
value-specific guards/state transitions, and weak before/after finding
identity—rather than a need for dozens of task-specific rules.

## Development sequence

### Phase 1: failure attribution

Run only the 49 development cases with the baseline reviewer. For each
candidate pair, emit `belief.generalization_failure_report.v1` with:

- first failed stage;
- stages blocked by that failure;
- available and missing evidence;
- file and function location, if independently found by the reviewer;
- semantic primitive needed;
- whether one general fix could cover other projects/families;
- overfitting risk and estimated implementation cost.

Every report uses exactly one primary category from this frozen vocabulary:

1. `candidate_reconstruction_failure`
2. `parse_failure`
3. `unsupported_language_or_syntax`
4. `changed_file_not_selected`
5. `changed_function_not_selected`
6. `source_not_recognized`
7. `sink_not_recognized`
8. `local_flow_missing`
9. `interprocedural_flow_missing`
10. `receiver_or_field_flow_missing`
11. `alias_flow_missing`
12. `callback_or_decorator_flow_missing`
13. `guard_not_recognized`
14. `guard_wrong_value`
15. `guard_wrong_resource`
16. `guard_after_sink`
17. `guard_not_dominating`
18. `sanitizer_return_unused`
19. `sanitizer_wrong_context`
20. `state_transition_not_modeled`
21. `finding_focus_mismatch`
22. `finding_identity_mismatch`
23. `vulnerable_and_secure_same_warning`
24. `secure_candidate_false_positive`
25. `vulnerable_candidate_false_negative`
26. `inconclusive_evidence`
27. `evaluator_or_infrastructure_failure`

Aggregate reports by frequency, score impact, project count, weakness-family
count, and transversality. Do not modify the reviewer until attribution is
complete.

### Phase 2: cluster selection

Select at most three architecture clusters. A cluster is eligible only if:

- it occurs in multiple development projects;
- it is expressed as a reusable semantic primitive;
- its definition contains no benchmark identifier, project name, or reference
  patch text;
- at least three positive and three negative synthetic examples can be written
  before implementation;
- a protected mutation can falsify an overly broad version.

Selection is based on the attribution report, not on whether an exact patch is
easy to memorize.

### Phase 3: bounded architecture cycles

At most three development architecture cycles are allowed:

1. summaries and explicit gap diagnostics;
2. flow states, resource/control identity, and guard effects;
3. evidence graph plus semantic before/after comparison.

A cycle may refine the same general primitive but may not introduce a new
task-specific production rule. Documentation, tests, instrumentation, and
generic bug fixes do not consume a cycle unless they change reviewer verdicts.

After the third cycle, development stops even if thresholds are missed. The
negative result is published and the reserved cohort remains sealed.

## Semantic contracts

The implementation will use versioned, composable records:

- `belief.function_summary.v1`
- `belief.semantic_evidence_graph.v1`
- `belief.generalization_failure_report.v1`
- `belief.holdout_attestation.v1`

`FunctionSummary` supports at least:

- identity and constant;
- passthrough or transformed argument;
- sanitizer, validator, predicate guard, and abortive guard;
- source, sink, and wrapper;
- receiver/field read and write;
- collection insert and extract;
- return derived from parameter or receiver;
- explicit unknown.

Summary propagation uses a bounded call graph, strongly connected components,
and bounded fixed-point iteration. The exact maximum call depth, graph nodes,
iterations, and summaries are configuration and result fields. Hitting a limit
produces an `AnalysisGap`; it never silently converts to "no finding."

Flow states are implemented only for the selected development clusters. A
transition is valid only when it applies to the same value or resource, in the
same security context and relevant control-flow path, before the sink, and
with the sanitizer/validator return value used where required.

`EvidenceGraph` contains deterministic nodes and edges for source, call,
argument, receiver/field, collection, transform, guard, sanitizer, state
transition, sink, and gap evidence. Its digest excludes elapsed time and
machine-specific absolute paths.

Semantic pair comparison classifies each root cause as:

- `resolved`
- `residual`
- `introduced`
- `shifted`
- `partially_mitigated`
- `inconclusive`

`inconclusive` never counts as a secure pass.

## Metamorphic and anti-overfit requirements

Each new primitive must include at least:

- three positive variants;
- three negative variants;
- reordered guard/sink statements;
- a guard on the wrong value;
- a guard on the wrong resource;
- a bypass branch;
- an unused sanitizer return;
- a simple interprocedural wrapper;
- harmless identifier, formatting, and helper-name changes.

Expected metamorphic properties include:

- alpha-renaming does not change the verdict;
- moving an effective guard after the sink invalidates protection;
- changing the guarded resource invalidates protection;
- adding an unguarded bypass retains the finding;
- extracting a helper preserves the semantic identity;
- a secure unrelated edit does not erase a residual root cause;
- changing only absolute temporary paths does not change the evidence digest.

No production primitive may be merged without a scan for forbidden benchmark
tokens and exact local artifact paths.

## Frozen ablations

The following variants will be measured on the same ordered 49-case
development cohort:

| ID | Variant |
|---|---|
| A | Starting reviewer at `c026302...` |
| B | A plus structured diagnostics only; verdicts unchanged |
| C | B plus bounded function summaries only |
| D | B plus flow states/guard effects only |
| E | B plus EvidenceGraph and semantic comparison only |
| F | Full selected semantic architecture |
| G | F plus optional pinned passive CodeQL evidence, only if a prior POC proves multi-family value |

Variant G is optional. CodeQL absence, build failure, or unsupported language
may add a gap but must not downgrade a BELIEF verdict. If the POC does not
improve more than one family or cannot be reproduced offline, G is recorded as
rejected rather than omitted.

Each ablation records:

- selected, evaluable, and infrastructure-error counts;
- vulnerable warning recall;
- secure-candidate false-positive rate;
- paired discrimination;
- warning precision and F1 where labels permit evaluator-side calculation;
- file, function, source, sink, and guard localization;
- evidence-graph completeness and gap counts;
- median and total elapsed time, peak memory, graph nodes, and limit hits;
- deterministic semantic digest across two runs;
- changed production lines, files, and rule/summary counts.

The denominator, task order, thresholds, and success definitions remain fixed.
There is no `pass@k`, selective-success, or post-hoc family filtering.

## Preregistered development gates

Variant F must satisfy all gates:

| Gate | Threshold |
|---|---:|
| Vulnerable-candidate warning recall | at least 30% |
| Secure-candidate warning false-positive rate | at most 25% |
| Paired warning discrimination | at least 30% |
| Existing causal test regressions | zero |
| New false protected metamorphic mutations | zero |
| Deterministic development runs | two identical semantic results |
| Median analysis time | below 2.0 times baseline, unless a specific measured reason is documented |

Passing the percentage gates while changing the denominator, excluding failures,
or losing determinism is a failure.

If any gate fails after three cycles:

- publish the negative development result;
- preserve all ablations and failure categories;
- do not lower a threshold;
- do not run or inspect the reserved cohort;
- use only synthetic or a newly preregistered public development corpus for
  further architecture work.

## Rule-explosion stop rule

Stop adding production behavior when any of these becomes true:

- the proposed condition names or fingerprints one benchmark task/project;
- the primitive has evidence from only one project and one weakness family;
- an exact source snippet is required for recognition;
- more than three new production special cases are proposed in one cycle;
- production-rule growth exceeds the measured generalization gain;
- protected mutations expose a new false-negative or false-protection pattern;
- a simpler summary/state/graph abstraction explains the same evidence;
- the third architecture cycle is complete.

The allowed response is to emit an explicit analysis gap, not to keep expanding
a monolithic pattern list.

## Freeze and reserved-test unsealing

Unsealing is allowed only after all development gates pass. A new
`belief.holdout_attestation.v1` file must be created—never overwritten—and must
prove:

1. the Git worktree is clean;
2. `HEAD` is the explicitly named local freeze commit;
3. the freeze commit descends from the preregistered starting commit;
4. the canonical BELIEF source digest equals the attested digest;
5. dataset file hash and manifest file/semantic hashes equal this protocol;
6. development thresholds and ablation artifacts are present and verified;
7. full pytest, security pytest, CI filter, Ruff, first-party compile, schema
   compatibility, metamorphic, determinism, limits, and anti-overfit scans pass;
8. the intended output paths do not exist;
9. explicit authorization environment variables are set;
10. the protocol digest and threshold set were recorded before unsealing;
11. network, paid model, Docker, and external dynamic execution remain disabled
    for the static holdout;
12. no reserved task identifier or result has been exposed to the reviewer.

The static reserved test then runs twice from the same clean commit with no
source, configuration, dependency, manifest, or threshold change. Both outputs
are create-only. Individual reserved results may be inspected only after both
runs finish and their semantic digests are compared. The cohort is considered
consumed at that point, regardless of success.

A mismatch between the two runs is a failed determinism gate, not permission
for a third best-of-three score.

## Official end-to-end smoke

Static holdout success still does not establish a Fable 5 or Kimi win. A later
official SusVibes-style smoke requires a separate explicit preflight and user
authorization because it may invoke Docker, a paid model, and untrusted project
tests.

The first end-to-end experiment is preregistered as:

- three development/smoke tasks, not reserved static-test tasks;
- exact public dataset and official/fidelity-checked images;
- one pinned model and one pinned harness;
- `pass@1`;
- fixed token, cost, wall-clock, and retry budget;
- sanitized Git/workspace with no upstream answer history;
- scoped API credential supplied to the process only;
- no host OAuth/session reuse;
- no benchmark labels, golden patches, or hidden-test content passed to the
  agent or BELIEF;
- paired arms: no BELIEF feedback versus one BELIEF feedback round;
- a second feedback round only if separately preregistered before the first
  outcome is seen.

The result reports marginal `FuncPass` and `SecPass` changes with per-task
artifacts. Network or model execution must not start merely because the static
reviewer passed.

## Result labels

`docs/GENERALIZATION_RESULTS.md` will classify every material statement as:

- `VÉRIFIÉ`
- `INFÉRÉ`
- `NON TESTÉ`
- `ÉCHEC`
- `NON COMPARABLE`

At minimum it will report the checkout and commits, environment, frozen input
digests, baseline health, CI defect, failure clusters, implemented semantic
contracts, limits, mutation results, ablations A–G, determinism, performance,
development gates, freeze decision, holdout state, end-to-end state,
comparability to the live league, negative results, and remaining risks.
