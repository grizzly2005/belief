# SusVibes paired-revision benchmark

This adapter measures whether BELIEF surfaces a security-relevant finding on a
vulnerable revision and stops surfacing it on the corresponding fixed
revision. It is deterministic, read-only with respect to the source corpus,
and does not import or execute third-party project code.

## Pinned public corpus

The first reproducible BELIEF run uses the official SusVibes v1.0 corpus:

- repository: `https://github.com/LeiLiLab/susvibes`;
- tag: `v1.0`;
- commit: `7e1b4b05240e56dc2b4e8253b2cc5c9481d016f3`;
- dataset: `datasets/default/susvibes_dataset.jsonl`;
- dataset SHA-256:
  `be9a4ca573559544c3f28146b3b3811e5565f0a8b4053ff4cc8f4aab6c6742f7`.

The upstream dataset contains 186 records across 101 projects. The initial
BELIEF vertical selects `CWE-22`, `CWE-639`, `CWE-862`, and `CWE-863`: 15
records across 14 projects.

The dataset and project repositories are intentionally not vendored. Pin and
verify them outside the BELIEF checkout. Evaluation requires all referenced
commits, their parents, and the changed Python blobs to be present in a
dedicated local Git object cache before the offline run starts.

## Explicit network preparation

Cache preparation is a separate, opt-in phase. It fetches fixed commits and
their first parents, hydrates only Python blobs named by the patches, performs
an offline verification pass, and never checks out project files:

```powershell
python scripts/prepare_susvibes_cache.py `
  --dataset F:\belief-rd\susvibes-v1.0\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --only-cwe CWE-22,CWE-639,CWE-862,CWE-863 `
  --allow-network
```

The command refuses to fetch without `--allow-network`, refuses non-empty
non-Git cache directories and unexpected existing remotes, and writes a
deterministic `belief-cache-manifest.json`. Cache preparation is resumable.
Use a dedicated cache directory: fetches necessarily write Git objects there.

## Offline evaluation

PowerShell example:

```powershell
$Dataset = "F:\belief-rd\susvibes-v1.0\datasets\default\susvibes_dataset.jsonl"
$Cache = "F:\belief-rd\repos"
$Output = "F:\belief-rd\results\belief-susvibes-paired.json"

python -m belief benchmark reportability `
  --mode susvibes_paired_static_v1 `
  --target $Dataset `
  --repository-cache $Cache `
  --only-cwe CWE-22,CWE-639,CWE-862,CWE-863 `
  --json-output $Output
```

The evaluator:

1. validates and sorts the JSONL cases;
2. reads fixed commits and parents from the explicit cache with Git network
   transports and lazy fetching disabled;
3. materializes only Python files named by the security patch into temporary
   directories;
4. focuses observations on functions and line ranges touched by the patch;
5. runs the shared BELIEF static pipeline with the explicit `patch_review`
   security profile;
6. reports vulnerable recall, fixed-revision disagreements, and paired
   discrimination;
7. emits a semantic digest that excludes elapsed wall-clock time.

Default acceptance thresholds are:

- vulnerable surfaced recall at least `0.30`;
- fixed surfaced disagreement rate at most `0.25`;
- paired discrimination rate at least `0.30`.

## What the score means

`paired_discrimination_rate` is the proportion of evaluable pairs for which a
BELIEF finding is surfaced on the vulnerable parent and not surfaced on the
fixed revision.

This is an **oracle-localized static discrimination metric**. The security
patch identifies which files and functions to inspect. It is useful for
regression engineering, but it is not:

- SusVibes `SecPass`, because BELIEF does not generate a patch or run the
  project's security tests;
- a pass@3 CVE rediscovery score;
- evidence that a model benchmark has been beaten end to end;
- proof that every surfaced item is exploitable.

The JSON output records these non-equivalences under `comparability`.

## Initial BELIEF result

On 2026-07-23, the pinned 15-case vertical produced:

| Metric | Result |
|---|---:|
| Evaluable cases | 15 / 15 |
| Vulnerable surfaced recall | 11 / 15 (73.3%) |
| Fixed surfaced disagreement | 1 / 15 (6.7%) |
| Paired discrimination | 10 / 15 (66.7%) |
| Path traversal paired discrimination | 8 / 9 (88.9%) |
| Access-control paired discrimination | 2 / 6 (33.3%) |

Two consecutive offline runs produced the same semantic digest:
`3cf9d44159baff0090c7a3a4db7b65afcf801d0cf59b567c3ce92c6a1f9461f1`.
Elapsed duration is deliberately excluded from that digest.

The one fixed-revision disagreement is Streamlit's historical use of
`commonprefix` for containment. BELIEF keeps flagging it because string-prefix
comparison does not prove filesystem containment; the benchmark conservatively
counts that disagreement against BELIEF.

The recorded percentage is numerically above the published 29% Fable 5
security score, but the tasks and metrics differ. It must not be presented as
an official Fable 5 or Kimi benchmark win.

## Expanded supported-family result

The follow-up run selected every Python case in the corpus whose CWE belongs
to a security family currently modeled by the `patch_review` profile. The
selection contains 71 cases, 40 projects, 20 CWE identifiers, and 11 reporting
categories.

The exact `--only-cwe` value used for cache preparation and evaluation was:

```text
CWE-22,CWE-23,CWE-284,CWE-285,CWE-29,CWE-295,CWE-327,CWE-330,CWE-344,CWE-347,CWE-639,CWE-77,CWE-78,CWE-79,CWE-80,CWE-863,CWE-88,CWE-89,CWE-918,CWE-94
```

On 2026-07-23, two consecutive offline runs produced:

| Metric | Result |
|---|---:|
| Evaluable cases | 71 / 71 |
| Vulnerable surfaced recall | 29 / 71 (40.8%) |
| Fixed surfaced disagreement | 5 / 71 (7.0%) |
| Paired discrimination | 24 / 71 (33.8%) |
| SQL injection paired discrimination | 5 / 6 (83.3%) |
| Path traversal paired discrimination | 8 / 16 (50.0%) |
| Cross-site scripting paired discrimination | 5 / 26 (19.2%) |
| Access-control paired discrimination | 2 / 9 (22.2%) |

Both runs passed the unchanged default acceptance thresholds and emitted the
same semantic digest:
`a58309833d00efa4835f98292b843bbecce1a2be15faaa29eb04e7ea92020118`.
Their wall-clock durations were 168.15 and 148.16 seconds; duration remains
excluded from the digest.

This expanded result is the current BELIEF engineering baseline. It is broader
and harder than the 15-case vertical, but it remains the same
oracle-localized metric described above. The zero or low-scoring categories
are retained in the result rather than filtered out.

## Oracle-separated candidate-review benchmark

`susvibes_candidate_review_v1` measures the component BELIEF can contribute to
an agent loop without leaking the benchmark answer. For each selected task, the
evaluator:

1. reads the fixed source blobs from the prepared local cache;
2. applies `task_patch` to create the masked task baseline and commits it as
   `HEAD`;
3. reconstructs the historical vulnerable candidate by reversing
   `mask_patch`;
4. independently reconstructs the canonical secure candidate with
   `golden_patch`;
5. gives the reviewer only one candidate worktree at a time;
6. counts an actionable warning on the vulnerable candidate, an actionable
   warning on the secure candidate, and the paired discrimination outcome.

The reviewer cannot read the JSONL record. It receives neither CWE/CVE labels,
reference patches, hidden tests, security patches, nor test outcomes.
Benchmark-only material remains in the evaluator.

Cache preparation for this mode must hydrate all four reconstruction fields:

```powershell
python scripts/prepare_susvibes_cache.py `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --only-cwe CWE-22,CWE-23,CWE-284,CWE-285,CWE-29,CWE-295,CWE-327,CWE-330,CWE-344,CWE-347,CWE-639,CWE-77,CWE-78,CWE-79,CWE-80,CWE-863,CWE-88,CWE-89,CWE-918,CWE-94 `
  --patch-field security_patch `
  --patch-field mask_patch `
  --patch-field task_patch `
  --patch-field golden_patch `
  --manifest F:\belief-rd\results\belief-cache-candidate-review-manifest.json `
  --allow-network
```

For a frozen experiment cohort, use the verified manifest instead of
`--only-cwe` or `--max-cases`. The preparer verifies the manifest digest and
dataset SHA-256, preserves the manifest's instance-ID order, and records the
selection provenance in its cache manifest:

```powershell
python scripts/prepare_susvibes_cache.py `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --experiment-manifest F:\belief-rd\results\belief-susvibes-v1-experiment-holdout-20260723.json `
  --cohort canary `
  --patch-field security_patch `
  --patch-field mask_patch `
  --patch-field task_patch `
  --patch-field golden_patch `
  --manifest F:\belief-rd\results\belief-cache-candidate-review-canary.json `
  --allow-network
```

Once the manifest's offline verification passes, evaluation is network-free:

```powershell
python -m belief benchmark reportability `
  --mode susvibes_candidate_review_v1 `
  --target F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --only-cwe CWE-22,CWE-23,CWE-284,CWE-285,CWE-29,CWE-295,CWE-327,CWE-330,CWE-344,CWE-347,CWE-639,CWE-77,CWE-78,CWE-79,CWE-80,CWE-863,CWE-88,CWE-89,CWE-918,CWE-94 `
  --json-output F:\belief-rd\results\belief-susvibes-candidate-review.json
```

The equivalent frozen-cohort evaluation is:

```powershell
python -m belief benchmark reportability `
  --mode susvibes_candidate_review_v1 `
  --target F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --experiment-manifest F:\belief-rd\results\belief-susvibes-v1-experiment-holdout-20260723.json `
  --cohort canary `
  --json-output F:\belief-rd\results\belief-susvibes-candidate-review-canary.json
```

Explicit cohort IDs cannot be combined with a CWE filter or case limit. This
prevents an apparently named cohort from silently evaluating a different
subset. The candidate-review artifact records the ordered-ID hash plus the
manifest, dataset, upstream commit, and cohort provenance.
For the default reviewer it also records a canonical SHA-256 over every
LF-normalized Python source file in the BELIEF package, so a result is bound
to the exact local reviewer implementation even before that worktree is
committed.

Default gates are intentionally unchanged from the paired benchmark:

- vulnerable-candidate warning recall at least `0.30`;
- secure-candidate warning false-positive rate at most `0.25`;
- paired warning discrimination at least `0.30`.

### Reproducible candidate-review result

On 2026-07-23, the 71-case supported-family selection produced:

| Metric | Result | Gate |
|---|---:|---:|
| Evaluable cases | 71 / 71 | no analysis errors |
| Vulnerable candidates warned | 33 / 71 (46.5%) | at least 30% |
| Secure candidates warned | 11 / 71 (15.5%) | at most 25% |
| Paired warning discrimination | 22 / 71 (31.0%) | at least 30% |
| Path-traversal paired discrimination | 8 / 16 (50.0%) | informational |
| SQL-injection paired discrimination | 3 / 6 (50.0%) | informational |
| XSS paired discrimination | 5 / 26 (19.2%) | informational |

Two independent offline runs produced byte-identical case rows and the same
semantic digest:
`be78297ac804e119933d7c71a224073e23339836bdedd3c59c6efc0fe7ecc7e7`.
Durations were 273.31 and 276.68 seconds and are excluded from the digest.

The paired gate is passed by one case. This narrow margin is recorded rather
than hidden by lowering the threshold. The final discriminating case recognizes
a general security structure: HTML-escaped regex callback text plus a
dominating, abortive `http`/`https` URL-scheme allowlist. Regression tests keep
the warning when the input is unescaped, the guard is absent, or an unsafe
scheme such as `javascript` is allowed.

### Frozen-canary supported-family intersection

Before inspecting any holdout task, the frozen 24-case canary was intersected
with the pre-existing 71-case supported-family cache. This yields exactly
seven already-hydrated cases. It is an engineering regression slice, not the
complete canary and not a `SecPass` estimate.

The same seven instance IDs changed as follows:

| Metric | Supported-family baseline | Current reviewer |
|---|---:|---:|
| Evaluable cases | 7 / 7 | 7 / 7 |
| Vulnerable candidates warned | 5 / 7 (71.4%) | 7 / 7 (100%) |
| Secure candidates warned | 1 / 7 (14.3%) | 1 / 7 (14.3%) |
| Paired warning discrimination | 4 / 7 (57.1%) | 6 / 7 (85.7%) |

Two independent runs produced the same semantic digest:
`536240f6c9c660c79846e7adbed7dc62f083e0044b53db8d3eed2a907c3e841c`.
Their durations were 12.36 and 12.33 seconds. The non-overwritten artifacts
and file hashes are:

- `belief-susvibes-candidate-review-canary-supported-20260723-03.json`:
  `71dc081d0cadd2062b25a6e1fae5b244a28e3a6b95e3e09e7fff5418bdfda94a`;
- `belief-susvibes-candidate-review-canary-supported-20260723-04.json`:
  `f24744734daa2575b02d1f4a476156218246b7b5ca4518888e5761e7fe98faea`.

Both artifacts record the ordered-ID hash, parent canary,
experiment-manifest digest and hash, dataset hash, upstream commit, and
cache-manifest hash. They also bind the default reviewer to 836 normalized
Python files with source digest
`d91a5cd4cabf8d1c772e292174bdb570bd22faad884a151f14b597a04d07be1e`.

The two newly discriminated pairs are python-libnmap's unguarded process
operands and CKAN's caller-supplied record ID. The rules require causal flow to
the process argument vector or record persistence and include negative
regressions for unrelated subprocess state, missing-ID checks, and partial or
optional ID removal.

The remaining canonical-secure disagreement is Jupyter Server Proxy. Its patch
isolates URL authority delimiters, so the new CWE-918 signal disappears, but
the route-supplied host is still written into the 403 response without visible
HTML escaping. BELIEF retains that CWE-79 warning; the evaluator conservatively
counts it as a secure-candidate false positive.

At this checkpoint, seventeen canary cases were not present in the old
supported-family cache. They were subsequently hydrated through the verified
manifest as described below. No result in this section uses or inspects the
162-case holdout.

### Complete frozen-canary result

On 2026-07-25, the verified canary cache contained all 24 frozen instance IDs
across 20 projects. Cache preparation recorded the cohort provenance, hydrated
all four candidate-reconstruction patch fields, and passed its offline object
verification. The cache-manifest SHA-256 is
`1a600d3b44eea16a922bf5ca76f85493750ea6b1bd8c5cef2b299ba2a8c9fd3b`.

Two independent offline candidate-review runs produced:

| Metric | Result | Default gate |
|---|---:|---:|
| Evaluable cases | 24 / 24 | no analysis errors |
| Vulnerable candidates warned | 12 / 24 (50.0%) | at least 30% |
| Secure candidates warned | 2 / 24 (8.3%) | at most 25% |
| Paired warning discrimination | 10 / 24 (41.7%) | at least 30% |

Both runs passed every unchanged default gate, emitted byte-identical case
rows, and produced the same semantic digest:
`193e36656da6c923b4932422c92f01bce540a5bb5e3af0e3982e82ec39e6616f`.
Their durations were 59.79 and 59.38 seconds and are excluded from the digest.
The non-overwritten artifact hashes are:

- `belief-susvibes-candidate-review-canary-full-20260725-07.json`:
  `5df8da92b0224599eb1c7c172ba158c14f9d3d4172cf2793f107b6850d1df749`;
- `belief-susvibes-candidate-review-canary-full-20260725-08.json`:
  `1df3e49769a00d4ed8548a45f0cacf614b4d6516134e7e9800d7e70662a08b2a`.

The artifacts bind the ordered 24-ID selection, dataset, upstream commit,
experiment manifest, and the default reviewer implementation. The reviewer
source digest for both runs is
`16eace68f2753bb11b64e5cd0f57cd9dd1ea9eabf4afa3290286dd38da2a6d2b`
across 836 normalized Python files.

The four additional discriminated pairs use general causal rules rather than
dataset labels:

- caller-supplied XML reaching an imported standard-library XML parser is
  warned, while the corresponding `defusedxml` calls are not;
- a boundary-derived redirect target reaching an HTTP redirect sink is warned
  unless a structurally verified regular-expression sanitizer removes both CR
  and LF characters from the value used by the sink;
- a route-selected model used by a generic editing view requires both a
  non-empty permission requirement and a permission policy bound to that same
  model;
- forwarding a reusable `Authorization` header to a supplied request requires
  a dominating same-origin or allowed-domain guard tied to that request.

Negative regressions keep internal subprocess-event XML out of the request
boundary, reject sanitizer names whose implementation does not remove CR/LF,
ignore constant redirect targets, reject permission policies bound to the
wrong model, and reject destination guards tied to another request.

The two remaining secure-candidate disagreements are retained. Tryton's nested
lexical path-containment helper is not yet propagated back to its caller, and
Jupyter Server Proxy still reflects the route host in a 403 response without
visible HTML escaping. The evaluator conservatively counts both warnings
against BELIEF.

This canary is an engineering set selected for CWE breadth. It is not
prevalence-weighted, score-bearing, or comparable to official `SecPass`. The
canary work did not evaluate IDs designated as holdout after the split; the
novelty audit below separately accounts for pre-split result artifacts.

### Artifact-unseen generalization audit

A novelty audit performed before generalization scoring found that the
historical 162-case cohort named `holdout` was not pristine: 64 of its IDs had
already appeared in result artifacts created before the split was treated as a
holdout. Together with all 24 canary IDs, 88 unique corpus cases had previously
been evaluated. Calling the complete 162-case cohort unseen would therefore
overstate the evidence.

The create-only derivation parsed 40 prior JSON result artifacts but used only
their `id` or `instance_id` fields. It excluded every previously evaluated
holdout ID while preserving the parent order, leaving 98 cases across 60
projects and 47 CWE labels. The final manifest
`belief-susvibes-v1-artifact-unseen-holdout-20260725-04.json` replays the exact
40-name input index and rejects a missing or hash-mismatched prior artifact, so
later result files cannot silently change the cohort. Its SHA-256 is
`163306bba0bdc4809b44a471ce4d1e9cbbb6d6d4bf5f927f7939f2e458509fb1`
and its semantic digest is
`21b1532a27448630777a03908d3106ada0d5cf2c49ffb618adcf080804dd8f7a`.
The complete parent cache was hydrated without checkout or code execution,
then verified offline; its manifest SHA-256 is
`97e4cd762f94275fa335e2532f886bbbd02b086b10b00e35fcfcd78fd8852abb`.

The replayable derivation command is:

```powershell
python scripts/prepare_susvibes_unseen_holdout.py `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --experiment-manifest F:\belief-rd\results\belief-susvibes-v1-experiment-holdout-20260723.json `
  --results-dir F:\belief-rd\results `
  --replay-artifact-index F:\belief-rd\results\belief-susvibes-v1-artifact-unseen-holdout-20260725-03.json `
  --output F:\belief-rd\results\belief-susvibes-v1-artifact-unseen-holdout-20260725-04.json
```

The frozen reviewer is then invoked through the normal cohort loader:

```powershell
python -m belief benchmark reportability `
  --mode susvibes_candidate_review_v1 `
  --target F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --experiment-manifest F:\belief-rd\results\belief-susvibes-v1-artifact-unseen-holdout-20260725-04.json `
  --cohort holdout `
  --json-output F:\belief-rd\results\belief-susvibes-candidate-review-artifact-unseen-holdout-20260725-04.json
```

BELIEF was frozen at commit
`2c6208fda2fa8fdbb281ae89a196a72a6d57b350`. Three runs, with no reviewer
change between them, produced:

| Metric | Artifact-unseen result | Default gate |
|---|---:|---:|
| Selected cases | 98 | informational |
| Evaluable cases | 94 / 98 | four reconstruction errors |
| Vulnerable candidates warned | 14 / 94 (14.9%) | at least 30% |
| Secure candidates warned | 15 / 94 (16.0%) | at most 25% |
| Paired warning discrimination | 0 / 94 (0.0%) | at least 30% |

The secure-candidate false-positive gate passed, but both recall and paired
discrimination failed. The four non-evaluable cases were candidate
reconstruction failures in one project; they are reported rather than silently
removed from the selected-case count.

The first two runs emitted byte-identical case rows, identical selection and
reviewer provenance, and semantic digest
`f03d21dd79a3e755d2b564c7593ea206f2637456566f25d7a104a65d686e069e`.
The third run used the replayable final manifest and reproduced the same case
rows, metrics, selection-ID hash, and reviewer provenance. Its semantic digest
is `3ff42acf6fdc5480a3fc150c990f09b59866a28f5668080ce7925095fae3f5d4`;
the difference binds the improved manifest provenance. Durations were 289.36,
288.93, and 290.79 seconds. The artifact hashes are:

- `belief-susvibes-candidate-review-artifact-unseen-holdout-20260725-02.json`:
  `8caf1eb49090aa39c8ed645252ae31ae1594ddc413b4259ba3edf67445aac4c4`;
- `belief-susvibes-candidate-review-artifact-unseen-holdout-20260725-03.json`:
  `9fa0b82b106d05dc673123c6bef79c5b51e9b3201f8c5ff7898a0a6e829cb8de`;
- `belief-susvibes-candidate-review-artifact-unseen-holdout-20260725-04.json`:
  `e61cb04ad782adff20432d29438d16f4be308f0af356d06e3115ed4acd27884a`.

The reviewer provenance remained 836 normalized BELIEF Python files with
source digest
`16eace68f2753bb11b64e5cd0f57cd9dd1ea9eabf4afa3290286dd38da2a6d2b`.
This result rejects the apparent canary improvement as evidence of
generalization. It is a failed static-feedback experiment, not a `SecPass`
score and not evidence that BELIEF exceeds Fable 5 or Kimi K3.

### Frozen nested development/test protocol

After the aggregate artifact-unseen result was known, but before any
individual security outcome or successful case was inspected, the 98 IDs were
split into a new 49-case development cohort and a 49-case reserved test
cohort. Allocation uses only:

- the instance ID;
- evaluator-side primary CWE stratum;
- the baseline `analysis_succeeded` boolean.

The four already-known candidate-reconstruction failures are forced into
development so the reserved test measures reviewer behavior rather than a
known evaluator failure. Vulnerable warnings, secure warnings, paired
outcomes, findings, task text, patches, and source code do not influence the
allocation.

The development cohort is exposed through the manifest's `canary` key and may
be inspected and tuned. The reserved test is exposed through `holdout` and
must not be inspected until the reviewer is frozen. It remains a local static
generalization test, not a leaderboard or `SecPass` cohort.

Two create-only derivations were byte-identical. The frozen manifest
`belief-susvibes-v1-nested-dev-test-20260725-01.json` has SHA-256
`74d916df62428882ae89cc46d10b9d14c01831a6e60826b317cbb77e3ae6631b`
and semantic digest
`668b247f6bbe811ece6ae5db07213bab62dadf52c6c0931ea4f5ab6b054a878b`.
Development covers 30 projects and 30 CWE labels; the reserved test covers 40
projects and 35 CWE labels.

```powershell
python scripts/prepare_susvibes_nested_split.py `
  --dataset F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --parent-manifest F:\belief-rd\results\belief-susvibes-v1-artifact-unseen-holdout-20260725-04.json `
  --baseline-result F:\belief-rd\results\belief-susvibes-candidate-review-artifact-unseen-holdout-20260725-04.json `
  --dev-size 49 `
  --batch-size 12 `
  --output F:\belief-rd\results\belief-susvibes-v1-nested-dev-test-20260725-01.json
```

### Comparison boundary

| Published or local result | Score | What it measures |
|---|---:|---|
| Cursor + Claude Fable 5 | 29% | official fair `SecPass`, 200-task Agent Security League |
| Kimi K3 specialized harness | 23 / 26 | private known-CVE pass@3 rediscovery |
| BELIEF candidate review | 22 / 71 (31.0%) | offline canonical-patch warning discrimination |
| BELIEF frozen engineering canary | 10 / 24 (41.7%) | offline canonical-patch warning discrimination; not score-bearing |
| BELIEF artifact-unseen audit | 0 / 94 (0.0%) | offline canonical-patch warning discrimination; failed gates |

The canary percentage is numerically above 29%, but the artifact-unseen result
shows that it did not generalize. Neither static metric is evidence that BELIEF
has beaten Fable 5: the denominator, task subset, output, and success criterion
differ. Kimi's result is also not reproducible from a public corpus and pools
three runs. Sources:

- <https://www.endorlabs.com/research/ai-code-security-benchmark>
- <https://www.endorlabs.com/learn/claude-fable-5-take-two-same-model-different-harness-and-a-very-different-result>
- <https://www.aikido.dev/blog/benchmarking-ai-models-known-cves>

The next comparable milestone is to feed BELIEF feedback into one coding-agent
attempt and grade its emitted patch with the official functional and hidden
security tests. See [`AGENT_HARNESS.md`](AGENT_HARNESS.md).

### Dataset provenance caveat

One public record currently demonstrates why benchmark labels must not be
treated as reviewer input. The SusVibes CKAN record
`ckan__ckan_4c22c135fa486afa13855d1cdb9765eaf418d2aa` carries
`CWE-330,CWE-344` and points to CVE-2023-22746. The
[GitHub advisory](https://github.com/ckan/ckan/security/advisories/GHSA-pr8j-v4c8-h62x)
describes a shared default Docker session secret. However, the
[linked commit](https://github.com/ckan/ckan/commit/4c22c135fa486afa13855d1cdb9765eaf418d2aa)
is titled “Perform checks on provided id when creating user” and implements
authorization and uniqueness checks for a caller-supplied user ID.
[NVD](https://nvd.nist.gov/vuln/detail/CVE-2023-22746) also links that commit
while retaining the session-secret description.

BELIEF therefore reports the code-causal mass-assignment/identifier-override
signal as CWE-915. It does not force the reviewer toward CWE-330 or CWE-344.
The evaluator may still use the frozen dataset metadata for stratified
reporting, but none of those labels are passed to the reviewer.

## Safety and scope

- The evaluator performs no checkout in the third-party repositories.
- It executes Git object reads and BELIEF's own parser only.
- It never imports target modules, runs proof-of-concept code, starts Docker,
  calls a public RPC, or writes to the source cache.
- Missing commits, missing blobs, malformed cases, and unsafe diff paths are
  explicit failures rather than implicit network fetches.
