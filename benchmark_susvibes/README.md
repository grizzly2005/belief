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

Once the manifest's offline verification passes, evaluation is network-free:

```powershell
python -m belief benchmark reportability `
  --mode susvibes_candidate_review_v1 `
  --target F:\belief-rd\susvibes-main\datasets\default\susvibes_dataset.jsonl `
  --repository-cache F:\belief-rd\repos `
  --only-cwe CWE-22,CWE-23,CWE-284,CWE-285,CWE-29,CWE-295,CWE-327,CWE-330,CWE-344,CWE-347,CWE-639,CWE-77,CWE-78,CWE-79,CWE-80,CWE-863,CWE-88,CWE-89,CWE-918,CWE-94 `
  --json-output F:\belief-rd\results\belief-susvibes-candidate-review.json
```

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

### Comparison boundary

| Published or local result | Score | What it measures |
|---|---:|---|
| Cursor + Claude Fable 5 | 29% | official fair `SecPass`, 200-task Agent Security League |
| Kimi K3 specialized harness | 23 / 26 | private known-CVE pass@3 rediscovery |
| BELIEF candidate review | 22 / 71 (31.0%) | offline canonical-patch warning discrimination |

The BELIEF percentage is numerically above 29%, but it is **not** evidence that
BELIEF has beaten Fable 5: the denominator, task subset, output, and success
criterion differ. Kimi's result is also not reproducible from a public corpus
and pools three runs. Sources:

- <https://www.endorlabs.com/research/ai-code-security-benchmark>
- <https://www.endorlabs.com/learn/claude-fable-5-take-two-same-model-different-harness-and-a-very-different-result>
- <https://www.aikido.dev/blog/benchmarking-ai-models-known-cves>

The next comparable milestone is to feed BELIEF feedback into one coding-agent
attempt and grade its emitted patch with the official functional and hidden
security tests. See [`AGENT_HARNESS.md`](AGENT_HARNESS.md).

## Safety and scope

- The evaluator performs no checkout in the third-party repositories.
- It executes Git object reads and BELIEF's own parser only.
- It never imports target modules, runs proof-of-concept code, starts Docker,
  calls a public RPC, or writes to the source cache.
- Missing commits, missing blobs, malformed cases, and unsafe diff paths are
  explicit failures rather than implicit network fetches.
