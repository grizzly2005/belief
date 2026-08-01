# Research Experiment Classification

`research/experiment-classification-v1.json` is the authoritative classification
layer for the research artifacts inspected during the mega-solidification pass.
It adds metadata only. It does not rerun, rewrite, import, or promote any research
result into the core branch.

## Claim boundaries

The manifest applies the following rules:

- an internally tuned synthetic corpus is an internal development fit;
- a public positive-only corpus can support a sensitivity observation, but not
  precision or specificity;
- a result tuned against a public corpus remains a public development result,
  not an unseen or externally blind evaluation;
- a safety preflight without a committed benchmark artifact is not an execution
  result or score;
- comparison with a benchmark leaderboard or a model is outside the recorded
  evidence;
- parser recovery provenance remains explicit and is never collapsed into the
  same evidence class as source parsed exactly as supplied.
- labeled-line recovery is oracle-localized; it is not a blind file or
  repository scan;
- full-file blind, repository blind, labeled-line localized, and recovered
  partial-snippet modes must be scored separately. Their recall must not be
  aggregated.

`precision_eligible` can be true only when negative controls are present. All
recorded experiments set `secpass_comparable` and `external_blind` to false.

## Recorded experiments

| Experiment | Classification | Evidence boundary |
| --- | --- | --- |
| Synthetic web development v2 | Internal public development fit | Precision is eligible only for the committed 32-case development artifact, which contains negative controls. |
| CyberSecEval v1 | First-exposure positive-only sensitivity | Public positive-only cases; no precision, specificity, or unseen-evaluation claim. |
| CyberSecEval v2 | Oracle-localized positive-case sensitivity | The public corpus and labeled vulnerable line informed bounded recovery. Modes A-D were not reported separately; no aggregate recall, end-to-end detection, precision, or blind-evaluation claim is allowed. |
| SecCodeBench Python | Safety preflight only | A branch exists, but no SecCodeBench-specific committed artifact or score was found. |

## Synthetic journal discrepancy

The local research journal describes 48 synthetic cases. The independently
verifiable Git artifact at commit
`12d6d25adbb1a1acb9e5a8b0ae03752195cdc602` contains 32 cases and has digest
`a73ba62aa8e6eb2c33e55f781aab2b16187c18f8b068c4831f95f3cefcd86a1b`.
No matching 48-case committed artifact was found. The manifest therefore records
both counts, marks them inconsistent, and limits every artifact-backed claim to
the committed 32-case result.

## Parser provenance

Only these values are valid:

- `parsed_as_provided`
- `parsed_after_dedent`
- `parsed_after_bounded_recovery`
- `unparseable`

The categories describe how a sample became available to static analysis. They
do not imply equivalent source fidelity or equivalent proof strength.

## CyberSecEval modes

The classification vocabulary keeps four evaluation modes distinct:

- Mode A: full-file blind scan;
- Mode B: repository blind scan;
- Mode C: labeled-line localized scan;
- Mode D: recovered partial-snippet classification.

The committed CyberSecEval v2 artifact used target-window recovery aligned to
the labeled vulnerable line and did not publish separate mode-level metrics.
It is therefore classified conservatively as oracle-localized positive-case
sensitivity. Its combined count is not an aggregate-recall result.

## Operational constraints

This classification pass did not open a reserved cohort or the SusVibes holdout.
It did not execute a benchmark, modify an existing result, integrate a research
commit, or create a new technical result.
