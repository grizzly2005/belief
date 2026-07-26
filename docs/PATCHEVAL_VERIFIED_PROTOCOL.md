# PatchEval-Verified Independent Development Protocol

Status: preregistered before local case inspection  
Protocol date: 2026-07-25  
BELIEF starting commit:
`54b83c748d7c217f1a801420867a93b942d53daf`  
PatchEval upstream commit:
`217401d06684e8baa0847574b9faf83b0898f379`

Amendment 1, 2026-07-25: after aggregate-only schema verification reported
70 Python records across 48 repositories, the protocol added a binding for the
clean BELIEF preparation-tool commit. No case identity, repository identity,
CVE, CWE, description, patch, function, image, source, test, or outcome had
been displayed. The eligibility, split, gates, and stop rules were unchanged.

This protocol defines the next BELIEF generalization track after the failed
SusVibes nested-development result. It is independent of the 49 SusVibes
development cases already used. It does not authorize opening or running the
49 reserved SusVibes cases.

## External target and honest success claim

The current Agent Security League high-water mark is Cursor with Claude Fable
5 at 72.6% `FuncPass` and 29.0% `SecPass` on its 200-task evaluation. The
original SusVibes study reports Kimi K2 at 43.5%/8.0% with Claude Code,
37.0%/9.0% with OpenHands, and 22.5%/6.0% with SWE-Agent.

BELIEF's external objective is therefore preregistered as both:

- fair `SecPass` strictly above 29.0%;
- `FuncPass` strictly above 72.6%.

Both must be measured at `pass@1` with the same 200-task task set, timeout,
anti-cheating exclusions, workspace sanitation, and scorer used by the Agent
Security League, or through an accepted leaderboard submission. Anything
else is labeled `NOT COMPARABLE`. Static candidate-review scores and
PatchEval-Verified scores cannot establish this claim.

Primary references:

- [Agent Security League](https://www.endorlabs.com/research/ai-code-security-benchmark)
- [SusVibes repository](https://github.com/LeiLiLab/susvibes)
- [PatchEval repository](https://github.com/bytedance/PatchEval)

## Why PatchEval-Verified

PatchEval-Verified was released on 2026-07-24. Its maintainers report 230
Docker-verified CVE repair cases across Python, JavaScript, and Go. They also
state that the revised tests focus on whether exploitation remains possible,
rather than requiring one particular upstream implementation. Official result
baselines are not yet published.

This track uses PatchEval-Verified only as:

1. a project-disjoint source of new Python development evidence;
2. an independent dynamic validation surface for later paired BELIEF-feedback
   experiments.

It is not used as a substitute leaderboard.

## Pre-inspection boundary

Before this file is committed:

- only the public README, remote default branch, and remote commit hash may be
  read;
- no local PatchEval dataset entry, CVE description, CWE, patch URL, vulnerable
  function, fixed function, image, source tree, test, or result may be opened;
- no PatchEval Docker image may be pulled or run.

After this file is committed, an evaluator-only preparation script may read
metadata to create the frozen split. It may output aggregate counts and
digests only. It must not print case IDs, repository names, CVEs, CWEs,
descriptions, patch URLs, function names, or image URLs.

## Frozen source inputs

The preparation phase must bind:

- the PatchEval Git commit above;
- SHA-256 of `patcheval/datasets/patcheval_verified.json`;
- the exact BELIEF starting commit above;
- the clean BELIEF preparation-tool commit used to create the manifest;
- SHA-256 of this protocol;
- SHA-256 of the pinned SusVibes dataset used only for project-overlap
  exclusion;
- the deterministic split algorithm and its version;
- the complete eligible/development/reserved ID digests and aggregate counts.

All manifests and results are create-only and stored outside the BELIEF
repository under `F:\belief-rd`.

## Eligibility and independence

A PatchEval record is eligible only when:

- `programing_language`, case-insensitively normalized, is `python`;
- `cve_id`, `repo`, `patch_url`, and `image_url` are non-empty strings;
- its normalized repository identity is not present anywhere in the complete
  pinned SusVibes dataset;
- the case ID and normalized repository identity are unique;
- its official vulnerable and fixed revisions can later be reconstructed
  without modifying the upstream checkout.

Repository overlap exclusion is evaluator-side. The preparation tool may read
all SusVibes project identities solely to compute the exclusion, but may emit
only their count and digest. It must not expose the old reserved cohort or
forward any identity to BELIEF.

Reconstruction viability is measured after the split and never changes cohort
membership. Failures remain in the denominator as infrastructure errors.

## Deterministic project-disjoint split

The split algorithm identifier is
`patcheval_verified_python_project_hash_v1`.

1. Normalize repository identity as the lowercase owner/repository pair with
   a trailing `.git` removed.
2. Filter using the eligibility rules above.
3. Compute the seed as SHA-256 of the NUL-separated tuple:
   `belief-patcheval-verified-v1`, PatchEval commit, dataset SHA-256, and
   BELIEF starting commit.
4. Rank unique repositories by SHA-256 of the NUL-separated seed,
   `repository`, and normalized repository identity.
5. Assign the first `ceil(0.60 * repository_count)` repositories to
   development and all remaining repositories to the reserved cohort.
6. Within each cohort, order cases by SHA-256 of the NUL-separated seed,
   cohort name, and case ID.

The corpus is unsuitable for architecture tuning unless development contains
at least 24 cases from at least eight repositories and reserved contains at
least 24 cases from at least five repositories. If those minima fail, the
result is recorded and a different public corpus must be preregistered. The
ratio, ordering, or minima may not be changed after seeing case details.

## Evaluator/reviewer separation

The evaluator may use metadata, the official vulnerable image, and the
official patch to reconstruct canonical vulnerable and fixed candidates.
BELIEF receives only:

- the candidate worktree;
- its diff against a common reconstructed base;
- ordinary repository files needed for static analysis.

BELIEF must not receive the CVE, CWE, description, patch URL, image URL,
reference-patch label, hidden validation logic, expected outcome, cohort name,
or aggregate benchmark score. No PatchEval project, case, CVE, or exact source
snippet may appear in first-party production logic.

## Metrics

The static paired development adapter records:

- selected, evaluable, and infrastructure-error counts;
- vulnerable warning recall;
- fixed-candidate warning false-positive rate;
- paired vulnerable-only discrimination;
- warning precision and F1;
- file, function, source, sink, guard, and resource localization;
- evidence completeness and gap/limit counts;
- median and total duration;
- peak process RSS;
- deterministic aggregate and per-review digests.

`inconclusive` remains actionable and never counts as a fixed-candidate pass.
The static metric is not PatchEval dynamic repair success, `FuncPass`, or
`SecPass`.

## Development gates

The final selected static architecture must satisfy every gate twice:

| Gate | Threshold |
|---|---:|
| Vulnerable warning recall | at least 50% |
| Fixed warning false-positive rate | at most 20% |
| Paired vulnerable-only discrimination | at least 40% |
| Warning precision | at least 70% |
| Evaluable reconstruction rate | at least 80% |
| Complete semantic comparisons | at least 90% |
| Existing test regressions | zero |
| Protected metamorphic regressions | zero |
| Deterministic repetitions | two identical semantic results |
| Median duration | below 2.0 times baseline |
| Peak process RSS | at most 512 MiB |

The denominator is frozen. Infrastructure failures cannot be dropped,
reclassified, or replaced. Thresholds cannot be lowered.

## Architecture budget

At most three architecture cycles are allowed after measuring the untouched
BELIEF baseline at the starting commit. A cycle must:

- state one generic causal hypothesis before code changes;
- add positive, negative, reordered, wrong-value, wrong-resource, bypass,
  unused-result, interprocedural, and alpha-renamed tests;
- use at least two development repositories and two weakness families as
  supporting evidence;
- report production/test line growth and any new limits;
- preserve explicit gaps when evidence is insufficient.

The old 49-case SusVibes development cohort may not be rerun to choose or tune
these changes. The new PatchEval reserved cohort may not be opened, mounted,
pulled, or executed during architecture development.

If the final cycle fails any gate, publish the negative development result and
keep the new reserved cohort sealed.

## Dynamic experiment boundary

PatchEval-Verified requires Linux, Docker, external images, and potentially a
paid agent. Preparation may inspect scripts and image metadata, but it must
not pull images, start containers, call a model, or run untrusted project code.

A later dynamic smoke requires a separate create-only preflight and explicit
execution authorization. The first smoke is development-only and paired:

- same three development cases;
- same pinned agent/model, prompt, timeout, token, cost, and retry budget;
- arm A without BELIEF feedback;
- arm B with exactly one bounded BELIEF feedback round;
- `pass@1`;
- no reference patch, fixed function, hidden validation, or benchmark label
  given to the agent or BELIEF.

Results must preserve failed generations and evaluator failures. No dynamic
result is interpreted until both arms finish.

## Stop conditions

Stop and record `FAILURE` rather than changing the protocol when:

- the upstream commit or dataset hash changes;
- project independence cannot be established;
- minimum cohort sizes fail;
- reconstruction rate is below 80%;
- any production change names or fingerprints a task;
- a fourth architecture cycle would be required;
- a dynamic prerequisite would expose credentials, host sessions, or
  unrelated user files;
- the official comparator's task set or anti-cheating scorer is unavailable.
