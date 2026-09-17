# Independent project pair qualification, v1

Registered on 2026-09-16 before running BELIEF on the new candidates.
Detector and runner starting commit: `83c65692239a85435cb8f17c0eb9a8cc951a1d9b`.

## Question and boundaries

Measure localized vulnerable/fixed discrimination on 20–30 additional Python
projects, targeting 24. Keep the existing three-project recovery corpus and
its thresholds unchanged. No detector implementation or configuration may be
adjusted while collecting, qualifying, or measuring this new corpus.

Independence means project-disjoint from the local SusVibes v1 population,
the local PatchEval verified population, existing local research repository
caches and the three recovery projects. Compare normalized project identities
and retain hashes of the exclusion inputs. This does not establish absence
from model pretraining or from every prior human/agent interaction. Do not
inspect reserved SusVibes cases, patches, labels or results; use only the
population's project names for exclusion.

Acquisition is passive, sequential and separate from evaluation. Read public
advisories, exact Git commit metadata, patches, source blobs and licenses.
Do not check out, import, install or execute any third-party project, run its
tests, launch services or perform live vulnerability tests. The local runner
continues to disable Git network/lazy fetching. During Overwatch, acquisitions
and checks remain sequential; CPU work uses BelowNormal priority and at most
two logical processors after a resource check.

## Discovery and selection

Use GitHub-reviewed, non-withdrawn PyPI advisories published from 2018-01-01
through 2026-08-31 with CWE 22, 23, 36, 73 or 89. Retain the exact API request,
retrieval time, response digest and ordered candidate list. Discovery is
bounded to the first three pages of 100 advisories ordered by publication
date descending. This is a purposive public sample, not an ecosystem-random
sample or a repository-blind discovery benchmark.

Evaluate eligibility from advisory/patch/source evidence before seeing any
BELIEF results. Record exclusions and unresolved candidates with a reason.
Prefer the newest eligible advisory for each distinct project, breaking ties
by GHSA id; take the first 24 qualifying distinct projects in that order. If
20–23 qualify, use all of them. Fewer than 20 is an incomplete qualification,
not a completed independent evaluation. Do not add candidates selected for
their detector output. Any later discovery expansion requires a dated
protocol amendment before its detector results are seen.

## Required qualification evidence

For every included pair:

1. Bind the official advisory, CVE, CWE and canonical repository identity.
   Require a public fixing commit and its exact first parent, both full SHAs.
2. Identify the affected Python function and the input-to-operation mechanism
   from source and the patch. An advisory label alone is insufficient.
3. Review the fixed control for that named mechanism. Record its actual
   containment/allowlist/parameterization behavior and assumptions, including
   roots, platforms, symlinks and caller trust where relevant. Reject an
   unresolved string-prefix containment claim or a fix whose decisive code
   cannot be inspected in the bound files.
4. Pin the Python paths, vulnerable and fixed blob SHA-256 values, localized
   scoring ranges, license identifier/path, and evidence for the qualification.
   At most eight files, 2 MiB per file and 8 MiB per variant, as in the runner.
5. Record any upstream regression-test changes as static supporting evidence;
   do not execute them. Absence of such tests is explicit, not a fabricated
   test result. A fixed control is qualified only for the named mechanism,
   not certified vulnerability-free.

Keep unrelated benign controls separate from fixed-variant controls. A
positive/fixed pair alone does not establish general precision. Additional
negative controls need an explicit benign contract and separate results;
unrelated warnings must not be counted as target detections. Existing CPython
negative-control results are historical regression evidence, not independent
projects in the new corpus.

## Freeze and verification plan

Commit the manifest, qualification record, exclusions and source fingerprints
before any new detector measurement. Verify the freeze commit and clean
checkout before evaluation. Preserve any failed or incomplete result artifact.

| Area | Verification | Required result |
|---|---|---|
| Selection | Check project uniqueness, exclusion intersection, minimum count and eligibility decisions | 20–30 qualified, distinct projects; no overlap |
| Provenance | Check repository origin, exact first-parent relation, source/license existence and source hashes | All selected inputs match |
| Negative controls | Static review of each fixed guard and assumptions, with source/patch evidence | No unresolved selected control |
| Runner contract | Existing focused synthetic tests for source binding, localized scoring, deterministic output and failed gates | Tests pass; no production detector edits |
| Measurement | Each vulnerable/fixed variant twice, using the existing offline runner | Preserve localized/unrelated warnings, errors and repetition digests |

Use the existing numerical thresholds unchanged: vulnerable-warning recall
at least 0.5; fixed-variant warning rate at most 0.2; paired discrimination at
least 0.4; deterministic repetition 1.0; analysis errors zero. Report the
underlying counts and each project result. A passing small sample does not
establish exploitability, repository-wide precision, SecPass, superiority to
another tool, or permission to merge a release. First measurement consumes
this sample as development evidence; later tuning needs another held-out
project population for a fresh generalization claim.

## Pre-measurement clarification, 2026-09-17

Qualification binds both the scored source files and any separately inspected
guard dependencies. `cases.json` is the complete list of files materialized
for the unchanged v1 runner; `qualification.json` marks additional context
as `analysis_target=false`. Report this limited source context when interpreting
fixed warnings. Preserve broad single-interval localization where moved code
requires it; do not silently claim semantic attribution from location alone.

Six isolated pure functions from six selected projects are separately registered
in `benign-controls.json` before either measurement. Extract the exact AST
function interval from the pinned blob, dedent, and parse/analyze twice without
executing/importing it. No decorators/imports are added. Report all warning
categories, analysis failures and both repetition digests. The expected count
is zero warnings per control, with a separate denominator from the 24 pairs.
These smoke controls do not estimate repository-wide precision.
