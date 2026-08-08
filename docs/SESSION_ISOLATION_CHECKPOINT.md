# Session isolation and triage hygiene checkpoint

This document freezes the review checkpoint for
`harden/session-isolation-and-triage-hygiene`, released as version `0.2.0`.

The checkpoint is local. It has not been pushed, and no pull request, merge,
release, leaderboard submission, or reserved-holdout evaluation is part of this
pass. It builds on
[`MEGA_SOLIDIFICATION_CHECKPOINT.md`](MEGA_SOLIDIFICATION_CHECKPOINT.md), whose
commit `a24038c` is an ancestor of this one, so this branch is a strict superset
of the line published for review there.

## Completed scope

- The MCP dispatcher isolates stored runs per caller session. Run identifiers
  are derived from analysed content, so two callers scanning the same bytes
  obtain the same `run_id`; a session now resolves to its own tools instance
  and store, and a cross-session read cannot resolve because the other
  session's runs live in a different object. Isolation is structural, not a
  check that could be forgotten on a new path.
- Store maxima are divided across sessions rather than multiplied, and the
  local validation semaphore is shared, so "one concurrent local validation"
  stays a process property. A default dispatcher is single-session and keeps
  the entire reviewed budget, which is what stdio has always had.
- The Bandit bridge filters informational test IDs before triage: the B4xx
  blacklist-import family, where an import is a reference rather than an
  anchored flow, and three control-flow hygiene checks. `B603` and `B607` are
  deliberately kept as call sites carrying a real CWE-78 mapping.
- Create-only measurement artifacts held outside the repository have an
  append-only index and a fail-closed verifier. See
  [`EXTERNAL_ARTIFACTS.md`](EXTERNAL_ARTIFACTS.md).
- Reviewer changes that affect comparability with recorded results are
  recorded separately from the results themselves, distinguishing a digest
  break from a behavior break. See
  [`REVIEWER_PROVENANCE_CHANGES.md`](REVIEWER_PROVENANCE_CHANGES.md).
- The CyberSecEval static preflight, the web validation generalization corpus
  and runner, bounded partial-Python recovery, the web security semantics pass,
  and the paired SusVibes execution hardening are merged into the line.
- `.gitattributes` pins the sealed web-validation corpus to byte-exact
  checkout. Without it, a clone with `core.autocrlf=true` rewrote all 32
  sources to CRLF and the fail-closed integrity gate refused a corpus nobody
  had modified, on any Windows clone.
- `tests_bridges/` is collected and linted. It had never run: `testpaths`
  pinned pytest to `tests/`, seventeen tests were dead, and one had rotted
  against a renamed enum member.
- The isolated-worker lifecycle check records the roots a run creates instead
  of globbing the shared system temporary directory, so a concurrent process
  no longer reports a leak the run did not cause.

## Local validation record

Environment: Windows, CPython 3.12.10, repository virtual environment.

| Gate | Result |
| --- | --- |
| CI local filter (`not slow and not external and not llm`) | `1517 passed, 35 skipped` |
| Security marker | `1006 passed, 4 skipped, 542 deselected` |
| CI targeted core selection | `199 passed` |
| Windows worker/MCP selection | `245 passed, 3 skipped` |
| Ruff (`belief`, `tests`, `tests_bridges`, `scripts`) | passed |
| Python source classification | `892` compiled Python 3 files; `29` classified legacy files; passed |
| `pip check` | no broken requirements |
| CLI smoke (`belief --help`, `belief scan --help`) | passed |
| `git diff --check` | passed |
| Benchmark `metadata_ground_truth_mvp` | `7` cases |
| Benchmark `static_analysis_ground_truth_v1` | passed, thresholds passed |
| External artifact verification | `14/14 verified` |

The static benchmark returns deterministic digest
`0941a4ec7976067059e5a931245efba78ae1c68334bef06730ad3094cb4d53a9`, unchanged
across this checkpoint including the research merge. Two consecutive runs
differ only in `duration_seconds`, which the digest excludes by design.

These are local results. No CI run is attached, because the branch has not been
pushed.

## Residual boundaries

- Reviewer behavior changed on the `default` analysis profile through the web
  security semantics pass and the `Path(x).name` suppression. New SusVibes
  measurements are not comparable to the recorded ones. The unchanged static
  benchmark digest covers eight cases and is not evidence about the 98-case
  artifact-unseen cohort or the 45 evaluable development cases; neither was
  re-run. The reserved 49-case cohort remains unopened.
- Session isolation is per process. Several sessions inside one dispatcher get
  separate stores, but they remain one operating-system process sharing one
  memory space and one filesystem identity. It is not a security boundary
  against a caller that can execute code in that process.
- The lifecycle state machine remains per dispatcher, not per session, so
  `initialize` and `notifications/initialized` are still global to the process.
- The Bandit filter is inert in this environment: `bandit` is not installed and
  is not a declared dependency, and the bridge is reachable only through the
  bridge registry, `HydraAgent`, and the opt-in cognitive loop. The subprocess
  path of that bridge is therefore not exercised by any suite here; the filter
  is covered through its pure classification surface only.
- The external artifact index detects loss and corruption. It is not a backup
  and cannot repair either. A single external volume remains a single point of
  failure for evidence that cannot be regenerated.
- Thirteen commits in this line exist only on this machine. The untracked
  bundles sit on the same disk as the repository, so they are not off-site
  redundancy.

## Review and reproduction

Reviewers should obtain the bundle named
`belief-session-isolation-checkpoint.bundle`, run `git bundle verify`, check
out the advertised branch, install the pinned project dependencies, and repeat
the gates above.

The bundle's identity is the annotated tag `v0.2.0`, which it carries alongside
the branch and which `git bundle verify` prints. Anchoring on the tag rather
than on a commit hash written into this file is deliberate: recording the hash
here would change the commit and leave the recorded value describing the
previous one, which is how the earlier checkpoint document came to name a
commit five commits behind its own measurements.

The tag message repeats the gate table, so a reviewer can compare the artifact
against its claims without trusting this file.

A sidecar `.sha256` file ships beside the bundle for transport integrity only.
It travels with the artifact and therefore authenticates nothing on its own.

The bundle is a local artifact and is not tracked in this repository.
