# Mega-solidification checkpoint

This document freezes the review checkpoint for
`harden/mega-solidification-v1`, based on commit
`a24038ce81ffefed2c570b5690d4fde69ef3f6ab`.

The commit reference was corrected on 2026-08-08. It still named
`fe56a189048021b0b5fecfdd45fc9201197f98c0`, the commit the document was first
written against, after five further commits landed and the validation record
below was re-measured. The record describes `a24038c`, not `fe56a18`: it counts
878 compiled Python 3 files, and the `belief/` tree holds 878 non-legacy Python
files at `a24038c` against 864 at `fe56a18`. Only the identity line moved; no
measured value in this document was altered.

The branch is published for independent review in
[GitHub pull request #6](https://github.com/grizzly2005/belief/pull/6). No merge,
release, leaderboard submission, or reserved-holdout evaluation is part of
this pass.

## Completed scope

- Static analysis consumes an exact, bounded, one-shot `SourceSnapshot` with
  separate source, analysis, and engine identities. The captured source map is
  the analysis input; analyzers do not reopen live source files.
- JSON entry points reject duplicate keys, non-finite numbers, invalid UTF-8,
  and oversized input before model construction.
- Predicate negation uses a structured AST instead of textual rewriting.
- Validation fixtures physically separate application code, oracles, and
  ground truth. Oracle data is not part of the scanner or worker input.
- The isolated worker executes an immutable `PreparedExecutionBundle`, imports
  captured in-memory code, and reports distinct source, descriptor,
  ground-truth, execution, and code-object identities.
- Evidence categories C1-C6 are conservative. A C1 mechanical proof requires
  a replayable proof artifact; legacy results migrate without silently gaining
  proof strength.
- The local MCP server enforces lifecycle states, bounded cancellation,
  atomic run-store publication, conservative tool annotations, strict input
  contracts, and bounded publication modes (`minimal`, `redacted`, and an
  explicitly enabled `full-local-only`).
- The authorized real-project pilot accepts only its hardcoded project,
  revision, and full source digest. It requires a separate authorization
  record, exposes no arbitrary module/path/callable surface, remains
  static-only, and abstains from target-vulnerability confirmation.
- Python 2 Z3 examples are digest-pinned non-runtime reference assets. The
  classifier's claim is limited to the declared `belief/` package root.
- CyberSecEval v2 is classified as oracle-localized positive-case sensitivity.
  Full-file blind, repository blind, localized-line, and recovered-snippet
  modes cannot be combined into an aggregate recall claim.

## Local validation record

Environment: Windows, CPython 3.12.10, repository virtual environment.

| Gate | Result |
| --- | --- |
| Full pytest suite | `1312 passed, 35 skipped` |
| Security marker | `819 passed, 4 skipped, 524 deselected` |
| CI local filter | `1312 passed, 35 skipped` |
| CI targeted core selection | `166 passed` |
| MCP final targeted selection | `94 passed` |
| Ruff (`belief`, `tests`) | passed |
| Python source classification | `878` compiled Python 3 files; `29` classified legacy files; passed |
| `pip check` | no broken requirements |
| CLI smoke (`belief --help`, `belief scan --help`) | passed |
| `git diff --check` | passed |

These are local results. The GitHub Actions results attached to pull request #6
are authoritative for the published head and are intentionally not duplicated
as a mutable status snapshot in this document.

## Residual boundaries

- Cancelling an MCP request prevents a later state commit and response, but a
  synchronous static scan already running may continue using CPU until it
  reaches its bounded end.
- `BELIEF_MCP_HOLDOUT_SHA256_DENYLIST` performs one bounded byte read to compute
  the digest. Preventing the process from reading sealed data requires external
  OS permissions, account separation, encryption, or a separate machine.
- The MCP server makes no outbound network publication, but a client can still
  forward returned content outside the server's control.
- The FastAPI adapter is a bounded synchronous ASGI micro-harness, not a
  general FastAPI or ASGI compatibility layer.
- The authorized real-project pilot binds one exact static project snapshot.
  Its local opt-in is not cryptographic proof of organizational authorization.
- The Python classification gate does not claim compilation coverage for root
  files, `scripts/`, `tests/`, or other undeclared roots; `execution =
  forbidden` is declarative policy, not an interpreter-level sandbox.
- The public development experiments do not establish superiority over Kimi,
  Fable, SecPass, or any external leaderboard. No reserved SusVibes holdout was
  opened or scored during this pass.
- Cross-platform behavior is limited to the platforms exercised by the local
  record and the GitHub Actions matrix attached to the published head.

## Review and reproduction

Reviewers should fetch the final bundle named
`belief-mega-solidification-final-checkpoint.bundle`, run `git bundle verify`,
check out its advertised branch, install the pinned project dependencies, and
repeat the gates above.

The bundle is a local review artifact. It is not tracked in this repository, so
it has to be obtained out of band, and its digest is the only way to confirm
the copy received is the intended one. That digest was previously described as
"reported with the checkpoint" but recorded nowhere, which left a reviewer with
nothing to compare against. Verified and recorded on 2026-08-08:

| Bundle | Advertised ref | SHA-256 |
|---|---|---|
| `belief-mega-solidification-final-checkpoint.bundle` | `a24038ce81ffefed2c570b5690d4fde69ef3f6ab`, complete history | `0998bd9861d9542e729f57138bf92d797000382e79b5c0ab9f85e605b6f86f6b` |
| `belief-mega-solidification-v1.bundle` | `fe56a189048021b0b5fecfdd45fc9201197f98c0`, requires `f42d07c3` | `ec3ee546311aa6e9255a7de60fb4c9c47fedf655443a2c0646fcebaa4fa0ea85` |

Both pass `git bundle verify`. The first advertises this document's checkpoint
commit; the second advertises the earlier commit the document was originally
written against and is not self-contained.

GitHub reviewers can instead use pull request #6, whose head branch preserves
the same unsquashed research and hardening chronology.
