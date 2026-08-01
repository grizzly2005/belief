# Mega-solidification checkpoint

This document freezes the local review checkpoint for
`harden/mega-solidification-v1`, based on commit
`fe56a189048021b0b5fecfdd45fc9201197f98c0`.

The checkpoint is intentionally local. No push, pull request, merge, release,
leaderboard submission, or reserved-holdout evaluation is part of this pass.

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
| Full pytest suite | `1311 passed, 35 skipped` |
| Security marker | `818 passed, 4 skipped, 524 deselected` |
| CI local filter | `1311 passed, 35 skipped` |
| CI targeted core selection | `165 passed` |
| MCP final targeted selection | `94 passed` |
| Ruff (`belief`, `tests`) | passed |
| Python source classification | `878` compiled Python 3 files; `29` classified legacy files; passed |
| `pip check` | no broken requirements |
| CLI smoke (`belief --help`, `belief scan --help`) | passed |
| `git diff --check` | passed |

These are local results, not a claim about the unpushed GitHub Actions matrix.
The branch's Ubuntu Python 3.11, Ubuntu Python 3.12, and Windows Python 3.11
jobs have not run remotely at this checkpoint.

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
- Cross-platform behavior remains unconfirmed for this unpushed changeset.

## Review and reproduction

Reviewers should fetch the final bundle named
`belief-mega-solidification-final-checkpoint.bundle`, run `git bundle verify`,
check out its advertised branch, install the pinned project dependencies, and
repeat the gates above. The bundle digest reported with the checkpoint is the
identity of the review artifact.
