# BELIEF v4

BELIEF v4 is an experimental white-box security reasoning engine for Python code.

It is designed for local, authorized code review and research workflows where raw findings are not enough. BELIEF keeps a stable finding model, then adds hypothesis metadata, lightweight dataflow, mined guarantees, optional boolean Z3 checks, route context, and audit-oriented output formats.

## What It Does

BELIEF's current review path is:

```text
Finding -> Hypothesis -> Dataflow -> Guarantees -> Z3 -> AuditCase
```

The goal is to help a reviewer understand why a finding may be actionable, protected by local guarantees, likely false-positive context, or still in need of manual review.

## Features

- local Python code scanning
- audit mode
- stable Finding / Hypothesis / AuditCase model
- lightweight source-to-sink dataflow
- guarantee extraction
- optional Z3 boolean contradiction checks
- Flask/FastAPI/Django route inventory
- `route_context` enrichment for `AuditCase`
- JSON / SARIF / Markdown outputs
- SARIF import skeleton for future bridge outputs
- audit deduplication / clustering
- centralized security taxonomy
- optional bridge-oriented architecture for external tools

## Responsible Use

BELIEF is intended for authorized code review, local auditing, research, education, and bug bounty work within program scope.

BELIEF is not an exploit generator.

BELIEF does not perform network attacks. Any future bridge or scanner integration should remain local, authorized, and explicit.

## Bundled Assets

This repository intentionally keeps `belief/tools_bundled/` and `belief/security_rules/`.

These directories contain optional local assets, compatibility resources, rule packs, or bridge-support materials used by BELIEF during analysis and testing. They are kept for reproducibility and research transparency.

Some files in these directories may originate from third-party ecosystems or rule formats. Their provenance and licensing should be reviewed per subdirectory before commercial redistribution, repackaging, or relicensing.

The BELIEF core remains in `belief/`.

See `BUNDLED_ASSETS.md` for the current asset inventory and publication notes.

## Limitations

- experimental MVP
- Python-focused
- conservative static analysis
- not a complete CFG/alias/interprocedural engine
- Z3 support currently limited to narrow boolean contradiction checks
- route extraction is static and heuristic
- human validation is still required
- bundled assets require per-subdirectory provenance and license review

## Quickstart

From the repository root:

```bash
python -m pip install -e ".[dev,z3]"
python -m belief --help
python -m belief scan --help
```

Example local scan:

```bash
python -m belief scan path/to/python/project --audit-mode --dataflow --routes --json-output out/audit.json
```

Example SARIF and Markdown outputs:

```bash
python -m belief scan path/to/python/project --audit-mode --sarif-output out/audit.sarif
python -m belief scan path/to/python/project --audit-mode --audit-markdown out/audit.md
```

## Tests

Run the default local suite:

```bash
python -m pytest -q
```

Run security-focused regressions:

```bash
python -m pytest -q -m security
```

Expected current local results are approximately:

- full suite: `292 passed, 31 skipped`
- security suite: `44 passed`

## License

`pyproject.toml` currently declares `license = {text = "MIT"}`.

A root `LICENSE` file is not yet present in this release-preparation tree. Add and confirm the intended repository license before relying on public redistribution terms.

The repository-level license does not necessarily replace or override licenses attached to bundled third-party assets, rule packs, examples, or compatibility resources under `belief/tools_bundled/` and `belief/security_rules/`.
