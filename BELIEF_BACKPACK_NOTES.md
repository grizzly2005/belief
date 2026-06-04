# BELIEF Backpack Notes

## Scope

This pass inspected external repositories only as a design backpack. BELIEF v4 keeps its own implementation and does not vendor or copy external source code.

## Repositories Inspected

All repositories were cloned shallowly under `/tmp/belief_backpack_sources` for local read-only inspection:

- `microsoft/sarif-python-om` - MIT license.
- `microsoft/sarif-tools` - MIT license.
- `PyCQA/bandit` - Apache-2.0 license.
- `pallets/flask` - BSD-style license.
- `fastapi/fastapi` - MIT license.
- `django/django` - BSD-style license.

## Files And Patterns Inspected

SARIF:

- SARIF 2.1.0 schema/result fields such as `ruleId`, `locations`, `partialFingerprints`, `fingerprints`, `properties`, `runs`, and `tool.driver.rules`.
- Decision: implement a small hand-built JSON exporter in `belief.exporters.sarif` instead of adding a dependency on `sarif-python-om`.

Bandit:

- Rule-family ideas around unsafe deserialization, shell/process calls, YAML loading, markup safety, hardcoded secrets, tar/file/path risks, and CWE metadata.
- Decision: centralize BELIEF's local names in `belief.security_taxonomy`; do not import Bandit plugins or implementation code.

Flask, FastAPI, Django:

- Public route declaration shapes such as `@app.route`, `@bp.route`, `@router.get`, `path(...)`, `re_path(...)`, and `add_url_rule(...)`.
- Decision: add AST-only route inventory modules under `belief.routes`; do not depend on or import these frameworks at runtime.

## Implemented Backpack Pieces

- `belief.security_taxonomy`: shared source/sink/sanitizer/guarantee pattern metadata.
- `belief.audit_dedup`: deterministic semantic clusters for near-duplicate `AuditCase` records.
- `belief.exporters.sarif`: minimal SARIF 2.1.0 audit-case exporter.
- `belief.importers.sarif`: minimal SARIF 2.1.0 importer for future bridge outputs.
- `belief.exporters.markdown`: concise human audit report renderer.
- `belief.routes`: AST-only Flask/FastAPI/Django route inventory.
- CLI flags for opt-in outputs:
  - `--sarif-output`
  - `--audit-markdown`
  - `--include-protected-in-report`
  - `--dedup-audit-cases`
  - `--routes`
  - `--show-routes`
  - `--routes-json`

## Attribution And Copying Policy

No external source code was copied into BELIEF v4. The integration uses independently written Python code and only adopts high-level, standard field names or framework idioms.

No GPL or AGPL repository was used as an implementation source. No third-party analyzer was vendored.

## Ignored Or Deferred Candidates

- Full SARIF object model dependency: deferred to keep the CLI lightweight.
- Full Bandit plugin bridge: deferred because BELIEF already has bridge infrastructure and local patterns should remain small.
- Runtime framework introspection for routes: avoided because route inventory must be static and side-effect free.
- Full CodeQL/Semgrep/Pyre/Pysa/PyT integration: continue to treat these as bridges, not core runtime dependencies.

## Remaining Limits

- Route extraction is heuristic and AST-only. It will miss dynamic route registration and complex include/router composition.
- Route-to-audit-case enrichment is conservative. It requires same-file evidence and only falls back when a file has exactly one route.
- SARIF output is intentionally minimal and focused on audit cases, not all BELIEF report fields.
- SARIF import is a skeleton for future bridges. It imports results into `Finding` objects but does not run Semgrep, CodeQL, Bandit, or any external engine.
- Markdown output is a triage report, not a full legal bug-bounty submission.
- Clustering is deterministic but conservative; semantically similar cases with different source/sink names may remain separate.
