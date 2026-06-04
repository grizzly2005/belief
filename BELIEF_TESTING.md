# BELIEF v4 Testing Notes

## Default Test Suite

Run from `BELIEF_V2/belief_v4`:

```powershell
python -m pytest -q
```

The default suite uses `testpaths = ["tests"]`. Tests that require optional tools, external services, slow execution, or LLM providers must be marked:

- `unit`
- `integration`
- `security`
- `slow`
- `llm`
- `external`

## Bridge Integration Tests

Bridge integration tests are outside the default `testpaths` and can be run explicitly:

```powershell
python -m pytest -q tests_bridges\test_integration.py
```

The bridge suite creates a local synthetic vulnerable project under the system temp directory. It does not scan external targets.

## Security-Marked Tests

Run the AppSec/SAST/Finding regressions with:

```powershell
python -m pytest -q -m security
```

The security marker is intentionally narrow. It currently covers dynamic Python code execution patterns, additional Python security sinks, bridge finding status normalization, and the stable `Finding`/CWE report model. Do not mark the entire suite as `security`; mark only files or tests whose assertions are directly AppSec, SAST, CWE, or finding/report-security related.

## CLI Smoke Tests

The module entrypoint should work without an installed console script:

```powershell
python -m belief --help
python -m belief scan --help
```

If the `belief` command is not found, install the package or run with `python -m belief`.

## Focused Regression Areas

Current targeted regression files include:

- `tests/test_core_runtime_p0.py`
- `tests/test_security_patterns_dynamic_code.py`
- `tests/test_security_patterns_extended.py`
- `tests/test_finding_report_model.py`
- `tests/test_parser_roots.py`
- `tests/test_bridge_status.py`
- `tests/test_checkpoint_findings.py`
- `tests/test_import_resolver.py`
- `tests/test_cycle_detector.py`
- `tests/test_pipeline_cycle_analysis.py`
- `tests/test_dataflow.py`
- `tests/test_audit_case.py`
- `tests/test_sarif_export.py`
- `tests/test_audit_markdown.py`
- `tests/test_audit_dedup.py`
- `tests/test_route_inventory.py`
- `tests/test_security_taxonomy.py`
- `tests/test_sarif_import.py`

## Optional Cycle Analysis Tests

Call-graph cycle findings are opt-in. The focused tests verify that the default pipeline emits no `CALL_GRAPH_CYCLE` findings, that `include_cycles=True` adds deterministic info findings, that `max_cycles` and `truncated` metadata are respected, and that `python -m belief scan --help` exposes `--include-cycles` and `--max-cycles`.

Run only this area with:

```powershell
python -m pytest -q tests/test_cycle_detector.py tests/test_pipeline_cycle_analysis.py
```

## Belief/Z3 Roadmap Tests

Future Z3 work should stay narrow and unit-tested first. The current minimal boolean-atom MVP is covered by:

```powershell
python -m pytest -q tests/test_z3_logic_ir.py
```

If `z3-solver` is absent, solver-dependent tests skip with `z3-solver not installed`; pure serialization/model-boundary tests still run. If Z3 is present, the test verifies compatible constraints are SAT, true/false constraints over one atom are UNSAT, `unsat_core` contains the originating belief IDs, and the proof can become a traceable `Conflict` without creating any automatic `Finding`.

The Belief adapter is covered by:

```powershell
python -m pytest -q tests/test_belief_logic_adapter.py
```

Those tests verify positive/negative boolean predicates, explicit `== true` and `== false`, clean rejection of ambiguous expressions, UNSAT core tracking through `belief.id`, optional `Conflict` conversion, and no automatic `Finding` creation.

## Invariant And Hypothesis Tests

Invariant mining and hypothesis enrichment are covered by:

```powershell
python -m pytest -q tests/test_invariant_miner.py
python -m pytest -q tests/test_hypothesis_engine.py
python -m pytest -q tests/test_guarantee_index.py
```

The fixtures live under `tests/real_world_snippets/` and include provenance comments for:

- SecureDrop 2.15.1 storage path verification;
- SecureDrop 2.15.1 source route ownership scoping;
- SecureDrop 2.15.1 journalist Markup escaping;
- Flask-Caching 1.10.1 pickle backend behavior;
- Square SDK Authorization header false-positive context.

These tests verify that guarantees remain separate from normal findings, that `--hypotheses` attaches JSON metadata only when requested, that `--show-proofs` includes Z3 proof detail, and that `--only-hypotheses` can filter by `unproven`, `weakened`, `strengthened`, or `contradicted`.

`tests/test_guarantee_index.py` covers cross-file propagation for the SecureDrop `Storage.path -> reply_path -> open(reply_path)` shape, the direct `open(Storage.get_default().path(...))` shape, import-adjacent resolution of `store.py` from a `source_app` target, deterministic ordering, and JSON export of propagated guarantees.

`tests/test_dataflow.py` covers the opt-in local def-use/dataflow layer. It uses the same real-world snippets and verifies:

- SecureDrop `request.form["reply_filename"] -> filter_by(filename=...)` with source scoping;
- SecureDrop `Storage.path -> reply_path -> open(reply_path)` as a low-priority guaranteed path;
- SecureDrop journalist `escape(display_name) -> Markup(...)`;
- Flask-Caching `cache_file.read() -> pickle.loads(payload)` as high-priority without a trust-boundary guarantee;
- Square SDK Authorization header strings do not become exploitable dataflow paths;
- `python -m belief scan --help` exposes `--dataflow` and `--show-dataflow`;
- JSON output contains dataflow metadata only when requested.

`tests/test_audit_case.py` covers MVP audit mode and `AuditCase` conversion. It verifies deterministic serialization, SecureDrop protected path and scoped IDOR/BOLA cases, Markup escaping, Flask-Caching pickle as critical actionable evidence, Square SDK Authorization header false-positive handling, `--audit-mode`/`--interesting-only` help text, deterministic audit JSON, and console hiding of protected cases from the top audit list.

Useful CLI smoke checks:

```powershell
python -m belief scan tests/real_world_snippets --hypotheses --show-proofs --only security
python -m belief scan tests/real_world_snippets --hypotheses --only-hypotheses contradicted --json-output out/hypotheses.json
python -m belief scan tests/real_world_snippets --hypotheses --dataflow --show-dataflow --only security
python -m belief scan tests/real_world_snippets --audit-mode --show-dataflow --json-output out/audit.json
python -m belief scan tests/real_world_snippets --audit-mode --sarif-output out/audit.sarif
python -m belief scan tests/real_world_snippets --audit-mode --audit-markdown out/audit.md
python -m belief scan tests/real_world_snippets --routes --show-routes --routes-json out/routes.json
```

## Backpack Output Tests

Backpack integration is covered by:

```powershell
python -m pytest -q tests/test_sarif_export.py
python -m pytest -q tests/test_audit_markdown.py
python -m pytest -q tests/test_audit_dedup.py
python -m pytest -q tests/test_route_inventory.py
python -m pytest -q tests/test_security_taxonomy.py
python -m pytest -q tests/test_sarif_import.py
```

These tests verify deterministic SARIF export/import shape, concise Markdown rendering, cluster deduplication, Flask/FastAPI/Django route inventory, conservative route-to-audit-case context attachment, and the centralized security taxonomy used by local dataflow.

`tests/test_cli_scan_triage.py` also checks that `belief scan --audit-mode --routes --json-output ...` emits `route_context` when a finding line is inside a matched route handler.

Real-world benchmark expectations for the MVP:

- SecureDrop source app: `reply_path` and escaped Markup should be protected or false-positive-likely, not high actionable; delete reply should show request input plus ownership/source scoping.
- Flask-Caching pickle: unsafe deserialization should remain high/critical actionable or needs-review without invented protection.
- Square SDK: Authorization/Bearer/header-name patterns should not dominate high actionable audit cases.
