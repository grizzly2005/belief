# BELIEF v4 Architecture Notes

## Active Runtime

The active Python package is `belief/`. The main runtime path is:

1. `belief.parser.CodeParser` collects Python source files, parses functions with `ast`, builds a call graph, and detects frontiers.
2. `belief.import_resolver.ImportResolver` can classify import edges using the same root/exclusion policy.
3. `belief.cycle_detector.detect_cycles` can inspect `CodeParser.call_graph` for deterministic function cycles.
4. `belief.dataflow` can extract opt-in local def-use/source-to-sink traces for hypothesis metadata.
5. `belief.extractor.BeliefExtractor` and `belief.structural.StructuralExtractor` produce `Belief` objects.
6. `belief.security_patterns.SecurityPatternExtractor` adds local Python security findings without external tools.
7. `belief.bridges` runs optional external analyzers and normalizes their output through `belief.bridges.belief_adapter`.
8. `belief.pipeline.Pipeline` coordinates parse, extraction, bridges, conflicts, report generation, and checkpoint resume.
9. `belief.models.AnalysisReport` serializes deterministic JSON reports.

The compatibility shim `belief.enhanced_orchestrator.EnhancedOrchestrator` still exists, but new code should use `Orchestrator(config, enable_bridges=True)` or `Pipeline`.

## Finding And Report Model

`belief.models.Finding` is the stable, tool-neutral finding model for report JSON:

- `id`
- `source`
- `rule_id`
- `title`
- `description`
- `file`
- `line`
- `end_line`
- `cwe`
- `severity`
- `confidence`
- `evidence`
- `fingerprint`
- `dedup_key`
- `metadata`

`AnalysisReport` now emits:

- `schema_version = belief.report.v2`
- `findings[]` with `schema_version = belief.finding.v1`
- deterministic ordering for beliefs, findings, frontiers, conflicts, and drift events
- `bridge_summary` with bridge `status`
- `run_metadata`

Compatibility fields such as `canonical_key`, `cwe`, `source_metadata`, and bridge metadata are preserved.

## Parser Roots

Default scanning excludes generated, vendored, corpus, rules, docs, examples, virtualenvs, caches, and build output. Important default exclusions include:

- `.git`
- `__pycache__`
- `.pytest_cache`
- `.venv`, `venv`, `env`
- `node_modules`
- `dist`, `build`
- `vendor`, `vendored`
- `adapted`, `*_adapted`
- `examples`
- `docs`, `doc`
- `security_rules`
- `target_flaskjwt`
- `tools_bundled`
- `generated`, `archives`

Explicit roots override the default root-name exclusion for that target. Examples:

```python
from belief.parser import CodeParser

parser = CodeParser(".", source_roots=["belief"])
parser.parse()

corpus = CodeParser(".", corpus_roots=["target_flaskjwt"])
corpus.parse()
```

From the CLI, pass the corpus directly when you really want to analyze it:

```powershell
python -m belief scan target_flaskjwt
python -m belief analyze target_flaskjwt --output out
```

`rule_roots` are configuration metadata and are not scanned as code by the parser.

`ImportResolver` is a narrow utility migrated from legacy BELIEF. It never executes imports; it parses `Import` and `ImportFrom` nodes, classifies targets as `stdlib`, `third_party`, `project`, `relative`, or `unresolved`, and relies on `CodeParser` for recursive scans.

`cycle_detector` is a v4-native utility, not a migration of legacy `graph_core`. It accepts `CodeParser.call_graph` or edge lists, deduplicates equivalent rotations, handles self-cycles, and can convert cycles into optional low-severity `Finding` objects.

## Optional Cycle Analysis

Call-graph cycle analysis is disabled by default to avoid changing existing report noise. It can be enabled explicitly through configuration with `include_cycles=True` and `max_cycles=100` by default, or from the quick CLI scan with:

```powershell
python -m belief scan . --include-cycles --max-cycles 100
```

When enabled in the pipeline or orchestrator, cycles are emitted as `Finding` objects with `rule_id = CALL_GRAPH_CYCLE`, `severity = info`, deterministic `fingerprint`/`dedup_key`, and metadata containing `cycle_id`, `nodes`, `length`, and `entry_node`. Reports also include `run_metadata["cycle_analysis"]` with `enabled`, `count`, `max_cycles`, and `truncated`.

## Belief/Z3 Roadmap

The current `Belief` model stores a `Predicate.expression` string and `LogicType`, and `z3_verifier` can reason over a limited set of parseable predicate expressions. The model does not store `z3_expr` directly.

The next safe step is a small decoupled path:

1. Belief.
2. Minimal Logic IR for boolean atoms.
3. Z3 translator.
4. Z3 solver with UNSAT and unsat core.
5. Traceable `Conflict`, with optional report `Finding` later.

The first MVP should only cover two contradictory formal beliefs over the same boolean atom.

## Minimal Boolean Logic IR

`belief.logic_ir` adds the first decoupled formal path without changing `Belief`:

1. `BooleanAtom` represents a stable boolean atom key.
2. `BooleanConstraint` asserts that the atom is true or false and keeps the originating `belief_id`.
3. `check_boolean_constraints()` translates the IR into Z3 `Bool` constraints.
4. Constraints are added with `assert_and_track`, so UNSAT results return an `unsat_core` of belief IDs.
5. `LogicConflictProof` serializes the proof and can optionally convert a two-belief UNSAT proof into the existing `Conflict` model.

This MVP does not add `z3_expr` to `Belief`, does not replace `z3_verifier.py`, and does not create report `Finding` objects automatically.

`belief.belief_logic_adapter` is the narrow adapter from existing `Belief` objects into that IR. It only accepts deterministic boolean atoms:

- `feature.enabled`
- `not feature.enabled`
- `!feature.enabled`
- `feature.enabled == true`
- `feature.enabled == false`

Unsupported or ambiguous predicate expressions return `None`. The originating `belief.id` is used as the Z3 tracking ID, so UNSAT cores stay traceable.

## Invariants And Hypotheses

`belief.invariant_miner` adds a lightweight local guarantee extractor. It mines explicit defensive patterns from real Python code and returns normal `Belief` objects with `source_metadata["category"] = "guarantee"`. These guarantees are not emitted as scan findings by default.

Covered guarantee families are intentionally narrow:

- path safety: `realpath`, `abspath`, `commonpath`, `basename`, `secure_filename`, filename regexes, and storage `verify`/`path` boundary delegation;
- ownership/auth: `@login_required`, `@admin_required`, ORM `filter_by(source_id=logged_in_source.db_record_id)`, user/owner/current-principal filters;
- escaping/rendering: `escape`, `Markup.escape`, `html.escape`, and `Markup(...format(escape(x)))`;
- generated values: `uuid4`, `secrets.token_*`, `interaction_count`, sanitized filename derivation;
- runtime surface: path-based classification for `source_app`, `journalist_app`, `api/api2`, `alembic/versions`, tests, and deployment/packaging paths.

`belief.hypothesis_engine` is opt-in. It attaches a `finding.metadata["hypothesis"]` object to relevant findings when requested by `belief scan --hypotheses`. It does not create new findings and does not suppress existing ones. The hypothesis object contains:

- `hypothesis_type`
- `danger_beliefs`
- `guarantee_beliefs`
- `missing_guarantees`
- `contradictions`
- `status` (`unproven`, `weakened`, `strengthened`, or `contradicted`)
- `human_next_steps`

Terminology:

- A `Finding` is the stable report item shown to users and exported to JSON.
- A `Belief` is the internal predicate/scope/justification object.
- A guarantee is a mined `Belief` that supports a local defensive invariant.
- A counter-proof is a small boolean contradiction checked through `belief.belief_logic_adapter` and Z3.
- A hypothesis is metadata that explains how a danger finding relates to mined guarantees and missing proof.

This is the first step beyond a classic SAST clone: BELIEF can now report not only "this sink looks dangerous" but also "this nearby or project-level invariant weakens/contradicts the danger, and here is what remains unproven." SecureDrop-style protected storage paths become contradicted or weakened hypotheses when storage boundary guarantees are visible; Flask-Caching-style unsafe pickle remains strengthened when no trust-boundary guarantee is found.

## Local Dataflow / Def-Use

`belief.dataflow` is a v4-native, AST-only dataflow layer. It is opt-in through `belief scan --dataflow` and does not create normal findings by default. Its job is to explain local paths around existing findings:

- source-like values: `request.form[...]`, `request.args.get(...)`, `request.files[...]`, `flask.request.*`, `os.environ.get(...)`, file reads, and function parameters;
- intermediate definitions and uses from simple assignments;
- sanitizer/guarantee calls: `escape`, `Markup.escape`, `html.escape`, `secure_filename`, `safe_join`, `os.path.basename`, and `Storage.path`-style storage helpers;
- sinks: `open`, `os.remove`, `shutil.rmtree`, `subprocess.run(..., shell=True)`, `os.system`, `requests.get`, `Markup`, `pickle.load(s)`, and ORM `filter_by(...)` ownership lookups.

The exported path shape is deliberately small:

```json
{
  "dataflow": {
    "source": "request.form[\"reply_filename\"]",
    "sink": "Reply.query.filter_by(filename=...)",
    "path": ["request.form[\"reply_filename\"]", "filter_by(...)"],
    "sanitizers": [],
    "guarantees": ["query.scoped_to_current_source == true"],
    "missing_guarantees": [],
    "confidence": 0.68,
    "review_priority": "low"
  }
}
```

When `--dataflow` is enabled, JSON reports also include a top-level `dataflow.paths[]` summary so useful traces remain visible even when no existing finding maps directly to that sink. When combined with `--hypotheses`, dataflow is attached under `finding.metadata["hypothesis"]["dataflow"]`. It can strengthen an otherwise unproven danger when a source reaches a sink without sanitizer, or weaken a danger when the local path contains a sanitizer/guarantee. It does not override a Z3-backed contradiction.

This layer is not PyT/Pyre/Semgrep and is not a full interprocedural engine. It only supports narrow same-file function return models such as `def sanitize(x): return secure_filename(x)` and simple local assignment flow.

## MVP Audit Mode

`belief.audit_case` is the final MVP triage layer for bug-bounty-assisted review. It converts existing `Finding` objects, hypothesis metadata, Z3 status, guarantee evidence, and dataflow traces into deterministic `AuditCase` records. It does not replace `Finding` and it does not add another static-analysis framework.

Terminology in the MVP:

- `Finding`: raw stable SAST/report item.
- `Hypothesis`: optional explanation attached to a finding, including guarantees, missing guarantees, and Z3 counter-proof status.
- `Dataflow`: optional local source -> variable -> sanitizer/guarantee -> sink trace.
- `AuditCase`: product-level triage item with `status`, `review_priority`, short reason, and next steps.

`belief scan --audit-mode` enables hypotheses and dataflow automatically, emits `schema_version = belief.audit.v1`, and adds:

- top-level `hypotheses[]`;
- top-level `dataflow.paths[]`;
- top-level `audit_cases[]`;
- `guarantee_summary` grouped by families such as `path_boundary`, `ownership_scope`, `escaping`, and `runtime_surface`.

Audit case statuses are:

- `actionable`;
- `needs_review`;
- `protected`;
- `false_positive_likely`.

The console output is intentionally short in audit mode. It shows counts and only the interesting top cases by default, hiding `protected` and `false_positive_likely` cases from the top list while preserving them in JSON. `--interesting-only` follows the same action-oriented filter.

Review priorities are normalized to `critical`, `high`, `medium`, `low`, and `info`. Examples:

- unsafe deserialization without trust-boundary proof stays `critical`/`actionable`;
- `Storage.path`/`commonpath` protected path traversal-looking reports become low-priority protected cases;
- `Markup` with escaping guarantees becomes protected;
- `Authorization`/`Bearer` header-name patterns become `false_positive_likely`/`info` instead of high actionable secret cases;
- ORM lookup paths with `source_id`/`user_id` current-principal scoping become protected or low-priority IDOR/BOLA cases.

Z3 remains a counter-proof backend only. `AuditCase` reports `z3_status` and `unsat_core` when present, but no `z3_expr` is added to `Belief`.

## Backpack Audit Outputs

The backpack integration adds small, permissively inspired adapters around the existing v4 audit model. It does not copy external project code and it does not add heavyweight analyzer dependencies.

New components:

- `belief.security_taxonomy` centralizes source, sink, sanitizer, and guarantee names used by local dataflow and audit explanations.
- `belief.audit_dedup` clusters near-duplicate `AuditCase` objects and keeps deterministic representatives.
- `belief.exporters.sarif` writes minimal SARIF 2.1.0 logs for audit cases without depending on `sarif-python-om`.
- `belief.exporters.markdown` writes concise human audit reports that hide `protected` and `false_positive_likely` cases by default.
- `belief.routes` extracts Flask, FastAPI, and Django route inventory with AST-only framework heuristics.

The quick scan CLI exposes these as explicit options only:

```powershell
python -m belief scan . --audit-mode --sarif-output out/audit.sarif
python -m belief scan . --audit-mode --audit-markdown out/audit.md
python -m belief scan . --audit-mode --dedup-audit-cases --json-output out/audit.json
python -m belief scan . --routes --show-routes --routes-json out/routes.json
```

Default scans remain unchanged: route inventory, SARIF, Markdown, and audit clustering are disabled unless a caller opts in.

`--include-protected-in-report` affects Markdown only. It is intended for internal review; the default Markdown output stays focused on `actionable` and `needs_review` cases.

When `--audit-mode --routes` is enabled, BELIEF now enriches `AuditCase` JSON with optional `route_context`. Matching is conservative: same file is required, function-span matching wins, and fallback by file is used only when a file has exactly one known route. Unmatched cases remain unchanged.

Example shape:

```json
{
  "route_context": {
    "framework": "flask",
    "route": "/delete",
    "methods": ["POST"],
    "handler": "delete",
    "decorators": ["login_required"],
    "auth_guarantees": ["route.requires_login == true"],
    "confidence": 0.9
  }
}
```

`belief.importers.sarif` is the minimal import-side counterpart to the SARIF exporter. It loads SARIF 2.1.0 JSON and converts `runs[].results[]` into stable `Finding` objects for future Semgrep, CodeQL, and Bandit bridges. It does not execute external tools and has no third-party package dependency.

## Cross-File Guarantee Propagation

`belief.guarantee_index` connects mined guarantees to findings that use protective helper functions from another file. It indexes guarantees by function/method qualname, for example `Storage.path`, and normalizes common call shapes:

- `Storage.path(...)`
- `Storage.get_default().path(...)`
- `current_app.storage.path(...)` when `path` is uniquely indexed

For path findings, it inspects the local source around file sinks and supports:

- assignment flow: `reply_path = Storage.get_default().path(...); open(reply_path)`
- direct sink flow: `open(Storage.get_default().path(...))`

The resolver is intentionally small and deterministic. During `belief scan --hypotheses`, if the target is `source_app` and it sees an import such as `from store import Storage`, it searches nearby parent directories for `store.py` and indexes that file too. It does not execute imports and it is not a general Python import resolver.

SecureDrop example:

1. `source_app/main.py` assigns `reply_path = Storage.get_default().path(reply.filename)`.
2. The quick scan flags `open(reply_path)` as a path traversal-looking sink.
3. `guarantee_index` resolves `Storage.path` in `store.py`.
4. `Storage.path`, `Storage.verify`, `Storage.store_contains`, and filename validation guarantees are attached as propagated guarantees.
5. The hypothesis changes from `strengthened` with zero guarantees to `weakened` or `contradicted` when the boolean counter-proof is available.

Local guarantees come from the same file as the finding. Propagated guarantees come from a called function/method definition and are marked in JSON with `propagated`, `propagated_via`, and `registered_function`.

## Bridges

`BridgeResult.status` is normalized to one of:

- `available`
- `missing`
- `failed`
- `skipped`

Missing tools and argument-mismatch bridge calls are represented as non-crashing `BridgeResult` values. Reports include status, errors, elapsed time, cache status, and metadata.

## Checkpoints

Pipeline checkpoints use schema version 2 and store real state, including functions, frontiers, beliefs, findings, conflicts, code cache, call graph, report data, phase timings, and completed phases. Old counter-only checkpoints are rejected with a clear `PipelineCheckpointError`.
