# BELIEF v4 Migration Notes

## What Changed

This pass keeps the existing `Belief` sextuplet API and adds a stable report-level `Finding` model. Existing code that consumes `beliefs[]` can continue to do so. New report consumers should prefer `findings[]` for security triage and deduplication.

## Backward Compatibility

The following compatibility paths remain:

- `JustificationCategory.C3_DOCUMENTED` maps to `C3_DOCUMENTED_CONVENTION`.
- `LogicType.CONTRACT` maps to `SEMANTIC`.
- `Belief.from_dict()` accepts old enum names and `metadata` as `source_metadata`.
- `Finding.from_dict()` accepts common bridge and legacy names such as `test_id`, `check_id`, `filename`, `path`, `anchor_line`, `line_start`, `issue_text`, and `canonical_key`.
- `EnhancedOrchestrator` remains as a shim over `Orchestrator`.

## Parser Behavior

The parser no longer treats the whole repository as source by default. It excludes corpora, rules, examples, docs, vendored code, generated files, virtualenvs, caches, and build outputs. To analyze a corpus intentionally, pass it as the target or configure it as a `corpus_root`.

## Legacy Modules Inspected

The following legacy modules were inspected without modifying legacy BELIEF:

- `advanced_drift/belief_drift.py`: useful report-diff idea, but needs v4 `canonical_key`/`Finding` semantics before migration.
- `advanced_drift/concept_drift.py`: useful pure-Python metrics-stream detectors, but not yet connected to v4 pipeline metrics.
- `advanced_drift/git_hotspots.py`: useful churn scoring, but depends on real Git repositories; defer until Git layout is stable.
- `dep_graph/import_resolver.py`: migrated in a reduced v4 form as `belief.import_resolver`.
- `dep_graph/call_graph.py`: overlaps with `CodeParser.call_graph`; defer unless richer typed graph APIs are needed.
- `dep_graph/cycle_detector.py`: useful cycle detection concept; migrated as a v4-native call-graph utility without legacy graph dependencies.
- `dep_graph/graph_core.py`: generic graph container; defer to avoid introducing a parallel graph model.
- `cfg/__init__.py`: larger CFG/def-use subsystem; defer because v4 already has `taint` and security AST patterns.
- `graph_visualizer/__init__.py`: useful reporting feature but unsafe to migrate before HTML escaping and output contract review.

## Migrated From Legacy

`belief.import_resolver` is a selective migration of the legacy import resolver. It keeps the valuable parts only:

- AST-only import extraction;
- stdlib/project/third-party/relative classification;
- conditional import detection;
- directory scanning through `CodeParser` so default exclusions and explicit corpus roots remain consistent.

`belief.cycle_detector` is a selective migration of the legacy cycle idea, not the legacy implementation. It works directly on the existing v4 call graph shape:

- normalizes `{caller: {callees}}` and simple edge lists;
- detects self-cycles and simple directed cycles;
- deduplicates equivalent rotations;
- returns deterministic `FunctionCycle` records;
- can convert cycles to optional `Finding` objects with `CALL_GRAPH_CYCLE`.

The detector is now wired into v4 only as an explicit option. `include_cycles` defaults to `False`, `max_cycles` defaults to `100`, and reports include cycle metadata only when the option is enabled. This keeps older report consumers stable while making cycle findings available for targeted audits.

## Belief/Z3 Migration Direction

Do not migrate legacy graph or symbolic subsystems wholesale. The v4-safe direction is a small decoupled path:

- keep `Belief` unchanged;
- translate supported belief predicates into a minimal Logic IR;
- translate that IR into Z3 constraints;
- use Z3 UNSAT and unsat cores to create traceable `Conflict` objects;
- convert to report `Finding` only after the conflict semantics are stable.

The next implementation should start with boolean atoms only, for example `feature.enabled` and `not feature.enabled` over the same atom.

## Minimal Boolean IR Added

`belief.logic_ir` is the first v4-native formal bridge:

- `BooleanAtom` and `BooleanConstraint` keep formal atoms separate from `Belief`;
- Z3 `Bool` expressions are created only inside the backend function;
- `assert_and_track` maps constraints back to `belief_id` values;
- `LogicCheckResult` reports `sat`, `unsat`, `unknown`, `unavailable`, or `error`;
- `LogicConflictProof` serializes an UNSAT proof and can convert it to the existing `Conflict` model when the involved beliefs are available.

No automatic `Finding` conversion is enabled yet. That should wait until formal conflict severity, CWE mapping, and evidence fields are explicit.

## Belief Boolean Adapter Added

`belief.belief_logic_adapter` adds a minimal `Belief -> BooleanConstraint` bridge. It deliberately supports only simple boolean atom shapes and ignores ambiguous predicates:

- `atom`
- `not atom`
- `!atom`
- `atom == true`
- `atom == false`

This keeps the formal path useful without pretending the full predicate language is solved. The adapter uses `belief.id` for tracking and can produce a `LogicConflictProof` or optional existing `Conflict`, but still does not create automatic `Finding` records.

## Invariant Mining And Hypotheses Added

`belief.invariant_miner` is a new v4-native module, not a legacy migration. It extracts explicit defensive guarantees from narrow real-code patterns and returns them as ordinary `Belief` objects tagged with `source_metadata["category"] = "guarantee"`.

`belief.hypothesis_engine` consumes existing `Finding` objects plus mined guarantees and attaches optional `metadata["hypothesis"]`. This preserves report compatibility: default scans do not change, and no guarantee becomes a visible finding unless a caller explicitly chooses to display it.

`belief.guarantee_index` extends this path across files without migrating legacy graph code. It registers function/method guarantees such as `Storage.path`, resolves simple nearby imports such as `from store import Storage`, and attaches called-function guarantees to findings when the local sink uses a variable assigned from that call.

`belief.dataflow` adds the first v4-native local def-use/source-to-sink layer. It reuses the existing AST-first direction instead of migrating legacy CFG wholesale. The layer is intentionally narrow:

- simple assignments and variable origins;
- direct source shapes such as `request.form[...]`, `request.args.get(...)`, `request.files[...]`, `os.environ.get(...)`, file reads, and parameters;
- direct sinks such as `open`, destructive path operations, shell commands, HTTP requests, `Markup`, `pickle.load(s)`, and ORM `filter_by(...)`;
- sanitizer/guarantee nodes such as `escape`, `html.escape`, `secure_filename`, `safe_join`, `os.path.basename`, `Storage.path`, and current-principal query scoping;
- same-file return helpers only when the return is directly a known sanitizer/guarantee.

It does not replace `belief.taint.TaintEngine`, does not migrate PyT into the core runtime, and does not emit new findings by default. Its output is attached as metadata when `belief scan --dataflow` is requested.

The quick scan CLI now supports:

- `--hypotheses`
- `--show-proofs`
- `--only-hypotheses unproven|weakened|strengthened|contradicted|all`
- `--dataflow`
- `--show-dataflow`
- `--audit-mode`
- `--interesting-only`

Only simple boolean counter-proofs use Z3, routed through `belief.belief_logic_adapter`. There is still no `z3_expr` field on `Belief`, and ambiguous predicates are left as human-review hypotheses instead of being forced into formal logic.

This is the intended migration direction away from pure SAST: BELIEF should preserve raw findings while adding evidence about guarantees, missing guarantees, and counter-proofs. SecureDrop-like storage path reports can now be annotated as weakened/contradicted when storage boundary invariants are present. Flask-Caching-like pickle deserialization remains strengthened when BELIEF finds no local trust-boundary proof.

## AuditCase MVP Added

`belief.audit_case` adds the MVP release layer for assisted bug-bounty triage. It is intentionally a thin serializer/mapper over existing v4 pieces:

- raw `Finding`;
- optional `hypothesis`;
- optional `dataflow`;
- mined/propgated guarantees;
- Z3 `unsat_core` when available.

It outputs deterministic `AuditCase` dictionaries with status, review priority, reason, source/sink, dataflow path, guarantees, missing guarantees, and human next steps. This is not automatic bug-bounty report generation and it is not exploit generation. It is a final triage surface.

Status mapping is intentionally conservative:

- strengthened dangerous hypotheses become `actionable` or `needs_review`;
- unproven hypotheses become `needs_review`;
- weakened hypotheses with low-priority guarantees become `protected`;
- contradicted hypotheses with Z3 UNSAT become `protected`;
- header-name/runtime-supplied credential contexts become `false_positive_likely`.

`--audit-mode` enables hypotheses and dataflow, emits `belief.audit.v1` JSON, and keeps protected/false-positive-likely cases out of the console top list by default. The JSON still preserves all audit cases for review and reproducibility.

## Backpack Integration Added

The backpack pass inspected permissively licensed public projects for output shapes and framework patterns, then implemented small v4-native modules instead of copying code:

- SARIF 2.1.0 field shape was inspected from Microsoft SARIF repositories.
- Markdown audit-report organization was kept local and intentionally minimal.
- Flask, FastAPI, and Django route examples informed AST route extraction heuristics.
- Bandit rule names/CWE ideas informed a centralized security taxonomy.

New modules:

- `belief.security_taxonomy`
- `belief.audit_dedup`
- `belief.exporters.sarif`
- `belief.exporters.markdown`
- `belief.importers.sarif`
- `belief.routes`

New scan options are explicit and default-off:

- `--sarif-output`
- `--audit-markdown`
- `--include-protected-in-report`
- `--dedup-audit-cases`
- `--routes`
- `--show-routes`
- `--routes-json`

No GPL/AGPL code was imported, no third-party analyzer was vendored, and no external scanner is required for these features.

The follow-up route-context pass adds optional `route_context` to `AuditCase`. This does not change raw `Finding` objects and does not infer routes when the match is ambiguous. It is intended to help auditors see whether a case is behind route-level guards such as `login_required` or FastAPI dependency guards.

SecureDrop `source_app/utils.py:90` was inspected manually. `check_url_file(path, regexp)` opens a generic `path`; the visible production caller passes a constant `/var/lib/securedrop/source_v3_url`, but the helper itself accepts arbitrary paths and tests call it with variable temp paths. BELIEF therefore keeps the case visible instead of hiding it without a complete caller proof, and the path-traversal next steps now explicitly ask reviewers to trace production callers.

Current resolver limits are deliberate:

- it does not execute imports;
- it does not build a full project symbol table;
- it only searches nearby parent directories for imported module files;
- propagated guarantees are marked separately from local guarantees with `propagated`, `propagated_via`, and `registered_function`.

## Security Pattern Coverage

Local Python security detection currently covers:

- dynamic code execution: `eval`, `exec`, `compile(..., "exec"|"eval")`
- command injection: user-controlled `os.system`, `os.popen`, and `subprocess(..., shell=True)`
- SQL string formatting in execute/raw/query sinks
- unsafe deserialization: pickle, unsafe yaml, marshal, shelve, jsonpickle
- disabled TLS verification through `verify=False`
- weak crypto and insecure random in security contexts
- SSRF-like variable URL requests
- path traversal-like variable file operations
- XSS-like unsafe HTML sinks
- hardcoded credentials
- debug mode and wildcard CORS
- JWT decode without algorithm pinning

The extractor is intentionally conservative for direct AST patterns and is not a full taint engine. Use bridge analyzers for deeper coverage.

## Remaining Limits

- Cross-function taint is still limited outside the dedicated taint engine and external bridges.
- Generated-file detection is heuristic.
- `rule_roots` are tracked for configuration clarity but are not interpreted as executable rule packs by `CodeParser`.
- Optional bridge tools may still be missing locally; missing tools should now report `status = missing` instead of crashing.
