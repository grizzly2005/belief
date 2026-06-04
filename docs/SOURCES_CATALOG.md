# BELIEF — Sources Catalog

This document maps every external source bundled into BELIEF to the
BELIEF module that uses it.

## Layout

```
belief/
├── bridges/                    # Python adapters to external tools
│   ├── __init__.py             # BridgeRegistry + BridgeResult
│   ├── belief_adapter.py       # BridgeResult → belief.models.Belief
│   ├── bandit_bridge.py
│   ├── dlint_bridge.py
│   ├── crosshair_bridge.py
│   ├── pyt_bridge.py
│   ├── contextgem_bridge.py
│   ├── semgrep_bridge.py
│   ├── pyre_bridge.py
│   ├── safety_db_bridge.py
│   └── ts_runner.py
├── tools_bundled/              # Vendored source code (20 tools)
│   ├── bandit/
│   ├── code_analyzer/
│   ├── codegraph/
│   ├── contextgem/
│   ├── crosshair/
│   ├── dlint/
│   ├── driftgan/
│   ├── findimports/
│   ├── frouros/
│   ├── git_of_theseus/
│   ├── importlab/
│   ├── modulegraph2/
│   ├── pyan/
│   ├── pydeps/
│   ├── pyexz3/
│   ├── pyre_full/
│   ├── pyt/
│   ├── safety_db/
│   ├── supply_chain_firewall/
│   └── z3_playground/
├── security_rules/             # Data-only rule packs
│   ├── semgrep/                # 500 Semgrep YAML rules
│   ├── codeql/
│   │   ├── python/             # 343 CodeQL queries
│   │   └── dataflow/
│   ├── nuclei/                 # 1822 Nuclei templates (HTTP misconfig + tech)
│   └── joern/                  # Joern CPG queries
└── enhanced_orchestrator.py    # Opt-in orchestrator wrapping base + bridges
```

## Source → Module mapping

| Source | Role in BELIEF | Bridge | Tool type |
|--------|----------------|--------|-----------|
| **bandit** | Scan Python for CWE-mapped patterns (100+) | `bandit_bridge.py` | subprocess |
| **dlint** | Complement Bandit (ReDoS, twisted, YAML) | `dlint_bridge.py` | flake8 plugin |
| **crosshair** | Symbolic execution → concrete counter-examples | `crosshair_bridge.py` | sandboxed subprocess |
| **pyt** | Python taint analyzer → source/sink flows | `pyt_bridge.py` | native import |
| **pyexz3** | Educational symbolic-execution toolkit | (used by symbolic/) | native import |
| **contextgem** | Structured LLM extraction, schema-validated | `contextgem_bridge.py` | native import |
| **code_analyzer** | Patterns for LLM-driven code analysis | (inspiration for extractor) | reference |
| **codegraph** | Class/function hierarchy for visualization | dep_graph | reference |
| **findimports** | Minimal import scanner | dep_graph | reference |
| **importlab** | Robust import resolver (Google) | dep_graph/import_resolver | reference |
| **modulegraph2** | Modern Python 3.10+ module graph | dep_graph | reference |
| **pyan** | AST call-graph builder | dep_graph/call_graph | reference |
| **pydeps** | Module dependency graphs + colors | dep_graph | reference |
| **pyre_full** / **pyre_sapp** | Type inference + Pysa taint | `pyre_bridge.py` | subprocess |
| **safety_db** | 4500+ CVE advisories for Python packages | `safety_db_bridge.py` | JSON DB |
| **supply_chain_firewall** | Datadog's block-list scanner | (used by supply_chain/) | reference |
| **driftgan** | Concept drift detection | advanced_drift | reference |
| **frouros** | Drift detection library (Page-Hinkley, ADWIN) | advanced_drift | reference |
| **git_of_theseus** | File-level churn/hotspot analysis | advanced_drift/git_hotspots | reference |
| **z3_playground** | Z3 examples for BELIEF predicates | symbolic/ | reference |
| **semgrep_rules** | 500 community security rules | `security_rules/semgrep/` | data |
| **codeql_python** / **codeql_dataflow** | 343 CodeQL queries | `security_rules/codeql/` | data |
| **nuclei_misconfig** / **nuclei_tech** | 1822 HTTP templates | `security_rules/nuclei/` | data (for belief_http_engine) |
| **joern_core** / **joern_queries** | CPG-based queries | `security_rules/joern/` | data |
| **src (Claude Code TS)** | Patterns for agent design | see ts_runner.py | TypeScript reference |

## How to use

### 1. Basic: run one bridge
```python
from belief.bridges import registry

result = registry.run("bandit", project_path="/path/to/project")
print(f"{len(result)} findings")
for f in result.findings[:5]:
    print(f)
```

### 2. All bridges → Belief sextuplets
```python
from belief.bridges.belief_adapter import analyze_project

beliefs = analyze_project("/path/to/project")
for b in beliefs:
    print(b.id, b.justification.value, b.predicate.expression)
```

### 3. Enhanced pipeline (LLM + bridges + cross-verify + report)
```python
from belief.config import BeliefConfig
from belief.enhanced_orchestrator import EnhancedOrchestrator

cfg = BeliefConfig()
orch = EnhancedOrchestrator(
    cfg,
    enabled_bridges={"bandit", "dlint", "safety_db", "semgrep"},
)
report = orch.analyze_project("/path/to/project")
# report.beliefs contains base LLM beliefs + bridge beliefs (deduped)
# report.bridge_summary contains per-bridge stats
```

### 4. TypeScript interop (count tokens via Anthropic API)
```python
from belief.bridges.ts_runner import count_tokens_precise

tokens = count_tokens_precise(
    messages=[{"role": "user", "content": "hello"}],
    model="claude-sonnet-4-5",
)
# Falls back to char/3 heuristic if no ANTHROPIC_API_KEY
```

## Installing the external tools

The bridges degrade gracefully when a tool is missing (they return a
`BridgeResult` with an error message, not a crash). Install as needed:

```bash
pip install bandit                  # enables bandit_bridge
pip install flake8 dlint            # enables dlint_bridge
pip install crosshair-tool          # enables crosshair_bridge
pip install semgrep                 # enables semgrep_bridge
pip install pyre-check              # enables pyre_bridge
pip install contextgem              # enables contextgem_bridge
pip install python-taint            # or use bundled pyt/
pip install packaging               # required by safety_db_bridge
```

For TypeScript interop (ts_runner):
```bash
apt install nodejs npm              # or equivalent
```

## Non-goals

This bundle is NOT:
- A fork of any upstream project. All sources remain under their original
  licenses (Apache-2.0, BSD-3, MIT, GPL-2+ depending on the tool).
- A replacement for BELIEF's LLM-based extraction. Bridges are a
  *pre-filter and complement*; the semantic belief extraction still
  happens via `belief.extractor`.
- A guarantee of zero false positives. Every bridge is a static analyzer
  with its own FP rate. Use the Z3 verifier (`belief.z3_verifier`) and
  crosshair (`crosshair_bridge`) to confirm high-priority beliefs.
