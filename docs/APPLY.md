# BELIEF v3 — bridges patch — installation

This patch adds the **bridges** layer on top of v2 correctif. It does NOT
modify any existing BELIEF file. Everything is additive.

## Prerequisites

- v2 correctif must be applied (dep_graph/ = 704 lines, advanced_drift/ = 629 lines)
- Python 3.9+
- `httpx` installed (already a BELIEF dep)

## What this patch adds

New files and directories (11 files + 4 data directories):

```
belief/bridges/                        # 10 files
  ├─ __init__.py                      # BridgeRegistry + BridgeResult
  ├─ belief_adapter.py                # BridgeResult → Belief
  ├─ bandit_bridge.py                 # + 8 tool-specific bridges
  ├─ dlint_bridge.py
  ├─ crosshair_bridge.py
  ├─ pyt_bridge.py
  ├─ contextgem_bridge.py
  ├─ semgrep_bridge.py
  ├─ pyre_bridge.py
  ├─ safety_db_bridge.py
  └─ ts_runner.py

belief/enhanced_orchestrator.py       # opt-in wrapper

belief/tools_bundled/                  # ~600 Python files, 5.2 MB
  ├─ bandit/
  ├─ dlint/
  ├─ crosshair/
  ├─ pyt/
  ├─ contextgem/
  ├─ pyexz3/
  ├─ pyre_full/
  ├─ safety_db/         (+data/insecure.json, +alias insecure_full.json)
  ├─ supply_chain_firewall/
  ├─ code_analyzer/
  ├─ codegraph/
  ├─ findimports/
  ├─ frouros/
  ├─ git_of_theseus/
  ├─ importlab/
  ├─ modulegraph2/
  ├─ pyan/
  ├─ pydeps/
  ├─ driftgan/
  └─ z3_playground/

belief/security_rules/                 # ~2700 rules, 7.8 MB
  ├─ semgrep/      (500 YAML rules)
  ├─ codeql/
  │   ├─ python/   (68 queries + includes)
  │   └─ dataflow/ (287 queries + includes)
  ├─ nuclei/       (1822 templates, for belief_http_engine)
  └─ joern/

tests_bridges/
  └─ test_integration.py              # 6 tests, no LLM required

docs/
  └─ SOURCES_CATALOG.md
```

## Install

```bash
cd /path/to/BELIEF/
# Backup first
cp -r belief belief_backup_pre_v3

# Apply
unzip -o belief_v3_bridges.zip
```

The zip places `belief/bridges/`, `belief/tools_bundled/`, `belief/security_rules/`,
`belief/enhanced_orchestrator.py`, `tests_bridges/`, and `docs/` directly
at the project root. No existing file is overwritten.

## Verify

```bash
# 1. Imports
python3 -c "
from belief.bridges import registry
from belief.bridges.belief_adapter import adapt_all, dict_to_belief
from belief.enhanced_orchestrator import EnhancedOrchestrator
print('Bridges loaded:', registry.available())
"
# Expected output:
# Bridges loaded: ['bandit', 'contextgem', 'crosshair', 'dlint',
#                  'pyre', 'pyt', 'safety_db', 'semgrep', 'ts_runner']

# 2. Integration test (runs offline, no LLM needed)
python3 tests_bridges/test_integration.py
# Expected: 6/6 passed
```

## Enable an external tool

The bridges degrade gracefully — no tool, no findings, no crash.
To actually USE a bridge, install its backend:

```bash
pip install bandit           # for bandit_bridge
pip install flake8 dlint     # for dlint_bridge
pip install crosshair-tool   # for crosshair_bridge
pip install semgrep          # for semgrep_bridge
pip install pyre-check       # for pyre_bridge
pip install contextgem       # for contextgem_bridge
pip install packaging        # required by safety_db_bridge (usually already present)
```

For TypeScript interop (ts_runner):
```bash
# Node.js 18+ must be on PATH
node --version
```

## Run against your own project

```python
from belief.bridges.belief_adapter import analyze_project

beliefs = analyze_project("/path/to/your/project")
print(f"{len(beliefs)} beliefs from bridges")
# Sort by fragility (how risky):
for b in sorted(beliefs, key=lambda x: -x.fragility)[:10]:
    print(f"  {b.fragility:.2f}  {b.scope.file_path}:{b.scope.line_start}  "
          f"{b.justification.value}  {b.predicate.expression[:60]}")
```

Or the full enhanced pipeline (requires LLM + Ollama):
```python
from belief.config import BeliefConfig
from belief.enhanced_orchestrator import EnhancedOrchestrator

orch = EnhancedOrchestrator(BeliefConfig())
report = orch.analyze_project("/path/to/your/project")
print(f"Base: {len(report.beliefs) - sum(len(r['findings']) for r in report.bridge_summary.values()) if hasattr(report, 'bridge_summary') else '?'}")
print(f"Bridge summary: {report.bridge_summary}")
```

## Troubleshooting

**"bridge <x> crashed"** in logs — a tool's subprocess errored. Check
`BridgeResult.errors` for the message. Usually: tool not installed, or
project contains a file that makes the tool choke (e.g. bandit on a
syntax-error file). Bridges isolate these errors — BELIEF keeps going.

**safety_db says DB not found** — the DB lives at
`belief/tools_bundled/safety_db/data/insecure.json` (and an alias
`insecure_full.json`). Verify both files exist after unzip.

**Integration test says N bridges unavailable** — expected. Only `bandit`,
`dlint`, `safety_db`, and `ts_runner` (if Node present) run in the
default env. Install more tools to unlock more bridges.
