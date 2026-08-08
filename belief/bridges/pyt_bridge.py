"""
pyt_bridge — Python Taint analyzer (pyt).

PyT is a static taint analyzer for Python. It models taint flow through:
- function calls
- assignments
- class instances
- Flask/Django request handlers

For BELIEF, taint paths are CROSSING BELIEFS. Each tainted flow from
source → sink implies:
- Belief at source: "this data is attacker-controlled"
- Belief at sink: "this data is safe to use"
- Violation: the two beliefs contradict → finding.

Design:
- Copy pyt's analyzer module into belief.tools_bundled.pyt
- Import it natively (pyt is pure stdlib; no extra deps)
- Run analyzer on each file, collect Vulnerability objects
- Convert each Vulnerability to a Belief sextuplet
"""
from __future__ import annotations

import logging
import sys
import time
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.pyt")


def _try_import_pyt():
    """pyt has a particular import path. Try multiple locations."""
    # First: try the bundled copy
    bundled = Path(__file__).parent.parent / "tools_bundled" / "pyt"
    if bundled.exists():
        sys.path.insert(0, str(bundled.parent))
    try:
        for module_name in (
            "pyt.analyser",
            "pyt.cfg_builder",
            "pyt.lattice",
            "pyt.vulnerability_helper",
        ):
            import_module(module_name)
        return True
    except ImportError:
        pass
    try:
        # Fallback: installed version
        import pyt  # noqa
        return True
    except ImportError:
        return False


def is_installed() -> bool:
    return _try_import_pyt()


def run_pyt(
    project_path: str,
    *,
    trigger_word_file: Optional[str] = None,
    max_files: int = 200,
    use_cache: bool = True,
) -> BridgeResult:
    t0 = time.time()
    result = BridgeResult(source="pyt")

    if not _try_import_pyt():
        result.errors.append(
            "pyt not available. Copy sources into belief/tools_bundled/pyt/ "
            "or `pip install python-taint`."
        )
        result.elapsed_s = time.time() - t0
        return result

    # Lazy import after path setup
    try:
        from pyt.core.ast_helper import generate_ast
        from pyt.analysis.constraint_table import initialize_constraint_table
        from pyt.analysis.fixed_point import analyse
        from pyt.cfg import make_cfg
        from pyt.vulnerabilities.vulnerabilities import find_vulnerabilities
        from pyt.web_frameworks.framework_adaptor import FrameworkAdaptor
        from pyt.web_frameworks import is_flask_route_function
    except Exception as e:
        result.errors.append(f"pyt modules not importable: {e}")
        result.elapsed_s = time.time() - t0
        return result

    # Default trigger file lives with the bundled pyt
    if not trigger_word_file:
        bundled = (Path(__file__).parent.parent / "tools_bundled" / "pyt"
                   / "vulnerability_definitions" / "all_trigger_words.pyt")
        if bundled.exists():
            trigger_word_file = str(bundled)
        else:
            # Fallback to pyt.usage.default_trigger_word_file if it's defined
            try:
                from pyt.usage import default_trigger_word_file
                trigger_word_file = default_trigger_word_file
            except Exception:
                result.errors.append(
                    "pyt trigger file not found (expected at "
                    "belief/tools_bundled/pyt/vulnerability_definitions/all_trigger_words.pyt)"
                )
                result.elapsed_s = time.time() - t0
                return result

    project = Path(project_path)
    py_files = [f for f in project.rglob("*.py")
                if "test" not in str(f).lower() and "__pycache__" not in str(f)]
    py_files = py_files[:max_files]

    if not py_files:
        result.errors.append(f"no .py files in {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    cfg_list = []
    for f in py_files:
        try:
            tree = generate_ast(str(f))
            cfg = make_cfg(tree, project_modules=[], local_modules=[],
                           filename=str(f), module_definitions=None)
            cfg_list.append(cfg)
        except Exception as e:
            logger.debug(f"pyt skip {f}: {e}")
            continue

    try:
        FrameworkAdaptor(cfg_list, [], [], is_flask_route_function)
        initialize_constraint_table(cfg_list)
        analyse(cfg_list)
        vulns = find_vulnerabilities(cfg_list, None, [], trigger_word_file)
    except Exception as e:
        result.errors.append(f"pyt analysis crashed: {type(e).__name__}: {e}")
        result.elapsed_s = time.time() - t0
        return result

    for v in vulns:
        result.findings.append({
            "source_file": getattr(v.source_node, "filename", None) if hasattr(v, "source_node") else None,
            "source_line": getattr(v.source_node, "line_number", None) if hasattr(v, "source_node") else None,
            "source_label": getattr(v, "source", "unknown"),
            "sink_file": getattr(v.sink_node, "filename", None) if hasattr(v, "sink_node") else None,
            "sink_line": getattr(v.sink_node, "line_number", None) if hasattr(v, "sink_node") else None,
            "sink_label": getattr(v, "sink", "unknown"),
            "vuln_type": type(v).__name__,
            "message": str(v),
        })

    result.elapsed_s = time.time() - t0
    logger.info(f"pyt: {len(result.findings)} taint flows in {result.elapsed_s:.1f}s")
    return result


def to_belief(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """A taint flow produces TWO beliefs: one at source, one at sink,
    plus their crossing link. Orchestrator handles the linkage."""
    beliefs = []
    if finding.get("source_file"):
        beliefs.append({
            "assumption": f"untrusted data enters via {finding['source_label']}",
            "anchor_file": finding["source_file"],
            "anchor_line": finding["source_line"] or 0,
            "anchor_line_end": finding["source_line"] or 0,
            "justification_type": "C2_STATICALLY_VERIFIED_PROPERTY",
            "contextual_constraint": f"taint_source={finding['source_label']}",
            "trust_domain": "untrusted",
            "logic_type": "semantic",
            "source": "pyt",
            "raw": finding,
        })
    if finding.get("sink_file"):
        beliefs.append({
            "assumption": f"data should be sanitized before reaching {finding['sink_label']}",
            "anchor_file": finding["sink_file"],
            "anchor_line": finding["sink_line"] or 0,
            "anchor_line_end": finding["sink_line"] or 0,
            "justification_type": "C2_STATICALLY_VERIFIED_PROPERTY",
            "contextual_constraint": f"taint_sink={finding['sink_label']}, vuln_type={finding['vuln_type']}",
            "trust_domain": "trusted_after_sanitize",
            "logic_type": "semantic",
            "source": "pyt",
            "raw": finding,
        })
    return beliefs


def register(registry) -> None:
    registry.register("pyt", run_pyt)
