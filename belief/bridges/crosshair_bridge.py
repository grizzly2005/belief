"""
crosshair_bridge — use CrossHair to CONCRETIZE a Belief.

Z3 tells us "predicate P is satisfiable" (=violable). CrossHair can go further:
it generates an actual Python input that violates P, via symbolic execution.

This is enormously valuable because:
- It turns a maybe-bug into a definite bug with a reproducer
- It reduces false positives dramatically (the belief is really violable)
- The counter-example is a concrete test the user can run

Integration:
- Input: a Belief sextuplet + the source file where its function lives
- Output: (violated: bool, counter_example: dict|None, reason: str)

CrossHair's API (`crosshair.core.analyze_function`) takes a callable + contract.
We dynamically import the function, wrap its pre/post in crosshair's
condition_parser format (PEP316-style docstring), then analyze.

Because crosshair runs the code under instrumentation, we sandbox it:
- 20s timeout per predicate
- runs in a subprocess so a crash doesn't kill BELIEF
- import path pinned to the project under analysis
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.crosshair")


def is_installed() -> bool:
    try:
        import crosshair  # noqa
        return True
    except ImportError:
        return False


# Template for the subprocess runner. It's written to a temp file
# and executed with the target project on sys.path.
_RUNNER_TEMPLATE = r'''
import importlib.util
import json
import sys
import traceback
from pathlib import Path

def _run():
    project_path = {project_path!r}
    module_file  = {module_file!r}
    func_name    = {func_name!r}
    pre_expr     = {pre_expr!r}   # e.g. "len(x) > 0"
    post_expr    = {post_expr!r}  # e.g. "result != None"
    param_names  = {param_names!r}
    timeout_s    = {timeout_s!r}

    sys.path.insert(0, project_path)

    try:
        from crosshair.core_and_libs import analyze_function
        from crosshair.options import AnalysisOptions, DEFAULT_OPTIONS
    except Exception as e:
        print(json.dumps({{"status": "unavailable", "error": str(e)}}))
        return

    try:
        spec = importlib.util.spec_from_file_location("_ch_target", module_file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, func_name, None)
        if fn is None:
            print(json.dumps({{"status": "error", "error": f"function {{func_name}} not found"}}))
            return

        # Build a PEP316 docstring contract around the function
        # to express pre/post conditions.
        original_doc = fn.__doc__ or ""
        contract = original_doc + "\n"
        if pre_expr:
            contract += f"pre: {{pre_expr}}\n"
        if post_expr:
            contract += f"post: {{post_expr}}\n"
        fn.__doc__ = contract

        options = AnalysisOptions(
            analysis_kind=DEFAULT_OPTIONS.analysis_kind,
            per_condition_timeout=float(timeout_s),
            per_path_timeout=float(timeout_s),
            max_iterations=50,
        )

        counter = None
        for msg in analyze_function(fn, options):
            if getattr(msg, "state", None) is not None:
                counter = {{
                    "message": str(msg),
                    "state": str(msg.state) if hasattr(msg, "state") else None,
                    "line": getattr(msg, "line", None),
                }}
                break
        if counter:
            print(json.dumps({{"status": "violated", "counter_example": counter}}))
        else:
            print(json.dumps({{"status": "ok", "counter_example": None}}))
    except Exception as e:
        print(json.dumps({{"status": "error", "error": f"{{type(e).__name__}}: {{e}}"}}))
        traceback.print_exc(file=sys.stderr)

_run()
'''


def verify_belief(
    *,
    project_path: str,
    module_file: str,
    func_name: str,
    pre_expr: str = "",
    post_expr: str = "",
    param_names: Optional[list] = None,
    timeout_s: int = 20,
) -> BridgeResult:
    """Attempt to find a counter-example showing post_expr can be violated
    under pre_expr, using CrossHair symbolic execution."""
    t0 = time.time()
    result = BridgeResult(source="crosshair")

    if not is_installed():
        result.errors.append(
            "crosshair not installed. `pip install crosshair-tool` to enable."
        )
        result.elapsed_s = time.time() - t0
        return result

    # Write runner to temp file
    runner_src = _RUNNER_TEMPLATE.format(
        project_path=project_path,
        module_file=module_file,
        func_name=func_name,
        pre_expr=pre_expr,
        post_expr=post_expr,
        param_names=param_names or [],
        timeout_s=timeout_s,
    )

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, dir=tempfile.gettempdir()
    ) as tf:
        tf.write(runner_src)
        runner_path = tf.name

    try:
        proc = subprocess.run(
            [sys.executable, runner_path],
            capture_output=True, text=True,
            timeout=timeout_s + 10,
        )
        out = (proc.stdout or "").strip()
        # Take LAST JSON line (crosshair may print others)
        last_line = out.splitlines()[-1] if out else "{}"
        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError:
            result.errors.append(f"crosshair output not JSON: {last_line[:200]}")
            parsed = {"status": "error"}

        result.findings = [parsed]
        if parsed.get("status") == "error":
            result.errors.append(parsed.get("error", "unknown"))

    except subprocess.TimeoutExpired:
        result.errors.append(f"crosshair timed out after {timeout_s+10}s")
    except Exception as e:
        result.errors.append(f"crosshair subprocess failed: {type(e).__name__}: {e}")
    finally:
        try:
            os.unlink(runner_path)
        except OSError:
            pass

    result.elapsed_s = time.time() - t0
    return result


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Mostly used as a VERIFIER, not a finder. When it does flag something,
    wrap as a high-confidence belief violation."""
    status = finding.get("status", "unknown")
    counter = finding.get("counter_example")
    if status != "violated" or not counter:
        return None
    return {
        "assumption": "crosshair counter-example found",
        "anchor_file": "<symbolic>",
        "anchor_line": counter.get("line", 0),
        "anchor_line_end": counter.get("line", 0),
        "justification_type": "C1",   # proven violable
        "contextual_constraint": str(counter.get("state", "unknown"))[:500],
        "trust_domain": "symbolic",
        "logic_type": "fol",
        "source": "crosshair",
        "raw": finding,
    }


def register(registry) -> None:
    registry.register("crosshair", verify_belief)
