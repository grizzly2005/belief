"""
pyexz3_bridge — Python Symbolic Execution via PyExZ3.

Complements crosshair_bridge. PyExZ3 is lighter (no bytecode instrumentation,
just a wrapper over Z3), faster for simple functions, and doesn't need
contracts — it explores all feasible branches of a function.

Usage: you supply a target function; PyExZ3 generates inputs that drive
it down different paths. BELIEF uses this to:
- Confirm a belief violation found by the LLM+Z3 pipeline (pyexz3 produces
  concrete inputs)
- Mine new beliefs: branches where certain invariants fail

PyExZ3 needs the target function to take simple-typed args. We isolate it
in a subprocess to sandbox it from BELIEF's process.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.pyexz3")


def _bundled_path() -> Optional[Path]:
    """Path to the bundled PyExZ3 package (its symbolic/ subdir)."""
    p = Path(__file__).parent.parent / "tools_bundled" / "pyexz3"
    return p if (p / "symbolic").is_dir() else None


def is_installed() -> bool:
    return _bundled_path() is not None


_RUNNER = r'''
"""
Subprocess runner for PyExZ3.
Reads {target_file, func_name, arg_spec} as JSON via args, writes results to stdout.
"""
import importlib.util
import json
import sys
import traceback

def main():
    target_file = sys.argv[1]
    func_name   = sys.argv[2]
    pyexz3_path = sys.argv[3]
    max_iters   = int(sys.argv[4]) if len(sys.argv) > 4 else 20

    sys.path.insert(0, pyexz3_path)

    try:
        from symbolic.explore import ExplorationEngine
        from symbolic.invocation import FunctionInvocation
    except Exception as e:
        print(json.dumps({"status": "import_error", "error": str(e)}))
        return

    # Load target module + function
    try:
        spec = importlib.util.spec_from_file_location("_tgt", target_file)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        print(json.dumps({"status": "load_error", "error": str(e)}))
        return

    fn = getattr(mod, func_name, None)
    if fn is None:
        print(json.dumps({"status": "no_function", "error": f"{func_name} not in {target_file}"}))
        return

    # Build FunctionInvocation — PyExZ3 needs arg names + default creator.
    # We inspect fn.__code__ for arg names; default to int inputs.
    try:
        argcount = fn.__code__.co_argcount
        argnames = list(fn.__code__.co_varnames[:argcount])
    except Exception:
        argnames = []

    def mk_args():
        return {n: 0 for n in argnames}  # concrete defaults

    try:
        inv = FunctionInvocation(fn, mk_args)
        for n in argnames:
            # By default PyExZ3 creates int symbolic values; type hint override not supported here.
            inv.addArgumentConstructor(n, 0, lambda v: v)
    except Exception as e:
        print(json.dumps({"status": "invocation_error", "error": str(e)}))
        return

    try:
        engine = ExplorationEngine(inv, solver="z3")
        generated = engine.explore(max_iterations=max_iters)
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        print(json.dumps({"status": "explore_error", "error": f"{type(e).__name__}: {e}"}))
        return

    paths = []
    try:
        for gen in (engine.generated_inputs or []):
            paths.append({
                "inputs": {k: repr(v) for k, v in (gen or {}).items()}
            })
    except Exception:
        pass
    returns = []
    try:
        for rv in (engine.execution_return_values or []):
            returns.append(repr(rv))
    except Exception:
        pass

    print(json.dumps({
        "status": "ok",
        "paths_explored": len(paths),
        "paths": paths[:20],
        "return_values": returns[:20],
    }))


main()
'''


def explore(
    *,
    target_file: str,
    func_name: str,
    max_iterations: int = 20,
    timeout_s: int = 30,
) -> BridgeResult:
    """Run PyExZ3 on `func_name` inside `target_file`. Returns paths explored."""
    t0 = time.time()
    result = BridgeResult(source="pyexz3")

    if not is_installed():
        result.errors.append(
            "pyexz3 bundle not found under belief/tools_bundled/pyexz3/"
        )
        result.elapsed_s = time.time() - t0
        return result

    # Check Z3 — pyexz3 needs z3-solver
    try:
        import z3  # noqa
    except ImportError:
        result.errors.append(
            "z3-solver not installed (pyexz3 requires it). `pip install z3-solver`."
        )
        result.elapsed_s = time.time() - t0
        return result

    if not os.path.exists(target_file):
        result.errors.append(f"target file not found: {target_file}")
        result.elapsed_s = time.time() - t0
        return result

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as tf:
        tf.write(_RUNNER)
        runner_path = tf.name

    try:
        proc = subprocess.run(
            [sys.executable, runner_path, target_file, func_name,
             str(_bundled_path()), str(max_iterations)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        out = (proc.stdout or "").strip().splitlines()
        last_json = None
        for line in reversed(out):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    last_json = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        if last_json is None:
            result.errors.append(
                f"no JSON in pyexz3 output. stderr={proc.stderr[:200]}"
            )
        else:
            if last_json.get("status") != "ok":
                result.errors.append(
                    f"{last_json.get('status')}: {last_json.get('error', '?')[:120]}"
                )
            result.findings = [last_json]
    except subprocess.TimeoutExpired:
        result.errors.append(f"pyexz3 timed out after {timeout_s}s")
    except Exception as e:
        result.errors.append(f"pyexz3 runner failed: {type(e).__name__}: {e}")
    finally:
        try:
            os.unlink(runner_path)
        except OSError:
            pass

    result.elapsed_s = time.time() - t0
    return result


def to_belief(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PyExZ3 is primarily a verifier/concretizer, not a belief producer.
    If the exploration completed with paths, we don't emit a belief.
    If a specific path failed an assertion, that's a belief — but PyExZ3
    doesn't distinguish. So default: no belief; the result enriches an
    existing belief."""
    return None


def register(registry) -> None:
    registry.register("pyexz3", explore)
