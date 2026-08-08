"""
pyre_bridge — use Pyre (Facebook) for type inference + taint analysis.

Pyre's strengths:
- Very fast type checker (OCaml backend)
- Pysa: its taint engine, rivals CodeQL on large codebases
- Infers types where no annotations exist
- Emits JSON errors amenable to post-processing

BELIEF uses Pyre for TWO things:
1. Type inference → feed types back into the LLM grounding context.
   ("argument X is known to be `List[str]`" is a STRONG prior for the LLM)
2. Taint flows via Pysa (similar to pyt but more industrial)

Integration: subprocess only. Pyre requires setup (`pyre init`) in the project.
We run `pyre check --output json` and parse errors.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.pyre")


def is_installed() -> bool:
    return shutil.which("pyre") is not None


def ensure_config(project_path: str) -> bool:
    """Write a minimal .pyre_configuration if none exists.
    Returns True if ready to use."""
    cfg = Path(project_path) / ".pyre_configuration"
    if cfg.exists():
        return True
    try:
        cfg.write_text(json.dumps({
            "source_directories": ["."],
            "exclude": [".*/\\..*", ".*__pycache__.*", ".*/test.*"],
            "strict": False,
        }, indent=2))
        return True
    except Exception as e:
        logger.warning(f"pyre config write failed: {e}")
        return False


def run_pyre(
    project_path: str,
    *,
    mode: str = "check",   # 'check' (type errors) or 'infer' (type inference)
    timeout_s: int = 300,
) -> BridgeResult:
    t0 = time.time()
    result = BridgeResult(source="pyre")

    if not is_installed():
        result.errors.append(
            "pyre not installed. `pip install pyre-check` to enable."
        )
        result.elapsed_s = time.time() - t0
        return result

    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        result.errors.append(f"not a directory: {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    if not ensure_config(project_path):
        result.errors.append("could not create pyre configuration")
        result.elapsed_s = time.time() - t0
        return result

    if mode == "infer":
        cmd = ["pyre", "--output", "json", "infer", "-p"]
    else:
        cmd = ["pyre", "--output", "json", "check"]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            cwd=project_path,
        )
        # Pyre exits non-zero when errors exist — that's what we want
        try:
            # Pyre's JSON may be on stdout; some versions use stderr
            raw = (proc.stdout or proc.stderr or "").strip()
            if not raw:
                result.findings = []
            elif raw.startswith("["):
                errors = json.loads(raw)
            else:
                # Newline-delimited JSON objects
                errors = [json.loads(l) for l in raw.splitlines() if l.strip().startswith("{")]
            if mode == "infer":
                result.findings = errors  # list of inferred types
            else:
                for e in errors:
                    result.findings.append({
                        "path": e.get("path"),
                        "line": e.get("line"),
                        "code": e.get("code"),
                        "name": e.get("name"),
                        "description": e.get("description"),
                        "concise_description": e.get("concise_description"),
                    })
        except json.JSONDecodeError as e:
            result.errors.append(f"pyre output parse failed: {e}")
    except subprocess.TimeoutExpired:
        result.errors.append(f"pyre timed out after {timeout_s}s")
    except Exception as e:
        result.errors.append(f"pyre subprocess failed: {type(e).__name__}: {e}")

    result.elapsed_s = time.time() - t0
    logger.info(f"pyre: {len(result.findings)} {mode} results in {result.elapsed_s:.1f}s")
    return result


def to_belief(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Pyre check findings = type errors. They imply a BROKEN belief:
    'x is expected to be type T, but may be type T'."""
    if "path" not in finding:
        return None
    return {
        "assumption": f"type contract holds: {finding.get('concise_description', finding.get('description', ''))}",
        "anchor_file": finding["path"],
        "anchor_line": finding.get("line", 0),
        "anchor_line_end": finding.get("line", 0),
        "justification_type": "C2_STATICALLY_VERIFIED_PROPERTY",
        "contextual_constraint": f"pyre_code={finding.get('code')}, name={finding.get('name')}",
        "trust_domain": Path(finding["path"]).stem,
        "logic_type": "contract",
        "source": "pyre",
        "raw": finding,
    }


def register(registry) -> None:
    registry.register("pyre", run_pyre)
