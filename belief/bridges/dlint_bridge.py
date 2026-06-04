"""
dlint_bridge — run DLint (via flake8) on a project.

DLint is a security-focused flake8 plugin. It detects patterns Bandit misses:
- bad_yaml_use, bad_zipfile_use, bad_hashlib_use, bad_pycrypto_use
- ReDoS-prone regex patterns
- Twisted inlineCallbacks misuse
- bad_onelogin_kwarg_use, bad_itsdangerous_kwarg_use

Bandit and DLint overlap ~30%. The union of both catches more CVE-class
issues than either alone. BELIEF uses both upstream of the LLM.

Invocation: `flake8 --select=DUO` (DUO prefix = DLint codes).
Output format: one line per finding, parsed with regex.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.dlint")

# flake8 line format: "path:line:col: CODE message"
_FLAKE8_LINE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):(?P<col>\d+):\s+(?P<code>\S+)\s+(?P<msg>.*)$")


def is_installed() -> bool:
    """flake8 must be installed AND dlint must be a registered plugin."""
    if not shutil.which("flake8"):
        return False
    try:
        out = subprocess.run(
            ["flake8", "--version"], capture_output=True, text=True, timeout=10
        ).stdout
        return "dlint" in out.lower()
    except Exception:
        return False


def run_dlint(
    project_path: str,
    *,
    exclude: Optional[List[str]] = None,
    use_cache: bool = True,
) -> BridgeResult:
    t0 = time.time()
    result = BridgeResult(source="dlint")

    if not is_installed():
        result.errors.append(
            "dlint not installed. `pip install flake8 dlint` to enable."
        )
        result.elapsed_s = time.time() - t0
        return result

    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        result.errors.append(f"not a directory: {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    excl_parts = ["tests", "test", "__pycache__", ".git", "build", "dist", "venv", ".venv"]
    if exclude:
        excl_parts += exclude
    cmd = [
        "flake8",
        "--select=DUO",                          # DLint codes only
        f"--exclude={','.join(excl_parts)}",
        project_path,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        # flake8 exits non-zero on findings — normal
        for line in (proc.stdout or "").splitlines():
            m = _FLAKE8_LINE.match(line.strip())
            if not m:
                continue
            result.findings.append({
                "path": m.group("path"),
                "line": int(m.group("line")),
                "col": int(m.group("col")),
                "code": m.group("code"),
                "message": m.group("msg"),
            })
    except subprocess.TimeoutExpired:
        result.errors.append("dlint scan timed out after 180s")
    except Exception as e:
        result.errors.append(f"dlint subprocess failed: {type(e).__name__}: {e}")

    result.elapsed_s = time.time() - t0
    logger.info(f"dlint: {len(result.findings)} findings in {result.elapsed_s:.1f}s")
    return result


# Map DLint codes to severity/justification
_DLINT_SEVERITY = {
    "DUO101": ("HIGH", "C1"),    # yaml.load without Loader
    "DUO102": ("HIGH", "C1"),    # random.* for security
    "DUO103": ("HIGH", "C1"),    # pickle.loads
    "DUO104": ("HIGH", "C1"),    # exec
    "DUO105": ("HIGH", "C1"),    # compile() with user input
    "DUO106": ("MED",  "C4"),    # bad zipfile use
    "DUO107": ("MED",  "C4"),    # bad hashlib
    "DUO111": ("MED",  "C4"),    # xml.etree
    "DUO112": ("HIGH", "C1"),    # xml.sax
    "DUO113": ("MED",  "C4"),    # xml.dom.minidom
    "DUO116": ("HIGH", "C1"),    # shell=True
    "DUO117": ("HIGH", "C1"),    # tempfile.mktemp
    "DUO118": ("MED",  "C4"),    # compile regex flag
    "DUO130": ("MED",  "C4"),    # redos
}


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    code = finding["code"]
    sev, justif = _DLINT_SEVERITY.get(code, ("LOW", "C5"))
    return {
        "assumption": f"DLint {code} should not match: {finding['message']}",
        "anchor_file": finding["path"],
        "anchor_line": finding["line"],
        "anchor_line_end": finding["line"],
        "justification_type": justif,
        "contextual_constraint": f"severity={sev}, code={code}",
        "trust_domain": Path(finding["path"]).stem,
        "logic_type": "semantic",
        "source": "dlint",
        "raw": finding,
    }


def register(registry) -> None:
    registry.register("dlint", run_dlint)
