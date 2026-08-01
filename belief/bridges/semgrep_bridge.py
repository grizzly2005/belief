"""
semgrep_bridge — run Semgrep on a project with BELIEF's bundled rules.

Semgrep matches syntactic+semantic patterns (pattern-match). We bundle
~2300 community rules targeted at Python, covering:
- OWASP Top 10 (injection, XSS, deser, IDOR, etc.)
- CWE Top 25 signatures
- Framework-specific (Django, Flask, FastAPI, Tornado, Pyramid)
- Crypto misuse (weak ciphers, hardcoded keys)

Like Bandit/DLint, Semgrep is a PRE-FILTER. It produces many findings
quickly; BELIEF's LLM extractor then refines them into semantic beliefs.

Rules location: belief/security_rules/semgrep/
Invocation: `semgrep --config <rules-dir> --json <project>`
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.semgrep")

# Rule packs in the belief package
_BUNDLED_RULES = Path(__file__).parent.parent / "security_rules" / "semgrep"
_CACHE = Path.home() / ".cache" / "belief" / "bridges" / "semgrep"
_CACHE.mkdir(parents=True, exist_ok=True)


def is_installed() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(
    project_path: str,
    *,
    config: Optional[str] = None,        # override bundled rules
    languages: Optional[List[str]] = None,  # ['python', 'javascript', ...]
    severity: str = "INFO",              # INFO | WARNING | ERROR
    use_cache: bool = True,
    timeout_s: int = 600,
) -> BridgeResult:
    t0 = time.time()
    result = BridgeResult(source="semgrep")

    if not is_installed():
        result.errors.append(
            "semgrep not installed. `pip install semgrep` to enable."
        )
        result.elapsed_s = time.time() - t0
        return result

    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        result.errors.append(f"not a directory: {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    cfg = config or str(_BUNDLED_RULES)
    if not Path(cfg).exists():
        result.errors.append(f"semgrep rules not found: {cfg}")
        result.elapsed_s = time.time() - t0
        return result

    cmd = [
        "semgrep",
        "--config", cfg,
        "--json",
        "--quiet",
        "--severity", severity,
        "--timeout", "60",            # per-rule timeout
        "--max-memory", "4000",
        "--no-git-ignore",
        project_path,
    ]
    if languages:
        for lang in languages:
            cmd += ["--lang", lang]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s
        )
        if not proc.stdout.strip():
            result.errors.append(f"semgrep empty output; stderr={proc.stderr[:200]}")
        else:
            data = json.loads(proc.stdout)
            for r in data.get("results", []):
                result.findings.append({
                    "check_id": r.get("check_id", ""),
                    "path": r.get("path", ""),
                    "line": r.get("start", {}).get("line", 0),
                    "end_line": r.get("end", {}).get("line", 0),
                    "severity": r.get("extra", {}).get("severity", "INFO"),
                    "message": r.get("extra", {}).get("message", ""),
                    "metadata": r.get("extra", {}).get("metadata", {}),
                })
    except subprocess.TimeoutExpired:
        result.errors.append(f"semgrep timed out after {timeout_s}s")
    except json.JSONDecodeError as e:
        result.errors.append(f"semgrep output not JSON: {e}")
    except Exception as e:
        result.errors.append(f"semgrep subprocess failed: {type(e).__name__}: {e}")

    result.elapsed_s = time.time() - t0
    logger.info(f"semgrep: {len(result.findings)} findings in {result.elapsed_s:.1f}s")
    return result


_SEMGREP_SEVERITY = {
    "ERROR":   ("HIGH", "C2_STATICALLY_VERIFIED_PROPERTY"),
    "WARNING": ("MED",  "C2_STATICALLY_VERIFIED_PROPERTY"),
    "INFO":    ("LOW",  "C2_STATICALLY_VERIFIED_PROPERTY"),
}


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    sev, justif = _SEMGREP_SEVERITY.get(finding.get("severity", "INFO"),
                                         ("LOW", "C2_STATICALLY_VERIFIED_PROPERTY"))
    meta = finding.get("metadata", {})
    cwe = (meta.get("cwe") if isinstance(meta.get("cwe"), str)
           else (meta.get("cwe") or [""])[0] if meta.get("cwe") else "")
    return {
        "assumption": f"Semgrep rule {finding['check_id']} should not match",
        "anchor_file": finding["path"],
        "anchor_line": finding["line"],
        "anchor_line_end": finding["end_line"] or finding["line"],
        "justification_type": justif,
        "contextual_constraint": f"severity={sev}, cwe={cwe}, rule={finding['check_id']}",
        "trust_domain": Path(finding["path"]).stem,
        "logic_type": "semantic",
        "source": "semgrep",
        "raw": finding,
    }


def register(registry) -> None:
    registry.register("semgrep", run_semgrep)
