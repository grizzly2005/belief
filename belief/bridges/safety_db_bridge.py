"""
safety_db_bridge — lookup project dependencies against pyupio/safety-db.

safety-db is a curated database of known-vulnerable Python package versions.
Format: insecure_full.json (dict: package_name → list of affected spec ranges).

For BELIEF, a dependency that is known-vulnerable is a belief violation:
- Belief: "dependency X version Y is secure"  (C3: convention / unstated)
- Evidence: X==Y matches a CVE in safety-db
- Result: explicit contradiction, highest priority finding

This bridge:
- Reads project's requirements (requirements.txt, pyproject.toml, poetry.lock)
- Parses safety-db/insecure_full.json (bundled in tools_bundled/safety_db/)
- For each dep@version, matches against the DB
- Emits a belief finding per hit, with CVE ID + advisory text
"""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import BridgeResult

logger = logging.getLogger("belief.bridges.safety")

_DB_DIR = Path(__file__).parent.parent / "tools_bundled" / "safety_db" / "data"
# Full has CVE+advisory text; lite has just specs. Prefer full, fall back to lite.
_DB_PATH_FULL = _DB_DIR / "insecure_full.json"
_DB_PATH_LITE = _DB_DIR / "insecure.json"


def _db_path() -> Optional[Path]:
    if _DB_PATH_FULL.exists():
        return _DB_PATH_FULL
    if _DB_PATH_LITE.exists():
        return _DB_PATH_LITE
    return None


def is_installed() -> bool:
    return _db_path() is not None


# Accept the common pin/range forms
_SPEC_RE = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s*(==|>=|<=|~=|>|<|!=)?\s*([0-9a-zA-Z\.\-\+]+)?")


def _parse_requirement(line: str) -> Optional[Tuple[str, str]]:
    """Very light parser for lines like `requests==2.25.1`.
    Skips comments, extras, URLs."""
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    if "@" in line:  # @git+https... — skip, can't pin
        return None
    # Strip extras: `requests[security]==2.25.1` → `requests==2.25.1`
    line = re.sub(r"\[[^\]]+\]", "", line)
    m = _SPEC_RE.match(line)
    if not m:
        return None
    name = m.group(1).lower()
    op = m.group(2)
    ver = m.group(3)
    if op == "==" and ver:
        return (name, ver)
    return None  # only handle exact pins


def _gather_requirements(project_path: str) -> List[Tuple[str, str, str]]:
    """Returns list of (package, version, source_file). Deduplicates
    (package, version, source_file) tuples since glob + rglob can overlap."""
    out = []
    seen = set()
    root = Path(project_path)

    def _add(name: str, ver: str, path: str):
        key = (name, ver, path)
        if key not in seen:
            seen.add(key)
            out.append(key)

    # 1. requirements*.txt — use rglob only, which finds everything
    for rf in set(root.rglob("requirements*.txt")):
        try:
            for line in rf.read_text().splitlines():
                pr = _parse_requirement(line)
                if pr:
                    _add(pr[0], pr[1], str(rf))
        except Exception:
            continue
    # 2. poetry.lock
    lock = root / "poetry.lock"
    if lock.exists():
        try:
            txt = lock.read_text()
            for m in re.finditer(
                r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"',
                txt,
            ):
                _add(m.group(1).lower(), m.group(2), str(lock))
        except Exception:
            pass
    # 3. Pipfile.lock
    pipfile = root / "Pipfile.lock"
    if pipfile.exists():
        try:
            data = json.loads(pipfile.read_text())
            for section in ("default", "develop"):
                for name, meta in (data.get(section, {}) or {}).items():
                    ver = (meta.get("version") or "").lstrip("=")
                    if ver:
                        _add(name.lower(), ver, str(pipfile))
        except Exception:
            pass
    return out


def _load_db() -> Dict[str, Any]:
    path = _db_path()
    if path is None:
        return {}
    try:
        raw = json.loads(path.read_text())
    except Exception as e:
        logger.error(f"safety-db load failed: {e}")
        return {}
    # Normalize: both formats → {package: [{specs: [...], cve, advisory_id, advisory}]}
    normalized: Dict[str, Any] = {}
    for pkg, entries in raw.items():
        if pkg.startswith("$"):  # skip $meta
            continue
        if not entries:
            continue
        # Lite format: list of spec strings
        if isinstance(entries[0], str):
            normalized[pkg.lower()] = [{
                "specs": entries,
                "cve": None,
                "advisory_id": None,
                "advisory": "(no advisory text in lite DB)",
            }]
        # Full format: list of dicts
        elif isinstance(entries[0], dict):
            normalized[pkg.lower()] = [{
                "specs": e.get("specs", [e.get("v", "")]),
                "cve": e.get("cve"),
                "advisory_id": e.get("id"),
                "advisory": e.get("advisory", ""),
            } for e in entries]
    return normalized


def _version_in_spec(version: str, spec: str) -> bool:
    """Check if version matches the spec string from safety-db.
    Spec examples: '<1.2.3', '>=1.0,<1.2.3', '==1.0'.
    Conservative: if unparseable, assume MATCH (better over-report than miss)."""
    try:
        from packaging.version import Version
        from packaging.specifiers import SpecifierSet
        return Version(version) in SpecifierSet(spec)
    except Exception:
        try:
            # Fallback: naive substring match (e.g. '1.2.3' in '<1.2.3,>=1.0')
            return version in spec
        except Exception:
            return True  # conservative


def run_safety(project_path: str, *, use_cache: bool = False) -> BridgeResult:
    t0 = time.time()
    result = BridgeResult(source="safety_db")

    if not is_installed():
        result.errors.append(
            f"safety-db not found at {_DB_PATH_FULL} or {_DB_PATH_LITE}. "
            "Copy pyupio/safety-db/data/insecure.json there."
        )
        result.elapsed_s = time.time() - t0
        return result

    db = _load_db()
    if not db:
        result.errors.append("safety-db is empty or malformed")
        result.elapsed_s = time.time() - t0
        return result

    reqs = _gather_requirements(project_path)
    if not reqs:
        result.errors.append(f"no requirements found in {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    for pkg, ver, src_file in reqs:
        advisories = db.get(pkg, [])
        for adv in advisories:
            # adv is a dict with keys: advisory, cve, id, specs, v
            for spec in (adv.get("specs") or []):
                if _version_in_spec(ver, spec):
                    result.findings.append({
                        "package": pkg,
                        "version": ver,
                        "cve": adv.get("cve"),
                        "advisory_id": adv.get("id"),
                        "advisory": adv.get("advisory", ""),
                        "matched_spec": spec,
                        "source_file": src_file,
                    })
                    break

    result.elapsed_s = time.time() - t0
    logger.info(f"safety-db: {len(result.findings)} CVE hits in {result.elapsed_s:.1f}s")
    return result


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "assumption": f"dependency {finding['package']}=={finding['version']} is not known-vulnerable",
        "anchor_file": finding["source_file"],
        "anchor_line": 1,
        "anchor_line_end": 1,
        "justification_type": "C3",     # unstated prior
        "contextual_constraint": f"CVE={finding.get('cve')}, spec={finding['matched_spec']}",
        "trust_domain": "supply_chain",
        "logic_type": "semantic",
        "source": "safety_db",
        "raw": finding,
    }


def register(registry) -> None:
    registry.register("safety_db", run_safety)
