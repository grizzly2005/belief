"""
supply_chain_bridge — supply-chain risk detection for Python projects.

Combines three sources:
1. safety-db (offline, bundled) — already exposed by safety_db_bridge
2. Typosquat heuristic — detect suspiciously similar package names to
   popular ones (inspired by scfw's age_verifier)
3. OSV.dev live query (OPTIONAL, if network+requests available) — the most
   authoritative free advisory DB

This bridge does NOT vendor scfw (too heavy, network-dependent). Instead
it implements scfw's core ideas in 200 lines using only stdlib + our
bundled safety-db.

Returns: per-package findings with severity and recommended action.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import BridgeResult

logger = logging.getLogger("belief.bridges.supply_chain")


# Top 500 PyPI packages (subset) — typosquat targets
# Source: pypistats.org / pypi.org/stats, cached. Keep list small; extend as needed.
_POPULAR_PACKAGES = {
    "requests", "urllib3", "certifi", "idna", "charset-normalizer",
    "setuptools", "pip", "wheel", "six", "python-dateutil",
    "numpy", "pandas", "scipy", "matplotlib", "scikit-learn", "tensorflow",
    "torch", "keras", "jupyter", "ipython",
    "django", "flask", "fastapi", "starlette", "uvicorn", "gunicorn",
    "pyyaml", "jinja2", "markupsafe", "click", "cryptography", "pycryptodome",
    "pytest", "pytest-cov", "tox", "black", "isort", "flake8", "mypy", "pylint",
    "boto3", "botocore", "s3transfer", "jmespath", "google-auth",
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql", "redis",
    "lxml", "beautifulsoup4", "selenium", "scrapy",
    "pillow", "opencv-python", "imageio",
    "tornado", "aiohttp", "httpx", "asyncio", "anyio", "trio",
    "celery", "kombu", "amqp",
    "pydantic", "marshmallow", "attrs", "dataclasses-json",
    "pyjwt", "oauthlib", "authlib", "passlib", "bcrypt",
    "docker", "kubernetes", "ansible",
}


def _levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein distance; small enough for package names."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def detect_typosquats(
    package_names: List[str],
    *,
    popular: Optional[set] = None,
    max_distance: int = 1,
) -> List[Tuple[str, str, int]]:
    """Flag package names that are ≤ max_distance edits from a popular one.

    Returns list of (suspicious_name, popular_target, edit_distance).
    Exact matches are ignored (a user installing 'requests' is fine).
    """
    popular = popular or _POPULAR_PACKAGES
    out: List[Tuple[str, str, int]] = []
    for name in package_names:
        name_lc = name.lower()
        if name_lc in popular:
            continue
        for pop in popular:
            d = _levenshtein(name_lc, pop)
            if 0 < d <= max_distance:
                out.append((name, pop, d))
                break
    return out


def query_osv(package: str, version: str, timeout_s: int = 5) -> List[Dict[str, Any]]:
    """Query osv.dev for a single package@version. Requires network.

    Returns list of advisories (may be empty). Returns [] on network error.
    """
    try:
        payload = json.dumps({
            "package": {"name": package, "ecosystem": "PyPI"},
            "version": version,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("vulns", []) or []
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ConnectionError) as e:
        logger.debug(f"OSV network error for {package}=={version}: {e}")
        return []
    except Exception as e:
        logger.debug(f"OSV query failed for {package}=={version}: {e}")
        return []


def scan(
    project_path: str,
    *,
    use_osv: bool = False,
    max_osv_queries: int = 20,
    timeout_s: int = 30,
) -> BridgeResult:
    """Comprehensive supply-chain scan combining safety-db + typosquats + OSV.

    - project_path: a dir containing requirements.txt/Pipfile.lock/poetry.lock
    - use_osv=True enables live OSV queries (requires network)
    """
    t0 = time.time()
    result = BridgeResult(source="supply_chain")

    # 1. Use the safety_db_bridge's requirement parser
    from .safety_db_bridge import _gather_requirements, run_safety
    reqs = _gather_requirements(project_path)
    if not reqs:
        result.errors.append(f"no Python requirements found in {project_path}")
        result.elapsed_s = time.time() - t0
        return result

    # 2. Safety-DB (offline, bundled)
    safety = run_safety(project_path)
    for f in safety.findings:
        result.findings.append({
            "kind": "cve",
            "package": f["package"],
            "version": f["version"],
            "severity": "HIGH",
            "matched_spec": f.get("matched_spec"),
            "cve": f.get("cve"),
            "source": "safety_db",
            "source_file": f.get("source_file"),
        })

    # 3. Typosquat detection
    pkg_names = [r[0] for r in reqs]
    typos = detect_typosquats(pkg_names)
    for name, target, dist in typos:
        result.findings.append({
            "kind": "typosquat",
            "package": name,
            "version": "-",
            "severity": "MEDIUM",
            "suggested": target,
            "edit_distance": dist,
            "source": "typosquat_heuristic",
            "source_file": next((r[2] for r in reqs if r[0] == name), None),
        })

    # 4. OSV live (optional)
    if use_osv:
        queries_made = 0
        for pkg, ver, src in reqs:
            if queries_made >= max_osv_queries:
                break
            vulns = query_osv(pkg, ver)
            queries_made += 1
            for v in vulns:
                result.findings.append({
                    "kind": "osv",
                    "package": pkg,
                    "version": ver,
                    "severity": v.get("database_specific", {}).get("severity", "UNKNOWN"),
                    "osv_id": v.get("id"),
                    "summary": (v.get("summary") or "")[:200],
                    "source": "osv.dev",
                    "source_file": src,
                })
        if queries_made:
            logger.info(f"OSV: queried {queries_made} packages")

    result.elapsed_s = time.time() - t0
    logger.info(
        f"supply_chain: {len(result.findings)} issues "
        f"(cve={len([f for f in result.findings if f['kind']=='cve'])}, "
        f"typosquat={len(typos)}, osv={len([f for f in result.findings if f['kind']=='osv'])}) "
        f"in {result.elapsed_s:.1f}s"
    )
    return result


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    kind = finding.get("kind", "unknown")
    if kind == "cve":
        return {
            "assumption": f"{finding['package']}=={finding['version']} has no known CVE",
            "anchor_file": finding.get("source_file") or "requirements.txt",
            "anchor_line": 1, "anchor_line_end": 1,
            "justification_type": "C5_DOCUMENTED_CONVENTION",
            "contextual_constraint": f"spec={finding.get('matched_spec')}, cve={finding.get('cve')}",
            "trust_domain": "supply_chain",
            "logic_type": "semantic",
            "source": "supply_chain",
            "raw": finding,
        }
    if kind == "typosquat":
        return {
            "assumption": f"{finding['package']} is the intended package (not a typo of '{finding['suggested']}')",
            "anchor_file": finding.get("source_file") or "requirements.txt",
            "anchor_line": 1, "anchor_line_end": 1,
            "justification_type": "C6_UNSUPPORTED_ASSUMPTION",
            "contextual_constraint": (
                f"edit_distance={finding.get('edit_distance')} from popular package "
                f"'{finding.get('suggested')}'"
            ),
            "trust_domain": "supply_chain",
            "logic_type": "semantic",
            "source": "supply_chain",
            "raw": finding,
        }
    if kind == "osv":
        return {
            "assumption": f"{finding['package']}=={finding['version']} has no OSV advisory",
            "anchor_file": finding.get("source_file") or "requirements.txt",
            "anchor_line": 1, "anchor_line_end": 1,
            "justification_type": "C5_DOCUMENTED_CONVENTION",
            "contextual_constraint": (
                f"osv={finding.get('osv_id')} severity={finding.get('severity')}"
            ),
            "trust_domain": "supply_chain",
            "logic_type": "semantic",
            "source": "supply_chain",
            "raw": finding,
        }
    return None


def register(registry) -> None:
    registry.register("supply_chain", scan)
