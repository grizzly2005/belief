"""
belief_adapter — the glue that converts bridge outputs to BELIEF sextuplets.

Each bridge produces dicts with loose keys (different tools use different
field names). This adapter normalizes them into `belief.models.Belief`.

Usage:
    from belief.bridges import registry
    from belief.bridges.belief_adapter import adapt_all

    results = registry.run_all_applicable(project_path="/proj")
    beliefs = adapt_all(results)
    # beliefs is now List[belief.models.Belief] ready for the orchestrator

This is the PIVOT point. Without this adapter each bridge is an island.
With it, the orchestrator sees a uniform belief stream regardless of
the tool that produced it.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

from . import BridgeResult

# Import BELIEF core models
try:
    from belief.models import (
        Belief, Finding, Predicate, Scope,
        JustificationCategory, EpistemicStatus, LogicType, ArtifactKind,
    )
    _MODELS_OK = True
except Exception:
    _MODELS_OK = False
    Belief = None  # type: ignore
    Finding = None  # type: ignore

logger = logging.getLogger("belief.bridges.adapter")


# Historical bridge codes predate the evidentiary taxonomy.  Never reinterpret
# an old C1 as a mechanical proof.  Static analyzers are upgraded separately
# below only when the bridge identifies the tool result that was observed.
_LEGACY_JUSTIF_MAP = {
    "C1": "C3_EXPLICIT_RUNTIME_GUARD",
    "C2": "C4_CALLER_ASSUMPTION",
    "C3": "C5_DOCUMENTED_CONVENTION",
    "C4": "C6_UNSUPPORTED_ASSUMPTION",
    "C5": "C6_UNSUPPORTED_ASSUMPTION",
    "C6": "C6_UNSUPPORTED_ASSUMPTION",
}

_STATIC_ANALYZER_SOURCES = {
    "bandit",
    "crosshair",
    "dlint",
    "path_traversal",
    "pyre",
    "pyt",
    "semgrep",
}

_LOGIC_MAP = {
    "fol": "FOL",
    "semantic": "SEMANTIC",
    "contract": "CONTRACT",
    "temporal": "TEMPORAL",
}


def _justif(code: str, *, source: str, raw: object) -> "JustificationCategory":
    normalized = str(code or "").strip()
    if normalized in JustificationCategory.__members__:
        category = JustificationCategory.__members__[normalized]
        if category is JustificationCategory.C1_MECHANICALLY_PROVEN:
            # Bridges currently expose findings/counterexamples, but no
            # immutable replay bundle bound to an exact source digest.
            return JustificationCategory.C2_STATICALLY_VERIFIED_PROPERTY
        return category

    if source in _STATIC_ANALYZER_SOURCES and isinstance(raw, dict):
        return JustificationCategory.C2_STATICALLY_VERIFIED_PROPERTY
    name = _LEGACY_JUSTIF_MAP.get(
        normalized.upper(), "C6_UNSUPPORTED_ASSUMPTION"
    )
    return getattr(JustificationCategory, name)


def _logic(code: str) -> "LogicType":
    name = _LOGIC_MAP.get((code or "semantic").lower(), "SEMANTIC")
    # FOL is the default if SEMANTIC doesn't exist
    try:
        return getattr(LogicType, name)
    except AttributeError:
        return getattr(LogicType, "FOL", list(LogicType)[0])


def _confidence(finding_source: str, raw: Dict[str, Any]) -> float:
    """Heuristic confidence based on the tool's own severity/confidence."""
    if finding_source == "bandit":
        sev = (raw.get("issue_severity") or "LOW").upper()
        conf = (raw.get("issue_confidence") or "LOW").upper()
        sev_score = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}.get(sev, 0.3)
        conf_score = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}.get(conf, 0.3)
        return (sev_score + conf_score) / 2
    if finding_source == "semgrep":
        sev = raw.get("severity", "INFO").upper()
        return {"ERROR": 0.85, "WARNING": 0.6, "INFO": 0.3}.get(sev, 0.5)
    if finding_source == "dlint":
        return 0.7   # flake8-level linters are deterministic = trustworthy
    if finding_source == "pyt":
        return 0.65  # taint has more FPs than bandit
    if finding_source == "crosshair":
        return 0.95  # concrete counter-example = very high
    if finding_source == "pyre":
        return 0.8
    if finding_source == "safety_db":
        return 1.0   # CVE match is definitive
    return 0.5


def dict_to_belief(d: Dict[str, Any]) -> Optional["Belief"]:
    """Convert a single bridge-finding dict to a full Belief sextuplet.
    Returns None if the dict is missing essentials or models are unavailable.

    v4 hotfix: bridges that don't implement their own to_belief() (e.g.
    path_traversal) previously had their findings silently dropped because
    this function only looked for "assumption"/"predicate" keys. Fall back
    to "message"/"issue_text"/"rule_id" so generic finding dicts are still
    convertible.
    Also: if the finding dict carries a "cwe" field (set by bridges like
    path_traversal), propagate it to Belief.cwe so downstream scoring has
    ground truth instead of re-guessing from the predicate text.
    """
    if not _MODELS_OK:
        return None
    if not d:
        return None
    # Required fields — try assumption/predicate first, fall back to message
    assumption = (
        d.get("assumption")
        or d.get("predicate")
        or d.get("message")
        or d.get("issue_text")
        or d.get("rule_id")
    )
    file_path = d.get("anchor_file") or d.get("file") or d.get("path") or "<unknown>"
    line_start = d.get("anchor_line") or d.get("line") or 0
    line_end = d.get("anchor_line_end") or d.get("end_line") or line_start
    if not assumption:
        return None

    try:
        pred = Predicate(
            expression=str(assumption)[:500],
            variables=tuple(d.get("variables", []) or []),
            anchor_lines=(int(line_start),) if line_start else (),
            natural_language=d.get("contextual_constraint", "") or "",
        )
        scope = Scope(
            file_path=file_path,
            function_name=d.get("function") or d.get("trust_domain"),
            class_name=d.get("class_name"),
            module=d.get("module"),
            line_start=int(line_start) if line_start else None,
            line_end=int(line_end) if line_end else None,
        )
        src = d.get("source", "unknown")
        justif = _justif(
            d.get("justification_type", "C6"),
            source=src,
            raw=d.get("raw"),
        )
        logic = _logic(d.get("logic_type", "semantic"))
        conf = _confidence(src, d.get("raw", {}))
        # Propagate explicit CWE from the bridge finding when present
        bridge_cwe = d.get("cwe") or ""
        return Belief(
            predicate=pred,
            scope=scope,
            justification=justif,
            dependencies=list(d.get("dependencies", []) or []),
            epistemic_status=EpistemicStatus.BELIEF,
            logic_type=logic,
            artifact_kind=ArtifactKind.SOURCE_CODE,
            confidence_score=conf,
            cwe=bridge_cwe,
            source_metadata={
                "source": src,
                "rule_id": d.get("rule_id") or d.get("test_id") or d.get("check_id", ""),
                "severity": d.get("severity") or d.get("issue_severity", ""),
            },
        )
    except Exception as e:
        logger.debug(f"dict_to_belief failed for {d.get('source')}: {e}")
        return None


def dict_to_finding(d: Dict[str, Any], source: str = "bridge") -> Optional["Finding"]:
    """Convert a loose bridge dict into the stable report Finding model."""
    if not _MODELS_OK or Finding is None:
        return None
    if not d:
        return None
    data = dict(d)
    data.setdefault("source", data.get("source") or source)
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {"value": metadata}
    metadata.setdefault("source", data["source"])
    data["metadata"] = metadata
    return Finding.from_dict(data)


def adapt_one(bridge_result: BridgeResult) -> List["Belief"]:
    """Convert every finding in a BridgeResult to a list of Belief.

    Some bridges (pyt) return one finding that maps to TWO beliefs
    (source+sink). We handle that by importing the bridge's own to_belief()
    function when it exists, which can return a list."""
    if not _MODELS_OK:
        return []
    beliefs: List[Belief] = []
    source = bridge_result.source

    # Try the bridge's native to_belief() first (it knows its own format)
    import importlib
    try:
        mod = importlib.import_module(f".{source}_bridge", package="belief.bridges")
    except ImportError:
        mod = None

    for f in bridge_result.findings:
        if not isinstance(f, dict):
            continue
        # Attach source name so _confidence can look it up
        f.setdefault("source", source)
        # Invoke bridge's converter if present
        if mod and hasattr(mod, "to_belief"):
            try:
                out = mod.to_belief(f)
                if out is None:
                    continue
                dicts = out if isinstance(out, list) else [out]
            except Exception as e:
                logger.debug(f"{source}.to_belief crashed: {e}")
                continue
        else:
            dicts = [f]
        for d in dicts:
            if d is None:
                continue
            d.setdefault("source", source)
            b = dict_to_belief(d)
            if b is not None:
                beliefs.append(b)
    return beliefs


def adapt_one_findings(bridge_result: BridgeResult) -> List["Finding"]:
    if not _MODELS_OK or Finding is None:
        return []
    out: List[Finding] = []
    for raw in bridge_result.findings:
        if not isinstance(raw, dict):
            continue
        finding = dict_to_finding(raw, source=bridge_result.source)
        if finding is not None:
            out.append(finding)
    return out


def adapt_all(results: Dict[str, BridgeResult]) -> List["Belief"]:
    """Convert a dict of {bridge_name: BridgeResult} to a flat belief list."""
    out: List["Belief"] = []
    for name, res in results.items():
        if res.errors:
            logger.info(f"bridge {name}: skipped ({res.errors[0][:80]})")
            continue
        b = adapt_one(res)
        logger.info(f"bridge {name}: {len(b)} beliefs")
        out.extend(b)
    return out


def adapt_all_findings(results: Dict[str, BridgeResult]) -> List["Finding"]:
    out: List[Finding] = []
    for res in results.values():
        if res.errors:
            continue
        out.extend(adapt_one_findings(res))
    return out


def run_all_applicable(
    project_path: str,
    *,
    skip: Optional[Iterable[str]] = None,
) -> Dict[str, BridgeResult]:
    """Run every bridge that operates on a project_path.
    Skips bridges that need different args (crosshair, contextgem, ts_runner)."""
    from . import registry
    project_bridges = {"bandit", "dlint", "pyt", "semgrep", "pyre", "safety_db"}
    if skip:
        project_bridges -= set(skip)
    out = {}
    for name in registry.available():
        if name not in project_bridges:
            continue
        out[name] = registry.run(name, project_path=project_path)
    return out


def analyze_project(project_path: str, **kwargs) -> List["Belief"]:
    """One-shot: scan a project with all applicable bridges, return beliefs.
    This is the function most users should call."""
    results = run_all_applicable(project_path, **kwargs)
    return adapt_all(results)


__all__ = [
    "adapt_one", "adapt_all", "adapt_one_findings", "adapt_all_findings",
    "dict_to_belief", "dict_to_finding",
    "run_all_applicable", "analyze_project",
]
