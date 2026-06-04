"""
belief.bridges — Python adapters that plug external security tools into BELIEF.

Each bridge:
- takes a path to a Python project (or source snippet)
- runs an external tool (subprocess or native import)
- converts its output to BELIEF sextuplets (Belief models)
- returns them for the extractor/orchestrator to consume

Design:
- Subprocess by default. Avoids dep conflicts with the external tool's requirements.
- Optional native mode when the tool exposes a clean Python API.
- Each bridge degrades gracefully: if the tool isn't installed, returns [] with a warning.
- Outputs are CACHED by content hash in ~/.cache/belief/bridges/ to avoid re-scans.

Registry: a single point to list available bridges programmatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import logging

logger = logging.getLogger("belief.bridges")


@dataclass
class BridgeResult:
    """Unified output format for every bridge."""
    source: str                    # 'bandit', 'dlint', 'crosshair', ...
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    cache_hit: bool = False
    status: str = "available"      # available | missing | failed | skipped
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.status = _normalize_status(self.status, self.errors, self.findings)

    def as_beliefs(self, converter: Optional[Callable] = None) -> List[Any]:
        """Convert findings to belief.models.Belief sextuplets.
        Each bridge provides its own converter via its module's `to_beliefs()` function."""
        if converter is None:
            return []
        return [converter(f) for f in self.findings]

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        return bool(self.findings)


def _normalize_status(status: str, errors: list[str], findings: list[dict]) -> str:
    text = (status or "").strip().lower()
    if text in {"missing", "failed", "skipped"}:
        return text
    if text == "available" and not errors:
        return "available"
    if not errors:
        return "available"
    joined = " ".join(str(e).lower() for e in errors)
    if any(word in joined for word in ["not found", "not installed", "not available", "missing", "no module named"]):
        return "missing"
    if "skipped" in joined:
        return "skipped"
    return "failed"


class BridgeRegistry:
    """Central registry of available bridges.
    Usage:
        from belief.bridges import registry
        result = registry.run('bandit', project_path='/path/to/project')
    """
    def __init__(self):
        self._bridges: Dict[str, Callable[..., BridgeResult]] = {}

    def register(self, name: str, fn: Callable[..., BridgeResult]) -> None:
        self._bridges[name] = fn
        logger.debug(f"bridge registered: {name}")

    def run(self, name: str, **kwargs) -> BridgeResult:
        if name not in self._bridges:
            return BridgeResult(
                source=name,
                errors=[f"bridge '{name}' not registered"],
                status="missing",
            )
        try:
            result = self._bridges[name](**kwargs)
            if isinstance(result, BridgeResult):
                result.__post_init__()
            return result
        except TypeError as e:
            # v4 hotfix #3: argument-mismatch (function-level bridge called at
            # project level) is expected for crosshair/pyexz3 and noisy. Demote
            # to debug, still report as error in BridgeResult so caller sees it.
            logger.debug(f"bridge {name} argument mismatch: {e}")
            return BridgeResult(source=name, errors=[f"TypeError: {e}"], status="skipped")
        except Exception as e:
            logger.exception(f"bridge {name} crashed")
            return BridgeResult(source=name, errors=[f"{type(e).__name__}: {e}"], status="failed")

    def available(self) -> List[str]:
        return sorted(self._bridges.keys())

    def run_all(self, project_path: str, **kwargs) -> Dict[str, BridgeResult]:
        """Run every registered bridge against the same project."""
        out = {}
        for name in self.available():
            out[name] = self.run(name, project_path=project_path, **kwargs)
        return out


registry = BridgeRegistry()


def _auto_register():
    """Lazy-import every bridge module and register its main function.
    Failures here do NOT crash the registry — they just skip that bridge."""
    import importlib
    names = [
        "bandit_bridge",
        "dlint_bridge",
        "crosshair_bridge",
        "pyt_bridge",
        "contextgem_bridge",
        "semgrep_bridge",
        "pyre_bridge",
        "safety_db_bridge",
        "ts_runner",
        "pyexz3_bridge",
        "supply_chain_bridge",
        "path_traversal_bridge",
    ]
    for n in names:
        try:
            mod = importlib.import_module(f".{n}", package="belief.bridges")
            if hasattr(mod, "register"):
                mod.register(registry)
        except Exception as e:
            logger.warning(f"bridge {n} failed to load: {e}")


_auto_register()


__all__ = ["registry", "BridgeResult", "BridgeRegistry"]
