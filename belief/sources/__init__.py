"""
belief.sources — unified abstraction for all belief-producing inputs.

BELIEF extracts beliefs from many kinds of sources:
- WHITE-BOX: source code (the original BELIEF core)
- BLACK-BOX: HTTP traffic observations (belief_http_engine.py)
- SUPPLY CHAIN: dependencies + CVE matches (safety_db, scfw)
- HAR/BURP: recorded web sessions for later analysis
- RUNTIME: observed program executions (future work)

Each source implements `collect_beliefs()` and returns a list of
`belief.models.Belief` sextuplets (possibly lossy when the source is
black-box, but the sextuplet shape is preserved).

This lets the orchestrator treat every input uniformly: scan a project,
replay a HAR file, or correlate runtime traces — same downstream pipeline
(cross-verify, Z3, drift, graph, report).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from belief.models import Belief
    _HAVE_MODELS = True
except ImportError:
    _HAVE_MODELS = False
    Belief = None  # type: ignore


@dataclass
class SourceMetadata:
    """Free-form metadata attached to every BeliefSource."""
    name: str
    kind: str                  # 'white_box' | 'black_box' | 'supply_chain' | 'runtime'
    project_path: Optional[str] = None
    timestamp_utc: Optional[str] = None
    tool_versions: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)


class BeliefSource(ABC):
    """Abstract producer of Belief sextuplets."""

    kind: str = "unknown"

    @abstractmethod
    def collect_beliefs(self) -> List[Belief]:
        """Return a list of Belief sextuplets derived from this source."""

    @abstractmethod
    def metadata(self) -> SourceMetadata:
        """Return a metadata snapshot."""


class MultiSource:
    """Collect beliefs from multiple sources into one stream.

    The order of sources matters for dedupe: earlier sources win
    on conflict (they are considered more trustworthy).
    """
    def __init__(self, sources: List[BeliefSource], dedupe: bool = True):
        self.sources = sources
        self.dedupe = dedupe

    def collect(self) -> List[Belief]:
        out: List[Belief] = []
        if not _HAVE_MODELS:
            return out
        for src in self.sources:
            try:
                beliefs = src.collect_beliefs() or []
            except Exception as e:
                import logging
                logging.getLogger("belief.sources").warning(
                    f"source {src.metadata().name} failed: {e}"
                )
                continue
            if self.dedupe:
                beliefs = self._dedupe_against(out, beliefs)
            out.extend(beliefs)
        return out

    @staticmethod
    def _dedupe_against(existing, new):
        """Keep new beliefs only if they don't match any existing by
        (file_path, line_start, predicate prefix)."""
        seen = {
            (
                (b.scope.file_path or ""),
                (b.scope.line_start or 0),
                (b.predicate.expression or "")[:20].lower(),
            )
            for b in existing
        }
        out = []
        for b in new:
            key = (
                (b.scope.file_path or ""),
                (b.scope.line_start or 0),
                (b.predicate.expression or "")[:20].lower(),
            )
            if key not in seen:
                out.append(b)
                seen.add(key)
        return out


__all__ = ["BeliefSource", "SourceMetadata", "MultiSource"]
