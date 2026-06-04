"""
belief.cognitive.memory_engine — Persistent belief memory.

Stores validated beliefs, learned patterns, and analysis history across
sessions. The MemoryEngine is the "long-term memory" of the system.

Architecture:
  - Short-term: current session's CognitiveGraph (in-memory)
  - Long-term:  JSON file per project (persistent)
  - Structured: indexed by CWE, file, confidence for fast retrieval

No external dependencies (no Neo4j, no vector DB). Uses plain JSON files
in a configurable directory. This is intentional: works offline, works
on Kali, works without Docker.

Future: add FAISS/Chroma vector index for semantic similarity search
on predicate text. For now, keyword-based retrieval is enough.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("belief.cognitive.memory_engine")


@dataclass
class MemoryEntry:
    """One validated belief stored in long-term memory."""
    belief_id: str
    belief_dict: Dict[str, Any]      # Belief.to_dict() snapshot
    validated: bool = False           # confirmed by verification layer
    validation_method: str = ""      # "z3", "fuzzing", "manual", "bridge"
    first_seen: float = 0.0          # unix timestamp
    last_seen: float = 0.0
    seen_count: int = 1
    false_positive: bool = False     # manually marked FP
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "belief_id": self.belief_id,
            "belief_dict": self.belief_dict,
            "validated": self.validated,
            "validation_method": self.validation_method,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "seen_count": self.seen_count,
            "false_positive": self.false_positive,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AnalysisRecord:
    """Summary of one analysis run (for learning trends)."""
    timestamp: float
    project_path: str
    total_beliefs: int
    contradictions_found: int
    true_positives: int = 0
    false_positives: int = 0
    bridges_used: List[str] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "project_path": self.project_path,
            "total_beliefs": self.total_beliefs,
            "contradictions_found": self.contradictions_found,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "bridges_used": self.bridges_used,
            "duration_s": round(self.duration_s, 2),
        }


class MemoryEngine:
    """Persistent belief memory with indexed retrieval.

    Usage:
        mem = MemoryEngine("/path/to/belief_memory/")
        mem.store_beliefs(beliefs, validated=True, method="bandit")
        similar = mem.recall_by_cwe("CWE-89")
        known_fps = mem.recall_false_positives()
        mem.save()
    """

    def __init__(self, storage_dir: str = "~/.belief/memory",
                 semantic_backend: str = "auto"):
        self._dir = Path(os.path.expanduser(storage_dir))
        self._dir.mkdir(parents=True, exist_ok=True)

        # In-memory stores
        self._entries: Dict[str, MemoryEntry] = {}
        self._history: List[AnalysisRecord] = []

        # Indexes (rebuilt on load)
        self._by_cwe: Dict[str, Set[str]] = defaultdict(set)
        self._by_file: Dict[str, Set[str]] = defaultdict(set)
        self._by_predicate: Dict[str, Set[str]] = defaultdict(set)

        # v4 (B-04 depth fix): semantic similarity layer for cross-session
        # retrieval that survives bridge message drift.
        try:
            from .semantic_memory import SemanticMemory
            self._semantic: Optional[Any] = SemanticMemory(
                persistence_dir=str(self._dir),
                backend=semantic_backend,
            )
            self._semantic.load()
        except Exception as e:
            logger.warning(f"Semantic memory disabled: {e}")
            self._semantic = None

        # Load existing data
        self._load()

    # ---- storage ----------------------------------------------------------

    def store_belief(self, belief, validated: bool = False,
                     method: str = "", tags: Optional[List[str]] = None) -> str:
        """Store or update a belief in long-term memory."""
        bid = belief.id
        now = time.time()

        if bid in self._entries:
            entry = self._entries[bid]
            entry.last_seen = now
            entry.seen_count += 1
            if validated and not entry.validated:
                entry.validated = True
                entry.validation_method = method
            if tags:
                entry.tags = list(set(entry.tags + tags))
        else:
            entry = MemoryEntry(
                belief_id=bid,
                belief_dict=belief.to_dict(),
                validated=validated,
                validation_method=method,
                first_seen=now,
                last_seen=now,
                tags=tags or [],
            )
            self._entries[bid] = entry

        # Update indexes
        self._index_entry(entry)

        # v4: semantic index update
        if self._semantic is not None:
            try:
                text_parts = [
                    belief.predicate.expression or "",
                    belief.predicate.natural_language or "",
                ]
                text = " ".join(p for p in text_parts if p)
                meta = {
                    "cwe": getattr(belief, "cwe", "") or "",
                    "file": belief.scope.file_path or "",
                    "function": belief.scope.function_name or "",
                    "validated": entry.validated,
                    "false_positive": entry.false_positive,
                }
                self._semantic.add(bid, text, meta)
            except Exception as e:
                logger.debug(f"Semantic add failed for {bid}: {e}")

        return bid

    def find_similar(self, belief, k: int = 5,
                     min_score: float = 0.5) -> list:
        """v4: semantic similarity search on stored beliefs."""
        if self._semantic is None:
            return []
        return self._semantic.find_similar(belief, k=k, min_score=min_score)

    def has_similar_fp(self, belief, threshold: float = 0.85) -> bool:
        """v4: is there a known FP semantically similar to this belief?"""
        if self._semantic is None:
            return self.is_known_fp(belief.id)
        if self.is_known_fp(belief.id):
            return True
        return self._semantic.has_similar_fp(belief, threshold=threshold)

    def store_beliefs(self, beliefs, **kwargs) -> int:
        """Bulk store. Returns count."""
        for b in beliefs:
            self.store_belief(b, **kwargs)
        return len(beliefs)

    def mark_false_positive(self, belief_id: str) -> bool:
        """Mark a belief as a known false positive."""
        entry = self._entries.get(belief_id)
        if entry:
            entry.false_positive = True
            return True
        return False

    def mark_validated(self, belief_id: str, method: str = "manual") -> bool:
        """Mark a belief as validated (confirmed vulnerability)."""
        entry = self._entries.get(belief_id)
        if entry:
            entry.validated = True
            entry.validation_method = method
            return True
        return False

    def record_analysis(self, record: AnalysisRecord) -> None:
        """Append an analysis run to history."""
        self._history.append(record)

    # ---- retrieval --------------------------------------------------------

    def recall_by_cwe(self, cwe: str) -> List[MemoryEntry]:
        """Retrieve all beliefs matching a CWE."""
        return [self._entries[bid] for bid in self._by_cwe.get(cwe, set())
                if bid in self._entries]

    def recall_by_file(self, file_path: str) -> List[MemoryEntry]:
        """Retrieve beliefs seen in a specific file."""
        return [self._entries[bid] for bid in self._by_file.get(file_path, set())
                if bid in self._entries]

    def recall_validated(self) -> List[MemoryEntry]:
        """All validated (confirmed) beliefs."""
        return [e for e in self._entries.values() if e.validated]

    def recall_false_positives(self) -> List[MemoryEntry]:
        """All known false positives (for future filtering)."""
        return [e for e in self._entries.values() if e.false_positive]

    def is_known_fp(self, belief_id: str) -> bool:
        """Quick check: was this belief previously marked FP?"""
        entry = self._entries.get(belief_id)
        return entry is not None and entry.false_positive

    def all_fp_ids(self) -> Set[str]:
        """v4 (B-05): all belief IDs known as false positives, as a set
        for O(1) membership tests in CognitiveLoop._decide()."""
        return {bid for bid, e in self._entries.items() if e.false_positive}

    def recall_high_confidence(self, threshold: float = 0.8) -> List[MemoryEntry]:
        """Beliefs above a confidence threshold."""
        return [
            e for e in self._entries.values()
            if e.belief_dict.get("confidence_score", 0) >= threshold
        ]

    def get_history(self, last_n: int = 10) -> List[AnalysisRecord]:
        """Recent analysis records."""
        return self._history[-last_n:]

    # ---- learning ---------------------------------------------------------

    def fp_rate_for_bridge(self, bridge_name: str) -> float:
        """Historical false positive rate for a specific bridge.
        Used by CognitiveLoop to weight bridge results."""
        tagged = [e for e in self._entries.values()
                  if bridge_name in e.tags]
        if not tagged:
            return 0.0
        fp_count = sum(1 for e in tagged if e.false_positive)
        return fp_count / len(tagged)

    def suggest_confidence_adjustment(self, belief) -> Optional[float]:
        """v4 (B-09 fix): adjust confidence using history, or return None.

        Old behavior: when N<3 or no history, returned 0.7*current (biased
        everything toward 0). And for entries that were both validated AND
        false_positive (rare but possible), counted them twice.

        New behavior:
          - Returns None when there is no usable history. Caller interprets
            None as "no adjustment" and keeps current confidence unchanged.
          - Entries flagged as FP are excluded from the validated count
            (no double-counting).
        """
        expr_key = belief.predicate.expression.lower()[:40]
        similar = self._by_predicate.get(expr_key, set())
        if not similar:
            return None

        entries = [self._entries[bid] for bid in similar if bid in self._entries]
        if len(entries) < 3:
            return None  # not enough history

        # B-09 de-dup: FP wins over validated (a FP-flagged entry is NOT
        # a success, even if it was validated at some point in the past).
        validated = sum(1 for e in entries if e.validated and not e.false_positive)
        fps = sum(1 for e in entries if e.false_positive)
        total_labeled = validated + fps
        if total_labeled == 0:
            return None  # all history entries are unlabeled

        historical_precision = validated / total_labeled
        # Blend: 70% current confidence + 30% historical precision
        return 0.7 * belief.confidence_score + 0.3 * historical_precision

    def suggest_prior_novelty(self, belief, cwe: str = "") -> float:
        """v4 (B-05): data-driven novelty prior for unseen beliefs.

        Used by CognitiveLoop._score_candidate when a belief is neither
        in the FP set nor the validated set. Instead of the old hard-coded
        0.8, we compute a prior from history:

          - If the belief came from a bridge with known FP rate → lower
            novelty proportional to FP rate (noisy bridge = less novel).
          - If this CWE has been seen often → lower novelty.
          - Else → neutral 0.5.
        """
        # Extract bridge hint from belief tags / justification if present
        bridge_hint = ""
        justif = str(getattr(belief, "justification", "") or "").lower()
        for name in ("bandit", "dlint", "pyt", "semgrep", "safety_db",
                     "path_traversal", "supply_chain"):
            if name in justif or name in getattr(belief, "id", ""):
                bridge_hint = name
                break

        novelty = 0.5  # neutral prior

        if bridge_hint:
            fp_rate = self.fp_rate_for_bridge(bridge_hint)
            # High FP rate (noisy bridge) → lower novelty, we've seen
            # this kind of noise before. Low FP rate → trust it more.
            novelty = max(0.2, 0.8 - fp_rate * 0.6)

        # If this CWE has been seen >10 times, reduce novelty further
        if cwe:
            cwe_seen = sum(
                1 for e in self._entries.values()
                if cwe in str(e.belief_dict.get("predicate", {}))
            )
            if cwe_seen > 10:
                novelty = max(0.1, novelty - 0.2)

        return novelty

    # ---- persistence ------------------------------------------------------

    def save(self) -> None:
        """Persist all data to disk."""
        data = {
            "entries": {bid: e.to_dict() for bid, e in self._entries.items()},
            "history": [r.to_dict() for r in self._history],
            "version": 1,
        }
        path = self._dir / "memory.json"
        tmp = self._dir / "memory.json.tmp"
        tmp.write_text(json.dumps(data, indent=2, default=str))
        tmp.replace(path)
        # v4: persist semantic memory too
        if self._semantic is not None:
            try:
                self._semantic.save()
            except Exception as e:
                logger.warning(f"Semantic save failed: {e}")
        logger.info(f"Memory saved: {len(self._entries)} entries, "
                     f"{len(self._history)} history records → {path}")

    def _load(self) -> None:
        """Load from disk if exists."""
        path = self._dir / "memory.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text())
            for bid, ed in data.get("entries", {}).items():
                entry = MemoryEntry.from_dict(ed)
                self._entries[bid] = entry
                self._index_entry(entry)
            for hd in data.get("history", []):
                self._history.append(AnalysisRecord(**{
                    k: v for k, v in hd.items()
                    if k in AnalysisRecord.__dataclass_fields__
                }))
            logger.info(f"Memory loaded: {len(self._entries)} entries, "
                         f"{len(self._history)} history records")
        except Exception as e:
            logger.warning(f"Failed to load memory from {path}: {e}")

    def _index_entry(self, entry: MemoryEntry) -> None:
        """Update retrieval indexes for an entry."""
        bd = entry.belief_dict
        bid = entry.belief_id

        # CWE index (from predicate keywords or tags)
        for tag in entry.tags:
            if tag.startswith("CWE-"):
                self._by_cwe[tag].add(bid)

        # File index
        file_path = bd.get("scope", {}).get("file_path", "")
        if file_path:
            self._by_file[file_path].add(bid)

        # Predicate prefix index (for similarity matching)
        expr = bd.get("predicate", {}).get("expression", "").lower()[:40]
        if expr:
            self._by_predicate[expr].add(bid)

    # ---- stats ------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "total_entries": len(self._entries),
            "validated": sum(1 for e in self._entries.values() if e.validated),
            "false_positives": sum(1 for e in self._entries.values() if e.false_positive),
            "analysis_runs": len(self._history),
            "cwes_tracked": len(self._by_cwe),
            "files_tracked": len(self._by_file),
        }
