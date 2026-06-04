"""
belief/cognitive/semantic_memory.py — pluggable semantic-similarity memory.

Fixes B-04 (belief ID fragility) at the retrieval layer: two bridge findings
with slightly different messages but the same underlying vulnerability should
match when we look them up, not miss each other because one extra word changed
the sha256.

Backends (auto-selected at runtime):
  1. "chroma"  — if chromadb + sentence-transformers are available, use them
  2. "tfidf"   — fallback: in-memory sklearn TfidfVectorizer + cosine
  3. "hashed"  — ultimate fallback: hashed bag-of-words + cosine (pure stdlib)

The semantic memory is a LAYER on top of MemoryEngine, not a replacement.
MemoryEngine still stores exact entries keyed by belief.id. SemanticMemory
adds a similarity index so CognitiveLoop can ask "have I seen anything
LIKE this before?" instead of "is this exact id known?".

Usage:
    sm = SemanticMemory(persistence_dir="~/.belief/memory")
    sm.add(belief_id="abc123", text="SQL injection in login", metadata={"cwe": "CWE-89"})
    hits = sm.query("user-controlled SQL string", k=5, min_score=0.6)
    # hits = [SimilarityHit(belief_id="abc123", score=0.82, metadata={...})]
"""
from __future__ import annotations

import json
import logging
import math
import re
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("belief.cognitive.semantic_memory")


# ─────────────────────────────────────────────────────────────────

@dataclass
class SimilarityHit:
    belief_id: str
    score: float
    text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────
# Backend detection
# ─────────────────────────────────────────────────────────────────

def _detect_backend(requested: str = "auto") -> str:
    if requested != "auto":
        return requested
    # Prefer Chroma if the user has installed it (cf. Phase 5 of the audit).
    try:
        import chromadb  # noqa: F401
        import sentence_transformers  # noqa: F401
        return "chroma"
    except Exception:
        pass
    try:
        import sklearn  # noqa: F401
        return "tfidf"
    except Exception:
        pass
    return "hashed"


# ─────────────────────────────────────────────────────────────────
# Shared: text normalization
# ─────────────────────────────────────────────────────────────────

_STOPWORDS = {
    "the", "a", "an", "of", "in", "to", "is", "are", "and", "or", "not",
    "that", "this", "for", "on", "be", "at", "by", "it", "as", "from",
    "with", "was", "were", "has", "have", "had", "but", "if", "so",
    # Noise from bridge messages:
    "possible", "potentially", "maybe", "could", "might", "may",
    "detected", "found", "issue", "warning", "info", "note",
}


def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    toks = re.findall(r"[a-z][a-z0-9_]+", text.lower())
    return [t for t in toks if t not in _STOPWORDS and len(t) > 2]


# ─────────────────────────────────────────────────────────────────
# Backend 1: Hashed bag-of-words (pure stdlib)
# ─────────────────────────────────────────────────────────────────

class _HashedBackend:
    """Simple stdlib-only backend using the hashing trick + cosine.
    Good enough to catch near-duplicate belief messages from bridges."""

    DIM = 1024

    def __init__(self):
        self._entries: Dict[str, Dict[str, Any]] = {}  # bid → {text, metadata, vec}

    @staticmethod
    def _vec(text: str) -> Dict[int, float]:
        tokens = _tokenize(text)
        if not tokens:
            return {}
        v: Dict[int, float] = {}
        for t in tokens:
            idx = int(hashlib.md5(t.encode()).hexdigest()[:8], 16) % _HashedBackend.DIM
            v[idx] = v.get(idx, 0.0) + 1.0
        # L2 normalize
        norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
        return {k: x / norm for k, x in v.items()}

    def add(self, bid: str, text: str, metadata: Optional[dict] = None) -> None:
        self._entries[bid] = {
            "text": text,
            "metadata": metadata or {},
            "vec": self._vec(text),
        }

    def query(self, text: str, k: int, min_score: float) -> List[SimilarityHit]:
        q = self._vec(text)
        if not q:
            return []
        hits: List[SimilarityHit] = []
        for bid, entry in self._entries.items():
            v = entry["vec"]
            if not v:
                continue
            # Sparse dot product
            shared = set(q.keys()) & set(v.keys())
            score = sum(q[k] * v[k] for k in shared)
            if score >= min_score:
                hits.append(SimilarityHit(
                    belief_id=bid, score=score,
                    text=entry["text"], metadata=entry["metadata"],
                ))
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:k]

    def remove(self, bid: str) -> None:
        self._entries.pop(bid, None)

    def size(self) -> int:
        return len(self._entries)

    def save(self, path: Path) -> None:
        serializable = {
            bid: {
                "text": e["text"],
                "metadata": e["metadata"],
                # dict[int,float] → dict[str,float] for JSON
                "vec": {str(k): v for k, v in e["vec"].items()},
            }
            for bid, e in self._entries.items()
        }
        path.write_text(json.dumps(serializable, default=str))

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for bid, e in data.items():
            self._entries[bid] = {
                "text": e["text"],
                "metadata": e["metadata"],
                "vec": {int(k): v for k, v in e["vec"].items()},
            }


# ─────────────────────────────────────────────────────────────────
# Backend 2: TF-IDF via sklearn
# ─────────────────────────────────────────────────────────────────

class _TfIdfBackend:
    """sklearn-based TF-IDF backend. Better quality than hashed bow,
    still pure-Python dep (no heavy ML)."""

    def __init__(self):
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._vec = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=1,
            stop_words=list(_STOPWORDS),
        )
        self._ids: List[str] = []
        self._texts: List[str] = []
        self._metadatas: List[dict] = []
        self._matrix = None  # recomputed on each add; benchmark-scale is fine

    def _rebuild(self) -> None:
        if not self._texts:
            self._matrix = None
            return
        self._matrix = self._vec.fit_transform(self._texts)

    def add(self, bid: str, text: str, metadata: Optional[dict] = None) -> None:
        if bid in self._ids:
            i = self._ids.index(bid)
            self._texts[i] = text
            self._metadatas[i] = metadata or {}
        else:
            self._ids.append(bid)
            self._texts.append(text)
            self._metadatas.append(metadata or {})
        self._rebuild()

    def query(self, text: str, k: int, min_score: float) -> List[SimilarityHit]:
        if self._matrix is None or not self._texts:
            return []
        from sklearn.metrics.pairwise import cosine_similarity
        qv = self._vec.transform([text])
        sims = cosine_similarity(qv, self._matrix).flatten()
        pairs = [
            (i, float(sims[i])) for i in range(len(self._ids))
            if sims[i] >= min_score
        ]
        pairs.sort(key=lambda p: p[1], reverse=True)
        return [
            SimilarityHit(
                belief_id=self._ids[i], score=s,
                text=self._texts[i], metadata=self._metadatas[i],
            )
            for i, s in pairs[:k]
        ]

    def remove(self, bid: str) -> None:
        if bid not in self._ids:
            return
        i = self._ids.index(bid)
        self._ids.pop(i)
        self._texts.pop(i)
        self._metadatas.pop(i)
        self._rebuild()

    def size(self) -> int:
        return len(self._ids)

    def save(self, path: Path) -> None:
        data = {
            "ids": self._ids,
            "texts": self._texts,
            "metadatas": self._metadatas,
        }
        path.write_text(json.dumps(data, default=str))

    def load(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text())
        self._ids = data.get("ids", [])
        self._texts = data.get("texts", [])
        self._metadatas = data.get("metadatas", [])
        self._rebuild()


# ─────────────────────────────────────────────────────────────────
# Backend 3: Chroma (optional heavy backend)
# ─────────────────────────────────────────────────────────────────

class _ChromaBackend:
    """Vector store via chromadb + sentence-transformers embeddings.
    Only instantiated if those libs are present on the system."""

    def __init__(self, persist_dir: Path):
        import chromadb
        from sentence_transformers import SentenceTransformer
        persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(persist_dir))
        self._coll = self._client.get_or_create_collection("belief_memory")
        # Small, fast, CPU-friendly. User can swap if they have GPU.
        self._encoder = SentenceTransformer("all-MiniLM-L6-v2")

    def add(self, bid: str, text: str, metadata: Optional[dict] = None) -> None:
        emb = self._encoder.encode([text]).tolist()
        # Chroma upserts by ID
        self._coll.upsert(
            ids=[bid],
            embeddings=emb,
            documents=[text],
            metadatas=[metadata or {}],
        )

    def query(self, text: str, k: int, min_score: float) -> List[SimilarityHit]:
        if self._coll.count() == 0:
            return []
        emb = self._encoder.encode([text]).tolist()
        res = self._coll.query(
            query_embeddings=emb,
            n_results=min(k, self._coll.count()),
        )
        hits: List[SimilarityHit] = []
        for i, bid in enumerate(res.get("ids", [[]])[0]):
            # Chroma returns L2 distance for default metric; convert to
            # a similarity in [0, 1] via 1 / (1 + d)
            dist = res.get("distances", [[0]])[0][i]
            score = 1.0 / (1.0 + dist)
            if score < min_score:
                continue
            hits.append(SimilarityHit(
                belief_id=bid,
                score=score,
                text=res.get("documents", [[""]])[0][i],
                metadata=res.get("metadatas", [[{}]])[0][i] or {},
            ))
        return hits

    def remove(self, bid: str) -> None:
        try:
            self._coll.delete(ids=[bid])
        except Exception:
            pass

    def size(self) -> int:
        return self._coll.count()

    # Chroma persists itself — save/load are no-ops
    def save(self, path: Path) -> None: pass
    def load(self, path: Path) -> None: pass


# ─────────────────────────────────────────────────────────────────
# Facade
# ─────────────────────────────────────────────────────────────────

class SemanticMemory:
    """Pluggable semantic memory with auto-detected backend.

    Public contract:
      add(belief_id, text, metadata=None)
      query(text, k=5, min_score=0.5) -> list[SimilarityHit]
      find_similar(belief, k=5, min_score=0.5) -> list[SimilarityHit]
      remove(belief_id)
      size()
      save() / load()
    """

    def __init__(self, persistence_dir: Optional[str] = None,
                 backend: str = "auto"):
        self._dir = Path(persistence_dir).expanduser() if persistence_dir else None
        chosen = _detect_backend(backend)
        if chosen == "chroma" and self._dir:
            try:
                self._backend = _ChromaBackend(self._dir / "chroma")
                self.backend_name = "chroma"
            except Exception as e:
                logger.warning(f"Chroma init failed ({e}), falling back")
                chosen = "tfidf"
        if chosen == "tfidf":
            try:
                self._backend = _TfIdfBackend()
                self.backend_name = "tfidf"
            except Exception as e:
                logger.warning(f"TF-IDF init failed ({e}), falling back to hashed")
                chosen = "hashed"
        if chosen == "hashed":
            self._backend = _HashedBackend()
            self.backend_name = "hashed"
        logger.info(f"[semantic_memory] backend={self.backend_name}")

    # ── core API ───────────────────────────────────────────────

    def add(self, belief_id: str, text: str,
            metadata: Optional[dict] = None) -> None:
        if not text:
            return
        self._backend.add(belief_id, text, metadata)

    def query(self, text: str, k: int = 5,
              min_score: float = 0.5) -> List[SimilarityHit]:
        return self._backend.query(text, k, min_score)

    def find_similar(self, belief, k: int = 5,
                     min_score: float = 0.5) -> List[SimilarityHit]:
        """Convenience for Belief objects — uses predicate.expression +
        natural_language as the query text."""
        parts = [
            belief.predicate.expression or "",
            belief.predicate.natural_language or "",
        ]
        text = " ".join(p for p in parts if p)
        if not text:
            return []
        # Don't match the belief against itself
        hits = self.query(text, k=k + 1, min_score=min_score)
        return [h for h in hits if h.belief_id != belief.id][:k]

    def has_similar_fp(self, belief, threshold: float = 0.85) -> bool:
        """v4 (B-04): is there a known FP similar to this belief?"""
        hits = self.find_similar(belief, k=3, min_score=threshold)
        return any(h.metadata.get("false_positive", False) for h in hits)

    def remove(self, belief_id: str) -> None:
        self._backend.remove(belief_id)

    def size(self) -> int:
        return self._backend.size()

    # ── persistence ────────────────────────────────────────────

    def save(self) -> None:
        if not self._dir:
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / f"semantic_memory_{self.backend_name}.json"
        self._backend.save(path)

    def load(self) -> None:
        if not self._dir:
            return
        path = self._dir / f"semantic_memory_{self.backend_name}.json"
        self._backend.load(path)


__all__ = ["SemanticMemory", "SimilarityHit"]
