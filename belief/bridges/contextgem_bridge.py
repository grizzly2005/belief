"""
contextgem_bridge — use ContextGem for STRUCTURED LLM extraction.

ContextGem is a framework for reliable structured output from LLMs.
It handles:
- Retry on malformed output (JSON schema validation)
- Chunking of long inputs with preserved context
- Multi-stage prompts (extract → verify → refine)
- Grounding (cite source passages)

For BELIEF, ContextGem replaces the hand-rolled JSON parser in llm_client.
Benefits:
- Fewer "LLM returned {'foo' instead of '{\"foo\"'" parse failures
- Auto-repair of truncated JSON (complements our tolerant parser)
- Concept-aware extraction: define a BeliefConcept class once, reuse it

Integration:
- This bridge wraps a subset of ContextGem: Document + Concept + LLM driver
- It uses the same LLM config (Ollama by default) as belief.llm_client
- Returns a list of Belief dicts, ready to feed into extractor
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.contextgem")


def is_installed() -> bool:
    """Either pip-installed or bundled in tools_bundled/contextgem/."""
    bundled = Path(__file__).parent.parent / "tools_bundled" / "contextgem"
    if bundled.exists():
        sys.path.insert(0, str(bundled.parent))
    try:
        import contextgem  # noqa
        return True
    except ImportError:
        return False


def extract_structured(
    *,
    source_code: str,
    prompt: str,
    schema: Optional[Dict[str, Any]] = None,
    llm_url: str = "http://localhost:11434",
    model: str = "qwen2.5-coder:14b",
    timeout_s: int = 120,
    use_cache: bool = False,
) -> BridgeResult:
    """Extract structured beliefs from a code snippet using ContextGem."""
    t0 = time.time()
    result = BridgeResult(source="contextgem")

    if not is_installed():
        result.errors.append(
            "contextgem not available. `pip install contextgem` or bundle it."
        )
        result.elapsed_s = time.time() - t0
        return result

    try:
        from contextgem import Document
        from contextgem.public.concepts import JsonObjectConcept
        from contextgem.public.llms import DocumentLLM
    except Exception as e:
        # Fallback to very minimal API if public surface differs
        result.errors.append(f"contextgem API layout not as expected: {e}")
        result.elapsed_s = time.time() - t0
        return result

    try:
        doc = Document(raw_text=source_code)

        # Define a concept representing the extraction target
        belief_schema = schema or {
            "type": "object",
            "properties": {
                "assumption": {"type": "string"},
                "anchor_line": {"type": "integer"},
                "justification_type": {"type": "string",
                                       "enum": ["C1", "C2", "C3", "C4", "C5"]},
                "contextual_constraint": {"type": "string"},
                "trust_domain": {"type": "string"},
                "logic_type": {"type": "string",
                               "enum": ["fol", "semantic", "contract"]},
                "variables": {"type": "array", "items": {"type": "string"}},
                "predicate": {"type": "string"},
            },
            "required": ["assumption", "anchor_line", "justification_type"],
        }
        concept = JsonObjectConcept(
            name="beliefs",
            description=prompt,
            json_schema=belief_schema,
        )
        doc.concepts = [concept]

        # Ollama-compatible LLM
        llm = DocumentLLM(
            provider="ollama",
            model=model,
            api_base=llm_url,
            timeout=timeout_s,
        )

        extracted = llm.extract_concepts_from_document(doc)
        for c in (extracted or []):
            for item in getattr(c, "items", []):
                if isinstance(item, dict):
                    result.findings.append(item)

    except Exception as e:
        result.errors.append(f"contextgem extraction failed: {type(e).__name__}: {e}")

    result.elapsed_s = time.time() - t0
    return result


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Direct passthrough — contextgem output already matches Belief schema."""
    out = dict(finding)
    out["source"] = "contextgem"
    out.setdefault("logic_type", "semantic")
    return out


def register(registry) -> None:
    registry.register("contextgem", extract_structured)
