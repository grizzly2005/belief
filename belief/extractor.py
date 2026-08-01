"""
BELIEF — Belief Extractor (v2).

The Comprehension layer: uses the LLM to translate code + context into
formal sextuplets (P, S, C, D, E, L). Includes:
- Hardened anti-hallucination filters
- Knowledge-base grounding (taint sources/sinks injected pre-LLM)
- Z3 repair loop (one retry when a 'fol' predicate fails translation)
- Automatic skeleton-extraction when a function is too big
- Optional self-consistency (multi-sample voting) for high-severity beliefs
"""

from __future__ import annotations

import ast
import json
import logging
import re
import time
from collections import Counter
from typing import Optional

from .config import BeliefConfig
from .llm_client import LLMClient, PromptTooLargeError
from .models import (
    ArtifactKind,
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from .prompts import (
    ADVERSARIAL_BELIEFS_PROMPT,
    EXTRACT_BELIEFS_PROMPT,
    EXTRACT_CONFIG_BELIEFS_PROMPT,
    GROUNDING_BLOCK_TEMPLATE,
    PREDICATE_DSL,
    PREDICATE_REPAIR_PROMPT,
    SYNTHESIZE_SPEC_PROMPT,
    SYSTEM_PROMPT,
)

logger = logging.getLogger("belief.extractor")


# ─────────────────────────────────────────────────────────────────────────────
#  Optional KB import — fully degrades if the file isn't on PYTHONPATH
# ─────────────────────────────────────────────────────────────────────────────

try:
    import belief_knowledge_base as _kb  # type: ignore
    _KB_AVAILABLE = True
except Exception:
    _KB_AVAILABLE = False
    logger.info("belief_knowledge_base not importable — KB grounding disabled")


# ─────────────────────────────────────────────────────────────────────────────
#  Extractor
# ─────────────────────────────────────────────────────────────────────────────

class BeliefExtractor:
    """Extract implicit beliefs from code using LLM + KB grounding + filters."""

    def __init__(self, config: BeliefConfig, llm: LLMClient):
        self.config = config
        self.llm = llm

    # ── Public API (compatible with v1) ──

    def extract_from_function(
        self,
        code: str,
        file_path: str,
        function_name: str,
        module_name: str = "",
        callers: list[dict] | None = None,
        documentation: str = "(none)",
        test_info: str = "no assertions found",
    ) -> list[Belief]:
        """Extract beliefs from a single function/class."""

        # 1. If code is too big, downscope to a skeleton
        code_for_llm = self._maybe_skeletonize(code)
        if code_for_llm != code:
            logger.info(
                f"  Code for {function_name} skeletonized: "
                f"{len(code)}→{len(code_for_llm)} chars"
            )

        # 2. Build grounding block from KB
        grounding_block = self._build_grounding_block(code) if self.config.enable_kb_grounding else ""

        # 3. Build full prompt
        prompt = EXTRACT_BELIEFS_PROMPT.format(
            code=code_for_llm,
            file_path=file_path,
            function_name=function_name,
            module_name=module_name or file_path,
            callers=json.dumps(callers or [])[:2000],  # cap caller info
            documentation=documentation[:1000],
            test_info=test_info[:500],
            grounding_block=grounding_block,
            dsl_block=PREDICATE_DSL,
        )

        # 4. Get raw beliefs (with retry, fallback, optional self-consistency)
        raw_beliefs = self._extract_robust(prompt, function_name, code_for_llm)

        # 5. Parse + filter
        beliefs: list[Belief] = []
        for raw in raw_beliefs[: self.config.max_beliefs_per_function]:
            belief = self._parse_raw_belief(raw, file_path, module_name)
            if belief and self._passes_filters(belief, code):
                beliefs.append(belief)

        logger.info(
            f"Extracted {len(beliefs)}/{len(raw_beliefs)} beliefs from {function_name} "
            f"({len(raw_beliefs) - len(beliefs)} filtered)"
        )
        return beliefs

    def extract_from_config(
        self,
        config_content: str,
        file_path: str,
        config_type: str = "yaml",
    ) -> list[Belief]:
        """Extract beliefs from configuration/infrastructure files."""

        # Truncate huge configs (k8s yamls can be massive)
        if len(config_content) > self.config.max_code_chars_per_call:
            logger.warning(
                f"Config {file_path} truncated "
                f"{len(config_content)}→{self.config.max_code_chars_per_call} chars"
            )
            config_content = config_content[: self.config.max_code_chars_per_call]

        prompt = EXTRACT_CONFIG_BELIEFS_PROMPT.format(
            config_content=config_content,
            file_path=file_path,
            config_type=config_type,
        )

        try:
            raw_beliefs = self.llm.complete_json(prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.warning(f"Config extraction failed for {file_path}: {e}")
            return []

        if not isinstance(raw_beliefs, list):
            return []

        beliefs: list[Belief] = []
        for raw in raw_beliefs:
            belief = self._parse_raw_belief(raw, file_path, "config")
            if belief:
                ct = config_type.lower()
                if any(x in ct for x in ["docker", "k8s", "terraform", "helm"]):
                    belief.artifact_kind = ArtifactKind.INFRASTRUCTURE
                elif any(x in ct for x in ["ci", "github", "gitlab", "jenkins"]):
                    belief.artifact_kind = ArtifactKind.CI_CD
                else:
                    belief.artifact_kind = ArtifactKind.CONFIGURATION
                beliefs.append(belief)

        return beliefs

    def cross_verify_beliefs(self, beliefs: list[Belief], code: str) -> list[Belief]:
        """Send beliefs to verification providers and adjust confidence."""
        if not self.config.enable_cross_verification or not beliefs:
            return beliefs

        verification_providers = self.config.verification_providers
        if not verification_providers:
            return beliefs

        beliefs_json = json.dumps([b.to_dict() for b in beliefs], indent=2)
        verify_prompt = (
            f"Review these extracted beliefs for accuracy. "
            f"For each belief, respond with its id and whether you agree "
            f"with the predicate and justification category.\n\n"
            f"Code:\n```\n{code[:6000]}\n```\n\n"
            f"Beliefs:\n{beliefs_json}\n\n"
            f"Return JSON array: "
            f'[{{"id": "...", "agree": true/false, '
            f'"corrected_justification": "C1-C6 or null"}}]. '
            f"C1 means a replayable mechanical proof artifact, C2 a static "
            f"verification result, C3 an explicit runtime guard, C4 a caller "
            f"assumption, C5 a documented convention, and C6 unsupported."
        )

        try:
            results = self.llm.cross_verify(verify_prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.warning(f"Cross-verification failed: {e}")
            return beliefs

        agreement_map: dict[str, list[bool]] = {b.id: [] for b in beliefs}

        for result in results:
            resp = result.get("response", [])
            if isinstance(resp, list):
                for item in resp:
                    bid = item.get("id", "")
                    if bid in agreement_map:
                        agreement_map[bid].append(bool(item.get("agree", True)))

        for belief in beliefs:
            votes = agreement_map.get(belief.id, [])
            if votes:
                agreement_ratio = sum(1 for v in votes if v) / len(votes)
                belief.confidence_score = (
                    belief.confidence_score * 0.6 + agreement_ratio * 0.4
                )

        return beliefs

    def repair_predicate(
        self,
        belief: Belief,
        code: str,
        translation_error: str,
    ) -> Belief | None:
        """When Z3 fails to translate a 'fol' predicate, ask the LLM to
        reformulate it in DSL or downgrade its logic_type. Single attempt."""
        if not self.config.enable_z3_repair_loop:
            return None
        if belief.logic_type != LogicType.FOL:
            return None  # nothing to repair

        prompt = PREDICATE_REPAIR_PROMPT.format(
            original_expression=belief.predicate.expression,
            error=translation_error[:500],
            dsl=PREDICATE_DSL,
            code=code[:4000],
        )

        try:
            repaired = self.llm.complete_json(prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.debug(f"Repair LLM call failed: {e}")
            return None

        if not isinstance(repaired, dict):
            return None

        new_expr = (repaired.get("expression") or "").strip()
        new_logic = repaired.get("logic_type", "fol")
        new_nl = repaired.get("natural_language") or belief.predicate.natural_language

        if not new_expr:
            return None

        logic = LogicType.parse(new_logic)
        if logic == LogicType.FOL and str(new_logic).strip().lower() not in {"", "fol"}:
            logic = LogicType.SEMANTIC

        # Build a new belief with the repaired predicate
        new_predicate = Predicate(
            expression=new_expr,
            variables=belief.predicate.variables,
            anchor_lines=belief.predicate.anchor_lines,
            natural_language=new_nl,
        )
        repaired_belief = Belief(
            predicate=new_predicate,
            scope=belief.scope,
            justification=belief.justification,
            dependencies=belief.dependencies,
            epistemic_status=belief.epistemic_status,
            logic_type=logic,
            confidence_score=max(0.3, belief.confidence_score - 0.1),
        )
        logger.debug(f"Repaired belief: '{belief.predicate.expression}' → '{new_expr}' ({logic.value})")
        return repaired_belief

    def model_adversarial_beliefs(
        self, code: str, beliefs: list[Belief]
    ) -> list[dict]:
        """Model which beliefs an attacker would target first."""
        if not beliefs:
            return []
        beliefs_json = json.dumps([b.to_dict() for b in beliefs], indent=2)
        prompt = ADVERSARIAL_BELIEFS_PROMPT.format(
            code=code[:6000], beliefs=beliefs_json
        )
        try:
            result = self.llm.complete_json(prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.warning(f"Adversarial modeling failed: {e}")
            return []
        return result if isinstance(result, list) else []

    def synthesize_specifications(
        self, beliefs: list[Belief], code: str
    ) -> list[dict]:
        """Generate assertions/tests for weakly supported beliefs (C4-C6)."""
        weak_beliefs = [
            b for b in beliefs
            if b.justification.robustness_score <= 0.4
        ]
        if not weak_beliefs:
            return []

        beliefs_json = json.dumps([b.to_dict() for b in weak_beliefs], indent=2)
        prompt = SYNTHESIZE_SPEC_PROMPT.format(
            beliefs=beliefs_json, code=code[:6000]
        )
        try:
            result = self.llm.complete_json(prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.warning(f"Spec synthesis failed: {e}")
            return []
        return result if isinstance(result, list) else []

    # ── Internal: chunking / skeletonization ──

    def _maybe_skeletonize(self, code: str) -> str:
        """If code is too big, return a skeleton (signatures + control flow,
        full bodies only for branches that touch tainted-looking variables)."""
        ceiling = self.config.max_code_chars_per_call
        if len(code) <= ceiling:
            return code

        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Can't parse — just hard-truncate
            return code[:ceiling] + "\n# ... [truncated]"

        # Identify lines that contain "interesting" tokens (taint-like)
        interesting_re = re.compile(
            r"\b(request|input|user|param|args|cookie|header|body|"
            r"sql|query|exec|system|popen|eval|pickle|yaml|"
            r"open|read|write|connect|recv|send|password|token|secret|"
            r"validate|sanitize|escape|verify|check|assert|raise)\b",
            re.IGNORECASE,
        )
        lines = code.split("\n")
        keep_lines: set[int] = set()
        for i, line in enumerate(lines):
            if interesting_re.search(line):
                # Keep this line plus 2 lines of context on each side
                for j in range(max(0, i - 2), min(len(lines), i + 3)):
                    keep_lines.add(j)

        # Always keep function/class signatures
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = node.lineno - 1
                # Keep signature line and any decorators
                for dec in node.decorator_list:
                    keep_lines.add(dec.lineno - 1)
                keep_lines.add(start)

        # Build skeleton: kept lines verbatim, runs of skipped lines replaced
        # by a single "# ... [N lines elided]" marker.
        out_parts: list[str] = []
        elided_run = 0
        for i, line in enumerate(lines):
            if i in keep_lines:
                if elided_run:
                    out_parts.append(f"    # ... [{elided_run} lines elided]")
                    elided_run = 0
                out_parts.append(line)
            else:
                elided_run += 1
        if elided_run:
            out_parts.append(f"    # ... [{elided_run} lines elided]")

        skeleton = "\n".join(out_parts)
        if len(skeleton) > ceiling:
            skeleton = skeleton[:ceiling] + "\n# ... [further truncated]"
        return skeleton

    # ── Internal: KB grounding ──

    def _build_grounding_block(self, code: str) -> str:
        """Match KB taint sources/sinks against the code and inject as context."""
        if not _KB_AVAILABLE:
            return ""

        try:
            sources, sinks = _kb_match(code)
        except Exception as e:
            logger.debug(f"KB matching failed: {e}")
            return ""

        if not sources and not sinks:
            return ""

        # Compact, useful representation
        srcs_str = "\n".join(f"  - {s}" for s in sources[:10]) if sources else "  (none detected)"
        sinks_str = "\n".join(f"  - {s}" for s in sinks[:10]) if sinks else "  (none detected)"

        # Pattern matches (semgrep-like) — optional, only if KB exposes the API
        patterns_str = "  (no pattern matcher available)"
        try:
            patterns = _kb_patterns(code)
            if patterns:
                patterns_str = "\n".join(f"  - {p}" for p in patterns[:5])
        except Exception:
            pass

        return GROUNDING_BLOCK_TEMPLATE.format(
            sources=srcs_str,
            sinks=sinks_str,
            pattern_matches=patterns_str,
        )

    # ── Internal: extraction with retry / fallback / self-consistency ──

    def _extract_robust(
        self,
        full_prompt: str,
        function_name: str,
        code: str,
        max_retries: int = 3,
    ) -> list:
        """Robust extraction loop: retries with backoff, provider fallback,
        optional self-consistency aggregation."""

        if self.config.enable_self_consistency:
            samples = self.llm.self_consistency(
                full_prompt,
                system=SYSTEM_PROMPT,
                n_samples=self.config.self_consistency_samples,
                temperature=0.4,
            )
            return _merge_self_consistency(
                samples, min_agreement=self.config.self_consistency_min_agreement,
            )

        base_delay = 1.0
        last_error: Exception | None = None
        for attempt in range(max_retries):
            if attempt > 0:
                delay = base_delay * (2 ** (attempt - 1))
                logger.debug(f"  Backoff {delay:.1f}s before retry {attempt}")
                time.sleep(delay)

            try:
                start = time.time()
                raw = self.llm.complete_json(full_prompt, system=SYSTEM_PROMPT)
                elapsed = time.time() - start

                if isinstance(raw, list) and raw:
                    logger.info(
                        f"  Extracted {len(raw)} raw beliefs from {function_name} "
                        f"in {elapsed:.1f}s (attempt {attempt + 1})"
                    )
                    return raw
                logger.debug(f"Empty/non-list response on attempt {attempt + 1}")
            except PromptTooLargeError as e:
                # Skeletonize harder and retry once
                logger.warning(f"Prompt too large for {function_name}: {e}")
                last_error = e
                # Re-skeletonize on a tighter budget
                full_prompt = full_prompt.replace(
                    code, code[: len(code) // 2] + "\n# ... [aggressively truncated]\n"
                )
                code = code[: len(code) // 2]
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Extraction attempt {attempt + 1}/{max_retries} failed "
                    f"for {function_name}: {e}"
                )

        logger.warning(f"All extraction attempts failed for {function_name}: {last_error}")
        return []

    # ── Internal: parsing & filtering ──

    def _parse_raw_belief(
        self, raw: dict, file_path: str, module: str
    ) -> Optional[Belief]:
        """Parse a raw JSON dict from LLM into a Belief object."""
        try:
            pred_data = raw.get("predicate", {}) or {}
            scope_data = raw.get("scope", {}) or {}

            predicate = Predicate(
                expression=pred_data.get("expression", "") or "",
                variables=tuple(pred_data.get("variables", []) or []),
                anchor_lines=tuple(pred_data.get("anchor_lines", []) or []),
                natural_language=pred_data.get("natural_language", "") or "",
            )

            scope = Scope(
                file_path=file_path,
                function_name=scope_data.get("function_name"),
                class_name=scope_data.get("class_name"),
                module=module,
                line_start=scope_data.get("line_start"),
                line_end=scope_data.get("line_end"),
            )

            justification = JustificationCategory.parse(
                raw.get("justification", "C6")
            )

            epistemic = EpistemicStatus(raw.get("epistemic_status", "belief"))

            logic = LogicType.parse(raw.get("logic_type", "fol"))

            return Belief(
                predicate=predicate,
                scope=scope,
                justification=justification,
                dependencies=raw.get("dependencies", []) or [],
                epistemic_status=epistemic,
                logic_type=logic,
                confidence_score=raw.get("confidence_score", 0.5),
                cwe=raw.get("cwe", "") or "",
                canonical_key=raw.get("canonical_key", "") or "",
                source_metadata=raw.get("source_metadata") or raw.get("metadata") or {},
            )

        except Exception as e:
            logger.debug(f"Failed to parse belief: {e}")
            return None

    def _passes_filters(self, belief: Belief, source_code: str) -> bool:
        """Hardened anti-hallucination filters (v2)."""

        expr = belief.predicate.expression.strip()

        # F1: predicate must be non-empty and specific
        if len(expr) < 5:
            return False

        # F2: reject vague predicates
        vague_patterns = [
            "is valid", "is correct", "works properly",
            "is safe", "is secure", "is good", "is fine",
            "should be", "must be ok", "looks ok",
        ]
        if any(v in expr.lower() for v in vague_patterns):
            return False

        # F3: every variable must appear textually in the code (case-sensitive,
        # word-boundary). Single-char vars are skipped (too ambiguous).
        vars_to_check = [
            v.split(".")[0] for v in belief.predicate.variables
            if v and len(v.split(".")[0]) >= 2
        ]
        if vars_to_check:
            missing = [
                v for v in vars_to_check
                if not re.search(r"\b" + re.escape(v) + r"\b", source_code)
            ]
            if missing and len(missing) == len(vars_to_check):
                # ALL variables are absent — very likely hallucinated
                logger.debug(f"Filtered: no variable matched code: {vars_to_check}")
                return False
            if missing:
                # Some vars missing → reduce confidence but keep
                belief.confidence_score *= 0.7

        # F4: anchor_lines must be inside [scope.line_start, scope.line_end]
        if belief.scope.line_start is not None and belief.scope.line_end is not None:
            for ln in belief.predicate.anchor_lines:
                if not (belief.scope.line_start <= ln <= belief.scope.line_end):
                    logger.debug(f"Filtered: anchor_line {ln} outside scope")
                    return False

        # F5: justification consistency. LLM extraction cannot manufacture a
        # proof/static-verifier artifact merely by naming C1 or C2.
        if belief.justification in {
            JustificationCategory.C1_MECHANICALLY_PROVEN,
            JustificationCategory.C2_STATICALLY_VERIFIED_PROPERTY,
        }:
            belief.justification = JustificationCategory.C6_UNSUPPORTED_ASSUMPTION
            belief.confidence_score *= 0.7

        if belief.justification == JustificationCategory.C3_EXPLICIT_RUNTIME_GUARD:
            if not re.search(
                r"\b(assert|raise|if\s+not|if\s+\w+\s+is\s+None)\b",
                source_code,
            ):
                belief.justification = (
                    JustificationCategory.C6_UNSUPPORTED_ASSUMPTION
                )
                belief.confidence_score *= 0.8

        if belief.justification == JustificationCategory.C5_DOCUMENTED_CONVENTION:
            # The keyword must appear in a comment or docstring
            comment_or_doc = "\n".join(
                line for line in source_code.split("\n")
                if line.strip().startswith("#") or '"""' in line or "'''" in line
            )
            keyword = (
                belief.predicate.natural_language.split()[:3]
                if belief.predicate.natural_language else []
            )
            if not any(
                k.lower() in comment_or_doc.lower() for k in keyword if len(k) >= 4
            ):
                belief.justification = (
                    JustificationCategory.C6_UNSUPPORTED_ASSUMPTION
                )
                belief.confidence_score *= 0.8

        # F6: minimum confidence threshold
        if belief.confidence_score < self.config.min_confidence_threshold:
            return False

        return True


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _kb_match(code: str) -> tuple[list[str], list[str]]:
    """Return (sources, sinks) found in the code via the knowledge base.
    Tolerant of various KB API shapes."""
    if not _KB_AVAILABLE:
        return [], []

    sources_found: list[str] = []
    sinks_found: list[str] = []

    # Try the modern API (KnowledgeBase class)
    try:
        kb = _kb.KnowledgeBase()
        if hasattr(kb, "find_taint_sources"):
            sources_found = list(kb.find_taint_sources(code))[:20]
        if hasattr(kb, "find_taint_sinks"):
            sinks_found = list(kb.find_taint_sinks(code))[:20]
        if sources_found or sinks_found:
            return [str(s) for s in sources_found], [str(s) for s in sinks_found]
    except Exception:
        pass

    # Fallback: scan the global TAINT_SOURCES / TAINT_SINKS lists by string match
    for attr_name, dest in [("TAINT_SOURCES", sources_found), ("TAINT_SINKS", sinks_found)]:
        items = getattr(_kb, attr_name, None) or []
        for item in items:
            # Each item has .path or .function attribute
            ident = getattr(item, "path", None) or getattr(item, "function", None) or ""
            if not ident:
                continue
            # Use the rightmost component as a search key (e.g. 'execute', 'system')
            tail = ident.split(".")[-1]
            if len(tail) >= 4 and re.search(r"\b" + re.escape(tail) + r"\b", code):
                dest.append(ident)
        if len(dest) > 20:
            del dest[20:]

    return sources_found, sinks_found


def _kb_patterns(code: str) -> list[str]:
    """Try to get pattern-match results from the KB. Returns a list of
    human-readable strings."""
    if not _KB_AVAILABLE:
        return []
    try:
        kb = _kb.KnowledgeBase()
        if hasattr(kb, "match_known_patterns"):
            matches = kb.match_known_patterns(code) or []
            return [str(m)[:120] for m in matches[:10]]
    except Exception:
        pass
    return []


def _merge_self_consistency(
    samples: list[list | dict], min_agreement: int = 2
) -> list:
    """Aggregate N belief-list samples into one, keeping beliefs whose
    predicate.expression appears in ≥min_agreement samples (after light
    normalization)."""
    if not samples:
        return []

    # Normalize each belief to (normalized_expr, raw_belief)
    def norm(expr: str) -> str:
        return re.sub(r"\s+", " ", expr.strip().lower())

    counter: Counter[str] = Counter()
    representative: dict[str, dict] = {}

    for sample in samples:
        if not isinstance(sample, list):
            continue
        seen_in_sample: set[str] = set()
        for raw in sample:
            if not isinstance(raw, dict):
                continue
            expr = (raw.get("predicate") or {}).get("expression") or ""
            if not expr:
                continue
            key = norm(expr)
            if key in seen_in_sample:
                continue
            seen_in_sample.add(key)
            counter[key] += 1
            if key not in representative:
                representative[key] = raw

    survivors = [
        representative[k] for k, count in counter.items()
        if count >= min_agreement
    ]
    logger.info(
        f"Self-consistency: {sum(len(s) if isinstance(s, list) else 0 for s in samples)} "
        f"raw → {len(survivors)} surviving (≥{min_agreement} votes)"
    )
    return survivors
