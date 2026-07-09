"""
semgrep_indexer — index BELIEF's bundled Semgrep rules.

We bundled 500 Semgrep rules under belief/security_rules/semgrep/. That's
too many to run as a single pass; the running cost is high AND the noise
floor grows with rule count.

This indexer:
- Walks every bundled rule YAML
- Parses its `metadata.cwe`, `languages`, `severity`, `tags`
- Builds in-memory indexes: by CWE, by language, by category
- Exposes simple query functions: `rules_for_cwe('CWE-78')`

Use case: orchestrator, given a belief-level CWE hypothesis (from LLM
grounding or bandit prior finding), can load ONLY the relevant semgrep
rules into a targeted scan — 10-50 rules instead of 500. Faster, quieter.

No network, no dependencies beyond PyYAML (fallback to naive parser if
PyYAML missing).
"""
from __future__ import annotations

import functools
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("belief.bridges.semgrep_indexer")

_RULES_DIR = Path(__file__).parent.parent / "security_rules" / "semgrep"


def _yaml_load(text: str):
    """Lazy YAML loader. Prefers PyYAML, falls back to a minimal parser
    for the metadata fields we care about."""
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        return _naive_parse(text)


def _naive_parse(text: str) -> Dict[str, Any]:
    """Extract ONLY top-level rule ID + metadata.cwe + metadata.technology +
    languages + severity from a semgrep YAML. Enough for indexing.
    """
    # Look for "id:", "cwe:", "severity:", "languages:" at reasonable indentation.
    out = {"rules": []}
    current: Dict[str, Any] = {}
    for line in text.splitlines():
        line_strip = line.strip()
        m = re.match(r"^-?\s*id:\s*(.+)$", line_strip)
        if m:
            if current:
                out["rules"].append(current)
            current = {"id": m.group(1).strip().strip("\"'")}
            continue
        m = re.match(r"^cwe:\s*(.+)$", line_strip)
        if m:
            current.setdefault("metadata", {})["cwe"] = m.group(1).strip().strip("\"'")
            continue
        m = re.match(r"^severity:\s*(\S+)", line_strip)
        if m:
            current["severity"] = m.group(1).strip().strip("\"'")
            continue
        m = re.match(r"^languages:\s*\[(.+)\]", line_strip)
        if m:
            langs = [x.strip().strip("\"'") for x in m.group(1).split(",")]
            current["languages"] = langs
            continue
        m = re.match(r"^technology:\s*\[(.+)\]", line_strip)
        if m:
            techs = [x.strip().strip("\"'") for x in m.group(1).split(",")]
            current.setdefault("metadata", {})["technology"] = techs
            continue
    if current:
        out["rules"].append(current)
    return out


def _normalize_cwes(raw) -> List[str]:
    """CWE field can be a string, a list, or missing. Normalize to list of 'CWE-X'."""
    out: List[str] = []
    if not raw:
        return out
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        return out
    for item in items:
        if not isinstance(item, str):
            continue
        m = re.match(r"CWE-(\d+)", item)
        if m:
            out.append(f"CWE-{m.group(1)}")
    return out


def _normalize_langs(raw) -> List[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return []


class SemgrepRuleIndex:
    """In-memory index over bundled semgrep rules."""

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else _RULES_DIR
        self._by_id: Dict[str, Dict[str, Any]] = {}
        self._by_cwe: Dict[str, Set[str]] = defaultdict(set)
        self._by_lang: Dict[str, Set[str]] = defaultdict(set)
        self._by_tech: Dict[str, Set[str]] = defaultdict(set)
        self._by_path: Dict[str, Set[str]] = defaultdict(set)  # rule_id → source file
        self._indexed = False

    def build(self) -> None:
        if not self.rules_dir.exists():
            logger.warning(f"rules dir missing: {self.rules_dir}")
            return
        files = sorted(self.rules_dir.rglob("*.yaml")) + \
                sorted(self.rules_dir.rglob("*.yml"))
        for f in files:
            try:
                text = f.read_text(errors="replace")
                data = _yaml_load(text) or {}
            except Exception as e:
                logger.debug(f"skip {f}: {e}")
                continue
            for rule in (data.get("rules") or []):
                if not isinstance(rule, dict):
                    continue
                rid = rule.get("id")
                if not rid:
                    continue
                meta = rule.get("metadata") or {}
                cwes = _normalize_cwes(meta.get("cwe"))
                langs = _normalize_langs(rule.get("languages"))
                techs = meta.get("technology") or []
                if isinstance(techs, str):
                    techs = [techs]
                severity = rule.get("severity", "INFO")

                # Store
                self._by_id[rid] = {
                    "id": rid,
                    "cwes": cwes,
                    "languages": langs,
                    "technology": list(techs) if isinstance(techs, list) else [],
                    "severity": severity,
                    "source_file": str(f.relative_to(self.rules_dir)),
                }
                for c in cwes:
                    self._by_cwe[c].add(rid)
                for lang in langs:
                    self._by_lang[lang.lower()].add(rid)
                for t in (techs or []):
                    if isinstance(t, str):
                        self._by_tech[t.lower()].add(rid)
                self._by_path[str(f)].add(rid)

        self._indexed = True
        logger.info(
            f"indexed {len(self._by_id)} rules, "
            f"{len(self._by_cwe)} CWEs, {len(self._by_lang)} languages"
        )

    def ensure_built(self) -> None:
        if not self._indexed:
            self.build()

    # ── Query API ───────────────────────────────────────────────────────

    def rules_for_cwe(self, cwe: str) -> List[Dict[str, Any]]:
        self.ensure_built()
        cwe = cwe.upper()
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        return [self._by_id[r] for r in self._by_cwe.get(cwe, [])]

    def rules_for_language(self, lang: str) -> List[Dict[str, Any]]:
        self.ensure_built()
        return [self._by_id[r] for r in self._by_lang.get(lang.lower(), [])]

    def rules_for_tech(self, tech: str) -> List[Dict[str, Any]]:
        self.ensure_built()
        return [self._by_id[r] for r in self._by_tech.get(tech.lower(), [])]

    def all_cwes(self) -> List[str]:
        self.ensure_built()
        return sorted(self._by_cwe.keys())

    def stats(self) -> Dict[str, Any]:
        self.ensure_built()
        return {
            "total_rules": len(self._by_id),
            "total_cwes": len(self._by_cwe),
            "top_cwes": sorted(
                [(c, len(rs)) for c, rs in self._by_cwe.items()],
                key=lambda x: -x[1],
            )[:10],
            "top_langs": sorted(
                [(l, len(rs)) for l, rs in self._by_lang.items()],
                key=lambda x: -x[1],
            )[:10],
        }

    def files_for_rules(self, rule_ids: List[str]) -> List[str]:
        """Return distinct source YAML files containing the given rule IDs.
        Useful for running `semgrep --config <file1> --config <file2> ...`."""
        self.ensure_built()
        rule_ids_set = set(rule_ids)
        files: Set[str] = set()
        for f, rs in self._by_path.items():
            if rs & rule_ids_set:
                files.add(f)
        return sorted(files)


@functools.lru_cache(maxsize=1)
def default_index() -> SemgrepRuleIndex:
    """Singleton: build the index once, reuse forever in this process."""
    idx = SemgrepRuleIndex()
    idx.build()
    return idx


# Convenience top-level functions -------------------------------------------

def rules_for_cwe(cwe: str) -> List[Dict[str, Any]]:
    return default_index().rules_for_cwe(cwe)


def rules_for_language(lang: str) -> List[Dict[str, Any]]:
    return default_index().rules_for_language(lang)


def stats() -> Dict[str, Any]:
    return default_index().stats()


__all__ = [
    "SemgrepRuleIndex", "default_index",
    "rules_for_cwe", "rules_for_language", "stats",
]
