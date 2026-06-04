"""Semgrep Rule Database for BELIEF.

Parses semgrep YAML rules and converts them into BELIEF-compatible
security patterns. Each semgrep rule encodes a belief:
"If this pattern is present, the developer believed it was safe, but it isn't."

Supports loading rules from the 2130-rule semgrep-rules corpus.
"""

import ast  # noqa: F401
import os  # noqa: F401
import re
from dataclasses import dataclass, field
from enum import Enum, auto  # noqa: F401
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Rule Models
# ---------------------------------------------------------------------------

class RuleSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class RuleCategory(Enum):
    SECURITY = "security"
    CORRECTNESS = "correctness"
    PERFORMANCE = "performance"
    BEST_PRACTICE = "best-practice"
    MAINTAINABILITY = "maintainability"


@dataclass
class CWEMapping:
    """CWE (Common Weakness Enumeration) mapping for a rule."""
    cwe_id: str
    description: str

    @classmethod
    def from_string(cls, s: str) -> "CWEMapping":
        # Parse "CWE-79: Improper Neutralization of Input" format
        match = re.match(r"CWE-(\d+):\s*(.*)", s)
        if match:
            return cls(f"CWE-{match.group(1)}", match.group(2).strip())
        return cls(s, "")


@dataclass
class SemgrepRule:
    """A parsed semgrep rule with BELIEF-relevant metadata."""
    rule_id: str
    message: str
    severity: RuleSeverity
    languages: list
    category: RuleCategory = RuleCategory.SECURITY
    cwe_mappings: list = field(default_factory=list)
    owasp_mappings: list = field(default_factory=list)
    technology: list = field(default_factory=list)
    confidence: str = "MEDIUM"
    likelihood: str = "MEDIUM"
    impact: str = "MEDIUM"
    subcategory: str = ""
    pattern: str = ""
    pattern_either: list = field(default_factory=list)
    pattern_not: list = field(default_factory=list)
    fix: str = ""
    references: list = field(default_factory=list)
    source_file: str = ""

    @property
    def belief_confidence(self) -> float:
        """Convert semgrep confidence to a float score."""
        mapping = {"HIGH": 0.95, "MEDIUM": 0.80, "LOW": 0.60}
        return mapping.get(self.confidence, 0.75)

    @property
    def risk_score(self) -> float:
        """Compute a risk score from likelihood × impact."""
        l_map = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
        i_map = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
        return l_map.get(self.likelihood, 0.5) * i_map.get(self.impact, 0.5)

    def to_belief_predicate(self) -> str:
        """Convert this rule to a BELIEF predicate string."""
        return f"code matches vulnerability pattern '{self.rule_id}': {self.message[:120]}"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "cwe": [{"id": c.cwe_id, "desc": c.description} for c in self.cwe_mappings],
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "languages": self.languages,
            "technology": self.technology,
        }


# ---------------------------------------------------------------------------
# YAML Parser (lightweight, no pyyaml dependency)
# ---------------------------------------------------------------------------

def _parse_yaml_simple(content: str) -> dict:
    """Minimal YAML-like parser for semgrep rule files.

    Handles the subset of YAML used by semgrep rules:
    - Key-value pairs
    - Lists (with -)
    - Nested mappings
    - Multi-line strings (>-)

    Not a full YAML parser — designed for semgrep rule format only.
    """
    result = {"rules": []}
    current_rule = {}
    current_key = None
    in_metadata = False
    metadata = {}
    metadata_key = None

    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        i += 1

        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Top-level rules: list
        if stripped == "rules:":
            continue

        # New rule start
        if stripped.startswith("- id:"):
            if current_rule:
                if metadata:
                    current_rule["metadata"] = dict(metadata)
                result["rules"].append(dict(current_rule))
            current_rule = {"id": stripped.split(":", 1)[1].strip()}
            current_key = None
            in_metadata = False
            metadata = {}
            metadata_key = None
            continue

        if not current_rule:
            continue

        # Handle metadata block
        if stripped == "metadata:":
            in_metadata = True
            metadata = {}
            metadata_key = None
            continue

        if in_metadata:
            if indent <= 4 and ":" in stripped and not stripped.startswith("-"):
                # Check if we left metadata
                key = stripped.split(":")[0].strip()
                if key in ("languages", "severity", "pattern", "pattern-either",
                           "pattern-not", "patterns", "fix", "message"):
                    in_metadata = False
                    # Fall through to normal processing
                else:
                    # Metadata key
                    parts = stripped.split(":", 1)
                    metadata_key = parts[0].strip()
                    val = parts[1].strip() if len(parts) > 1 else ""
                    if val:
                        metadata[metadata_key] = val
                    else:
                        metadata[metadata_key] = []
                    continue
            elif stripped.startswith("-") and metadata_key:
                val = stripped.lstrip("- ").strip().strip("'\"")
                if isinstance(metadata.get(metadata_key), list):
                    metadata[metadata_key].append(val)
                else:
                    metadata[metadata_key] = [val]
                continue
            else:
                # Sub-metadata item
                if metadata_key and stripped.startswith("-"):
                    val = stripped.lstrip("- ").strip().strip("'\"")
                    if isinstance(metadata.get(metadata_key), list):
                        metadata[metadata_key].append(val)
                    continue

        if in_metadata:
            continue

        # Normal key-value processing
        if ":" in stripped and not stripped.startswith("-") and not stripped.startswith("|") and not stripped.startswith(">"):
            parts = stripped.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip() if len(parts) > 1 else ""

            if key == "message" and val.startswith(">"):
                # Multi-line message
                msg_lines = []
                while i < len(lines):
                    next_line = lines[i]
                    next_stripped = next_line.strip()
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_stripped and next_indent <= indent:
                        break
                    if next_stripped:
                        msg_lines.append(next_stripped)
                    i += 1
                current_rule["message"] = " ".join(msg_lines)
                current_key = None
                continue

            if val and val not in (">-", "|", ">"):
                val = val.strip("'\"")
                current_rule[key] = val
                current_key = key
            elif not val or val in (">-", "|", ">"):
                current_rule[key] = []
                current_key = key
            continue

        # List items
        if stripped.startswith("- ") and current_key:
            val = stripped[2:].strip().strip("'\"")
            if isinstance(current_rule.get(current_key), list):
                current_rule[current_key].append(val)
            continue

        # Multi-line pattern continuation
        if current_key == "pattern" and isinstance(current_rule.get("pattern"), str):
            current_rule["pattern"] += "\n" + stripped

    # Don't forget the last rule
    if current_rule:
        if metadata:
            current_rule["metadata"] = dict(metadata)
        result["rules"].append(dict(current_rule))

    return result


def _parse_rule(raw: dict) -> Optional[SemgrepRule]:
    """Parse a raw YAML dict into a SemgrepRule."""
    rule_id = raw.get("id", "")
    if not rule_id:
        return None

    message = raw.get("message", "")
    severity_str = raw.get("severity", "WARNING").upper()
    try:
        severity = RuleSeverity(severity_str)
    except ValueError:
        severity = RuleSeverity.WARNING

    languages = raw.get("languages", [])
    if isinstance(languages, str):
        languages = [languages]

    metadata = raw.get("metadata", {})

    # CWE mappings
    cwe_list = metadata.get("cwe", [])
    if isinstance(cwe_list, str):
        cwe_list = [cwe_list]
    cwe_mappings = [CWEMapping.from_string(c) for c in cwe_list if c]

    # OWASP
    owasp = metadata.get("owasp", [])
    if isinstance(owasp, str):
        owasp = [owasp]

    # Technology
    tech = metadata.get("technology", [])
    if isinstance(tech, str):
        tech = [tech]

    # Category
    cat_str = metadata.get("category", "security")
    try:
        category = RuleCategory(cat_str)
    except ValueError:
        category = RuleCategory.SECURITY

    pattern = raw.get("pattern", "")
    if isinstance(pattern, list):
        pattern = "\n".join(pattern)

    pattern_either = raw.get("pattern-either", [])
    if isinstance(pattern_either, str):
        pattern_either = [pattern_either]

    return SemgrepRule(
        rule_id=rule_id,
        message=message,
        severity=severity,
        languages=languages,
        category=category,
        cwe_mappings=cwe_mappings,
        owasp_mappings=owasp,
        technology=tech,
        confidence=metadata.get("confidence", "MEDIUM"),
        likelihood=metadata.get("likelihood", "MEDIUM"),
        impact=metadata.get("impact", "MEDIUM"),
        subcategory=str(metadata.get("subcategory", "")),
        pattern=pattern,
        pattern_either=pattern_either,
        fix=raw.get("fix", ""),
        references=metadata.get("references", []),
    )


# ---------------------------------------------------------------------------
# Rule Database
# ---------------------------------------------------------------------------

class SemgrepRuleDB:
    """Database of semgrep rules loaded from YAML files.

    Can load from:
    - A directory of YAML files (e.g., cloned semgrep-rules repo)
    - Individual YAML files
    - Built-in rules (subset of critical security rules)
    """

    def __init__(self):
        self.rules: list = []
        self._by_id: dict = {}
        self._by_cwe: dict = {}
        self._by_language: dict = {}
        self._by_technology: dict = {}

    @property
    def count(self) -> int:
        return len(self.rules)

    def load_from_directory(self, directory: str, max_files: int = 5000) -> int:
        """Load rules from a directory tree of YAML files. Returns count loaded."""
        loaded = 0
        path = Path(directory)
        if not path.exists():
            return 0

        yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        for yf in yaml_files[:max_files]:
            try:
                content = yf.read_text(encoding="utf-8", errors="replace")
                if "rules:" not in content and "- id:" not in content:
                    continue
                parsed = _parse_yaml_simple(content)
                for raw_rule in parsed.get("rules", []):
                    rule = _parse_rule(raw_rule)
                    if rule:
                        rule.source_file = str(yf)
                        self._add_rule(rule)
                        loaded += 1
            except Exception:
                continue
        return loaded

    def load_from_file(self, filepath: str) -> int:
        """Load rules from a single YAML file. Returns count loaded."""
        loaded = 0
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
            parsed = _parse_yaml_simple(content)
            for raw_rule in parsed.get("rules", []):
                rule = _parse_rule(raw_rule)
                if rule:
                    rule.source_file = filepath
                    self._add_rule(rule)
                    loaded += 1
        except Exception:
            pass
        return loaded

    def load_builtin_rules(self) -> int:
        """Load built-in critical security rules (no files needed)."""
        builtins = self._get_builtin_rules()
        for rule in builtins:
            self._add_rule(rule)
        return len(builtins)

    def _add_rule(self, rule: SemgrepRule):
        self.rules.append(rule)
        self._by_id[rule.rule_id] = rule

        for cwe in rule.cwe_mappings:
            self._by_cwe.setdefault(cwe.cwe_id, []).append(rule)

        for lang in rule.languages:
            self._by_language.setdefault(lang, []).append(rule)

        for tech in rule.technology:
            self._by_technology.setdefault(tech, []).append(rule)

    def get_by_id(self, rule_id: str) -> Optional[SemgrepRule]:
        return self._by_id.get(rule_id)

    def get_by_cwe(self, cwe_id: str) -> list:
        return self._by_cwe.get(cwe_id, [])

    def get_by_language(self, language: str) -> list:
        return self._by_language.get(language, [])

    def get_by_technology(self, technology: str) -> list:
        return self._by_technology.get(technology, [])

    def get_security_rules(self) -> list:
        return [r for r in self.rules if r.category == RuleCategory.SECURITY]

    def get_high_risk_rules(self, threshold: float = 0.5) -> list:
        return [r for r in self.rules if r.risk_score >= threshold]

    def match_source(self, source_code: str, language: str = "python") -> list:
        """Simple pattern matching against source code.

        This is NOT a full semgrep engine — it does basic substring/regex
        matching against the rule patterns. For full semgrep analysis,
        use the actual semgrep CLI.

        Returns list of (rule, line_number, matched_text) tuples.
        """
        matches = []
        lang_rules = self.get_by_language(language)

        lines = source_code.split("\n")
        for rule in lang_rules:
            patterns = []
            if rule.pattern:
                patterns.append(rule.pattern)
            patterns.extend(rule.pattern_either)

            for pattern in patterns:
                # Extract the core identifiers from the pattern
                # Remove semgrep-specific syntax
                clean = pattern.replace("...", "").replace("$X", "").replace("$Y", "")
                clean = clean.replace("$Z", "").replace("$W", "").strip()

                if not clean or len(clean) < 4:
                    continue

                # Look for key function calls in the pattern
                call_matches = re.findall(r'(\w+(?:\.\w+)*)\s*\(', clean)
                for call in call_matches:
                    if len(call) < 3:
                        continue
                    for i, line in enumerate(lines):
                        if call in line:
                            matches.append((rule, i + 1, line.strip()))

        # Deduplicate by (rule_id, line)
        seen = set()
        unique = []
        for rule, line, text in matches:
            key = (rule.rule_id, line)
            if key not in seen:
                seen.add(key)
                unique.append((rule, line, text))

        return unique

    def to_beliefs(self, source_code: str, function_name: str = "",
                   language: str = "python") -> list:
        """Match rules against source and convert to belief dicts."""
        beliefs = []
        matches = self.match_source(source_code, language)

        for rule, line, text in matches:
            beliefs.append({
                "predicate": rule.to_belief_predicate(),
                "scope": f"{function_name}:L{line}" if function_name else f"L{line}",
                "justification": f"semgrep_rule:{rule.rule_id}",
                "confidence": rule.belief_confidence,
                "logic_type": "INFO_FLOW" if "injection" in rule.message.lower() else "FOL",
                "line_number": line,
                "matched_text": text,
                "cwe": [c.cwe_id for c in rule.cwe_mappings],
                "severity": rule.severity.value,
                "risk_score": rule.risk_score,
            })

        return beliefs

    def summary(self) -> dict:
        """Get a summary of loaded rules."""
        return {
            "total_rules": self.count,
            "by_severity": {
                s.value: len([r for r in self.rules if r.severity == s])
                for s in RuleSeverity
            },
            "by_category": {
                c.value: len([r for r in self.rules if r.category == c])
                for c in RuleCategory if any(r.category == c for r in self.rules)
            },
            "languages": sorted(self._by_language.keys()),
            "technologies": sorted(self._by_technology.keys()),
            "unique_cwes": len(self._by_cwe),
            "high_risk_count": len(self.get_high_risk_rules()),
        }

    @staticmethod
    def _get_builtin_rules() -> list:
        """Built-in critical security rules — no YAML files needed."""
        rules = []

        # SQL Injection
        rules.append(SemgrepRule(
            rule_id="belief-sqli-001",
            message="String formatting used in SQL query. Use parameterized queries.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-89", "SQL Injection")],
            confidence="HIGH", likelihood="HIGH", impact="HIGH",
            pattern='cursor.execute(f"...',
        ))

        # Command Injection
        rules.append(SemgrepRule(
            rule_id="belief-cmdi-001",
            message="User input passed to os.system/subprocess without sanitization.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-78", "OS Command Injection")],
            confidence="HIGH", likelihood="HIGH", impact="HIGH",
            pattern="os.system(...)",
        ))

        # Deserialization
        rules.append(SemgrepRule(
            rule_id="belief-deser-001",
            message="Unsafe deserialization with pickle/yaml.load. Use safe alternatives.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-502", "Deserialization of Untrusted Data")],
            confidence="HIGH", likelihood="MEDIUM", impact="HIGH",
            pattern="pickle.loads(...)",
        ))

        # Hardcoded secrets
        rules.append(SemgrepRule(
            rule_id="belief-secret-001",
            message="Hardcoded secret or password in source code.",
            severity=RuleSeverity.ERROR,
            languages=["python", "javascript", "go", "java"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-798", "Use of Hard-coded Credentials")],
            confidence="MEDIUM", likelihood="MEDIUM", impact="HIGH",
            pattern='password = "...',
        ))

        # XSS
        rules.append(SemgrepRule(
            rule_id="belief-xss-001",
            message="User input rendered without escaping. Potential XSS.",
            severity=RuleSeverity.ERROR,
            languages=["python", "javascript"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-79", "Cross-site Scripting")],
            confidence="MEDIUM", likelihood="MEDIUM", impact="MEDIUM",
            pattern="render_template_string(...)",
        ))

        # SSRF
        rules.append(SemgrepRule(
            rule_id="belief-ssrf-001",
            message="User-controlled URL in HTTP request. Potential SSRF.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-918", "Server-Side Request Forgery")],
            confidence="MEDIUM", likelihood="MEDIUM", impact="HIGH",
            pattern="requests.get(user_input)",
        ))

        # Weak crypto
        rules.append(SemgrepRule(
            rule_id="belief-crypto-001",
            message="Weak cryptographic algorithm (MD5/SHA1/DES/RC4).",
            severity=RuleSeverity.WARNING,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-327", "Use of Broken Cryptographic Algorithm")],
            confidence="HIGH", likelihood="MEDIUM", impact="MEDIUM",
            pattern="hashlib.md5(",
        ))

        # JWT none algorithm
        rules.append(SemgrepRule(
            rule_id="belief-jwt-001",
            message="JWT with 'none' algorithm allows token forgery.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-327", "Use of Broken Cryptographic Algorithm")],
            confidence="HIGH", likelihood="MEDIUM", impact="HIGH",
            pattern='jwt.encode(...,algorithm="none",...)',
        ))

        # Path traversal
        rules.append(SemgrepRule(
            rule_id="belief-path-001",
            message="User input in file path without sanitization. Potential path traversal.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-22", "Path Traversal")],
            confidence="MEDIUM", likelihood="MEDIUM", impact="HIGH",
            pattern="open(user_input)",
        ))

        # Eval injection
        rules.append(SemgrepRule(
            rule_id="belief-eval-001",
            message="Dynamic code execution with eval/exec. Potential code injection.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-94", "Code Injection")],
            confidence="HIGH", likelihood="HIGH", impact="HIGH",
            pattern="eval(...)",
        ))

        # XXE
        rules.append(SemgrepRule(
            rule_id="belief-xxe-001",
            message="XML parsing without disabling external entities. Potential XXE.",
            severity=RuleSeverity.ERROR,
            languages=["python", "java"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-611", "XML External Entity Reference")],
            confidence="MEDIUM", likelihood="MEDIUM", impact="HIGH",
            pattern="xml.etree.ElementTree.parse(",
        ))

        # LDAP injection
        rules.append(SemgrepRule(
            rule_id="belief-ldap-001",
            message="User input in LDAP query. Potential LDAP injection.",
            severity=RuleSeverity.ERROR,
            languages=["python"],
            category=RuleCategory.SECURITY,
            cwe_mappings=[CWEMapping("CWE-90", "LDAP Injection")],
            confidence="MEDIUM", likelihood="LOW", impact="HIGH",
            pattern="ldap.search_s(",
        ))

        return rules


# ---------------------------------------------------------------------------
# Integration with extracted semgrep-rules corpus (1364 real rules)
# ---------------------------------------------------------------------------

def load_extracted_rules() -> list[dict]:
    """Load the 1364 rules extracted from semgrep/semgrep-rules repo."""
    try:
        from .rules_data import _ALL_RULES
        return _ALL_RULES
    except ImportError:
        return []


def get_extracted_rules_for_cwe(cwe: str) -> list[dict]:
    """Get extracted rules matching a CWE."""
    try:
        from .rules_data import get_rules_for_cwe
        return get_rules_for_cwe(cwe)
    except ImportError:
        return []


def get_extracted_rules_for_language(language: str) -> list[dict]:
    """Get extracted rules for a specific language."""
    try:
        from .rules_data import get_rules_for_language
        return get_rules_for_language(language)
    except ImportError:
        return []


def get_extracted_rule_count() -> int:
    """Get total number of extracted rules."""
    try:
        from .rules_data import RULE_COUNT
        return RULE_COUNT
    except ImportError:
        return 0
