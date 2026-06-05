"""Minimal deterministic quality checks for BELIEF SFT JSONL datasets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


QUALITY_SCHEMA_VERSION = "belief.dataset_quality.v1"


@dataclass(frozen=True)
class DatasetQualityIssue:
    row_index: int
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_index": int(self.row_index),
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True)
class DatasetQualityResult:
    passed: bool
    score: int
    issues: tuple[DatasetQualityIssue, ...] = field(default_factory=tuple)
    schema_version: str = QUALITY_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "passed": bool(self.passed),
            "score": int(self.score),
            "issues": [issue.to_dict() for issue in self.issues],
        }


_SECRET_PATTERNS = {
    "bearer_token": re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}"),
    "api_key": re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*[^\s,;]{6,}"),
    "cookie": re.compile(r"(?i)\b(cookie|set-cookie)\s*[:=]\s*[^\n;]{6,}"),
    "password": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "long_hex": re.compile(r"\b[a-fA-F0-9]{40,}\b"),
}
_COT_RE = re.compile(r"(?i)(chain[- ]of[- ]thought|hidden reasoning|private reasoning|scratchpad|internal reasoning trace)")
_ACTIVE_EXPLOIT_RE = re.compile(
    r"(?i)(run this exploit|weaponized payload|reverse shell|exploit chain|autonomous exploitation|unrestricted exploitation)"
)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_REAL_TLDS = {
    "app",
    "biz",
    "co",
    "com",
    "dev",
    "fr",
    "io",
    "net",
    "org",
    "site",
}


def validate_sft_row(row: dict[str, Any], row_index: int = 0) -> list[DatasetQualityIssue]:
    issues: list[DatasetQualityIssue] = []
    if not isinstance(row, dict):
        return [_issue(row_index, "invalid_row", "SFT row must be a JSON object")]

    messages = row.get("messages")
    if not isinstance(messages, list) or not messages:
        issues.append(_issue(row_index, "missing_messages", "SFT row is missing messages"))
        messages = []

    roles = []
    text_parts = []
    for message in messages:
        if not isinstance(message, dict):
            issues.append(_issue(row_index, "invalid_message", "message must be a JSON object"))
            continue
        role = str(message.get("role") or "")
        content = str(message.get("content") or "")
        roles.append(role)
        text_parts.append(content)
        if not role:
            issues.append(_issue(row_index, "empty_role", "message role is empty"))
        if not content.strip():
            issues.append(_issue(row_index, "empty_message", f"{role or 'unknown'} message content is empty"))

    for required in ("system", "user", "assistant"):
        if required not in roles:
            issues.append(_issue(row_index, f"missing_{required}_role", f"SFT row is missing {required} role"))

    metadata = row.get("metadata")
    if not isinstance(metadata, dict):
        issues.append(_issue(row_index, "missing_metadata", "SFT row is missing metadata"))
        metadata = {}
    if not metadata.get("schema_version"):
        issues.append(_issue(row_index, "missing_schema_version", "metadata.schema_version is required"))
    if not metadata.get("case_id"):
        issues.append(_issue(row_index, "missing_case_id", "metadata.case_id is required"))

    text = "\n".join(text_parts)
    if _COT_RE.search(text):
        issues.append(_issue(row_index, "chain_of_thought_leakage", "dataset row contains private reasoning wording"))
    if _ACTIVE_EXPLOIT_RE.search(text):
        issues.append(_issue(row_index, "active_exploit_instruction", "dataset row contains active exploit wording"))
    for code, pattern in _SECRET_PATTERNS.items():
        if pattern.search(text):
            issues.append(_issue(row_index, f"secret_{code}", f"dataset row contains {code.replace('_', ' ')} pattern"))
    for domain in sorted(set(match.group(0).lower() for match in _DOMAIN_RE.finditer(text))):
        if not _allowed_domain(domain):
            issues.append(_issue(row_index, "real_looking_domain", f"real-looking domain is not allowed: {domain}"))

    encoded_size = len(json.dumps(row, sort_keys=True, default=str))
    if encoded_size > 20000:
        issues.append(_issue(row_index, "excessive_row_size", "dataset row is too large for minimal SFT export"))
    return issues


def validate_sft_jsonl(path: Path | str) -> DatasetQualityResult:
    input_path = Path(path)
    issues: list[DatasetQualityIssue] = []
    if not input_path.exists():
        raise ValueError(f"dataset file does not exist: {input_path}")
    lines = input_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        issues.append(_issue(0, "empty_dataset", "dataset JSONL is empty"))
    for row_index, line in enumerate(lines, start=1):
        if not line.strip():
            issues.append(_issue(row_index, "blank_line", "dataset JSONL contains a blank line"))
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSONL at {input_path}:{row_index}: {exc}") from exc
        issues.extend(validate_sft_row(row, row_index=row_index))
    score = max(0, 100 - len(issues) * 10)
    return DatasetQualityResult(
        passed=not issues,
        score=score,
        issues=tuple(issues),
    )


def _allowed_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1]
    if tld not in _REAL_TLDS and not domain.endswith((".test", ".local", ".example")):
        return True
    return (
        domain == "localhost"
        or domain.startswith("example.")
        or domain.endswith(".example")
        or domain.endswith(".test")
        or domain.endswith(".local")
    )


def _issue(row_index: int, code: str, message: str, severity: str = "error") -> DatasetQualityIssue:
    return DatasetQualityIssue(
        row_index=row_index,
        severity=severity,
        code=code,
        message=message,
    )


__all__ = [
    "DatasetQualityIssue",
    "DatasetQualityResult",
    "QUALITY_SCHEMA_VERSION",
    "validate_sft_jsonl",
    "validate_sft_row",
]
