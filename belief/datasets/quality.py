"""Strict deterministic quality checks for BELIEF SFT v2 JSONL datasets."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from belief.audit_case import AuditCase
from belief.json_contracts import (
    StrictJSONError,
    read_bounded_utf8,
    strict_json_dumps,
    strict_json_loads,
)

from .sft_contract import (
    SFT_ASSESSMENT_SOURCE,
    SFT_SCHEMA_VERSION,
    SFT_SYSTEM_MESSAGE,
    build_authority_safe_sft_row,
)

QUALITY_SCHEMA_VERSION = "belief.dataset_quality.v1"
SFT_MAX_DATASET_BYTES = 64 * 1024 * 1024
SFT_MAX_ROWS = 10_000
SFT_MAX_ROW_BYTES = 20_000

_EXPECTED_ROLES = ("system", "user", "assistant")
_TOP_LEVEL_FIELDS = {"messages", "metadata"}
_MESSAGE_FIELDS = {"role", "content"}
_METADATA_FIELDS = {
    "assessment_source",
    "authority_sha256",
    "case_id",
    "case_type",
    "ledger_snapshot_id",
    "proof_state",
    "schema_version",
    "source",
    "subject_sha256",
    "verified_proof_ids",
}
_USER_FIELDS = {"audit_case", "proof_authority"}
_ASSISTANT_FIELDS = {
    "missing_evidence",
    "negative_factors",
    "next_step",
    "positive_factors",
    "proof_state",
    "score",
    "validation_steps",
    "verdict",
    "verified_proof_ids",
}
_PROOF_STATES = {"signal_only", "unresolved", "quarantined"}
_VERDICTS = {
    "reportable_candidate",
    "needs_manual_validation",
    "weak_signal",
    "likely_false_positive",
    "protected_by_guard",
}
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_AUDIT_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


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
    "api_key": re.compile(
        r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*[^\s,;]{6,}"
    ),
    "cookie": re.compile(r"(?i)\b(cookie|set-cookie)\s*[:=]\s*[^\n;]{6,}"),
    "password": re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "long_hex": re.compile(r"\b[a-fA-F0-9]{40,}\b"),
}
_COT_RE = re.compile(
    r"(?i)(chain[- ]of[- ]thought|hidden reasoning|private reasoning|scratchpad|"
    r"internal reasoning trace)"
)
_ACTIVE_EXPLOIT_RE = re.compile(
    r"(?i)(run this exploit|weaponized payload|reverse shell|exploit chain|"
    r"autonomous exploitation|unrestricted exploitation)"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
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
    """Validate one v2 row, including its embedded canonical JSON payloads."""
    issues: list[DatasetQualityIssue] = []
    if not isinstance(row, dict):
        return [_issue(row_index, "invalid_row", "SFT row must be a JSON object")]
    _check_exact_fields(row, _TOP_LEVEL_FIELDS, row_index, "row", issues)

    messages = row.get("messages")
    parsed_payloads: dict[str, dict[str, Any]] = {}
    text_parts: list[str] = []
    if not isinstance(messages, list):
        issues.append(_issue(row_index, "missing_messages", "messages must be a list"))
        messages = []
    elif len(messages) != len(_EXPECTED_ROLES):
        issues.append(
            _issue(
                row_index,
                "invalid_message_count",
                "messages must contain exactly system, user, and assistant",
            )
        )
    for index, expected_role in enumerate(_EXPECTED_ROLES):
        if index >= len(messages):
            issues.append(
                _issue(
                    row_index,
                    f"missing_{expected_role}_role",
                    f"SFT row is missing {expected_role} role",
                )
            )
            continue
        message = messages[index]
        if not isinstance(message, dict):
            issues.append(_issue(row_index, "invalid_message", "message must be an object"))
            continue
        _check_exact_fields(message, _MESSAGE_FIELDS, row_index, "message", issues)
        role = message.get("role")
        content = message.get("content")
        if role != expected_role:
            issues.append(
                _issue(
                    row_index,
                    "invalid_role_order",
                    f"message {index} role must be {expected_role!r}",
                )
            )
        if not isinstance(content, str) or not content.strip():
            issues.append(
                _issue(
                    row_index,
                    "invalid_message_content",
                    f"{expected_role} content must be a non-empty string",
                )
            )
            continue
        text_parts.append(content)
        if expected_role in {"user", "assistant"} and len(content) > 10_000:
            issues.append(
                _issue(
                    row_index,
                    "excessive_message_content",
                    f"{expected_role} content exceeds 10000 characters",
                )
            )
        if expected_role == "system" and content != SFT_SYSTEM_MESSAGE:
            issues.append(
                _issue(
                    row_index,
                    "invalid_system_message",
                    "system content must match the BELIEF SFT v2 contract",
                )
            )
        if expected_role in {"user", "assistant"}:
            payload = _parse_embedded_payload(
                content,
                expected_role=expected_role,
                row_index=row_index,
                issues=issues,
            )
            if payload is not None:
                parsed_payloads[expected_role] = payload

    metadata = row.get("metadata")
    if not isinstance(metadata, dict):
        issues.append(_issue(row_index, "missing_metadata", "metadata must be an object"))
        metadata = {}
    else:
        _check_exact_fields(metadata, _METADATA_FIELDS, row_index, "metadata", issues)
    _validate_metadata(metadata, row_index, issues)
    if user_payload := parsed_payloads.get("user"):
        _validate_user_payload(user_payload, row_index, issues)
        audit_case = user_payload.get("audit_case")
        if isinstance(audit_case, dict) and (
            audit_case.get("case_id") != metadata.get("case_id")
            or audit_case.get("case_type") != metadata.get("case_type")
        ):
            issues.append(
                _issue(
                    row_index,
                    "case_identity_mismatch",
                    "user and metadata case identity values differ",
                )
            )
    if assistant_payload := parsed_payloads.get("assistant"):
        _validate_assistant_payload(assistant_payload, metadata, row_index, issues)
    _validate_recomputed_contract(
        row,
        parsed_payloads.get("user"),
        row_index,
        issues,
    )

    text = "\n".join(text_parts)
    if _COT_RE.search(text):
        issues.append(
            _issue(
                row_index,
                "chain_of_thought_leakage",
                "dataset row contains private reasoning wording",
            )
        )
    if _ACTIVE_EXPLOIT_RE.search(text):
        issues.append(
            _issue(
                row_index,
                "active_exploit_instruction",
                "dataset row contains active exploit wording",
            )
        )
    for code, pattern in _SECRET_PATTERNS.items():
        if pattern.search(text):
            issues.append(
                _issue(
                    row_index,
                    f"secret_{code}",
                    f"dataset row contains {code.replace('_', ' ')} pattern",
                )
            )
    for domain in sorted(set(match.group(0).lower() for match in _DOMAIN_RE.finditer(text))):
        if not _allowed_domain(domain):
            issues.append(
                _issue(
                    row_index,
                    "real_looking_domain",
                    f"real-looking domain is not allowed: {domain}",
                )
            )

    try:
        encoded_size = len(
            strict_json_dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    except (StrictJSONError, TypeError, ValueError):
        issues.append(_issue(row_index, "non_json_value", "SFT row contains a non-JSON value"))
    else:
        if encoded_size > SFT_MAX_ROW_BYTES:
            issues.append(
                _issue(
                    row_index,
                    "excessive_row_size",
                    f"dataset row exceeds {SFT_MAX_ROW_BYTES} bytes",
                )
            )
    return issues


def validate_sft_jsonl(path: Path | str) -> DatasetQualityResult:
    """Validate a bounded SFT v2 JSONL file with strict JSON decoding."""
    input_path = Path(path)
    text = read_bounded_utf8(input_path, max_bytes=SFT_MAX_DATASET_BYTES)
    lines = text.splitlines()
    issues: list[DatasetQualityIssue] = []
    if not lines:
        issues.append(_issue(0, "empty_dataset", "dataset JSONL is empty"))
    if len(lines) > SFT_MAX_ROWS:
        issues.append(
            _issue(
                0,
                "excessive_row_count",
                f"dataset exceeds {SFT_MAX_ROWS} rows",
            )
        )
    for row_index, line in enumerate(lines[: SFT_MAX_ROWS + 1], start=1):
        if not line.strip():
            issues.append(_issue(row_index, "blank_line", "dataset JSONL contains a blank line"))
            continue
        if len(line.encode("utf-8")) > SFT_MAX_ROW_BYTES:
            issues.append(
                _issue(
                    row_index,
                    "excessive_row_size",
                    f"dataset row exceeds {SFT_MAX_ROW_BYTES} bytes",
                )
            )
            continue
        try:
            row = strict_json_loads(line)
        except StrictJSONError as exc:
            raise ValueError(f"invalid JSONL at {input_path}:{row_index}: {exc}") from exc
        issues.extend(validate_sft_row(row, row_index=row_index))
    score = max(0, 100 - len(issues) * 10)
    return DatasetQualityResult(
        passed=not issues,
        score=score,
        issues=tuple(issues),
    )


def _parse_embedded_payload(
    content: str,
    *,
    expected_role: str,
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> dict[str, Any] | None:
    try:
        payload = strict_json_loads(content)
    except StrictJSONError:
        issues.append(
            _issue(
                row_index,
                f"invalid_{expected_role}_json",
                f"{expected_role} content must be strict JSON",
            )
        )
        return None
    if not isinstance(payload, dict):
        issues.append(
            _issue(
                row_index,
                f"invalid_{expected_role}_payload",
                f"{expected_role} content must encode a JSON object",
            )
        )
        return None
    expected_fields = _USER_FIELDS if expected_role == "user" else _ASSISTANT_FIELDS
    _check_exact_fields(
        payload,
        expected_fields,
        row_index,
        f"{expected_role} payload",
        issues,
    )
    return payload


def _validate_user_payload(
    payload: dict[str, Any],
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> None:
    if payload.get("proof_authority") != "none":
        issues.append(
            _issue(
                row_index,
                "invalid_proof_authority",
                "user proof_authority must be none",
            )
        )
    audit_case = payload.get("audit_case")
    if not isinstance(audit_case, dict):
        issues.append(
            _issue(
                row_index,
                "invalid_audit_case",
                "user audit_case must be a JSON object",
            )
        )
        return
    try:
        AuditCase.from_dict(audit_case)
    except ValueError as exc:
        issues.append(
            _issue(
                row_index,
                "invalid_audit_case",
                f"user audit_case violates the strict contract: {exc}",
            )
        )


def _validate_assistant_payload(
    payload: dict[str, Any],
    metadata: dict[str, Any],
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> None:
    verdict = payload.get("verdict")
    proof_state = payload.get("proof_state")
    score = payload.get("score")
    if verdict not in _VERDICTS:
        issues.append(_issue(row_index, "invalid_verdict", "assistant verdict is invalid"))
    if proof_state not in _PROOF_STATES:
        issues.append(_issue(row_index, "invalid_proof_state", "assistant proof_state is invalid"))
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        issues.append(
            _issue(row_index, "invalid_score", "assistant score must be an integer from 0 to 100")
        )
    if not isinstance(payload.get("next_step"), str):
        issues.append(
            _issue(row_index, "invalid_next_step", "assistant next_step must be a string")
        )
    for field_name in (
        "missing_evidence",
        "negative_factors",
        "positive_factors",
        "validation_steps",
        "verified_proof_ids",
    ):
        _validate_string_list(payload.get(field_name), field_name, row_index, issues)
    if proof_state != metadata.get("proof_state"):
        issues.append(
            _issue(
                row_index,
                "proof_state_mismatch",
                "assistant and metadata proof_state values differ",
            )
        )
    if payload.get("verified_proof_ids") != metadata.get("verified_proof_ids"):
        issues.append(
            _issue(
                row_index,
                "verified_proof_ids_mismatch",
                "assistant and metadata verified_proof_ids differ",
            )
        )
    if verdict == "reportable_candidate":
        issues.append(
            _issue(
                row_index,
                "reportable_label_forbidden",
                "belief.sft.v2 cannot encode reportable_candidate",
            )
        )


def _validate_recomputed_contract(
    row: dict[str, Any],
    user_payload: dict[str, Any] | None,
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> None:
    if not isinstance(user_payload, dict):
        return
    audit_case = user_payload.get("audit_case")
    if user_payload.get("proof_authority") != "none" or not isinstance(audit_case, dict):
        return
    try:
        expected = build_authority_safe_sft_row(AuditCase.from_dict(audit_case))
    except (TypeError, ValueError):
        return
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        return
    if messages[1] != expected["messages"][1]:
        issues.append(
            _issue(
                row_index,
                "noncanonical_user_projection",
                "user content is not the canonical scored AuditCase projection",
            )
        )
    if messages[2] != expected["messages"][2]:
        issues.append(
            _issue(
                row_index,
                "recomputed_label_mismatch",
                "assistant target does not match recomputed reportability",
            )
        )
    if row.get("metadata") != expected["metadata"]:
        issues.append(
            _issue(
                row_index,
                "recomputed_metadata_mismatch",
                "metadata does not match the recomputed SFT contract",
            )
        )


def _validate_metadata(
    metadata: dict[str, Any],
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> None:
    schema_version = metadata.get("schema_version")
    if schema_version == "belief.sft.v1":
        issues.append(
            _issue(
                row_index,
                "legacy_schema_version",
                "belief.sft.v1 labels are not authority-safe",
            )
        )
    elif schema_version != SFT_SCHEMA_VERSION:
        issues.append(
            _issue(
                row_index,
                "invalid_schema_version",
                f"metadata.schema_version must be {SFT_SCHEMA_VERSION}",
            )
        )
    if metadata.get("source") != "belief":
        issues.append(_issue(row_index, "invalid_source", "metadata.source must be belief"))
    if metadata.get("assessment_source") != SFT_ASSESSMENT_SOURCE:
        issues.append(
            _issue(
                row_index,
                "invalid_assessment_source",
                "metadata.assessment_source must identify the recomputed reportability contract",
            )
        )
    for field_name in ("case_id", "case_type"):
        value = metadata.get(field_name)
        if (
            not isinstance(value, str)
            or _AUDIT_IDENTIFIER_RE.fullmatch(value) is None
        ):
            issues.append(
                _issue(
                    row_index,
                    f"invalid_{field_name}",
                    f"metadata.{field_name} must be a canonical identifier",
                )
            )
    if not _is_sha256(metadata.get("subject_sha256")):
        issues.append(
            _issue(
                row_index,
                "invalid_subject_sha256",
                "metadata.subject_sha256 must be lowercase SHA-256",
            )
        )
    proof_state = metadata.get("proof_state")
    if proof_state not in _PROOF_STATES:
        issues.append(_issue(row_index, "invalid_proof_state", "metadata.proof_state is invalid"))
    proof_ids = metadata.get("verified_proof_ids")
    _validate_string_list(proof_ids, "verified_proof_ids", row_index, issues)
    if proof_ids != []:
        issues.append(
            _issue(
                row_index,
                "invalid_verified_proof_id",
                "belief.sft.v2 verified_proof_ids must be empty",
            )
        )

    snapshot_id = metadata.get("ledger_snapshot_id")
    authority_sha256 = metadata.get("authority_sha256")
    if snapshot_id is not None or authority_sha256 is not None:
        issues.append(
            _issue(
                row_index,
                "invalid_snapshot_provenance",
                "belief.sft.v2 snapshot provenance must be null",
            )
        )


def _validate_string_list(
    value: Any,
    field_name: str,
    row_index: int,
    issues: list[DatasetQualityIssue],
) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        issues.append(
            _issue(
                row_index,
                "invalid_string_list",
                f"{field_name} must be a list of strings",
            )
        )


def _check_exact_fields(
    value: dict[str, Any],
    expected: set[str],
    row_index: int,
    location: str,
    issues: list[DatasetQualityIssue],
) -> None:
    missing = sorted(expected.difference(value))
    extra = sorted(set(value).difference(expected))
    if missing:
        issues.append(
            _issue(
                row_index,
                "missing_fields",
                f"{location} is missing fields: {', '.join(missing)}",
            )
        )
    if extra:
        issues.append(
            _issue(
                row_index,
                "unexpected_fields",
                f"{location} has unexpected fields: {', '.join(extra)}",
            )
        )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


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


def _issue(
    row_index: int,
    code: str,
    message: str,
    severity: str = "error",
) -> DatasetQualityIssue:
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
