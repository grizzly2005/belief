"""Authority-safe, deterministic SFT export for BELIEF audit reports."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable, Mapping
from itertools import islice
from pathlib import Path
from typing import Any

from belief.audit_case import AUDIT_SCHEMA_VERSION, AuditCase
from belief.json_contracts import load_json_file, strict_json_dumps
from belief.validation.ledger import VerifiedProofSnapshot

from .quality import validate_sft_row
from .sft_contract import (
    SFT_ASSESSMENT_SOURCE,
    SFT_SCHEMA_VERSION,
    build_authority_safe_sft_row,
)
SFT_MAX_AUDIT_CASES = 10_000
SFT_MAX_INPUT_BYTES = 64 * 1024 * 1024
SFT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
SFT_MAX_ROW_BYTES = 20_000

class SFTContractError(ValueError):
    """Raised when an audit cannot be converted into safe non-authoritative labels."""


def audit_cases_to_sft_rows(
    cases: Iterable[AuditCase],
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
) -> list[dict[str, Any]]:
    """Recompute non-authoritative SFT labels from typed audit cases."""
    _validate_snapshot(proof_snapshot)
    case_list = list(islice(iter(cases), SFT_MAX_AUDIT_CASES + 1))
    if not case_list:
        raise SFTContractError("SFT export requires at least one audit case")
    if len(case_list) > SFT_MAX_AUDIT_CASES:
        raise SFTContractError(f"SFT export exceeds the {SFT_MAX_AUDIT_CASES} audit case limit")
    if any(not isinstance(case, AuditCase) for case in case_list):
        raise SFTContractError("SFT export accepts only AuditCase instances")

    case_ids = [case.case_id for case in case_list]
    if len(case_ids) != len(set(case_ids)):
        raise SFTContractError("SFT export contains duplicate case_id values")

    rows: list[dict[str, Any]] = []
    for case in sorted(case_list, key=lambda item: item.case_id):
        try:
            row = build_authority_safe_sft_row(case)
        except (TypeError, ValueError) as exc:
            raise SFTContractError(
                f"cannot recompute reportability for case {case.case_id!r}: {exc}"
            ) from exc
        issues = validate_sft_row(row, row_index=len(rows) + 1)
        if issues:
            details = "; ".join(f"{issue.code}: {issue.message}" for issue in issues)
            raise SFTContractError(
                f"generated SFT row for case {case.case_id!r} failed quality checks: " + details
            )
        rows.append(row)
    return rows


def audit_report_to_sft_rows(
    report: Mapping[str, Any],
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
) -> list[dict[str, Any]]:
    """Strictly reconstruct an audit report and recompute all SFT labels."""
    if not isinstance(report, Mapping):
        raise SFTContractError("audit report must be a JSON object")
    if report.get("schema_version") != AUDIT_SCHEMA_VERSION:
        raise SFTContractError(f"audit report schema_version must be {AUDIT_SCHEMA_VERSION!r}")
    audit_cases = report.get("audit_cases")
    if not isinstance(audit_cases, list) or not audit_cases:
        raise SFTContractError("audit report audit_cases must be a non-empty list")
    if len(audit_cases) > SFT_MAX_AUDIT_CASES:
        raise SFTContractError(f"audit report exceeds the {SFT_MAX_AUDIT_CASES} audit case limit")

    cases: list[AuditCase] = []
    for index, raw_case in enumerate(audit_cases):
        if not isinstance(raw_case, dict):
            raise SFTContractError(f"audit_cases[{index}] must be a JSON object")
        try:
            cases.append(AuditCase.from_dict(raw_case))
        except ValueError as exc:
            raise SFTContractError(f"invalid audit_cases[{index}]: {exc}") from exc
    return audit_cases_to_sft_rows(cases, proof_snapshot=proof_snapshot)


def export_sft_dataset_from_audit_report(
    report_path: Path | str,
    output_path: Path | str,
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
    max_input_bytes: int = SFT_MAX_INPUT_BYTES,
) -> list[dict[str, Any]]:
    """Validate completely, then atomically replace a deterministic SFT JSONL file."""
    report = load_json_file(report_path, max_bytes=max_input_bytes)
    rows = audit_report_to_sft_rows(report, proof_snapshot=proof_snapshot)
    lines: list[str] = []
    total_bytes = 0
    for row in rows:
        line = strict_json_dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        encoded_size = len(line.encode("utf-8"))
        if encoded_size > SFT_MAX_ROW_BYTES:
            raise SFTContractError(f"generated SFT row exceeds {SFT_MAX_ROW_BYTES} bytes")
        total_bytes += encoded_size + 1
        if total_bytes > SFT_MAX_OUTPUT_BYTES:
            raise SFTContractError(f"generated SFT dataset exceeds {SFT_MAX_OUTPUT_BYTES} bytes")
        lines.append(line)

    content = ("\n".join(lines) + "\n").encode("utf-8")
    _atomic_write(Path(output_path), content)
    return rows


def _validate_snapshot(proof_snapshot: VerifiedProofSnapshot | None) -> None:
    if proof_snapshot is None:
        return
    raise SFTContractError(
        "belief.sft.v2 does not accept proof_snapshot; verified proof evidence "
        "requires a future message-visible dataset contract"
    )


def _atomic_write(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(destination.parent),
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
__all__ = [
    "SFT_ASSESSMENT_SOURCE",
    "SFT_SCHEMA_VERSION",
    "SFTContractError",
    "audit_cases_to_sft_rows",
    "audit_report_to_sft_rows",
    "export_sft_dataset_from_audit_report",
]
