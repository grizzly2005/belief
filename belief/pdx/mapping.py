"""Map JSON-only PDX bundles into BELIEF normalized tool-result signals."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from belief.tools.schemas import AttackPath, ExternalFinding, NormalizedToolResult, RequestStep
from belief.validation.models import ValidationResult
from belief.validation.pdx import pdx_verdicts_to_validation_results

from .models import PDXBundle, PDXChain, PDXConflict, PDXDelta, PDXVerdict
from .redaction import redact_pdx_value


_DELTA_CWE_HINTS = {
    "AUTH_BYPASS": ("CWE-862", "CWE-863"),
    "INJECTION": ("CWE-94",),
    "MISCONFIG": ("CWE-16",),
    "CRYPTO_WEAK": ("CWE-327",),
    "LOGIC_FLAW": ("CWE-840",),
    "TIMING": ("CWE-208",),
    "DESERIAL": ("CWE-502",),
    "SSRF": ("CWE-918",),
    "SSTI": ("CWE-94",),
    "FILE_UPLOAD": ("CWE-434",),
    "RACE_COND": ("CWE-362",),
    "SMUGGLING": ("CWE-444",),
    "CVE_KNOWN": ("CWE-937",),
}


def pdx_bundle_to_normalized_tool_result(bundle: PDXBundle) -> NormalizedToolResult:
    """Convert a PDX bundle into BELIEF's passive normalized tool schema."""
    validations_by_delta = _validations_by_delta(bundle.verdicts)
    conflicts_by_delta = _conflicts_by_delta(bundle.conflicts)
    findings = [
        pdx_delta_to_external_finding(
            delta,
            validation_results=validations_by_delta.get(delta.id, []),
            conflicts=conflicts_by_delta.get(delta.id, []),
        )
        for delta in sorted(bundle.deltas, key=lambda item: item.id)
    ]
    attack_paths = [
        pdx_chain_to_attack_path(chain, bundle)
        for chain in sorted(bundle.chains, key=lambda item: item.chain_id)
    ]
    return NormalizedToolResult(
        tool_id="pdx",
        findings=findings,
        attack_paths=attack_paths,
        raw={
            "source_schema": bundle.schema_version,
            "pdx_meta": bundle.meta.to_dict(),
            "validation_results": [
                item.to_dict()
                for values in validations_by_delta.values()
                for item in values
            ],
            "conflicts": [item.to_dict() for item in sorted(bundle.conflicts, key=lambda item: (item.delta_ref, item.resolution))],
        },
    )


def pdx_delta_to_external_finding(
    delta: PDXDelta,
    *,
    validation_results: list[ValidationResult] | None = None,
    conflicts: list[PDXConflict] | None = None,
) -> ExternalFinding:
    """Convert one PDX delta into a conservative ExternalFinding."""
    validation_results = validation_results or []
    conflicts = conflicts or []
    severity = _severity_from_delta(delta)
    confidence = _confidence_from_delta(delta, validation_results)
    title = delta.description or f"PDX {delta.delta_type.lower().replace('_', ' ')} signal"
    evidence = list(delta.evidence)
    if delta.expected not in (None, ""):
        evidence.append(f"expected: {delta.expected}")
    if delta.observed not in (None, ""):
        evidence.append(f"observed: {delta.observed}")
    evidence.extend(
        f"validation:{result.outcome}:{result.reason}"
        for result in validation_results
        if result.reason
    )
    cwe = list(delta.cwe) or list(_DELTA_CWE_HINTS.get(delta.delta_type, ()))
    return ExternalFinding(
        tool_id="pdx",
        rule_id=f"PDX_{delta.delta_type}",
        title=title,
        message=delta.description or None,
        severity=severity,
        confidence=confidence,
        file=delta.file or None,
        line=delta.line,
        column=delta.column,
        cwe=cwe,
        route=delta.route or None,
        evidence=[str(item) for item in evidence if str(item)],
        raw={
            "pdx": {
                "delta": delta.to_dict(),
                "validation_results": [item.to_dict() for item in validation_results],
                "conflicts": [item.to_dict() for item in conflicts],
            }
        },
    )


def pdx_chain_to_attack_path(chain: PDXChain, bundle: PDXBundle) -> AttackPath:
    """Represent a passive PDX chain as a review workflow, not an exploit recipe."""
    deltas_by_id = {delta.id: delta for delta in bundle.deltas}
    steps = []
    for delta_ref in chain.delta_refs:
        delta = deltas_by_id.get(delta_ref)
        route = delta.route if delta else ""
        location = route or (delta.file if delta else "") or f"pdx://delta/{delta_ref}"
        steps.append(RequestStep(
            method="REVIEW",
            path=location,
            produces=[delta_ref],
            notes=(delta.description if delta else "PDX delta referenced by chain"),
        ))
    return AttackPath(
        source_tool="pdx",
        title=chain.description or f"PDX chain {chain.chain_id}",
        steps=steps,
        hypothesis=(
            chain.description
            or "PDX grouped related deltas into a passive validation chain."
        ),
        evidence_needed=[
            f"Review PDX delta {delta_ref} in authorized scope."
            for delta_ref in chain.delta_refs
        ],
        risk=_severity_from_score(max(chain.combined_severity, chain.combined_exploitability)),
    )


def normalized_tool_result_to_pdx_bundle(result: NormalizedToolResult) -> PDXBundle:
    """Best-effort JSON export from normalized BELIEF tool results back to PDX."""
    from .models import PDXBundle, PDXDelta, PDXMeta

    deltas = []
    for finding in sorted(result.findings, key=lambda item: (item.file or "", item.line or 0, item.rule_id or "", item.title)):
        deltas.append(PDXDelta(
            id="",
            spec_ref=finding.rule_id or "",
            delta_type=_delta_type_from_finding(finding),
            category="external_finding",
            description=finding.message or finding.title,
            expected="guarded or safe behavior",
            observed=finding.title,
            vector={
                "severity": _score_from_severity(finding.severity),
                "confidence": _score_from_confidence(finding.confidence),
            },
            file=finding.file or "",
            line=finding.line,
            column=finding.column,
            route=finding.route or "",
            evidence=tuple(finding.evidence),
            cwe=tuple(finding.cwe),
            raw={"source_tool": finding.tool_id},
        ))
    return PDXBundle(
        meta=PDXMeta(provenance_chain=(f"belief-normalized:{result.tool_id}",)),
        deltas=tuple(deltas),
    )


def _validations_by_delta(verdicts: tuple[PDXVerdict, ...]) -> dict[str, list[ValidationResult]]:
    by_delta: dict[str, list[ValidationResult]] = defaultdict(list)
    for result in pdx_verdicts_to_validation_results(verdicts):
        by_delta[result.subject_id].append(result)
    return {
        key: sorted(values, key=lambda item: (item.outcome, item.result_id))
        for key, values in sorted(by_delta.items())
    }


def _conflicts_by_delta(conflicts: tuple[PDXConflict, ...]) -> dict[str, list[PDXConflict]]:
    by_delta: dict[str, list[PDXConflict]] = defaultdict(list)
    for conflict in conflicts:
        by_delta[conflict.delta_ref].append(conflict)
    return {
        key: sorted(values, key=lambda item: (item.resolution, item.divergence_score))
        for key, values in sorted(by_delta.items())
    }


def _severity_from_delta(delta: PDXDelta) -> str:
    return _severity_from_score(delta.vector.get("severity", 0.0))


def _severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.45:
        return "medium"
    if score >= 0.2:
        return "low"
    return "info"


def _confidence_from_delta(delta: PDXDelta, validation_results: list[ValidationResult]) -> str:
    if any(
        result.outcome in {"bypassed", "validated_candidate", "enforced", "false_positive"}
        and (result.tested or result.human_validated)
        for result in validation_results
    ):
        return "high"
    score = delta.vector.get("confidence", 0.0)
    if score >= 0.4:
        return "medium"
    return "low"


def _delta_type_from_finding(finding: ExternalFinding) -> str:
    text = " ".join([
        finding.rule_id or "",
        finding.title or "",
        finding.message or "",
        " ".join(finding.cwe),
    ]).lower()
    if "ssrf" in text or "cwe-918" in text:
        return "SSRF"
    if "deserial" in text or "cwe-502" in text:
        return "DESERIAL"
    if "auth" in text or "access" in text or "cwe-862" in text or "cwe-863" in text:
        return "AUTH_BYPASS"
    if "inject" in text:
        return "INJECTION"
    return "UNKNOWN"


def _score_from_severity(value: str | None) -> float:
    return {
        "critical": 0.95,
        "high": 0.8,
        "medium": 0.55,
        "low": 0.3,
        "info": 0.1,
    }.get(str(value or "").lower(), 0.2)


def _score_from_confidence(value: str | None) -> float:
    return {
        "high": 0.85,
        "medium": 0.55,
        "low": 0.25,
    }.get(str(value or "").lower(), 0.5)


def redacted_mapping_payload(value: Any) -> Any:
    return redact_pdx_value(value)


__all__ = [
    "normalized_tool_result_to_pdx_bundle",
    "pdx_bundle_to_normalized_tool_result",
    "pdx_chain_to_attack_path",
    "pdx_delta_to_external_finding",
    "redacted_mapping_payload",
]
