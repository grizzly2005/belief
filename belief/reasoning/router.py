"""Router helpers for BELIEF's offline reasoning layer."""

from __future__ import annotations

import copy
from typing import Any, Protocol

from .models import ReasoningRequest, ReasoningResponse
from .offline import OfflineReasoningEngine


REASONING_REPORT_SCHEMA_VERSION = "belief.reasoning_report.v1"


class ReasoningEngine(Protocol):
    name: str

    def analyze(self, request: ReasoningRequest) -> ReasoningResponse:
        ...


class ReasoningRouter:
    def __init__(self, engines: list[ReasoningEngine] | None = None) -> None:
        engines = engines or [OfflineReasoningEngine()]
        self._engines = {engine.name: engine for engine in engines}

    def analyze(self, request: ReasoningRequest, engine: str = "offline") -> ReasoningResponse:
        selected = str(engine or "offline")
        if selected not in self._engines:
            if "offline" not in self._engines:
                raise ValueError(f"unknown reasoning engine: {selected}")
            selected = "offline"
        return self._engines[selected].analyze(request)


def audit_case_to_reasoning_request(case: dict[str, Any]) -> ReasoningRequest:
    if not isinstance(case, dict):
        raise ValueError("audit case must be a JSON object")
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    reportability = metadata.get("reportability") if isinstance(metadata.get("reportability"), dict) else {}
    return ReasoningRequest(
        case_id=str(case.get("case_id") or ""),
        title=str(metadata.get("title") or case.get("reason") or case.get("case_type") or ""),
        case_type=str(case.get("case_type") or ""),
        severity=str(case.get("severity") or ""),
        confidence=_safe_float(case.get("confidence"), default=0.0),
        evidence=tuple(_strings(case.get("dataflow_path"))),
        positive_factors=tuple(_strings(reportability.get("positive_factors"))),
        negative_factors=tuple(_strings(reportability.get("negative_factors"))),
        missing_evidence=tuple(_strings(reportability.get("missing_evidence") or case.get("missing_guarantees"))),
        validation_steps=tuple(_strings(reportability.get("validation_steps") or case.get("human_next_steps"))),
        validation_results=tuple(_validation_results(metadata)),
        feedback_events=tuple(_feedback_events(metadata)),
        metadata=metadata,
    )


def reason_audit_report(report: dict[str, Any], engine: str = "offline") -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("audit report must be a JSON object")
    audit_cases = report.get("audit_cases")
    if not isinstance(audit_cases, list):
        raise ValueError("audit report is missing audit_cases list")

    router = ReasoningRouter()
    reasoned_cases = []
    responses = []
    for case in sorted((item for item in audit_cases if isinstance(item, dict)), key=lambda item: str(item.get("case_id") or "")):
        request = audit_case_to_reasoning_request(case)
        response = router.analyze(request, engine=engine)
        response_payload = response.to_dict()
        enriched = copy.deepcopy(case)
        metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), dict) else {}
        metadata = dict(metadata)
        metadata["reasoning"] = response_payload
        enriched["metadata"] = metadata
        reasoned_cases.append(enriched)
        responses.append(response_payload)

    return {
        "schema_version": REASONING_REPORT_SCHEMA_VERSION,
        "engine": engine,
        "counts": {
            "audit_cases": len(audit_cases),
            "responses": len(responses),
        },
        "reasoning": responses,
        "audit_cases": reasoned_cases,
    }


def _validation_results(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[Any] = []
    direct = metadata.get("validation_results")
    if isinstance(direct, list):
        values.extend(direct)
    external_raw = metadata.get("external_raw")
    if isinstance(external_raw, dict):
        nested = external_raw.get("validation_results")
        if isinstance(nested, list):
            values.extend(nested)
        pdx = external_raw.get("pdx")
        if isinstance(pdx, dict) and isinstance(pdx.get("validation_results"), list):
            values.extend(pdx["validation_results"])
    return [item for item in values if isinstance(item, dict)]


def _feedback_events(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    values = metadata.get("feedback_events")
    return [item for item in values] if isinstance(values, list) and all(isinstance(item, dict) for item in values) else []


def _strings(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    return [str(value)]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)


__all__ = [
    "REASONING_REPORT_SCHEMA_VERSION",
    "ReasoningEngine",
    "ReasoningRouter",
    "audit_case_to_reasoning_request",
    "reason_audit_report",
]
