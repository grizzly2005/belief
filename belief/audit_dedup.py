"""Deterministic deduplication and clustering for BELIEF audit cases."""

from __future__ import annotations

import hashlib
import re
from typing import Iterable

from .audit_case import AUDIT_CASE_STATUSES, REVIEW_PRIORITIES, AuditCase, sort_audit_cases


def audit_case_cluster_key(case: AuditCase) -> str:
    """Return a stable semantic cluster key for near-duplicate audit cases."""
    parts = [
        case.case_type,
        _norm_path(case.file),
        case.sink,
        case.source,
        case.rule_id or case.cwe,
        "|".join(_path_tail(case.dataflow_path)),
        "|".join(sorted(case.missing_guarantees)),
    ]
    normalized = "\x1f".join(_normalize(part) for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def deduplicate_audit_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    """Keep one representative per semantic cluster."""
    clusters = cluster_audit_cases(cases)
    return [cluster["representative"] for cluster in clusters]


def cluster_audit_cases(cases: Iterable[AuditCase]) -> list[dict]:
    """Group similar audit cases and return deterministic cluster records."""
    grouped: dict[str, list[AuditCase]] = {}
    for case in sort_audit_cases(cases):
        grouped.setdefault(audit_case_cluster_key(case), []).append(case)

    clusters = []
    for key, items in sorted(grouped.items()):
        sorted_items = sort_audit_cases(items)
        representative = sorted_items[0]
        clusters.append({
            "cluster_id": "cluster_" + key,
            "count": len(sorted_items),
            "key": key,
            "case_type": representative.case_type,
            "status": representative.status,
            "review_priority": representative.review_priority,
            "representative": representative,
            "case_ids": [case.case_id for case in sorted_items],
            "files": sorted({case.file for case in sorted_items}),
        })
    return sorted(
        clusters,
        key=lambda cluster: (
            _status_rank(cluster["representative"].status),
            _priority_rank(cluster["representative"].review_priority),
            cluster["representative"].file,
            cluster["representative"].line or 0,
            cluster["representative"].case_type,
            cluster["cluster_id"],
        ),
    )


def cluster_to_dict(cluster: dict) -> dict:
    representative = cluster["representative"]
    return {
        "cluster_id": cluster["cluster_id"],
        "count": cluster["count"],
        "case_type": cluster["case_type"],
        "status": cluster["status"],
        "review_priority": cluster["review_priority"],
        "representative_case_id": representative.case_id,
        "case_ids": list(cluster["case_ids"]),
        "files": list(cluster["files"]),
        "representative": representative.to_dict(),
    }


def _path_tail(path: tuple[str, ...], max_items: int = 3) -> tuple[str, ...]:
    return tuple(path[-max_items:])


def _norm_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower()


def _normalize(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _status_rank(status: str) -> int:
    order = {name: idx for idx, name in enumerate(AUDIT_CASE_STATUSES)}
    return order.get(status, 99)


def _priority_rank(priority: str) -> int:
    order = {name: idx for idx, name in enumerate(REVIEW_PRIORITIES)}
    return order.get(priority, 99)


__all__ = [
    "audit_case_cluster_key",
    "deduplicate_audit_cases",
    "cluster_audit_cases",
    "cluster_to_dict",
]
