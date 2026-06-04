"""Audit-case clustering and deduplication tests."""

from __future__ import annotations

from belief.audit_case import AuditCase
from belief.audit_dedup import (
    audit_case_cluster_key,
    cluster_audit_cases,
    cluster_to_dict,
    deduplicate_audit_cases,
)


def _case(
    case_id: str,
    *,
    file: str = "app/cache.py",
    source: str = "cache_file.read()",
    sink: str = "pickle.loads",
) -> AuditCase:
    return AuditCase(
        case_id=case_id,
        case_type="unsafe_deserialization_possible",
        status="actionable",
        review_priority="critical",
        confidence=0.9,
        severity="critical",
        file=file,
        line=10,
        rule_id="B301",
        cwe="CWE-502",
        source=source,
        sink=sink,
        dataflow_path=(source, "payload", sink),
        missing_guarantees=("deserialization.input_trusted == true",),
        reason="unsafe deserialization",
    )


def test_cluster_key_groups_equivalent_cases():
    first = _case("case_a")
    second = _case("case_b")

    assert audit_case_cluster_key(first) == audit_case_cluster_key(second)
    assert len(deduplicate_audit_cases([first, second])) == 1


def test_cluster_key_separates_distinct_files_or_sinks():
    cases = [
        _case("case_a"),
        _case("case_b", file="other/cache.py"),
        _case("case_c", sink="yaml.load"),
    ]

    clusters = cluster_audit_cases(cases)

    assert len(clusters) == 3
    assert [cluster["cluster_id"] for cluster in clusters] == [
        cluster["cluster_id"] for cluster in cluster_audit_cases(list(reversed(cases)))
    ]


def test_cluster_to_dict_is_serializable_shape():
    cluster = cluster_audit_cases([_case("case_a"), _case("case_b")])[0]
    data = cluster_to_dict(cluster)

    assert data["count"] == 2
    assert data["representative_case_id"] == "case_a"
    assert data["case_ids"] == ["case_a", "case_b"]
    assert data["representative"]["case_type"] == "unsafe_deserialization_possible"
