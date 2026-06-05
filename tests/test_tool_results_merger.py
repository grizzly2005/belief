from belief.tool_results.mapper import external_finding_to_audit_case
from belief.tool_results.merger import audit_case_key, merge_audit_cases
from belief.tools.schemas import ExternalFinding


def _finding(tool: str, line: int, route: str = "/item"):
    return ExternalFinding(
        tool_id=tool,
        rule_id="python.sql.injection",
        title="SQL injection candidate",
        message="query uses formatted input",
        severity="high",
        file="app.py",
        line=line,
        cwe=["CWE-89"],
        route=route,
        evidence=[f"{tool} evidence"],
    )


def test_similar_semgrep_and_codeql_findings_merge():
    cases = [
        external_finding_to_audit_case(_finding("semgrep", 10)),
        external_finding_to_audit_case(_finding("codeql", 14)),
    ]

    merged = merge_audit_cases(cases)

    assert len(merged) == 1
    assert merged[0].metadata["source_tools"] == ["codeql", "semgrep"]
    assert merged[0].metadata["merged_signal_count"] == 2
    assert "semgrep evidence" in merged[0].metadata["tool_evidence"]
    assert "codeql evidence" in merged[0].metadata["tool_evidence"]


def test_different_routes_do_not_merge():
    cases = [
        external_finding_to_audit_case(_finding("semgrep", 10, "/a")),
        external_finding_to_audit_case(_finding("codeql", 10, "/b")),
    ]

    assert len(merge_audit_cases(cases)) == 2


def test_audit_case_key_buckets_nearby_lines():
    first = external_finding_to_audit_case(_finding("semgrep", 10))
    second = external_finding_to_audit_case(_finding("codeql", 14))

    assert audit_case_key(first) == audit_case_key(second)
