"""MVP audit-case triage tests using real-world snippets."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.audit_case import (
    AuditCase,
    attach_route_context_to_audit_cases,
    build_audit_cases,
)
from belief.dataflow import analyze_source_dataflow, attach_dataflow_to_findings
from belief.hypothesis_engine import attach_hypotheses_to_findings
from belief.invariant_miner import InvariantMiner
from belief.models import Finding
from belief.routes import extract_routes_from_files
from belief.security_patterns import SecurityPatternExtractor

pytestmark = pytest.mark.security

SNIPPETS = Path(__file__).parent / "real_world_snippets"


def _snippet(name: str) -> str:
    return (SNIPPETS / name).read_text(encoding="utf-8")


def _security_findings(name: str, file_path: str) -> list[Finding]:
    beliefs = SecurityPatternExtractor().extract(_snippet(name), file_path)
    return [Finding.from_belief(belief, source="security") for belief in beliefs]


def _guarantees(*items: tuple[str, str]):
    miner = InvariantMiner()
    beliefs = []
    for name, path in items:
        beliefs.extend(miner.extract(_snippet(name), path))
    return beliefs


def _summary(name: str, file_path: str):
    return analyze_source_dataflow(_snippet(name), file_path)


def _cases(
    findings: list[Finding],
    guarantees,
    summaries,
) -> list[AuditCase]:
    attach_dataflow_to_findings(findings, summaries, show_dataflow=True)
    attach_hypotheses_to_findings(
        findings,
        guarantees,
        show_proofs=True,
        dataflow_summaries=summaries,
        show_dataflow=True,
    )
    return build_audit_cases(findings, dataflow_summaries=summaries)


def _route_case(file_path: str, line: int) -> AuditCase:
    return build_audit_cases([
        Finding(
            source="manual",
            rule_id="PATH_TRAVERSAL",
            title="Path traversal candidate",
            description="open(path)",
            file=file_path,
            line=line,
            cwe="CWE-22",
            severity="high",
            confidence=0.9,
            evidence="open(path)",
        )
    ])[0]


def test_audit_case_serialization_is_deterministic():
    finding = Finding(
        source="manual",
        rule_id="CWE-502",
        title="Unsafe pickle deserialization",
        description="pickle.loads on untrusted bytes",
        file="flask_caching/backends/filesystemcache.py",
        line=7,
        cwe="CWE-502",
        severity="critical",
        confidence=0.95,
        evidence="pickle.loads(payload)",
        metadata={
            "hypothesis": {
                "hypothesis_type": "unsafe_deserialization_possible",
                "status": "strengthened",
                "missing_guarantees": ["trusted deserialization boundary or safe loader proof"],
                "human_next_steps": [],
                "z3": {"checked": False, "status": "not_applicable"},
            }
        },
    )

    first = build_audit_cases([finding])
    second = build_audit_cases([finding])

    assert [case.to_dict() for case in first] == [case.to_dict() for case in second]
    assert json.dumps([case.to_dict() for case in first], sort_keys=True) == json.dumps(
        [case.to_dict() for case in second],
        sort_keys=True,
    )


def test_route_context_attaches_flask_route_to_audit_case(tmp_path):
    source = """
from flask import Flask
from auth import login_required
app = Flask(__name__)

@app.post("/delete")
@login_required
def delete():
    path = request.form["path"]
    return open(path).read()
"""
    app = tmp_path / "app.py"
    app.write_text(source, encoding="utf-8")
    routes = extract_routes_from_files([app], target_root=tmp_path)
    cases = attach_route_context_to_audit_cases(
        [_route_case("app.py", 9)],
        routes,
        source_contexts={"app.py": source},
    )

    context = cases[0].to_dict()["route_context"]
    assert context["framework"] == "flask"
    assert context["route"] == "/delete"
    assert context["methods"] == ["POST"]
    assert context["handler"] == "delete"
    assert context["auth_guarantees"] == ["route.requires_login == true"]
    assert context["confidence"] == 0.9


def test_route_context_attaches_fastapi_dependency_guard(tmp_path):
    source = """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/items/{item_id}")
async def get_item(item_id: str, user = Depends(require_user)):
    return open(item_id).read()
"""
    api = tmp_path / "api.py"
    api.write_text(source, encoding="utf-8")
    routes = extract_routes_from_files([api], target_root=tmp_path)
    cases = attach_route_context_to_audit_cases(
        [_route_case("api.py", 7)],
        routes,
        source_contexts={"api.py": source},
    )

    context = cases[0].to_dict()["route_context"]
    assert context["framework"] == "fastapi"
    assert context["route"] == "/items/{item_id}"
    assert context["params"] == ["item_id"]
    assert "route.has_dependency_guard == true" in context["auth_guarantees"]


def test_route_context_attaches_django_unique_file_fallback(tmp_path):
    source = """
from django.urls import path
from . import views

urlpatterns = [
    path("items/<int:item_id>/", views.detail, name="detail"),
]
"""
    urls = tmp_path / "urls.py"
    urls.write_text(source, encoding="utf-8")
    routes = extract_routes_from_files([urls], target_root=tmp_path)
    cases = attach_route_context_to_audit_cases(
        [_route_case("urls.py", 6)],
        routes,
        source_contexts={"urls.py": source},
    )

    context = cases[0].to_dict()["route_context"]
    assert context["framework"] == "django"
    assert context["route"] == "items/<int:item_id>/"
    assert context["handler"] == "views.detail"
    assert context["confidence"] == 0.55


def test_route_context_does_not_attach_on_ambiguous_mismatch(tmp_path):
    source = """
@app.get("/a")
def a():
    return "a"

@app.get("/b")
def b():
    return "b"

def helper():
    return open("x").read()
"""
    app = tmp_path / "app.py"
    app.write_text(source, encoding="utf-8")
    routes = extract_routes_from_files([app], target_root=tmp_path)
    cases = attach_route_context_to_audit_cases(
        [_route_case("app.py", 11)],
        routes,
        source_contexts={"app.py": source},
    )

    assert "route_context" not in cases[0].to_dict()


def test_flask_caching_pickle_becomes_high_priority_audit_case():
    path = "flask_caching/backends/filesystemcache.py"
    findings = [
        finding for finding in _security_findings("flask_caching_pickle_backend.py", path)
        if finding.cwe == "CWE-502"
    ]
    assert findings
    summaries = {path: _summary("flask_caching_pickle_backend.py", path)}
    cases = _cases(
        findings,
        _guarantees(("flask_caching_pickle_backend.py", path)),
        summaries,
    )

    case = next(case for case in cases if case.case_type == "unsafe_deserialization_possible")
    assert case.status == "actionable"
    assert case.review_priority == "critical"
    assert case.source == "cache_file.read()"
    assert "deserialization.input_trusted" in case.missing_guarantees


def test_securedrop_reply_path_is_protected_not_actionable():
    path = "securedrop/source_app/main.py"
    findings = [
        finding for finding in _security_findings("securedrop_source_app.py", path)
        if finding.cwe == "CWE-22"
    ]
    assert findings
    summaries = {path: _summary("securedrop_source_app.py", path)}
    cases = _cases(
        findings,
        _guarantees(
            ("securedrop_store.py", "securedrop/store.py"),
            ("securedrop_source_app.py", path),
        ),
        summaries,
    )

    path_cases = [case for case in cases if case.case_type == "path_traversal_possible"]
    assert path_cases
    assert {case.status for case in path_cases} <= {"protected", "false_positive_likely"}
    assert all(case.review_priority in {"low", "info"} for case in path_cases)
    assert any("storage.path.enforces_store_boundary == true" in case.guarantees for case in path_cases)


def test_securedrop_delete_reply_idor_bola_has_source_scope_guarantee():
    path = "securedrop/source_app/main.py"
    summary = _summary("securedrop_source_app.py", path)
    cases = build_audit_cases([], dataflow_summaries={path: summary})

    case = next(case for case in cases if case.case_type == "idor_bola_possible")
    assert case.status == "protected"
    assert case.review_priority == "low"
    assert case.source == 'request.form["reply_filename"]'
    assert "filter_by" in case.sink
    assert case.guarantees == ("query.scoped_to_current_source == true",)


def test_markup_escaped_becomes_protected_audit_case():
    path = "securedrop/journalist_app/main.py"
    findings = [
        finding for finding in _security_findings("securedrop_journalist_app.py", path)
        if finding.cwe == "CWE-79"
    ]
    assert findings
    summaries = {path: _summary("securedrop_journalist_app.py", path)}
    cases = _cases(
        findings,
        _guarantees(("securedrop_journalist_app.py", path)),
        summaries,
    )

    case = next(case for case in cases if case.case_type == "xss_possible")
    assert case.status == "protected"
    assert case.review_priority in {"low", "info"}
    assert "escape(display_name)" in case.sanitizers


def test_square_authorization_header_pattern_is_not_high_actionable():
    snippet = _snippet("square_sdk_headers.py")
    finding = Finding(
        source="manual-real-snippet",
        rule_id="CWE-798",
        title="Hardcoded credential candidate",
        description="Square SDK Authorization header pattern looked like a credential.",
        file="square/client.py",
        line=4,
        cwe="CWE-798",
        severity="high",
        confidence=0.88,
        evidence=snippet,
    )
    guarantees = _guarantees(("square_sdk_headers.py", "square/client.py"))
    attach_hypotheses_to_findings([finding], guarantees)

    cases = build_audit_cases([finding])
    assert len(cases) == 1
    case = cases[0]
    assert case.case_type == "hardcoded_secret_possible"
    assert case.status == "false_positive_likely"
    assert case.review_priority == "info"


def test_cli_audit_mode_help_json_and_interesting_filter(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text(_snippet("securedrop_source_app.py"), encoding="utf-8")
    (project / "store.py").write_text(_snippet("securedrop_store.py"), encoding="utf-8")
    first = tmp_path / "audit1.json"
    second = tmp_path / "audit2.json"
    project_root = Path(__file__).resolve().parents[1]

    help_result = subprocess.run(
        [sys.executable, "-m", "belief", "scan", "--help"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--audit-mode" in help_result.stdout
    assert "--interesting-only" in help_result.stdout

    base_cmd = [
        sys.executable,
        "-m",
        "belief",
        "scan",
        str(project),
        "--audit-mode",
        "--show-proofs",
        "--show-dataflow",
        "--top",
        "20",
    ]
    result = subprocess.run(
        [*base_cmd, "--json-output", str(first)],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "Audit cases:" in result.stdout
    assert "Top audit cases:\n  (none after audit filter)" in result.stdout
    assert "[LOW] path_traversal_possible protected" not in result.stdout

    repeat = subprocess.run(
        [*base_cmd, "--json-output", str(second)],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert repeat.returncode == 0, repeat.stderr
    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")

    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "belief.audit.v1"
    assert payload["filters"]["audit_mode"] is True
    assert payload["audit_cases"]
    assert payload["dataflow"]["paths"]
    assert any(case["case_type"] == "idor_bola_possible" for case in payload["audit_cases"])
    assert payload["counts"]["audit_cases"]["protected"] >= 1
