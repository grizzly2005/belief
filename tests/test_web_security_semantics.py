"""General and metamorphic tests for route-reachable web semantics."""

from __future__ import annotations

import ast
from textwrap import dedent

import pytest

from belief.security_patterns import SecurityPatternExtractor
from belief.web_security_semantics import analyze_web_security_semantics


pytestmark = pytest.mark.security


def _issues(source: str):
    return analyze_web_security_semantics(ast.parse(dedent(source)))


def _path_source(action: str) -> str:
    return f"""
        from pathlib import Path

        ROOT = Path("/srv/files").resolve()

        def emit_file(location):
            return location.read_text()

        def load_document(untrusted_path):
{action}

        @router.get("/documents")
        def document_route():
            return load_document(request.args.get("document"))
    """


def _resource_source(action: str) -> str:
    return f"""
        def field_value(record, name):
            return getattr(record, name)

        def encode_record(record):
            return {{"id": record.document_id}}

        def mark_seen(record, account_user_id):
            record.last_seen_by = account_user_id

        def load_document(
            document_id,
            account_user_id,
            workspace_id,
        ):
            record = DOCUMENTS.get(document_id)
            if record is None:
                abort(404)
{action}

        @router.get("/documents/{{document_id}}")
        def document_route(document_id):
            return load_document(
                document_id,
                request.headers.get("X-User"),
                request.headers.get("X-Workspace"),
            )
    """


def test_route_reachable_path_wrapper_detects_real_sink():
    issues = _issues(_path_source(
        """
            candidate = (ROOT / untrusted_path).resolve()
            return emit_file(candidate)
        """
    ))

    assert len(issues) == 1
    assert issues[0].cwe == "CWE-22"
    assert issues[0].function_name == "load_document"
    assert issues[0].sink == "emit_file"


@pytest.mark.parametrize(
    "action",
    (
        """
            safe_name = Path(untrusted_path).name
            candidate = (ROOT / safe_name).resolve()
            if not candidate.is_relative_to(ROOT):
                abort(404)
            return emit_file(candidate)
        """,
        """
            decoy = (ROOT / untrusted_path).resolve()
            _ = str(decoy)
            safe_name = Path(untrusted_path).name
            candidate = (ROOT / safe_name).resolve()
            return emit_file(candidate)
        """,
        """
            candidate = external_policy.resolve_file(
                untrusted_path,
                ROOT,
            )
            return emit_file(candidate)
        """,
        """
            candidate = (ROOT / untrusted_path).resolve()
            if candidate.is_relative_to(ROOT):
                return emit_file(candidate)
            abort(404)
        """,
    ),
)
def test_path_sanitizer_decoy_and_external_policy_are_not_candidates(
    action,
):
    assert _issues(_path_source(action)) == ()


def test_path_guard_after_sink_does_not_retroactively_protect():
    issues = _issues(_path_source(
        """
            candidate = (ROOT / untrusted_path).resolve()
            content = emit_file(candidate)
            if not candidate.is_relative_to(ROOT):
                abort(404)
            return content
        """
    ))

    assert len(issues) == 1
    assert issues[0].cwe == "CWE-22"


def test_unreachable_internal_path_helper_is_not_promoted_to_web_input():
    source = """
        from pathlib import Path

        def write_report(output_dir):
            destination = Path(output_dir) / "report.json"
            destination.write_text("{}")
    """

    assert _issues(source) == ()


def test_recursive_wrapper_summary_converges_without_mutating_iteration():
    source = """
        def recursive_read(first_path, second_path):
            open(first_path)
            recursive_read(second_path, first_path)

        @router.get("/documents")
        def document_route(path):
            recursive_read(path, "fallback")
    """

    first = _issues(source)
    second = _issues(source)

    assert first == second
    assert any(issue.cwe == "CWE-22" for issue in first)


def test_security_extractor_does_not_flag_path_name_sanitizer_as_sink():
    source = _path_source(
        """
            safe_name = Path(untrusted_path).name
            candidate = (ROOT / safe_name).resolve()
            return emit_file(candidate)
        """
    )

    findings = SecurityPatternExtractor().extract(
        dedent(source),
        "application.py",
    )

    assert [
        belief
        for belief in findings
        if belief.cwe == "CWE-22"
    ] == []


@pytest.mark.parametrize(
    ("action", "expected_missing"),
    (
        (
            """
            if not account_user_id:
                abort(403)
            payload = encode_record(record)
            return payload
            """,
            {"resource bound to owner", "resource bound to tenant"},
        ),
        (
            """
            if field_value(record, "owner_id") != account_user_id:
                abort(403)
            payload = encode_record(record)
            return payload
            """,
            {"resource bound to tenant"},
        ),
        (
            """
            if field_value(record, "workspace_id") != workspace_id:
                abort(403)
            payload = encode_record(record)
            return payload
            """,
            {"resource bound to owner"},
        ),
        (
            """
            other = DOCUMENTS["fixed"]
            if field_value(other, "owner_id") != account_user_id:
                abort(403)
            payload = encode_record(record)
            return payload
            """,
            {"resource bound to owner", "resource bound to tenant"},
        ),
        (
            """
            mark_seen(record, account_user_id)
            if (
                field_value(record, "owner_id") != account_user_id
                or field_value(record, "workspace_id") != workspace_id
            ):
                abort(403)
            payload = encode_record(record)
            return payload
            """,
            {"resource bound to owner", "resource bound to tenant"},
        ),
    ),
)
def test_resource_binding_detects_missing_or_late_dimensions(
    action,
    expected_missing,
):
    issues = _issues(_resource_source(action))

    assert len(issues) == 1
    assert issues[0].cwe == "CWE-639"
    assert set(issues[0].missing_guarantees) == expected_missing


@pytest.mark.parametrize(
    "action",
    (
        """
            if (
                field_value(record, "owner_id") != account_user_id
                or field_value(record, "workspace_id") != workspace_id
            ):
                abort(403)
            payload = encode_record(record)
            return payload
        """,
        """
            decoy = record
            _ = encode_record(decoy)
            selected = next((
                candidate
                for candidate in DOCUMENTS.values()
                if field_value(candidate, "document_id") == document_id
                and field_value(candidate, "owner_id") == account_user_id
                and field_value(candidate, "workspace_id") == workspace_id
            ), None)
            if selected is None:
                abort(403)
            payload = encode_record(selected)
            return payload
        """,
        """
            if not policy.authorize(
                account_user_id,
                workspace_id,
                record,
            ):
                abort(403)
            payload = encode_record(record)
            return payload
        """,
        """
            if (
                field_value(record, "owner_id") == account_user_id
                and field_value(record, "workspace_id") == workspace_id
            ):
                payload = encode_record(record)
                return payload
            abort(403)
        """,
    ),
)
def test_complete_binding_decoy_and_external_policy_are_not_candidates(
    action,
):
    assert _issues(_resource_source(action)) == ()


def test_request_assigned_resource_identifier_is_tracked():
    source = """
        def encode_record(record):
            return {"id": record.document_id}

        @router.get("/documents")
        def document_route():
            document_id = request.args.get("document_id")
            account_user_id = request.headers.get("X-User")
            workspace_id = request.headers.get("X-Workspace")
            record = DOCUMENTS.get(document_id)
            payload = encode_record(record)
            return payload
    """

    issues = _issues(source)

    assert len(issues) == 1
    assert issues[0].cwe == "CWE-639"
    assert set(issues[0].missing_guarantees) == {
        "resource bound to owner",
        "resource bound to tenant",
    }


def test_security_pattern_projection_keeps_structured_missing_evidence():
    source = _resource_source(
        """
            if field_value(record, "owner_id") != account_user_id:
                abort(403)
            payload = encode_record(record)
            return payload
        """
    )

    findings = SecurityPatternExtractor().extract(
        dedent(source),
        "application.py",
    )
    projected = [
        belief
        for belief in findings
        if (belief.source_metadata or {}).get("detector")
        == "web_security_semantics_v1"
    ]

    assert len(projected) == 1
    assert projected[0].cwe == "CWE-639"
    assert projected[0].source_metadata["dataflow"][
        "missing_guarantees"
    ] == ["resource bound to tenant"]
