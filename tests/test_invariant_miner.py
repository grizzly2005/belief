"""Invariant mining against annotated real-world snippets."""

from __future__ import annotations

from pathlib import Path

import pytest

from belief.invariant_miner import InvariantMiner, classify_runtime_surface

SNIPPETS = Path(__file__).parent / "real_world_snippets"


def _snippet(name: str) -> str:
    return (SNIPPETS / name).read_text(encoding="utf-8")


def _expressions(name: str, file_path: str) -> set[str]:
    beliefs = InvariantMiner().extract(_snippet(name), file_path)
    return {belief.predicate.expression for belief in beliefs}


def test_securedrop_store_mines_path_boundary_and_generated_filename_guarantees():
    expressions = _expressions("securedrop_store.py", "securedrop/store.py")

    assert "path.is_normalized == true" in expressions
    assert "path.is_within_store == true" in expressions
    assert "storage.path.enforces_store_boundary == true" in expressions
    assert "storage.verify.enforces_store_boundary == true" in expressions
    assert "filename.matches_allowed_pattern == true" in expressions
    assert "filename.server_generated == true" in expressions


def test_securedrop_source_app_mines_auth_and_query_scoping_guarantees():
    expressions = _expressions("securedrop_source_app.py", "securedrop/source_app/main.py")

    assert "runtime.surface.runtime_web == true" in expressions
    assert "route.requires_login == true" in expressions
    assert "query.scoped_to_current_source == true" in expressions


def test_securedrop_journalist_app_mines_escape_and_admin_guarantees():
    expressions = _expressions(
        "securedrop_journalist_app.py",
        "securedrop/journalist_app/main.py",
    )

    assert "runtime.surface.runtime_web == true" in expressions
    assert "route.requires_admin == true" in expressions
    assert "html_output.user_values_escaped == true" in expressions
    assert "markup.has_unescaped_user_input == false" in expressions


def test_square_sdk_header_pattern_is_mined_as_context_not_secret():
    expressions = _expressions("square_sdk_headers.py", "square/client.py")

    assert "credential.value_is_header_name == true" in expressions
    assert "credential.value_is_runtime_supplied == true" in expressions


def test_runtime_surface_classification_is_stable():
    assert classify_runtime_surface("securedrop/source_app/main.py") == "runtime_web"
    assert classify_runtime_surface("securedrop/journalist_app/main.py") == "runtime_web"
    assert classify_runtime_surface("project/api/api2/views.py") == "runtime_web"
    assert classify_runtime_surface("project/alembic/versions/123_add_table.py") == "migration"
    assert classify_runtime_surface("tests/test_store.py") == "test"
    assert classify_runtime_surface("debian/install_files/rules.py") == "deployment_or_packaging"


def test_invariant_metadata_is_traceable_and_serializable():
    beliefs = InvariantMiner().extract(_snippet("securedrop_store.py"), "securedrop/store.py")
    path_belief = next(
        belief for belief in beliefs
        if belief.predicate.expression == "storage.path.enforces_store_boundary == true"
    )
    data = path_belief.to_dict()

    assert data["source_metadata"]["source"] == "invariant_miner"
    assert data["source_metadata"]["category"] == "guarantee"
    assert data["source_metadata"]["invariant_type"] == "path_safety"
    assert data["id"].startswith("inv_")


def test_commonpath_guarantee_keeps_call_line_and_concrete_value():
    source = """\
def read_file(user_path):
    if commonpath([ROOT, user_path]) != ROOT:
        raise ValueError("outside root")
    return open(user_path).read()
"""

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "path.is_within_store == true"
    )

    assert guard.scope.line_start == 2
    assert guard.predicate.variables == ("user_path",)
    assert guard.source_metadata["result_used"] is True


def test_inverted_commonpath_branch_is_not_recorded_as_an_enforced_guard():
    source = """\
def read_file(user_path):
    if commonpath([ROOT, user_path]) == ROOT:
        raise ValueError("inside root")
    return open(user_path).read()
"""

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "path.is_within_store == true"
    )

    assert guard.source_metadata["result_used"] is False


def test_commonpath_compared_to_an_unrelated_root_is_not_enforced():
    source = """\
def read_file(user_path):
    if commonpath([ROOT, user_path]) != OTHER_ROOT:
        raise ValueError("outside unrelated root")
    return open(user_path).read()
"""

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "path.is_within_store == true"
    )

    assert guard.source_metadata["result_used"] is False


@pytest.mark.parametrize(
    "body",
    [
        """\
    if feature_enabled:
        if commonpath([ROOT, user_path]) != ROOT:
            raise ValueError("outside root")
    return open(user_path).read()
""",
        """\
    try:
        if commonpath([ROOT, user_path]) != ROOT:
            raise ValueError("outside root")
    except ValueError:
        pass
    return open(user_path).read()
""",
    ],
)
def test_conditional_or_absorbable_commonpath_guard_is_not_dominating(body):
    source = "def read_file(user_path, feature_enabled=True):\n" + body

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "path.is_within_store == true"
    )

    assert guard.source_metadata["result_used"] is False


def test_ignored_secure_filename_records_unused_result_and_input_value():
    source = """\
def read_file(user_path):
    secure_filename(user_path)
    return open(user_path).read()
"""

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "filename.matches_allowed_pattern == true"
    )

    assert guard.scope.line_start == 2
    assert guard.predicate.variables == ("user_path",)
    assert guard.source_metadata["result_used"] is False


def test_assigned_sanitizer_names_the_output_value_not_the_original_input():
    source = """\
def read_file(user_path):
    safe_path = secure_filename(user_path)
    return open(safe_path).read()
"""

    guard = next(
        belief
        for belief in InvariantMiner().extract(source, "files.py")
        if belief.predicate.expression == "filename.matches_allowed_pattern == true"
    )

    assert guard.predicate.variables == ("safe_path",)
    assert guard.source_metadata["result_used"] is True
