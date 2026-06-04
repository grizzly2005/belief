"""Invariant mining against annotated real-world snippets."""

from __future__ import annotations

from pathlib import Path

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
