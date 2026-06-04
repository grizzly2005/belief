"""Security taxonomy regression tests."""

from __future__ import annotations

from belief.security_taxonomy import (
    find_sink,
    guarantee_expressions,
    is_ownership_guarantee,
    is_path_boundary_guarantee,
    sanitizer_names,
    sink_names,
    source_names,
)


def test_taxonomy_exposes_existing_source_and_sanitizer_names():
    assert "request.form" in source_names()
    assert "request.args" in source_names()
    assert "escape" in sanitizer_names("xss")
    assert "secure_filename" in sanitizer_names("path")


def test_find_sink_maps_deserialization_and_xss_to_cwe():
    pickle_sink = find_sink("pickle.loads")
    xss_sink = find_sink("markupsafe.Markup")

    assert pickle_sink is not None
    assert pickle_sink.category == "deserialization"
    assert pickle_sink.cwe == "CWE-502"
    assert xss_sink is not None
    assert xss_sink.category == "xss"
    assert xss_sink.cwe == "CWE-79"
    assert "pickle.loads" in sink_names("deserialization")


def test_guarantee_helpers_detect_path_and_ownership_patterns():
    assert is_path_boundary_guarantee("Storage.path enforces store boundary")
    assert is_ownership_guarantee("source_id=logged_in_source.db_record_id")
    assert "storage.path.enforces_store_boundary == true" in guarantee_expressions(
        "path_boundary"
    )
    assert "query.scoped_to_current_source == true" in guarantee_expressions(
        "ownership_scope"
    )
