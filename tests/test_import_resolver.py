"""Import resolver migration coverage."""

from __future__ import annotations

from belief.import_resolver import ImportKind, ImportResolver, scan_imports


def test_import_resolver_classifies_imports_and_conditionals(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "app.py").write_text(
        """
import os
import requests as http
from pkg import helper
from .local import thing
try:
    import optional_dep
except ImportError:
    optional_dep = None
""",
        encoding="utf-8",
    )

    resolver = ImportResolver(str(tmp_path))
    edges = resolver.scan_directory()
    by_target = {edge.target: edge for edge in edges}

    assert by_target["os"].kind is ImportKind.STDLIB
    assert by_target["requests"].kind is ImportKind.THIRD_PARTY
    assert by_target["pkg"].kind is ImportKind.PROJECT
    assert by_target[".local"].kind is ImportKind.RELATIVE
    assert by_target["optional_dep"].is_conditional is True
    assert by_target["requests"].aliases == ("http",)


def test_import_resolver_uses_code_parser_default_exclusions(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "app.py").write_text("import json\n", encoding="utf-8")
    (tmp_path / "security_rules").mkdir()
    (tmp_path / "security_rules" / "rule.py").write_text("import unsafe_rule\n", encoding="utf-8")

    edges = scan_imports(str(tmp_path))

    assert {edge.target for edge in edges} == {"json"}


def test_import_resolver_allows_explicit_corpus_roots(tmp_path):
    (tmp_path / "target_flaskjwt").mkdir()
    (tmp_path / "target_flaskjwt" / "case.py").write_text("import json\n", encoding="utf-8")

    edges = scan_imports(str(tmp_path), corpus_roots=["target_flaskjwt"])

    assert len(edges) == 1
    assert edges[0].source_module == "target_flaskjwt.case"
    assert edges[0].target == "json"
