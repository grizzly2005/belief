"""Regression coverage for structural path-operation triage."""

from __future__ import annotations

from textwrap import dedent

from belief.structural import StructuralExtractor


def _path_beliefs(source: str):
    beliefs = StructuralExtractor().extract(dedent(source), "case.py")
    return [
        belief
        for belief in beliefs
        if "PATH_TRAVERSAL_PATTERNS" in belief.predicate.expression
    ]


def test_structural_path_check_tracks_request_aliases():
    beliefs = _path_beliefs(
        """
        def download(request):
            requested_path = request.args.get("path")
            local_path = requested_path
            return open(local_path).read()
        """
    )

    assert len(beliefs) == 1
    assert "Externally controlled path" in beliefs[0].predicate.natural_language


def test_structural_path_check_tracks_explicit_user_input_parameter():
    beliefs = _path_beliefs(
        """
        from pathlib import Path

        def read(user_path):
            return Path(user_path).read_text()
        """
    )

    assert len(beliefs) == 1


def test_structural_path_check_ignores_generic_local_file_apis():
    beliefs = _path_beliefs(
        """
        def save_results(result, project_path):
            with open(project_path, "w") as stream:
                stream.write(result)
        """
    )

    assert beliefs == []
