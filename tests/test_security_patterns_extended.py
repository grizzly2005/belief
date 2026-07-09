"""Security pattern regressions beyond eval/exec."""

from __future__ import annotations

from textwrap import dedent

import pytest

from belief.security_patterns import SecurityPatternExtractor

pytestmark = pytest.mark.security


def _extract(source: str):
    return SecurityPatternExtractor().extract(dedent(source), "case.py")


def _by_cwe(source: str, cwe: str):
    return [belief for belief in _extract(source) if belief.cwe == cwe]


def test_detects_os_system_user_input_but_not_constant_command():
    vulnerable = _by_cwe(
        """
        import os

        def run(user_input):
            os.system(user_input)
        """,
        "CWE-78",
    )
    safe = _by_cwe(
        """
        import os

        def run(user_input):
            os.system("echo ok")
        """,
        "CWE-78",
    )

    assert len(vulnerable) == 1
    assert vulnerable[0].source_metadata["source"] == "security_patterns"
    assert safe == []


def test_detects_subprocess_shell_true_with_simple_tainted_alias():
    findings = _by_cwe(
        """
        import subprocess

        def run(user_input):
            cmd = user_input
            subprocess.run(cmd, shell=True)
        """,
        "CWE-78",
    )

    assert len(findings) == 1
    assert findings[0].predicate.anchor_lines == (6,)


def test_does_not_flag_subprocess_shell_true_with_constant_command():
    findings = _by_cwe(
        """
        import subprocess

        def run(user_input):
            cmd = "echo ok"
            subprocess.run(cmd, shell=True)
        """,
        "CWE-78",
    )

    assert findings == []


def test_detects_requests_verify_false():
    findings = _by_cwe(
        """
        import requests

        def fetch(url):
            return requests.get(url, verify=False)
        """,
        "CWE-295",
    )

    assert len(findings) == 1
    assert "verification disabled" in findings[0].predicate.natural_language


def test_detects_sql_fstring_and_unsafe_deserialization():
    findings = _extract(
        """
        import pickle

        def query(cursor, user_id, blob):
            cursor.execute(f"select * from users where id = {user_id}")
            return pickle.loads(blob)
        """
    )
    cwes = {belief.cwe for belief in findings}

    assert "CWE-89" in cwes
    assert "CWE-502" in cwes


def test_detects_path_traversal_from_request_alias():
    findings = _by_cwe(
        """
        def download(request):
            requested_path = request.args.get("path")
            local_alias = requested_path
            with open(local_alias, "rb") as handle:
                return handle.read()
        """,
        "CWE-22",
    )

    assert len(findings) == 1
    assert "externally controlled path" in findings[0].predicate.natural_language


def test_detects_direct_path_input_but_ignores_internal_output_directory():
    vulnerable = _by_cwe(
        """
        from pathlib import Path

        def download(user_input):
            return Path(user_input).read_text()
        """,
        "CWE-22",
    )
    safe = _by_cwe(
        """
        from pathlib import Path

        def write_report(output_dir):
            output = Path(output_dir) / "report.json"
            output.write_text("{}")
        """,
        "CWE-22",
    )

    assert len(vulnerable) == 1
    assert safe == []


def test_does_not_treat_generic_internal_project_path_as_external_input():
    findings = _by_cwe(
        """
        def save_results(project_path):
            with open(project_path, "w") as handle:
                handle.write("ok")
        """,
        "CWE-22",
    )

    assert findings == []
