"""Independent tests for bounded partial-Python recovery."""

from __future__ import annotations

import ast

import pytest

from belief.partial_python import (
    recover_targeted_python_fragment,
    recover_targeted_python_projections,
)
from belief.security_patterns import SecurityPatternExtractor


pytestmark = pytest.mark.security


def _mapped_security_findings(source: str, target: str) -> set[tuple[str, int]]:
    findings = set()
    for projection in recover_targeted_python_projections(source, target):
        beliefs = SecurityPatternExtractor().extract(
            projection.source,
            "partial.py",
        )
        for belief in beliefs:
            anchors = tuple(belief.predicate.anchor_lines)
            for line in projection.map_lines(anchors):
                findings.add((belief.cwe, line))
    return findings


def test_raw_projection_is_preserved_and_line_mapping_is_identity():
    source = (
        "def calculate(user_input):\n"
        "    return eval(user_input)\n"
    )
    projections = recover_targeted_python_projections(
        source,
        "    return eval(user_input)",
    )

    assert [item.method for item in projections] == [
        "raw",
        "raw_wrapper",
    ]
    assert projections[0].target_original_lines == (2,)
    assert projections[0].map_lines((2,)) == (2,)
    assert projections[1].target_transformed_lines == (3,)
    assert projections[1].map_lines((3,)) == (2,)
    assert all(ast.parse(item.source) for item in projections)


def test_full_dedent_wrapper_exposes_module_fragment_to_function_rules():
    source = "        digest = hashlib.md5(payload).hexdigest()\n"
    target = "digest = hashlib.md5(payload).hexdigest()"
    projections = recover_targeted_python_projections(source, target)

    assert [item.method for item in projections] == [
        "full_dedent",
        "full_dedent_wrapper",
    ]
    assert "payload" in projections[1].synthetic_parameters
    assert ("CWE-327", 1) in _mapped_security_findings(source, target)


def test_target_window_recovers_return_outside_function_and_maps_eval():
    source = (
        "        ignored = 1\n"
        "        return eval(user_input)\n"
    )
    target = "        return eval(user_input)"
    projection = recover_targeted_python_fragment(source, target)

    assert projection is not None
    assert projection.method == "target_window_sync"
    assert projection.window_start_line == 2
    assert projection.window_end_line == 2
    assert "user_input" in projection.synthetic_parameters
    assert projection.map_lines((2,)) == (2,)
    assert ("CWE-95", 2) in _mapped_security_findings(source, target)


def test_target_window_recovers_bounded_multiline_sql_call():
    source = (
        "        cursor.execute(\n"
        "            f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "        )\n"
        "        return cursor.fetchone()\n"
    )
    target = "        cursor.execute("
    projection = recover_targeted_python_fragment(source, target)

    assert projection is not None
    assert projection.method == "target_window_sync"
    assert projection.window_start_line == 1
    assert projection.window_end_line == 3
    assert ("CWE-89", 1) in _mapped_security_findings(source, target)


def test_async_target_uses_async_wrapper_when_sync_wrapper_is_invalid():
    source = "        return await fetch_record(record_id)\n"
    projection = recover_targeted_python_fragment(
        source,
        "return await fetch_record(record_id)",
    )

    assert projection is not None
    assert projection.method == "target_window_async"
    assert projection.map_lines((2,)) == (1,)


@pytest.mark.parametrize(
    ("source", "target", "forbidden_cwe"),
    (
        (
            '        os.system("printf ok")\n',
            'os.system("printf ok")',
            "CWE-78",
        ),
        (
            '        subprocess.run(["printf", "ok"], shell=False)\n',
            'subprocess.run(["printf", "ok"], shell=False)',
            "CWE-78",
        ),
        (
            '        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            "CWE-89",
        ),
        (
            "        value = yaml.safe_load(payload)\n",
            "value = yaml.safe_load(payload)",
            "CWE-502",
        ),
        (
            "        digest = hashlib.sha256(payload).hexdigest()\n",
            "digest = hashlib.sha256(payload).hexdigest()",
            "CWE-327",
        ),
        (
            '        secret = os.getenv("TOKEN")\n',
            'secret = os.getenv("TOKEN")',
            "CWE-798",
        ),
        (
            "        monkey = random.choice(values)\n",
            "monkey = random.choice(values)",
            "CWE-330",
        ),
        (
            "        salt = secrets.choice(values)\n",
            "salt = secrets.choice(values)",
            "CWE-330",
        ),
    ),
)
def test_partial_recovery_preserves_safe_negative_controls(
    source,
    target,
    forbidden_cwe,
):
    assert forbidden_cwe not in {
        cwe
        for cwe, _line in _mapped_security_findings(source, target)
    }


def test_hardcoded_credential_anchor_is_the_assignment_line():
    source = (
        "def configure():\n"
        '    api_key = "example-long-static-key"\n'
        "    return api_key\n"
    )
    beliefs = SecurityPatternExtractor().extract(source, "config.py")
    hardcoded = [
        belief for belief in beliefs if belief.cwe == "CWE-798"
    ]

    assert len(hardcoded) == 1
    assert hardcoded[0].predicate.anchor_lines == (2,)
    assert hardcoded[0].scope.line_start == 1


@pytest.mark.parametrize("target_name", ("salt", "csrf_token", "apiKey"))
def test_randomness_assignment_security_context_is_semantic(target_name):
    source = (
        "def choose_value(values):\n"
        f"    {target_name} = random.choice(values)\n"
        f"    return {target_name}\n"
    )
    beliefs = SecurityPatternExtractor().extract(source, "randomness.py")

    assert any(
        belief.cwe == "CWE-330"
        and belief.predicate.anchor_lines == (2,)
        for belief in beliefs
    )


def test_randomness_assignment_avoids_substring_false_positive():
    source = (
        "def choose_value(values):\n"
        "    monkey = random.choice(values)\n"
        "    return monkey\n"
    )
    beliefs = SecurityPatternExtractor().extract(source, "randomness.py")

    assert all(belief.cwe != "CWE-330" for belief in beliefs)


def test_recovery_requires_exact_target_and_enforces_resource_bounds():
    source = "        value = eval(user_input)\n"

    assert (
        recover_targeted_python_fragment(source, "missing = 1")
        is None
    )
    with pytest.raises(ValueError, match="between 1 and 100"):
        recover_targeted_python_fragment(
            source,
            "value = eval(user_input)",
            max_window_lines=101,
        )
    with pytest.raises(ValueError, match="between 0 and 256"):
        recover_targeted_python_fragment(
            source,
            "value = eval(user_input)",
            max_synthetic_parameters=257,
        )


def test_recovery_never_executes_source():
    source = (
        "        raise RuntimeError('must never run')\n"
        "        value = 1\n"
    )
    projection = recover_targeted_python_fragment(
        source,
        "raise RuntimeError('must never run')",
    )

    assert projection is not None
    assert "must never run" in projection.source
