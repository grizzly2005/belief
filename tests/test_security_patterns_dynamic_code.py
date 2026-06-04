from textwrap import dedent

import pytest

from belief.security_patterns import SecurityPatternExtractor

pytestmark = pytest.mark.security


def _extract(source: str):
    return SecurityPatternExtractor().extract(dedent(source), "case.py")


def _dynamic_code_findings(source: str):
    return [
        belief for belief in _extract(source)
        if belief.cwe == "CWE-95"
    ]


def test_detects_direct_eval_on_user_input():
    findings = _dynamic_code_findings(
        """
        def handle(user_input):
            return eval(user_input)
        """
    )

    assert len(findings) == 1
    assert findings[0].predicate.anchor_lines == (3,)
    assert "eval()" in findings[0].predicate.natural_language


def test_detects_module_level_eval_on_input():
    findings = _dynamic_code_findings(
        "user_input = input()\neval(user_input)\n"
    )

    assert len(findings) == 1
    assert findings[0].predicate.anchor_lines == (2,)
    assert findings[0].scope.function_name is None


def test_detects_exec_via_simple_variable_alias():
    findings = _dynamic_code_findings(
        """
        def run(user_input):
            code = user_input
            exec(code)
        """
    )

    assert len(findings) == 1
    assert findings[0].predicate.anchor_lines == (4,)
    assert "exec()" in findings[0].predicate.natural_language


@pytest.mark.parametrize("mode", ["exec", "eval"])
def test_detects_compile_on_user_input_for_exec_and_eval_modes(mode):
    findings = _dynamic_code_findings(
        f"""
        def build(user_input):
            return compile(user_input, "<user>", "{mode}")
        """
    )

    assert len(findings) == 1
    assert findings[0].predicate.anchor_lines == (3,)
    assert findings[0].cwe == "CWE-95"
    assert f"mode='{mode}'" in findings[0].predicate.natural_language


def test_does_not_flag_ast_literal_eval():
    findings = _dynamic_code_findings(
        """
        import ast

        def parse(user_input):
            return ast.literal_eval(user_input)
        """
    )

    assert findings == []


def test_does_not_flag_locally_controlled_constants():
    findings = _dynamic_code_findings(
        """
        def safe(user_input):
            expr = "1 + 1"
            eval(expr)
            exec("value = 1")
            mode = "exec"
            return compile("print('ok')", "<safe>", mode)
        """
    )

    assert findings == []
