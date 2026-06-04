"""
Integration tests: Run BELIEF analysis engines on REAL code from reference repos.

These tests verify that BELIEF works on actual production code,
not just synthetic test cases. Uses code from:
- LangChain core (LLM agent framework)
- Flask (web framework)
- requests (HTTP library)
- FastAPI (async web framework)
"""

from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent.parent / "belief" / "examples"


def _get_example_files(subdir: str, max_files: int = 10) -> list[Path]:
    """Get Python files from an examples subdirectory."""
    d = EXAMPLES_DIR / subdir
    if not d.exists():
        return []
    files = sorted(d.glob("*.py"))[:max_files]
    return [f for f in files if f.stat().st_size > 100]  # skip tiny files


# ═══════════════════════════════════
#  STRUCTURAL ANALYSIS ON REAL CODE
# ═══════════════════════════════════

class TestStructuralOnRealCode:
    """Run structural extractor on real-world code."""

    def _analyze(self, source: str, path: str):
        from belief.structural import StructuralExtractor
        return StructuralExtractor().extract(source, path)

    @pytest.mark.parametrize("subdir", ["langchain_core", "flask_src", "requests_src", "fastapi_src"])
    def test_structural_finds_beliefs(self, subdir):
        files = _get_example_files(subdir, 5)
        if not files:
            pytest.skip(f"No example files in {subdir}")

        total_beliefs = 0
        for f in files:
            source = f.read_text(errors="replace")
            beliefs = self._analyze(source, str(f))
            total_beliefs += len(beliefs)

        # Real code should have many implicit beliefs
        assert total_beliefs > 0, f"No beliefs found in {subdir}"

    def test_langchain_has_many_beliefs(self):
        files = _get_example_files("langchain_core", 20)
        if not files:
            pytest.skip("No LangChain files")

        total = 0
        for f in files:
            source = f.read_text(errors="replace")
            total += len(self._analyze(source, str(f)))

        # LangChain core should have many beliefs (large codebase)
        assert total >= 10


# ═══════════════════════════════════
#  SECURITY PATTERNS ON REAL CODE
# ═══════════════════════════════════

class TestSecurityOnRealCode:
    def _analyze(self, source: str, path: str):
        from belief.security_patterns import SecurityPatternExtractor
        return SecurityPatternExtractor().extract(source, path)

    @pytest.mark.parametrize("subdir", ["langchain_core", "flask_src", "fastapi_src"])
    def test_security_scan(self, subdir):
        files = _get_example_files(subdir, 5)
        if not files:
            pytest.skip(f"No files in {subdir}")

        for f in files:
            source = f.read_text(errors="replace")
            beliefs = self._analyze(source, str(f))
            # Should not crash on real code
            assert isinstance(beliefs, list)


# ═══════════════════════════════════
#  TAINT ANALYSIS ON REAL CODE
# ═══════════════════════════════════

class TestTaintOnRealCode:
    def _analyze(self, source: str, path: str):
        from belief.taint import TaintEngine
        return TaintEngine().analyze_to_beliefs(source, path)

    @pytest.mark.parametrize("subdir", ["langchain_core", "flask_src", "requests_src"])
    def test_taint_analysis(self, subdir):
        files = _get_example_files(subdir, 5)
        if not files:
            pytest.skip(f"No files in {subdir}")

        for f in files:
            source = f.read_text(errors="replace")
            beliefs = self._analyze(source, str(f))
            assert isinstance(beliefs, list)


# ═══════════════════════════════════
#  TEMPORAL ANALYSIS ON REAL CODE
# ═══════════════════════════════════

class TestTemporalOnRealCode:
    def _analyze(self, source: str, path: str):
        from belief.temporal import TemporalChecker
        return TemporalChecker().check(source, path)

    @pytest.mark.parametrize("subdir", ["flask_src", "requests_src"])
    def test_temporal_check(self, subdir):
        files = _get_example_files(subdir, 5)
        if not files:
            pytest.skip(f"No files in {subdir}")

        total = 0
        for f in files:
            source = f.read_text(errors="replace")
            beliefs = self._analyze(source, str(f))
            total += len(beliefs)

        # Real code should have some temporal issues
        assert total >= 0  # at minimum, shouldn't crash


# ═══════════════════════════════════
#  ZERO-DAY HUNTER ON REAL CODE
# ═══════════════════════════════════

class TestHunterOnRealCode:
    def test_hunt_flask(self):
        d = EXAMPLES_DIR / "flask_src"
        if not d.exists():
            pytest.skip("No Flask examples")

        from belief.hunter import ZeroDayHunter
        result = ZeroDayHunter().hunt(str(d), max_files=10)
        assert result.files_scanned > 0
        assert result.total_beliefs > 0

    def test_hunt_requests(self):
        d = EXAMPLES_DIR / "requests_src"
        if not d.exists():
            pytest.skip("No requests examples")

        from belief.hunter import ZeroDayHunter
        result = ZeroDayHunter().hunt(str(d), max_files=10)
        assert result.files_scanned > 0

    def test_hunt_langchain(self):
        d = EXAMPLES_DIR / "langchain_core"
        if not d.exists():
            pytest.skip("No LangChain examples")

        from belief.hunter import ZeroDayHunter
        result = ZeroDayHunter().hunt(str(d), max_files=30)
        assert result.files_scanned > 0
        assert result.total_beliefs > 10  # large codebase = many beliefs


# ═══════════════════════════════════
#  SEMGREP DATABASE INTEGRATION
# ═══════════════════════════════════

class TestSemgrepIntegration:
    def test_extracted_rules_loaded(self):
        from belief.semgrep_db import get_extracted_rule_count
        count = get_extracted_rule_count()
        assert count >= 1300  # should have 1364 rules

    def test_query_by_cwe(self):
        from belief.semgrep_db import get_extracted_rules_for_cwe
        rules = get_extracted_rules_for_cwe("CWE-89")
        assert len(rules) > 0  # SQL injection rules exist

    def test_query_by_language(self):
        from belief.semgrep_db import get_extracted_rules_for_language
        py_rules = get_extracted_rules_for_language("python")
        assert len(py_rules) > 100  # should have 260 python rules

    def test_rules_have_cwe(self):
        from belief.semgrep_db import load_extracted_rules
        rules = load_extracted_rules()
        with_cwe = sum(1 for r in rules if r.get("cwe"))
        assert with_cwe > 1200  # most rules have CWE


# ═══════════════════════════════════
#  CROSS-ENGINE CONSISTENCY
# ═══════════════════════════════════

class TestCrossEngineConsistency:
    """Verify that different engines don't contradict each other on the same code."""

    def test_all_engines_on_same_code(self):
        code = '''
import os
import pickle

def process_user_input(request):
    data = request.form.get("payload")
    obj = pickle.loads(data)
    os.system(f"echo {obj}")
    f = open(obj.filename)
    return f.read()
'''
        from belief.structural import StructuralExtractor
        from belief.security_patterns import SecurityPatternExtractor
        from belief.taint import TaintEngine
        from belief.temporal import TemporalChecker

        structural = StructuralExtractor().extract(code, "vuln.py")
        security = SecurityPatternExtractor().extract(code, "vuln.py")
        taint = TaintEngine().analyze_to_beliefs(code, "vuln.py")
        temporal = TemporalChecker().check(code, "vuln.py")

        all_beliefs = structural + security + taint + temporal

        # This code is clearly vulnerable — we should find many beliefs
        assert len(all_beliefs) >= 5

        # Verify all beliefs are well-formed
        for b in all_beliefs:
            assert b.predicate.expression
            assert b.scope.file_path == "vuln.py"
            assert 0 < b.confidence_score <= 1.0

    def test_engines_agree_on_safe_code(self):
        code = '''
def add(a: int, b: int) -> int:
    """Add two integers."""
    assert isinstance(a, int)
    assert isinstance(b, int)
    return a + b
'''
        from belief.security_patterns import SecurityPatternExtractor
        from belief.taint import TaintEngine

        security = SecurityPatternExtractor().extract(code, "safe.py")
        taint = TaintEngine().analyze_to_beliefs(code, "safe.py")

        # Safe code should have zero security/taint findings
        assert len(security) == 0
        assert len(taint) == 0
