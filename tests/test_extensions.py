"""Tests for extended Z3 translator and structural belief extractor."""

import pytest

from belief.models import (
    JustificationCategory,
)
from belief.structural import StructuralExtractor


# ─── Extended Z3 Translator Tests ───

class TestExtendedTranslator:
    @pytest.fixture(autouse=True)
    def _check_z3(self):
        try:
            import z3  # noqa: F401
            self.has_z3 = True
        except ImportError:
            self.has_z3 = False

    def test_conjunction(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("x > 0 and x < 100")
        assert result is not None

    def test_disjunction(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("x == 0 or x == 1")
        assert result is not None

    def test_implication_implies(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("x > 0 implies y > 0")
        assert result is not None

    def test_implication_if_then(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("if x > 0 then y > 0")
        assert result is not None

    def test_chained_comparison(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("0 <= x <= 255")
        assert result is not None

    def test_chained_comparison_strict(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("0 < size < 1024")
        assert result is not None

    def test_string_equality(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("encoding == 'utf-8'")
        assert result is not None

    def test_string_inequality(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("content_type != 'text/html'")
        assert result is not None

    def test_conjunction_contradicts_disjunction(self):
        """Verify Z3 can detect conflict between compound predicates."""
        if not self.has_z3:
            pytest.skip("z3 not installed")
        import z3
        from belief.z3_verifier import PredicateTranslator

        t = PredicateTranslator()
        # "x > 10 and x < 5" should be unsatisfiable
        a = t.translate("x > 10 and x < 5")
        if a is not None:
            solver = z3.Solver()
            solver.add(a)
            assert solver.check() == z3.unsat

    def test_chained_contradicts_simple(self):
        """Verify chained comparison conflicts with simple comparison."""
        if not self.has_z3:
            pytest.skip("z3 not installed")
        import z3
        from belief.z3_verifier import PredicateTranslator

        t = PredicateTranslator()
        a = t.translate("0 <= x <= 10")
        b = t.translate("x > 100")
        if a is not None and b is not None:
            solver = z3.Solver()
            solver.add(a)
            solver.add(b)
            assert solver.check() == z3.unsat


# ─── Structural Extractor Tests ───

class TestStructuralExtractor:
    def test_untyped_params(self):
        code = "def process(data, count):\n    return data[:count]\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        # Should find beliefs about untyped 'data' and 'count'
        type_beliefs = [b for b in beliefs if "type(" in b.predicate.expression]
        assert len(type_beliefs) >= 2

    def test_typed_params_no_belief(self):
        code = "def process(data: list, count: int) -> list:\n    return data[:count]\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        type_beliefs = [b for b in beliefs if "type(" in b.predicate.expression]
        assert len(type_beliefs) == 0

    def test_unchecked_indexing(self):
        code = "def get_first(items):\n    return items[0]\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        index_beliefs = [b for b in beliefs if "len(" in b.predicate.expression]
        assert len(index_beliefs) >= 1

    def test_unguarded_external_call(self):
        code = "def fetch(url):\n    data = open(url).read()\n    return data\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        success_beliefs = [b for b in beliefs if "succeeds" in b.predicate.expression]
        assert len(success_beliefs) >= 1
        # Should be marked as "hope"
        for b in success_beliefs:
            from belief.models import EpistemicStatus
            assert b.epistemic_status == EpistemicStatus.HOPE

    def test_guarded_external_call_no_belief(self):
        code = "def fetch(url):\n    try:\n        data = open(url).read()\n        return data\n    except Exception:\n        return None\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        success_beliefs = [b for b in beliefs if "succeeds" in b.predicate.expression]
        assert len(success_beliefs) == 0

    def test_unchecked_division(self):
        code = "def average(total, count):\n    return total / count\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        div_beliefs = [b for b in beliefs if "!= 0" in b.predicate.expression]
        assert len(div_beliefs) >= 1

    def test_all_beliefs_have_high_confidence(self):
        """Structural beliefs should have high confidence since they're deterministic."""
        code = "def f(x):\n    return x[0] / x[1]\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        for b in beliefs:
            assert b.confidence_score >= 0.75

    def test_all_beliefs_are_c5(self):
        """Structural findings are by definition unjustified (C5)."""
        code = "def f(x):\n    return x[0]\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        for b in beliefs:
            assert b.justification == JustificationCategory.C5_NO_JUSTIFICATION

    def test_empty_function(self):
        code = "def noop():\n    pass\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        # No parameters, no operations → no structural beliefs
        assert len(beliefs) == 0

    def test_syntax_error_returns_empty(self):
        code = "def broken(\n    this is not valid"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        assert beliefs == []

    # ─── New patterns (v0.2) ───

    def test_mutable_default(self):
        code = "def append_to(item, target=[]):\n    target.append(item)\n    return target\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        mutable = [b for b in beliefs if "mutable" in b.predicate.expression.lower()
                   or "shared" in b.predicate.natural_language.lower()]
        assert len(mutable) >= 1

    def test_no_mutable_default_with_none(self):
        code = "def append_to(item, target=None):\n    if target is None:\n        target = []\n    target.append(item)\n    return target\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        mutable = [b for b in beliefs if "mutable" in b.predicate.expression.lower()]
        assert len(mutable) == 0

    def test_bare_except(self):
        code = "def risky():\n    try:\n        return 1/0\n    except:\n        pass\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        bare = [b for b in beliefs if "ALL exceptions" in b.predicate.natural_language
                or "severity" in b.predicate.expression.lower()]
        assert len(bare) >= 1

    def test_swallowed_exception(self):
        code = "def risky():\n    try:\n        return do_thing()\n    except ValueError as e:\n        return None\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        swallowed = [b for b in beliefs if "discarded" in b.predicate.natural_language.lower()
                     or "unimportant" in b.predicate.expression.lower()]
        assert len(swallowed) >= 1

    def test_exception_used_no_belief(self):
        code = "def risky():\n    try:\n        return do_thing()\n    except ValueError as e:\n        logger.error(e)\n        return None\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        swallowed = [b for b in beliefs if "discarded" in b.predicate.natural_language.lower()]
        assert len(swallowed) == 0

    def test_unchecked_int_coercion(self):
        code = "def parse(value):\n    return int(value)\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        coercion = [b for b in beliefs if "convertible" in b.predicate.expression]
        assert len(coercion) >= 1

    def test_missing_timeout(self):
        code = "def fetch(url):\n    import requests\n    return requests.get(url)\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        timeout = [b for b in beliefs if "responds" in b.predicate.expression
                   or "timeout" in b.predicate.natural_language.lower()]
        assert len(timeout) >= 1

    def test_timeout_present_no_belief(self):
        code = "def fetch(url):\n    import requests\n    return requests.get(url, timeout=30)\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        timeout = [b for b in beliefs if "responds" in b.predicate.expression
                   and "timeout" in b.predicate.natural_language.lower()]
        assert len(timeout) == 0

    def test_global_mutation(self):
        code = "counter = 0\ndef increment():\n    global counter\n    counter += 1\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        global_b = [b for b in beliefs if "concurrent" in b.predicate.expression.lower()
                    or "global" in b.predicate.natural_language.lower()]
        assert len(global_b) >= 1

    def test_float_equality(self):
        code = "def check(x):\n    if x == 0.1:\n        return True\n    return False\n"
        ext = StructuralExtractor()
        beliefs = ext.extract(code, "test.py")
        float_b = [b for b in beliefs if "precision" in b.predicate.expression.lower()
                   or "float" in b.predicate.natural_language.lower()]
        assert len(float_b) >= 1
