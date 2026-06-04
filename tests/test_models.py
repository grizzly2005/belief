"""Tests for BELIEF core models and logic."""


from belief.models import (
    AnalysisReport,
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)


# ─── Predicate ───

class TestPredicate:
    def test_negation_lte(self):
        p = Predicate(expression="x <= 10")
        assert p.negation() == "x > 10"

    def test_negation_gte(self):
        p = Predicate(expression="x >= 0")
        assert p.negation() == "x < 0"

    def test_negation_eq(self):
        p = Predicate(expression="x == 5")
        assert p.negation() == "x != 5"

    def test_negation_neq(self):
        p = Predicate(expression="x != None")
        assert p.negation() == "x == None"

    def test_negation_in(self):
        p = Predicate(expression="x in TRUSTED_SET")
        assert p.negation() == "x not in TRUSTED_SET"

    def test_negation_is_none(self):
        p = Predicate(expression="ptr is None")
        assert p.negation() == "ptr is not None"

    def test_negation_not_prefix(self):
        p = Predicate(expression="not active")
        assert p.negation() == "active"

    def test_negation_fallback(self):
        p = Predicate(expression="some_complex_thing()")
        assert p.negation() == "not (some_complex_thing())"


# ─── Scope ───

class TestScope:
    def test_qualified_name_full(self):
        s = Scope(
            file_path="src/main.py",
            module="src.main",
            class_name="Handler",
            function_name="process",
        )
        assert s.qualified_name == "src.main.Handler.process"

    def test_qualified_name_no_class(self):
        s = Scope(file_path="utils.py", module="utils", function_name="parse")
        assert s.qualified_name == "utils.parse"

    def test_overlaps_same_file_with_lines(self):
        a = Scope(file_path="a.py", line_start=10, line_end=20)
        b = Scope(file_path="a.py", line_start=15, line_end=25)
        assert a.overlaps(b)

    def test_no_overlap_different_files(self):
        a = Scope(file_path="a.py", line_start=10, line_end=20)
        b = Scope(file_path="b.py", line_start=10, line_end=20)
        assert not a.overlaps(b)

    def test_no_overlap_same_file_disjoint(self):
        a = Scope(file_path="a.py", line_start=10, line_end=20)
        b = Scope(file_path="a.py", line_start=30, line_end=40)
        assert not a.overlaps(b)

    def test_overlaps_same_file_no_lines(self):
        a = Scope(file_path="a.py")
        b = Scope(file_path="a.py")
        assert a.overlaps(b)  # conservative


# ─── Belief ───

class TestBelief:
    def _make_belief(self, **kwargs):
        defaults = dict(
            predicate=Predicate(expression="x <= 10", variables=("x",)),
            scope=Scope(file_path="test.py", function_name="func"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        defaults.update(kwargs)
        return Belief(**defaults)

    def test_auto_id_generation(self):
        b = self._make_belief()
        assert len(b.id) == 12

    def test_fragility_c5_belief(self):
        b = self._make_belief(
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
            epistemic_status=EpistemicStatus.BELIEF,
            confidence_score=0.5,
        )
        # C5 weight = (1 - 0.2) * 0.4 = 0.32
        # belief weight = 0.3 * 0.3 = 0.09
        # confidence weight = (1 - 0.5) * 0.3 = 0.15
        assert 0.5 < b.fragility < 0.6

    def test_fragility_c1_belief(self):
        b = self._make_belief(
            justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            epistemic_status=EpistemicStatus.BELIEF,
            confidence_score=0.9,
        )
        assert b.fragility < 0.2  # very solid

    def test_fragility_c6_unknown(self):
        b = self._make_belief(
            justification=JustificationCategory.C6_OPAQUE_INFERENCE,
            epistemic_status=EpistemicStatus.UNKNOWN,
            confidence_score=0.2,
        )
        assert b.fragility > 0.7  # very fragile

    def test_serialization_roundtrip(self):
        b = self._make_belief(
            predicate=Predicate(
                expression="buf.size >= input.length",
                variables=("buf", "input"),
                anchor_lines=(42, 43),
                natural_language="Buffer is large enough",
            ),
            justification=JustificationCategory.C3_DOCUMENTED_CONVENTION,
            logic_type=LogicType.FOL,
            epistemic_status=EpistemicStatus.HOPE,
            confidence_score=0.75,
        )

        data = b.to_dict()
        restored = Belief.from_dict(data)

        assert restored.predicate.expression == b.predicate.expression
        assert restored.justification == b.justification
        assert restored.epistemic_status == b.epistemic_status
        assert restored.logic_type == b.logic_type
        assert restored.confidence_score == b.confidence_score


# ─── JustificationCategory ───

class TestJustificationCategory:
    def test_robustness_ordering(self):
        cats = list(JustificationCategory)
        scores = [c.robustness_score for c in cats]
        # C1 should be highest, C6 lowest
        assert scores[0] > scores[-1]

    def test_c1_is_strongest(self):
        assert JustificationCategory.C1_FORMAL_VERIFICATION.robustness_score == 1.0

    def test_c6_is_weakest(self):
        assert JustificationCategory.C6_OPAQUE_INFERENCE.robustness_score == 0.1


# ─── AnalysisReport ───

class TestAnalysisReport:
    def test_cognitive_debt_all_weak(self):
        beliefs = [
            Belief(
                predicate=Predicate(expression=f"x{i} > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C5_NO_JUSTIFICATION,
            )
            for i in range(10)
        ]
        report = AnalysisReport(project_name="test", beliefs=beliefs)
        assert report.cognitive_debt == 1.0

    def test_cognitive_debt_all_strong(self):
        beliefs = [
            Belief(
                predicate=Predicate(expression=f"x{i} > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            )
            for i in range(10)
        ]
        report = AnalysisReport(project_name="test", beliefs=beliefs)
        assert report.cognitive_debt == 0.0

    def test_cognitive_debt_mixed(self):
        beliefs = [
            Belief(
                predicate=Predicate(expression="a > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            ),
            Belief(
                predicate=Predicate(expression="b > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C5_NO_JUSTIFICATION,
            ),
        ]
        report = AnalysisReport(project_name="test", beliefs=beliefs)
        assert report.cognitive_debt == 0.5

    def test_epistemic_health(self):
        beliefs = [
            Belief(
                predicate=Predicate(expression="x > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            ),
            Belief(
                predicate=Predicate(expression="y > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            ),
            Belief(
                predicate=Predicate(expression="z > 0"),
                scope=Scope(file_path="t.py"),
                justification=JustificationCategory.C5_NO_JUSTIFICATION,
            ),
        ]
        report = AnalysisReport(project_name="test", beliefs=beliefs)
        health = report.epistemic_health
        assert health["C1"]["count"] == 2
        assert health["C5"]["count"] == 1

    def test_save_and_load(self, tmp_path):
        beliefs = [
            Belief(
                predicate=Predicate(
                    expression="x > 0",
                    variables=("x",),
                    natural_language="x is positive",
                ),
                scope=Scope(file_path="t.py", function_name="f"),
                justification=JustificationCategory.C3_DOCUMENTED_CONVENTION,
            )
        ]
        report = AnalysisReport(project_name="test_proj", beliefs=beliefs)
        path = str(tmp_path / "report.json")
        report.save(path)

        loaded = AnalysisReport.load(path)
        assert loaded.project_name == "test_proj"
        assert len(loaded.beliefs) == 1
        assert loaded.beliefs[0].predicate.expression == "x > 0"
