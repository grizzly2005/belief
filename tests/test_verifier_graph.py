"""Tests for BELIEF Z3 verifier and belief graph."""

import pytest

from belief.models import (
    Belief,
    ConflictSeverity,
    JustificationCategory,
    Predicate,
    Scope,
)
from belief.graph import BeliefGraph


# ─── Z3 Verifier Tests ───

class TestPredicateTranslator:
    """Test predicate translation to Z3 constraints."""

    @pytest.fixture(autouse=True)
    def _check_z3(self):
        try:
            import z3  # noqa: F401
            self.has_z3 = True
        except ImportError:
            self.has_z3 = False

    def test_numeric_lte(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("x <= 10")
        assert result is not None

    def test_numeric_gt(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("length > 0")
        assert result is not None

    def test_equality(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("x == 5")
        assert result is not None

    def test_is_none(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("ptr is None")
        assert result is not None

    def test_is_not_none(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("ptr is not None")
        assert result is not None

    def test_boolean(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("is_valid == True")
        assert result is not None

    def test_negation(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("not x <= 10")
        assert result is not None

    def test_untranslatable(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("the system is working correctly")
        assert result is None

    def test_len_expression(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import PredicateTranslator
        t = PredicateTranslator()
        result = t.translate("len(input) <= 1024")
        assert result is not None


class TestConflictDetector:
    def _make_belief(self, expr, justification=JustificationCategory.C5_NO_JUSTIFICATION,
                     variables=(), confidence=0.8):
        return Belief(
            predicate=Predicate(expression=expr, variables=variables),
            scope=Scope(file_path="test.py", function_name="f"),
            justification=justification,
            confidence_score=confidence,
        )

    def test_heuristic_negation_conflict(self):
        from belief.z3_verifier import ConflictDetector
        detector = ConflictDetector()

        a = self._make_belief("x <= 10", variables=("x",))
        b = self._make_belief("x > 10", variables=("x",))

        conflicts = detector.detect_pairwise([a], [b])
        assert len(conflicts) >= 1

    def test_no_conflict_unrelated(self):
        from belief.z3_verifier import ConflictDetector
        detector = ConflictDetector()

        a = self._make_belief("x <= 10", variables=("x",))
        b = self._make_belief("y > 5", variables=("y",))

        conflicts = detector.detect_pairwise([a], [b])
        assert len(conflicts) == 0

    def test_severity_calculation(self):
        from belief.z3_verifier import ConflictDetector
        detector = ConflictDetector()

        # Two C5 beliefs should produce higher severity
        a = self._make_belief(
            "x <= 10", variables=("x",),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        b = self._make_belief(
            "x > 10", variables=("x",),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )

        conflicts = detector.detect_pairwise([a], [b])
        if conflicts:
            # Should be high or critical severity
            assert conflicts[0].severity in (
                ConflictSeverity.HIGH,
                ConflictSeverity.CRITICAL,
            )


# ─── Belief Graph Tests ───

class TestBeliefGraph:
    def _make_belief(self, expr, deps=None, justification=JustificationCategory.C3_DOCUMENTED_CONVENTION):
        return Belief(
            predicate=Predicate(expression=expr),
            scope=Scope(file_path="test.py"),
            justification=justification,
            dependencies=deps or [],
        )

    def test_add_beliefs(self):
        graph = BeliefGraph()
        beliefs = [
            self._make_belief("x > 0"),
            self._make_belief("y > 0"),
        ]
        graph.add_beliefs(beliefs)
        assert len(graph.nodes) == 2

    def test_dependency_edges(self):
        graph = BeliefGraph()
        b1 = self._make_belief("malloc succeeds")
        b2 = self._make_belief("buffer.size >= 1024", deps=["malloc succeeds"])
        graph.add_beliefs([b1, b2])

        # b2 depends on b1, so edge b1 → b2
        assert len(graph.edges) > 0

    def test_cascade_impact(self):
        graph = BeliefGraph()
        b1 = self._make_belief("memory available")
        b2 = self._make_belief("malloc succeeds", deps=["memory available"])
        b3 = self._make_belief("buffer allocated", deps=["malloc succeeds"])
        graph.add_beliefs([b1, b2, b3])

        # Violating b1 should cascade to b2 and b3
        impacted = graph.cascade_impact(b1.id)
        assert len(impacted) >= 1  # at least b2

    def test_fragile_roots(self):
        graph = BeliefGraph()
        root = self._make_belief(
            "network available",
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        dep1 = self._make_belief("api responds", deps=["network available"])
        dep2 = self._make_belief("data valid", deps=["network available"])
        graph.add_beliefs([root, dep1, dep2])

        roots = graph.fragile_roots(top_n=1)
        assert len(roots) >= 1

    def test_unjustified_foundations(self):
        graph = BeliefGraph()
        root = self._make_belief(
            "env is safe",
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        dep = self._make_belief("can trust input", deps=["env is safe"])
        graph.add_beliefs([root, dep])

        unjustified = graph.unjustified_foundations()
        assert len(unjustified) >= 1
        assert unjustified[0].belief.predicate.expression == "env is safe"

    def test_belief_clusters(self):
        graph = BeliefGraph()
        # Two disconnected clusters
        a1 = self._make_belief("x > 0")
        a2 = self._make_belief("x < 100", deps=["x > 0"])
        b1 = self._make_belief("y is not None")
        graph.add_beliefs([a1, a2, b1])

        clusters = graph.belief_clusters()
        assert len(clusters) >= 2

    def test_to_dict(self):
        graph = BeliefGraph()
        beliefs = [
            self._make_belief("a > 0"),
            self._make_belief("b > 0", deps=["a > 0"]),
        ]
        graph.add_beliefs(beliefs)

        data = graph.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert "stats" in data
        assert data["stats"]["total_nodes"] == 2
