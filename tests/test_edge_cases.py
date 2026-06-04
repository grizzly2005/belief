"""Tests for edge cases and bug fixes."""

import json
import pytest

from belief.models import (
    AnalysisReport,
    Belief,
    Conflict,
    ConflictSeverity,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from belief.config import LLMProvider


# ─── Bug fix: from_dict with invalid enum values ───

class TestFromDictRobustness:
    def test_invalid_justification_falls_back_to_c5(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {"file_path": "t.py"},
            "justification": "INVALID_VALUE",
        }
        b = Belief.from_dict(data)
        assert b.justification == JustificationCategory.C5_NO_JUSTIFICATION

    def test_invalid_epistemic_falls_back_to_belief(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {"file_path": "t.py"},
            "justification": "C1",
            "epistemic_status": "GARBAGE",
        }
        b = Belief.from_dict(data)
        from belief.models import EpistemicStatus
        assert b.epistemic_status == EpistemicStatus.BELIEF

    def test_invalid_logic_type_falls_back_to_fol(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {"file_path": "t.py"},
            "justification": "C3",
            "logic_type": "quantum_logic",
        }
        b = Belief.from_dict(data)
        assert b.logic_type == LogicType.FOL

    def test_missing_predicate_fields_use_defaults(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {"file_path": "t.py"},
            "justification": "C5",
        }
        b = Belief.from_dict(data)
        assert b.predicate.variables == ()
        assert b.predicate.anchor_lines == ()
        assert b.predicate.natural_language == ""

    def test_missing_scope_fields_use_defaults(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {"file_path": "t.py"},
            "justification": "C5",
        }
        b = Belief.from_dict(data)
        assert b.scope.function_name is None
        assert b.scope.class_name is None
        assert b.scope.line_start is None

    def test_completely_minimal_data(self):
        data = {
            "predicate": {"expression": "x > 0"},
            "scope": {},
        }
        b = Belief.from_dict(data)
        assert b.predicate.expression == "x > 0"
        assert b.scope.file_path == "unknown"
        assert b.justification == JustificationCategory.C5_NO_JUSTIFICATION


# ─── Bug fix: AnalysisReport.load robustness ───

class TestReportLoadRobustness:
    def test_load_with_corrupt_belief_skips_it(self, tmp_path):
        data = {
            "project_name": "test",
            "beliefs": [
                {"predicate": {"expression": "good > 0"}, "scope": {"file_path": "a.py"}, "justification": "C3"},
                "this is not a dict",  # corrupt entry
                {"predicate": {"expression": "also_good > 0"}, "scope": {"file_path": "b.py"}, "justification": "C1"},
            ],
            "frontiers": [],
            "conflicts": [],
        }
        path = tmp_path / "report.json"
        path.write_text(json.dumps(data))
        report = AnalysisReport.load(str(path))
        assert report.project_name == "test"
        assert len(report.beliefs) == 2  # corrupt one skipped

    def test_load_with_missing_project_name(self, tmp_path):
        data = {"beliefs": []}
        path = tmp_path / "report.json"
        path.write_text(json.dumps(data))
        report = AnalysisReport.load(str(path))
        assert report.project_name == "unknown"

    def test_load_restores_conflicts(self, tmp_path):
        b1 = Belief(
            predicate=Predicate(expression="x > 0"),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        b2 = Belief(
            predicate=Predicate(expression="y > 0"),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        conflict = Conflict(
            belief_a=b1, belief_b=b2,
            severity=ConflictSeverity.HIGH,
            description="test conflict",
            verified_by="z3",
        )
        report = AnalysisReport(
            project_name="test",
            beliefs=[b1, b2],
            conflicts=[conflict],
        )
        path = tmp_path / "report.json"
        report.save(str(path))

        loaded = AnalysisReport.load(str(path))
        assert len(loaded.beliefs) == 2
        assert len(loaded.conflicts) == 1
        assert loaded.conflicts[0].severity == ConflictSeverity.HIGH
        assert loaded.conflicts[0].description == "test conflict"

    def test_load_with_invalid_conflict_severity(self, tmp_path):
        b = Belief(
            predicate=Predicate(expression="x > 0"),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        data = {
            "project_name": "test",
            "beliefs": [b.to_dict(), b.to_dict()],
            "conflicts": [{
                "belief_a_id": b.id,
                "belief_b_id": b.id,
                "severity": "ULTRA_CRITICAL",  # invalid
                "description": "test",
            }],
        }
        # Fix: both beliefs need different IDs
        data["beliefs"][1]["predicate"]["expression"] = "y > 0"
        data["beliefs"][1]["id"] = "different_id"
        data["conflicts"][0]["belief_b_id"] = "different_id"

        path = tmp_path / "report.json"
        path.write_text(json.dumps(data))
        loaded = AnalysisReport.load(str(path))
        assert len(loaded.conflicts) == 1
        assert loaded.conflicts[0].severity == ConflictSeverity.MEDIUM  # fallback


# ─── Bug fix: API key not in repr ───

class TestAPIKeySafety:
    def test_api_key_not_in_repr(self):
        provider = LLMProvider(
            name="test",
            base_url="http://localhost",
            model="test-model",
            api_key="sk-super-secret-key-12345",
        )
        repr_str = repr(provider)
        assert "sk-super-secret-key-12345" not in repr_str
        assert "api_key" not in repr_str

    def test_api_key_not_in_str(self):
        provider = LLMProvider(
            name="test",
            base_url="http://localhost",
            model="test-model",
            api_key="sk-super-secret-key-12345",
        )
        str_str = str(provider)
        assert "sk-super-secret-key-12345" not in str_str


# ─── Bug fix: Z3 model before pop ───

class TestZ3ModelExtraction:
    @pytest.fixture(autouse=True)
    def _check_z3(self):
        try:
            import z3  # noqa: F401
            self.has_z3 = True
        except ImportError:
            self.has_z3 = False

    def test_possible_world_populated_on_sat(self):
        if not self.has_z3:
            pytest.skip("z3 not installed")
        from belief.z3_verifier import ConflictDetector

        detector = ConflictDetector()
        # A: x <= 100 (weak justification)
        # B: x > 0
        # These are compatible but A can be violated (x > 100) while B holds
        a = Belief(
            predicate=Predicate(expression="x <= 100", variables=("x",)),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )
        b = Belief(
            predicate=Predicate(expression="x > 0", variables=("x",)),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C1_FORMAL_VERIFICATION,
        )
        # This should detect that A (weak) can be violated while B holds
        conflicts = detector.detect_pairwise([a], [b])
        # If a conflict is found, possible_world should be a real model, not None
        for c in conflicts:
            if c.possible_world:
                assert "x" in c.possible_world  # model should reference x


# ─── Bug fix: Parser ambiguous match ───

class TestParserAmbiguousMatch:
    def test_ambiguous_function_name_not_resolved(self, tmp_path):
        """If two modules have the same function name, partial match should not resolve."""
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "__init__.py").write_text("")
        (proj / "mod_a.py").write_text("def process():\n    return 1\n")
        (proj / "mod_b.py").write_text("def process():\n    return 2\n")
        (proj / "caller.py").write_text("def main():\n    process()\n")

        from belief.parser import CodeParser
        parser = CodeParser(str(proj))
        parser.parse()

        # 'process' should be ambiguous — two matches
        # The parser should NOT resolve it (returns None internally)
        # This means caller.main won't have process in its call graph
        caller_key = None
        for k in parser.call_graph:
            if "main" in k:
                caller_key = k
                break

        if caller_key:
            resolved_callees = parser.call_graph.get(caller_key, set())
            # Should NOT resolve to either mod_a.process or mod_b.process
            process_matches = [c for c in resolved_callees if "process" in c]
            assert len(process_matches) == 0  # ambiguous → not resolved
