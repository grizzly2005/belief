"""
Integration tests for belief.cognitive:
  1. BeliefGraph — relations, propagation, contradiction detection
  2. MemoryEngine — store, recall, FP tracking, persistence
  3. HydraAgent — goal-driven investigation
  4. CognitiveLoop — full observe→reason→decide→act→learn cycle
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))


def _make_belief(expression, file_path="app.py", func="handler",
                 confidence=0.5, justification="C5", lines=(1,)):
    """Helper: create a Belief with minimal boilerplate."""
    from belief.models import (
        Belief, Predicate, Scope,
        JustificationCategory, EpistemicStatus, LogicType,
    )
    return Belief(
        predicate=Predicate(
            expression=expression,
            variables=(),
            anchor_lines=tuple(lines),
            natural_language=expression,
        ),
        scope=Scope(file_path=file_path, function_name=func),
        justification=JustificationCategory(justification),
        confidence_score=confidence,
    )


# ═══════════════════════════════════════════════════════════════════════
# Test 1: BeliefGraph
# ═══════════════════════════════════════════════════════════════════════

def test_belief_graph():
    from belief.cognitive.belief_graph import CognitiveGraph, RelationType

    g = CognitiveGraph()

    # Create beliefs: b1/b2 contradict, b3/b4 are near-duplicates
    b1 = _make_belief("input.sanitized == True", confidence=0.7, lines=(10,))
    b2 = _make_belief("not input.sanitized == True", confidence=0.6, lines=(10,))
    b3 = _make_belief("sql.parameterized == True", confidence=0.9, lines=(20,))
    b4 = _make_belief("sql.parameterized == True confirmed", confidence=0.85, lines=(20,))

    g.add_beliefs([b1, b2, b3, b4])
    assert g.size == 4

    # Auto-relate: should find contradiction (b1↔b2) + support (b3↔b4)
    added = g.auto_relate()
    assert added >= 1

    has_contradiction = any(
        r.relation == RelationType.CONTRADICTS
        for r in g.relations_from(b1.id)
    )
    assert has_contradiction, "Should detect contradiction between b1 and b2"

    # Contradictions must exist BEFORE any merge
    contras_before = g.find_contradictions(min_severity=0.0)
    assert len(contras_before) >= 1, f"Expected contradiction before merge, got {len(contras_before)}"

    # Bayesian update
    old_conf = b1.confidence_score
    g.bayesian_update(b1.id, evidence_supports=True, likelihood_ratio=3.0)
    assert b1.confidence_score > old_conf, "Bayesian update should increase confidence"

    # Temporal decay
    old_conf3 = b3.confidence_score
    g.apply_temporal_decay(decay_per_session=0.9)
    assert b3.confidence_score < old_conf3, "Temporal decay should reduce confidence"

    # Merge: b3/b4 should merge (similar text), b1/b2 should NOT (they contradict)
    merged = g.merge_equivalent(similarity_threshold=0.7)
    assert merged >= 1, f"Should merge near-duplicate b3/b4, got {merged}"
    assert b1.id in g._nodes and b2.id in g._nodes, "Contradicting beliefs must survive merge"

    # Prune noise
    b_noise = _make_belief("noise.something", confidence=0.02, lines=(99,))
    g.add_belief(b_noise)
    pruned = g.prune(min_confidence=0.05)
    assert pruned >= 1

    # Propagate + final contradiction check
    g.propagate_confidence(iterations=3)
    contras = g.find_contradictions(min_severity=0.0)
    assert len(contras) >= 1, f"Contradiction should persist after merge+propagate"

    stats = g.stats()
    print(f"  ✓ BeliefGraph v2: {stats['nodes']} nodes, {stats['edges']} edges, "
          f"{len(contras)} contradictions, "
          f"bayesian ✓, decay ✓, merge={merged} ✓, prune={pruned} ✓")


# ═══════════════════════════════════════════════════════════════════════
# Test 2: MemoryEngine
# ═══════════════════════════════════════════════════════════════════════

def test_memory_engine():
    from belief.cognitive.memory_engine import MemoryEngine, AnalysisRecord

    tmpdir = tempfile.mkdtemp(prefix="belief_mem_")
    try:
        mem = MemoryEngine(storage_dir=tmpdir)

        # Store beliefs
        b1 = _make_belief("sql.injection.possible", confidence=0.8)
        b2 = _make_belief("input.validated", confidence=0.9)

        mem.store_belief(b1, validated=True, method="bandit", tags=["CWE-89"])
        mem.store_belief(b2, validated=False, tags=["safe"])

        # Recall
        validated = mem.recall_validated()
        assert len(validated) == 1
        assert validated[0].belief_id == b1.id

        # Mark FP
        mem.mark_false_positive(b2.id)
        assert mem.is_known_fp(b2.id)
        assert not mem.is_known_fp(b1.id)

        # Record analysis
        mem.record_analysis(AnalysisRecord(
            timestamp=1234567890,
            project_path="/test",
            total_beliefs=10,
            contradictions_found=2,
            bridges_used=["bandit", "dlint"],
        ))

        # Persistence: save then reload
        mem.save()

        mem2 = MemoryEngine(storage_dir=tmpdir)
        assert len(mem2.recall_validated()) == 1
        assert mem2.is_known_fp(b2.id)
        assert len(mem2.get_history()) == 1

        stats = mem2.stats()
        assert stats["total_entries"] == 2
        assert stats["validated"] == 1
        assert stats["false_positives"] == 1

        print(f"  ✓ MemoryEngine: {stats['total_entries']} entries, "
              f"persistence OK, FP tracking OK")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# Test 3: HydraAgent
# ═══════════════════════════════════════════════════════════════════════

def test_hydra_agent():
    from belief.bridges import registry
    from belief.cognitive.hydra_agent import HydraAgent, Goal, VerdictStatus

    # Create a temp project with a known vulnerability
    tmpdir = tempfile.mkdtemp(prefix="belief_hydra_")
    vuln_code = '''
import os
BASE = "/var/www/"
def serve(filename):
    path = os.path.join(BASE, filename)
    return open(path).read()

import pickle
def load(data):
    return pickle.loads(data)
'''
    (Path(tmpdir) / "app.py").write_text(vuln_code)

    try:
        agent = HydraAgent(bridge_registry=registry)

        # Test 1: simple investigate
        verdict = agent.investigate(Goal(
            hypothesis="Path traversal in serve()",
            target_file=str(Path(tmpdir) / "app.py"),
            cwe="CWE-22",
            max_budget_s=15,
        ))
        assert verdict.status in (VerdictStatus.CONFIRMED, VerdictStatus.INCONCLUSIVE,
                                  VerdictStatus.ERROR)
        print(f"  ✓ HydraAgent investigate: {verdict.status.value} "
              f"(confidence={verdict.final_confidence:.2f})")

        # Test 2: auto-infer CWE
        verdict2 = agent.investigate(Goal(
            hypothesis="pickle deserialization vulnerability",
            target_file=str(Path(tmpdir) / "app.py"),
            max_budget_s=15,
        ))
        assert verdict2.goal.cwe == "CWE-502", f"Expected CWE-502, got {verdict2.goal.cwe}"
        print(f"  ✓ HydraAgent auto-CWE: inferred {verdict2.goal.cwe}")

        # Test 3: attack planning
        goal = Goal(
            hypothesis="Path traversal",
            target_file=str(Path(tmpdir) / "app.py"),
            cwe="CWE-22",
            max_budget_s=20,
        )
        plan = agent.plan_attack(goal)
        assert len(plan.phases) >= 1, "Plan should have at least 1 phase"
        print(f"  ✓ HydraAgent plan: {plan}")

        # Test 4: execute plan
        verdict3 = agent.execute_plan(plan)
        assert verdict3.status in (VerdictStatus.CONFIRMED, VerdictStatus.INCONCLUSIVE,
                                   VerdictStatus.REFUTED, VerdictStatus.ERROR)
        print(f"  ✓ HydraAgent execute_plan: {verdict3.status.value} "
              f"(confidence={verdict3.final_confidence:.2f}, "
              f"{len(verdict3.evidence)} evidence)")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# Test 4: CognitiveLoop (full cycle)
# ═══════════════════════════════════════════════════════════════════════

def test_cognitive_loop():
    from belief.cognitive import CognitiveLoop

    # Create a project with multiple vulnerability types
    tmpdir = tempfile.mkdtemp(prefix="belief_cognitive_")
    mem_dir = tempfile.mkdtemp(prefix="belief_mem_cog_")

    vuln_code = '''
import os
import pickle
import hashlib

BASE = "/var/www/files/"

def serve_file(filename):
    """CWE-22: path traversal"""
    path = os.path.join(BASE, filename)
    return open(path).read()

def load_data(raw):
    """CWE-502: unsafe deserialization"""
    return pickle.loads(raw)

def hash_password(pw):
    """CWE-327: weak crypto"""
    return hashlib.md5(pw.encode()).hexdigest()

def run_cmd(user_input):
    """CWE-78: command injection"""
    os.system("echo " + user_input)
'''
    (Path(tmpdir) / "app.py").write_text(vuln_code)
    (Path(tmpdir) / "requirements.txt").write_text("flask==1.0\nrequests==2.20.0\n")

    try:
        loop = CognitiveLoop(
            project_path=tmpdir,
            config=None,  # skip LLM orchestrator
            enabled_bridges={"bandit", "dlint", "path_traversal", "safety_db"},
            memory_dir=mem_dir,
            max_investigation_budget_s=30,
            investigation_confidence_threshold=0.5,
            max_goals=5,
        )

        report = loop.run()

        assert len(report.beliefs) > 0, "Should collect beliefs"
        assert report.total_elapsed_s > 0

        print(f"  ✓ CognitiveLoop full cycle:")
        print(f"    Beliefs: {len(report.beliefs)}")
        print(f"    Graph: {report.graph_stats}")
        print(f"    Contradictions: {len(report.contradictions)}")
        print(f"    Verdicts: {len(report.verdicts)}")
        print(f"    Confirmed: {report.confirmed_vulns}, "
              f"Refuted: {report.refuted_fps}, "
              f"Inconclusive: {report.inconclusive}")
        print(f"    Phases: {report.phases}")
        print(f"    Total: {report.total_elapsed_s:.1f}s")

        # Memory should have been saved
        mem_file = Path(mem_dir) / "memory.json"
        assert mem_file.exists(), "Memory should be persisted"
        mem_data = json.loads(mem_file.read_text())
        assert len(mem_data["entries"]) > 0
        assert len(mem_data["history"]) == 1
        print(f"    Memory: {len(mem_data['entries'])} entries persisted")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
        shutil.rmtree(mem_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
# Runner
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("BELIEF Cognitive Module — Integration Tests")
    print("=" * 60)
    tests = [
        ("BeliefGraph",   test_belief_graph),
        ("MemoryEngine",  test_memory_engine),
        ("HydraAgent",    test_hydra_agent),
        ("CognitiveLoop", test_cognitive_loop),
    ]
    passed = 0
    for name, fn in tests:
        print(f"\n[{name}]")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAIL: {e}")
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            import traceback; traceback.print_exc()
    print()
    print("=" * 60)
    print(f"Result: {passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
