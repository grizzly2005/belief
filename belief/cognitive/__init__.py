"""
belief.cognitive — The intelligent core of BELIEF.

Transforms BELIEF from a linear pipeline into a cognitive system with:

  - CognitiveGraph: probabilistic typed graph with contradiction detection
  - CognitiveLoop: observe → reason → decide → act → learn cycle
  - HydraAgent:    goal-driven security investigation agent
  - MemoryEngine:  persistent learning across sessions

Quick start:
    from belief.cognitive import CognitiveLoop

    loop = CognitiveLoop(
        project_path="/path/to/code",
        enabled_bridges={"bandit", "dlint", "path_traversal", "safety_db"},
    )
    report = loop.run()
    print(report.summary())
"""

from .belief_graph import CognitiveGraph, Contradiction, Relation, RelationType
from .cognitive_loop import CognitiveLoop, CognitiveReport
from .hydra_agent import (HydraAgent, Goal, Verdict, VerdictStatus, Evidence,
                          AttackPlan, AttackPhase)
from .memory_engine import MemoryEngine, MemoryEntry, AnalysisRecord

__all__ = [
    # Graph
    "CognitiveGraph", "Contradiction", "Relation", "RelationType",
    # Loop
    "CognitiveLoop", "CognitiveReport",
    # Agent
    "HydraAgent", "Goal", "Verdict", "VerdictStatus", "Evidence",
    "AttackPlan", "AttackPhase",
    # Memory
    "MemoryEngine", "MemoryEntry", "AnalysisRecord",
]
