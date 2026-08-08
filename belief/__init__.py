"""
BELIEF — Belief Extraction and Logical Inference for Exploitable Flaws

A paradigm-shifting framework for software security analysis based on the
principle that vulnerabilities are conflicts between implicit developer beliefs.

Usage:
    from belief import Orchestrator, BeliefConfig

    config = BeliefConfig.default()
    with Orchestrator(config) as orch:
        report = orch.analyze_project("/path/to/project")
        report.save("belief_report.json")
"""

__version__ = "0.2.0"
__author__ = "BELIEF Research"

from .models import (
    AnalysisReport,
    ArtifactKind,
    Belief,
    Conflict,
    ConflictSeverity,
    DriftEvent,
    DriftType,
    EpistemicStatus,
    Frontier,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from .config import BeliefConfig
from .orchestrator import Orchestrator
from .structural import StructuralExtractor
from .multilang import MultiLangParser

__all__ = [
    "AnalysisReport",
    "ArtifactKind",
    "Belief",
    "BeliefConfig",
    "Conflict",
    "ConflictSeverity",
    "DriftEvent",
    "DriftType",
    "EpistemicStatus",
    "Frontier",
    "JustificationCategory",
    "LogicType",
    "MultiLangParser",
    "Orchestrator",
    "Predicate",
    "Scope",
    "StructuralExtractor",
]
