"""Composable deterministic semantic-analysis primitives."""

from .models import (
    ANALYSIS_GAP_SCHEMA_VERSION,
    FLOW_STATE_SCHEMA_VERSION,
    FUNCTION_SUMMARY_SCHEMA_VERSION,
    AnalysisGap,
    FlowState,
    FunctionEffect,
    FunctionSummary,
    GuardEffect,
    ResourceIdentity,
    RootCauseIdentity,
    SecurityTransition,
    SummaryKind,
)
from .summaries import (
    FunctionSummaryAnalysis,
    FunctionSummaryLimits,
    analyze_function_summaries,
)
from .flow import analyze_semantic_flow
from .observations import (
    SEMANTIC_CONCERN_SCHEMA_VERSION,
    SEMANTIC_FLOW_ANALYSIS_SCHEMA_VERSION,
    SemanticConcern,
    SemanticFlowAnalysis,
    SemanticFlowLimits,
)

__all__ = [
    "ANALYSIS_GAP_SCHEMA_VERSION",
    "FLOW_STATE_SCHEMA_VERSION",
    "FUNCTION_SUMMARY_SCHEMA_VERSION",
    "AnalysisGap",
    "FlowState",
    "FunctionEffect",
    "FunctionSummary",
    "FunctionSummaryAnalysis",
    "FunctionSummaryLimits",
    "GuardEffect",
    "ResourceIdentity",
    "RootCauseIdentity",
    "SecurityTransition",
    "SummaryKind",
    "SEMANTIC_CONCERN_SCHEMA_VERSION",
    "SEMANTIC_FLOW_ANALYSIS_SCHEMA_VERSION",
    "SemanticConcern",
    "SemanticFlowAnalysis",
    "SemanticFlowLimits",
    "analyze_function_summaries",
    "analyze_semantic_flow",
]
