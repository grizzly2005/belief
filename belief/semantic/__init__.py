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
    "analyze_function_summaries",
]
