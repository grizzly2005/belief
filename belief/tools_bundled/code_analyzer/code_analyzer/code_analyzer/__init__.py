"""Code Analyzer - Deep source code analysis and documentation tool."""

__version__ = "0.1.0"

from .analyzer import CodeAnalyzer
from .models import AnalysisResult, CodeLocation, Issue, IssueType, IssueSeverity
from .plugins import AnalyzerPlugin, CustomRulePlugin, PluginManager
from .code_library import (
    CodeLibrary, CodeExample, CodeQuality, PatternType, 
    PatternMatcher, create_default_library
)

__all__ = [
    "CodeAnalyzer",
    "AnalysisResult",
    "CodeLocation",
    "Issue",
    "IssueType",
    "IssueSeverity",
    "AnalyzerPlugin",
    "CustomRulePlugin",
    "PluginManager",
    "CodeLibrary",
    "CodeExample",
    "CodeQuality",
    "PatternType",
    "PatternMatcher",
    "create_default_library",
]
