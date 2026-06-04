"""Data models for code analysis results."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import hashlib


class IssueType(Enum):
    """Types of issues that can be detected."""
    BUG = "bug"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CODE_SMELL = "code_smell"
    UNUSED_CODE = "unused_code"
    COMPLEXITY = "complexity"
    CONCEPTUAL = "conceptual"
    DOCUMENTATION = "documentation"
    DEPRECATION = "deprecation"
    TYPE_ERROR = "type_error"


class IssueSeverity(Enum):
    """Severity levels for issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeLocation:
    """Represents a location in source code."""
    file_path: str
    line_start: int
    line_end: int
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    
    def __str__(self):
        """String representation of location."""
        loc = f"{self.file_path}:{self.line_start}"
        if self.line_end != self.line_start:
            loc += f"-{self.line_end}"
        if self.function_name:
            loc += f" in {self.function_name}()"
        if self.class_name:
            loc += f" [{self.class_name}]"
        return loc


@dataclass
class Issue:
    """Represents a detected issue in the code."""
    issue_type: IssueType
    severity: IssueSeverity
    title: str
    description: str
    location: CodeLocation
    recommendation: Optional[str] = None
    code_snippet: Optional[str] = None
    related_locations: List[CodeLocation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def fingerprint(self) -> str:
        """Generate unique fingerprint for issue tracking."""
        # Use location and title to generate stable fingerprint
        key = f"{self.location.file_path}:{self.location.line_start}:{self.title}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to dictionary."""
        return {
            "type": self.issue_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": str(self.location),
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    location: CodeLocation
    parameters: List[str]
    return_type: Optional[str]
    docstring: Optional[str]
    complexity: int = 0
    is_async: bool = False
    is_generator: bool = False
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    source_code: Optional[str] = None
    lines_of_code: Optional[int] = None


@dataclass
class ClassInfo:
    """Information about a class."""
    name: str
    location: CodeLocation
    bases: List[str]
    docstring: Optional[str]
    methods: List[FunctionInfo] = field(default_factory=list)
    attributes: List[str] = field(default_factory=list)
    is_abstract: bool = False
    source_code: Optional[str] = None
    lines_of_code: Optional[int] = None


@dataclass
class ModuleInfo:
    """Information about a module."""
    name: str
    file_path: str
    docstring: Optional[str]
    imports: List[str] = field(default_factory=list)
    classes: List[ClassInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    constants: Dict[str, Any] = field(default_factory=dict)
    lines_of_code: int = 0
    complexity: int = 0


@dataclass
class CriticalSection:
    """Represents a critical section of code."""
    name: str
    location: CodeLocation
    reason: str
    risk_level: IssueSeverity
    dependencies: List[str] = field(default_factory=list)
    impact_areas: List[str] = field(default_factory=list)


@dataclass
class AnalysisMetrics:
    """Overall metrics from code analysis."""
    total_files: int = 0
    total_lines: int = 0
    total_classes: int = 0
    total_functions: int = 0
    total_issues: int = 0
    issues_by_severity: Dict[str, int] = field(default_factory=dict)
    issues_by_type: Dict[str, int] = field(default_factory=dict)
    average_complexity: float = 0.0
    max_complexity: int = 0
    test_coverage: Optional[float] = None


@dataclass
class AnalysisResult:
    """Complete result of code analysis."""
    project_path: str
    analysis_date: datetime
    modules: List[ModuleInfo] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    critical_sections: List[CriticalSection] = field(default_factory=list)
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    dependency_graph: Dict[str, List[str]] = field(default_factory=dict)
    entry_points: List[str] = field(default_factory=list)
    important_sections: List[Any] = field(default_factory=list)  # List[ImportantSection]
    improvements: List[Any] = field(default_factory=list)  # List[ImprovementOpportunity]
    
    def get_issues_by_severity(self, severity: IssueSeverity) -> List[Issue]:
        """Get all issues of a specific severity."""
        return [i for i in self.issues if i.severity == severity]
    
    def get_issues_by_type(self, issue_type: IssueType) -> List[Issue]:
        """Get all issues of a specific type."""
        return [i for i in self.issues if i.issue_type == issue_type]
