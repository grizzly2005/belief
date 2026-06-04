"""Code library system for learning from classified code examples.

Allows users to build a library of code classified as excellent, good, smelly, or bad
for pattern matching and quality assessment.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import yaml
import ast
import difflib
from collections import Counter

from .models import ModuleInfo, FunctionInfo, ClassInfo, Issue, IssueType, IssueSeverity, CodeLocation


class CodeQuality(str, Enum):
    """Code quality classification."""
    EXCELLENT = "excellent"
    GOOD = "good"
    SMELLY = "smelly"
    BAD = "bad"


class PatternType(str, Enum):
    """Type of code pattern."""
    SINGLETON = "singleton"
    FACTORY = "factory"
    OBSERVER = "observer"
    STRATEGY = "strategy"
    ERROR_HANDLING = "error_handling"
    VALIDATION = "validation"
    SECURITY = "security"
    PERFORMANCE = "performance"
    TESTING = "testing"
    DOCUMENTATION = "documentation"
    NAMING = "naming"
    STRUCTURE = "structure"
    GENERAL = "general"


@dataclass
class CodeExample:
    """A classified code example."""
    id: str
    classification: CodeQuality
    pattern_type: PatternType
    language: str
    code: str
    description: str = ""
    reason: str = ""
    tags: List[str] = field(default_factory=list)
    alternative: Optional[str] = None  # Better alternative for bad/smelly code
    
    def __post_init__(self):
        # Convert strings to enums if needed
        if isinstance(self.classification, str):
            self.classification = CodeQuality(self.classification)
        if isinstance(self.pattern_type, str):
            self.pattern_type = PatternType(self.pattern_type)


@dataclass
class PatternMatch:
    """A match between code and a library example."""
    example: CodeExample
    location: CodeLocation
    similarity: float  # 0.0 to 1.0
    matched_code: str
    context: str = ""


class CodeLibrary:
    """Manages a library of classified code examples."""
    
    def __init__(self, library_path: Optional[Path] = None):
        """
        Initialize code library.
        
        Args:
            library_path: Path to YAML file containing code examples
        """
        self.examples: List[CodeExample] = []
        self.library_path = library_path
        
        if library_path and library_path.exists():
            self.load_from_file(library_path)
    
    def load_from_file(self, path: Path):
        """Load code examples from YAML file."""
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data or 'examples' not in data:
                return
            
            for example_data in data['examples']:
                try:
                    example = CodeExample(**example_data)
                    self.examples.append(example)
                except Exception as e:
                    print(f"   ⚠️  Failed to load example {example_data.get('id')}: {e}")
        
        except Exception as e:
            print(f"   ⚠️  Failed to load code library from {path}: {e}")
    
    def save_to_file(self, path: Path):
        """Save code examples to YAML file."""
        data = {
            'examples': [
                {
                    'id': ex.id,
                    'classification': ex.classification.value,
                    'pattern_type': ex.pattern_type.value,
                    'language': ex.language,
                    'code': ex.code,
                    'description': ex.description,
                    'reason': ex.reason,
                    'tags': ex.tags,
                    'alternative': ex.alternative
                }
                for ex in self.examples
            ]
        }
        
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    def add_example(self, example: CodeExample):
        """Add an example to the library."""
        self.examples.append(example)
    
    def get_by_quality(self, quality: CodeQuality) -> List[CodeExample]:
        """Get all examples of a specific quality level."""
        return [ex for ex in self.examples if ex.classification == quality]
    
    def get_by_pattern(self, pattern_type: PatternType) -> List[CodeExample]:
        """Get all examples of a specific pattern type."""
        return [ex for ex in self.examples if ex.pattern_type == pattern_type]
    
    def get_by_tag(self, tag: str) -> List[CodeExample]:
        """Get all examples with a specific tag."""
        return [ex for ex in self.examples if tag in ex.tags]


class PatternMatcher:
    """Matches code against library examples."""
    
    def __init__(self, library: CodeLibrary, similarity_threshold: float = 0.7):
        """
        Initialize pattern matcher.
        
        Args:
            library: Code library to match against
            similarity_threshold: Minimum similarity score (0.0 to 1.0)
        """
        self.library = library
        self.similarity_threshold = similarity_threshold
    
    def _calculate_similarity(self, code1: str, code2: str) -> float:
        """
        Calculate similarity between two code snippets.
        
        Uses a combination of:
        - Text similarity (difflib)
        - AST structure similarity
        - Token similarity
        
        Returns:
            Similarity score from 0.0 to 1.0
        """
        # Text similarity
        text_sim = difflib.SequenceMatcher(None, code1, code2).ratio()
        
        try:
            # AST structure similarity
            tree1 = ast.parse(code1)
            tree2 = ast.parse(code2)
            
            nodes1 = [type(node).__name__ for node in ast.walk(tree1)]
            nodes2 = [type(node).__name__ for node in ast.walk(tree2)]
            
            # Compare node type sequences
            ast_sim = difflib.SequenceMatcher(None, nodes1, nodes2).ratio()
            
            # Token similarity (node type frequencies)
            counter1 = Counter(nodes1)
            counter2 = Counter(nodes2)
            
            all_nodes = set(counter1.keys()) | set(counter2.keys())
            token_sim = sum(min(counter1[n], counter2[n]) for n in all_nodes) / max(len(nodes1), len(nodes2))
            
            # Weighted average
            return 0.3 * text_sim + 0.4 * ast_sim + 0.3 * token_sim
        
        except:
            # Fall back to text similarity if AST parsing fails
            return text_sim
    
    def _extract_code_snippets(self, module: ModuleInfo) -> List[tuple]:
        """
        Extract code snippets from module.
        
        Returns:
            List of (code, location, context) tuples
        """
        snippets = []
        
        # Extract functions
        for func in module.functions:
            if func.source_code:
                snippets.append((
                    func.source_code,
                    func.location,
                    f"Function: {func.name}"
                ))
        
        # Extract classes
        for cls in module.classes:
            if cls.source_code:
                snippets.append((
                    cls.source_code,
                    cls.location,
                    f"Class: {cls.name}"
                ))
            
            # Extract methods
            for method in cls.methods:
                if method.source_code:
                    snippets.append((
                        method.source_code,
                        method.location,
                        f"Method: {cls.name}.{method.name}"
                    ))
        
        return snippets
    
    def find_matches(self, module: ModuleInfo) -> List[PatternMatch]:
        """
        Find matches between module code and library examples.
        
        Args:
            module: Module to analyze
            
        Returns:
            List of pattern matches
        """
        matches = []
        snippets = self._extract_code_snippets(module)
        
        for code, location, context in snippets:
            for example in self.library.examples:
                similarity = self._calculate_similarity(code, example.code)
                
                if similarity >= self.similarity_threshold:
                    matches.append(PatternMatch(
                        example=example,
                        location=location,
                        similarity=similarity,
                        matched_code=code,
                        context=context
                    ))
        
        # Sort by similarity (highest first)
        matches.sort(key=lambda m: m.similarity, reverse=True)
        
        return matches
    
    def generate_issues_from_matches(self, matches: List[PatternMatch]) -> List[Issue]:
        """
        Generate issues from pattern matches.
        
        Args:
            matches: List of pattern matches
            
        Returns:
            List of issues
        """
        issues = []
        
        for match in matches:
            example = match.example
            
            # Skip excellent and good patterns
            if example.classification in [CodeQuality.EXCELLENT, CodeQuality.GOOD]:
                continue
            
            # Generate issue for smelly/bad patterns
            severity = IssueSeverity.HIGH if example.classification == CodeQuality.BAD else IssueSeverity.MEDIUM
            
            issue = Issue(
                issue_type=IssueType.CODE_SMELL,
                severity=severity,
                title=f"{example.classification.value.title()} code pattern detected: {example.pattern_type.value}",
                description=f"{example.reason}\n\nMatched with {match.similarity:.1%} similarity in {match.context}",
                location=match.location,
                recommendation=example.alternative or f"Review and refactor this {example.pattern_type.value} pattern"
            )
            
            issues.append(issue)
        
        return issues
    
    def generate_quality_report(self, matches: List[PatternMatch]) -> Dict[str, Any]:
        """
        Generate quality report from pattern matches.
        
        Args:
            matches: List of pattern matches
            
        Returns:
            Dictionary with quality metrics
        """
        quality_counts = {q: 0 for q in CodeQuality}
        pattern_counts = {p: 0 for p in PatternType}
        
        for match in matches:
            quality_counts[match.example.classification] += 1
            pattern_counts[match.example.pattern_type] += 1
        
        # Calculate quality score (0-100)
        total = len(matches)
        if total > 0:
            quality_score = (
                quality_counts[CodeQuality.EXCELLENT] * 100 +
                quality_counts[CodeQuality.GOOD] * 75 +
                quality_counts[CodeQuality.SMELLY] * 40 +
                quality_counts[CodeQuality.BAD] * 0
            ) / total
        else:
            quality_score = 0
        
        return {
            'total_matches': total,
            'quality_score': round(quality_score, 1),
            'quality_distribution': {
                q.value: quality_counts[q] for q in CodeQuality
            },
            'pattern_distribution': {
                p.value: pattern_counts[p] for p in PatternType if pattern_counts[p] > 0
            },
            'top_patterns': sorted(
                [(p.value, count) for p, count in pattern_counts.items() if count > 0],
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }


def create_default_library() -> CodeLibrary:
    """Create a code library with default examples."""
    library = CodeLibrary()
    
    # Excellent examples
    library.add_example(CodeExample(
        id="singleton-excellent-001",
        classification=CodeQuality.EXCELLENT,
        pattern_type=PatternType.SINGLETON,
        language="python",
        code="""class Singleton:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance""",
        description="Thread-safe singleton with double-checked locking",
        tags=["design-pattern", "thread-safe"]
    ))
    
    library.add_example(CodeExample(
        id="error-handling-excellent-001",
        classification=CodeQuality.EXCELLENT,
        pattern_type=PatternType.ERROR_HANDLING,
        language="python",
        code="""def read_file(path: str) -> str:
    try:
        with open(path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        raise
    except PermissionError:
        logger.error(f"Permission denied: {path}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error reading {path}: {e}")
        raise""",
        description="Proper error handling with specific exceptions and logging",
        tags=["error-handling", "logging"]
    ))
    
    # Bad examples
    library.add_example(CodeExample(
        id="eval-bad-001",
        classification=CodeQuality.BAD,
        pattern_type=PatternType.SECURITY,
        language="python",
        code="""result = eval(user_input)""",
        description="Using eval() on user input",
        reason="Arbitrary code execution vulnerability - eval allows execution of any Python code",
        tags=["security", "injection"],
        alternative="Use ast.literal_eval() for safe evaluation or validate/parse input explicitly"
    ))
    
    library.add_example(CodeExample(
        id="bare-except-bad-001",
        classification=CodeQuality.BAD,
        pattern_type=PatternType.ERROR_HANDLING,
        language="python",
        code="""try:
    do_something()
except:
    pass""",
        description="Bare except clause that swallows all exceptions",
        reason="Silently catches all exceptions including KeyboardInterrupt and SystemExit, making debugging impossible",
        tags=["error-handling"],
        alternative="Catch specific exceptions and handle or log them appropriately"
    ))
    
    # Smelly examples
    library.add_example(CodeExample(
        id="god-class-smelly-001",
        classification=CodeQuality.SMELLY,
        pattern_type=PatternType.STRUCTURE,
        language="python",
        code="""class Manager:
    def __init__(self):
        pass
    
    def do_everything(self):
        self.connect_database()
        self.send_email()
        self.process_payment()
        self.generate_report()
        self.update_cache()""",
        description="God class doing too many unrelated things",
        reason="Violates Single Responsibility Principle - class has too many responsibilities",
        tags=["solid", "structure"],
        alternative="Split into separate classes: DatabaseManager, EmailService, PaymentProcessor, ReportGenerator, CacheManager"
    ))
    
    return library
