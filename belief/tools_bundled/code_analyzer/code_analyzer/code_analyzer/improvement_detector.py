"""Detects code sections that need updates and improvements.

This module identifies:
- Deprecated patterns and APIs
- Hard-coded values that should be configurable
- Code that needs refactoring
- Missing error handling
- Missing validation
- Areas needing tests
- Performance bottlenecks
- Scalability concerns
"""

from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
import re

from .models import ModuleInfo, FunctionInfo, ClassInfo, CodeLocation, Issue, IssueType, IssueSeverity


@dataclass
class ImprovementOpportunity:
    """Represents an opportunity for code improvement."""
    name: str
    location: CodeLocation
    category: str  # refactoring, configuration, error_handling, validation, testing, performance, scalability
    priority: str  # critical, high, medium, low
    issue: str
    suggestion: str
    effort: str  # small, medium, large
    impact: str  # low, medium, high
    examples: List[str] = field(default_factory=list)
    related_code: List[str] = field(default_factory=list)


class ImprovementDetector:
    """Detects code that needs updates and improvements."""
    
    def __init__(self):
        self.improvements: List[ImprovementOpportunity] = []
        
        # Patterns to detect
        self.deprecated_patterns = {
            'os.system': 'Use subprocess.run() instead',
            'eval(': 'Use ast.literal_eval() for safe evaluation',
            'exec(': 'Avoid dynamic code execution',
            'pickle.load': 'Consider safer serialization formats (JSON, msgpack)',
            '__import__': 'Use importlib.import_module() instead',
        }
        
        self.magic_numbers = set()
        self.hard_coded_paths = []
        self.missing_error_handlers = []
    
    def detect_improvements(self, modules: List[ModuleInfo]) -> List[ImprovementOpportunity]:
        """
        Detect all improvement opportunities in the codebase.
        
        Args:
            modules: List of analyzed modules
            
        Returns:
            List of improvement opportunities
        """
        self.improvements = []
        
        for module in modules:
            # Detect deprecated patterns
            self._detect_deprecated_patterns(module)
            
            # Detect hard-coded values
            self._detect_hard_coded_values(module)
            
            # Detect missing error handling
            self._detect_missing_error_handling(module)
            
            # Detect missing validation
            self._detect_missing_validation(module)
            
            # Detect code needing tests
            self._detect_untested_code(module)
            
            # Detect performance issues
            self._detect_performance_issues(module)
            
            # Detect scalability concerns
            self._detect_scalability_issues(module)
            
            # Detect refactoring opportunities
            self._detect_refactoring_opportunities(module)
            
            # Detect configuration opportunities
            self._detect_configuration_opportunities(module)
        
        return self.improvements
    
    def _detect_deprecated_patterns(self, module: ModuleInfo):
        """Detect deprecated patterns and APIs."""
        for func in module.functions:
            for deprecated, suggestion in self.deprecated_patterns.items():
                if deprecated in str(func.calls):
                    self.improvements.append(ImprovementOpportunity(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="refactoring",
                        priority="high",
                        issue=f"Uses deprecated pattern: {deprecated}",
                        suggestion=suggestion,
                        effort="small",
                        impact="high",
                        examples=[f"Replace {deprecated} with safer alternative"]
                    ))
    
    def _detect_hard_coded_values(self, module: ModuleInfo):
        """Detect hard-coded values that should be configurable."""
        # Check for hard-coded paths
        path_patterns = [
            r'/home/\w+', r'/Users/\w+', r'C:\\Users\\',
            r'/var/\w+', r'/tmp/\w+', r'/etc/\w+'
        ]
        
        for func in module.functions:
            # This is a simplified check - in reality would need AST analysis
            if any(re.search(pattern, func.name) for pattern in path_patterns):
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="configuration",
                    priority="medium",
                    issue="Contains hard-coded path",
                    suggestion="Move to configuration file or environment variable",
                    effort="small",
                    impact="medium",
                    examples=["Use pathlib and config: Path(config.data_dir) / 'file.txt'"]
                ))
        
        # Check for magic numbers in complex functions
        for func in module.functions:
            if func.complexity > 5:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="refactoring",
                    priority="low",
                    issue="Complex function may contain magic numbers",
                    suggestion="Extract magic numbers to named constants",
                    effort="small",
                    impact="low",
                    examples=["MAX_RETRIES = 3", "TIMEOUT_SECONDS = 30"]
                ))
    
    def _detect_missing_error_handling(self, module: ModuleInfo):
        """Detect functions missing error handling."""
        for func in module.functions:
            # Functions that interact with external resources need error handling
            risky_operations = ['open', 'requests', 'urllib', 'socket', 'subprocess']
            
            if any(op in str(func.calls) for op in risky_operations):
                # Check if function name suggests no error handling
                if 'try' not in func.name.lower() and 'safe' not in func.name.lower():
                    self.improvements.append(ImprovementOpportunity(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="error_handling",
                        priority="high",
                        issue="Performs risky operations without apparent error handling",
                        suggestion="Add try-except blocks for external operations",
                        effort="small",
                        impact="high",
                        examples=[
                            "try:",
                            "    result = risky_operation()",
                            "except SpecificError as e:",
                            "    logger.error(f'Operation failed: {e}')",
                            "    raise CustomError() from e"
                        ]
                    ))
    
    def _detect_missing_validation(self, module: ModuleInfo):
        """Detect functions missing input validation."""
        for func in module.functions:
            # Public functions with parameters should validate inputs
            if not func.name.startswith('_') and len(func.parameters) > 1:
                if not func.docstring or 'raises' not in func.docstring.lower():
                    self.improvements.append(ImprovementOpportunity(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="validation",
                        priority="medium",
                        issue="Public function may lack input validation",
                        suggestion="Add validation for parameters and document exceptions",
                        effort="small",
                        impact="medium",
                        examples=[
                            "if not isinstance(param, expected_type):",
                            "    raise TypeError(f'Expected {expected_type}, got {type(param)}')",
                            "if param < 0:",
                            "    raise ValueError('Parameter must be non-negative')"
                        ]
                    ))
    
    def _detect_untested_code(self, module: ModuleInfo):
        """Detect code that likely needs tests."""
        # Skip test modules themselves
        if 'test' in module.name.lower():
            return
        
        for func in module.functions:
            # Complex or critical functions need tests
            if func.complexity > 5 or func.name in ['main', 'process', 'calculate']:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="testing",
                    priority="high" if func.complexity > 10 else "medium",
                    issue=f"Complex function (complexity {func.complexity}) needs tests",
                    suggestion="Add unit tests covering happy path and edge cases",
                    effort="medium",
                    impact="high",
                    examples=[
                        "def test_function_happy_path():",
                        "    result = function(valid_input)",
                        "    assert result == expected",
                        "",
                        "def test_function_edge_cases():",
                        "    with pytest.raises(ValueError):",
                        "        function(invalid_input)"
                    ]
                ))
        
        # Classes with many methods need tests
        for cls in module.classes:
            if len(cls.methods) > 5:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="testing",
                    priority="high",
                    issue=f"Large class ({len(cls.methods)} methods) needs comprehensive tests",
                    suggestion="Add test class with fixtures and test methods for all public methods",
                    effort="large",
                    impact="high",
                    examples=[
                        "class TestClassName:",
                        "    @pytest.fixture",
                        "    def instance(self):",
                        "        return ClassName()",
                        "    ",
                        "    def test_method_name(self, instance):",
                        "        result = instance.method()",
                        "        assert result is not None"
                    ]
                ))
    
    def _detect_performance_issues(self, module: ModuleInfo):
        """Detect potential performance issues."""
        for func in module.functions:
            # Nested loops indicate O(n²) or worse
            if 'for' in str(func.calls):
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="performance",
                    priority="medium",
                    issue="May contain nested loops leading to O(n²) complexity",
                    suggestion="Consider using data structures (dict, set) or algorithms to reduce complexity",
                    effort="medium",
                    impact="medium",
                    examples=[
                        "# Instead of nested loops:",
                        "lookup = {item.key: item for item in items}",
                        "for key in keys:",
                        "    item = lookup.get(key)  # O(1) instead of O(n)"
                    ]
                ))
            
            # Functions making multiple similar calls could benefit from caching
            if func.complexity > 8 and any(call in str(func.calls) for call in ['get', 'find', 'fetch']):
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="performance",
                    priority="low",
                    issue="Complex function with repeated lookups could benefit from caching",
                    suggestion="Add @lru_cache decorator or implement custom caching",
                    effort="small",
                    impact="medium",
                    examples=[
                        "from functools import lru_cache",
                        "",
                        "@lru_cache(maxsize=128)",
                        "def expensive_function(param):",
                        "    # Expensive computation",
                        "    return result"
                    ]
                ))
    
    def _detect_scalability_issues(self, module: ModuleInfo):
        """Detect scalability concerns."""
        for func in module.functions:
            # Functions loading all data into memory
            load_indicators = ['load_all', 'get_all', 'fetch_all', 'read_all']
            if any(indicator in func.name.lower() for indicator in load_indicators):
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="scalability",
                    priority="high",
                    issue="Loads all data into memory, won't scale with large datasets",
                    suggestion="Implement pagination or streaming/generator pattern",
                    effort="medium",
                    impact="high",
                    examples=[
                        "# Generator pattern:",
                        "def load_items_batch(batch_size=100):",
                        "    offset = 0",
                        "    while True:",
                        "        batch = fetch_batch(offset, batch_size)",
                        "        if not batch:",
                        "            break",
                        "        yield from batch",
                        "        offset += batch_size"
                    ]
                ))
            
            # Synchronous operations that should be async
            if func.name.startswith('fetch') or func.name.startswith('get'):
                if not func.is_async and any(op in str(func.calls) for op in ['requests', 'urllib']):
                    self.improvements.append(ImprovementOpportunity(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="scalability",
                        priority="medium",
                        issue="Synchronous I/O operation blocks execution",
                        suggestion="Consider async/await for concurrent operations",
                        effort="medium",
                        impact="medium",
                        examples=[
                            "import asyncio",
                            "import aiohttp",
                            "",
                            "async def fetch_data(url):",
                            "    async with aiohttp.ClientSession() as session:",
                            "        async with session.get(url) as response:",
                            "            return await response.json()"
                        ]
                    ))
    
    def _detect_refactoring_opportunities(self, module: ModuleInfo):
        """Detect code needing refactoring."""
        for func in module.functions:
            # Very long functions
            if func.complexity > 15:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="refactoring",
                    priority="high",
                    issue=f"Very high complexity ({func.complexity}) - function does too much",
                    suggestion="Extract methods to break down functionality",
                    effort="large",
                    impact="high",
                    examples=[
                        "# Extract logical sections:",
                        "def main_function(data):",
                        "    validated = _validate_input(data)",
                        "    processed = _process_data(validated)",
                        "    result = _format_output(processed)",
                        "    return result"
                    ]
                ))
            
            # Long parameter lists
            if len(func.parameters) > 5:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="refactoring",
                    priority="medium",
                    issue=f"Too many parameters ({len(func.parameters)})",
                    suggestion="Group related parameters into a config object or use **kwargs",
                    effort="medium",
                    impact="medium",
                    examples=[
                        "# Use dataclass for config:",
                        "@dataclass",
                        "class ProcessConfig:",
                        "    param1: str",
                        "    param2: int",
                        "    param3: bool = False",
                        "",
                        "def process(data, config: ProcessConfig):",
                        "    # Use config.param1, config.param2, etc."
                    ]
                ))
        
        # God classes
        for cls in module.classes:
            if len(cls.methods) > 20:
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="refactoring",
                    priority="critical",
                    issue=f"God class with {len(cls.methods)} methods - violates SRP",
                    suggestion="Split into smaller, focused classes by responsibility",
                    effort="large",
                    impact="high",
                    examples=[
                        "# Split by responsibility:",
                        "class UserDataManager:  # Data operations",
                        "    pass",
                        "",
                        "class UserValidator:  # Validation logic",
                        "    pass",
                        "",
                        "class UserNotifier:  # Notifications",
                        "    pass"
                    ]
                ))
    
    def _detect_configuration_opportunities(self, module: ModuleInfo):
        """Detect values that should be configuration."""
        config_indicators = [
            'timeout', 'max_', 'min_', 'limit', 'threshold',
            'port', 'host', 'url', 'api_key', 'secret'
        ]
        
        for func in module.functions:
            if any(indicator in func.name.lower() for indicator in config_indicators):
                self.improvements.append(ImprovementOpportunity(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="configuration",
                    priority="medium",
                    issue="Contains values that should be configurable",
                    suggestion="Move to configuration file or environment variables",
                    effort="small",
                    impact="medium",
                    examples=[
                        "# config.yaml:",
                        "timeout: 30",
                        "max_retries: 3",
                        "",
                        "# In code:",
                        "config = load_config()",
                        "timeout = config.get('timeout', 30)"
                    ]
                ))
    
    def generate_summary(self, improvements: List[ImprovementOpportunity]) -> Dict[str, any]:
        """Generate summary of improvements."""
        by_category = {}
        by_priority = {}
        by_effort = {}
        
        for imp in improvements:
            # By category
            if imp.category not in by_category:
                by_category[imp.category] = []
            by_category[imp.category].append(imp)
            
            # By priority
            if imp.priority not in by_priority:
                by_priority[imp.priority] = []
            by_priority[imp.priority].append(imp)
            
            # By effort
            if imp.effort not in by_effort:
                by_effort[imp.effort] = []
            by_effort[imp.effort].append(imp)
        
        return {
            "total": len(improvements),
            "by_category": {k: len(v) for k, v in by_category.items()},
            "by_priority": {k: len(v) for k, v in by_priority.items()},
            "by_effort": {k: len(v) for k, v in by_effort.items()},
            "categories": by_category,
            "priorities": by_priority,
            "efforts": by_effort
        }
