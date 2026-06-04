"""Edge cases documentation - identifies and documents boundary conditions and special scenarios."""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
from .models import ModuleInfo, FunctionInfo


class EdgeCaseAnalyzer:
    """Analyzes code to identify and document edge cases."""
    
    def __init__(self):
        # Patterns that suggest edge case handling
        self.edge_case_keywords = [
            'empty', 'null', 'none', 'zero', 'negative', 'max', 'min',
            'overflow', 'underflow', 'boundary', 'limit', 'edge',
            'invalid', 'error', 'exception', 'special', 'corner'
        ]
        
        # Common edge case categories
        self.categories = {
            'empty_input': 'Empty or Missing Input',
            'null_values': 'Null/None Values',
            'boundaries': 'Boundary Values (min/max)',
            'type_errors': 'Type Mismatches',
            'size_limits': 'Size/Length Limits',
            'concurrency': 'Concurrent Access',
            'resource_limits': 'Resource Exhaustion',
            'format_errors': 'Invalid Formats',
        }
    
    def analyze_edge_cases(self, modules: List[ModuleInfo]) -> Dict[str, List[Tuple[str, str, str]]]:
        """Analyze modules for edge case handling."""
        edge_cases_by_category = defaultdict(list)
        
        for module in modules:
            # Analyze functions
            for func in module.functions:
                cases = self._analyze_function(func, module)
                for category, case in cases:
                    edge_cases_by_category[category].append(case)
            
            # Analyze classes
            for cls in module.classes:
                for method in cls.methods:
                    cases = self._analyze_function(method, module, cls_name=cls.name)
                    for category, case in cases:
                        edge_cases_by_category[category].append(case)
        
        return dict(edge_cases_by_category)
    
    def _analyze_function(self, func: FunctionInfo, module: ModuleInfo, cls_name: str = None) -> List[Tuple[str, Tuple[str, str, str]]]:
        """Analyze a function for edge cases."""
        cases = []
        
        # Build full function name
        if cls_name:
            func_name = f"{cls_name}.{func.name}"
        else:
            func_name = func.name
        
        location = f"{module.name}.{func_name}"
        
        # Check docstring for edge case mentions
        if func.docstring:
            doc_lower = func.docstring.lower()
            
            # Empty input handling
            if any(keyword in doc_lower for keyword in ['empty', 'no input', 'missing']):
                cases.append(('empty_input', (
                    location,
                    "Handles empty input",
                    self._extract_edge_case_detail(func.docstring, 'empty')
                )))
            
            # Null/None handling
            if any(keyword in doc_lower for keyword in ['null', 'none', 'optional']):
                cases.append(('null_values', (
                    location,
                    "Handles null/None values",
                    self._extract_edge_case_detail(func.docstring, 'none')
                )))
            
            # Boundary values
            if any(keyword in doc_lower for keyword in ['max', 'min', 'limit', 'boundary']):
                cases.append(('boundaries', (
                    location,
                    "Handles boundary values",
                    self._extract_edge_case_detail(func.docstring, 'boundary')
                )))
            
            # Invalid formats
            if any(keyword in doc_lower for keyword in ['invalid', 'malformed', 'corrupt']):
                cases.append(('format_errors', (
                    location,
                    "Handles invalid formats",
                    self._extract_edge_case_detail(func.docstring, 'invalid')
                )))
        
        # Check function name for edge case handling
        func_name_lower = func.name.lower()
        if 'validate' in func_name_lower or 'check' in func_name_lower:
            cases.append(('type_errors', (
                location,
                "Validates input",
                "Performs validation checks"
            )))
        
        # Check for exception handling patterns (raises clause)
        if func.docstring and 'raises' in func.docstring.lower():
            cases.append(('type_errors', (
                location,
                "Raises exceptions for errors",
                self._extract_raises_info(func.docstring)
            )))
        
        return cases
    
    def _extract_edge_case_detail(self, docstring: str, keyword: str) -> str:
        """Extract details about edge case from docstring."""
        lines = docstring.split('\n')
        
        # Find lines mentioning the keyword
        for i, line in enumerate(lines):
            if keyword in line.lower():
                # Get this line and possibly next line
                detail = line.strip()
                if i + 1 < len(lines) and lines[i + 1].strip():
                    detail += " " + lines[i + 1].strip()
                return detail[:200]  # Limit length
        
        return f"Handles {keyword} cases"
    
    def _extract_raises_info(self, docstring: str) -> str:
        """Extract information about raised exceptions."""
        lines = docstring.split('\n')
        
        for i, line in enumerate(lines):
            if 'raises' in line.lower():
                # Get next few lines
                info = []
                for j in range(i, min(i + 3, len(lines))):
                    if lines[j].strip():
                        info.append(lines[j].strip())
                return " ".join(info)[:200]
        
        return "Raises exceptions for error conditions"
    
    def generate_recommendations(self, modules: List[ModuleInfo]) -> List[Tuple[str, str]]:
        """Generate recommendations for edge cases that should be handled."""
        recommendations = []
        
        # Check for functions that take parameters but might not validate
        for module in modules:
            for func in module.functions:
                if func.parameters and not self._has_validation(func):
                    recommendations.append((
                        f"{module.name}.{func.name}",
                        "Consider adding input validation for parameters"
                    ))
                
                # Check for list/dict operations without size checks
                if func.docstring:
                    doc = func.docstring.lower()
                    if ('list' in doc or 'array' in doc) and 'empty' not in doc:
                        recommendations.append((
                            f"{module.name}.{func.name}",
                            "Consider handling empty list/array case"
                        ))
        
        return recommendations[:10]  # Limit to top 10
    
    def _has_validation(self, func: FunctionInfo) -> bool:
        """Check if function appears to have validation."""
        if not func.docstring:
            return False
        
        doc_lower = func.docstring.lower()
        validation_keywords = ['validate', 'check', 'verify', 'raises', 'assert']
        return any(keyword in doc_lower for keyword in validation_keywords)


def format_edge_cases(modules: List[ModuleInfo]) -> str:
    """Format edge cases documentation."""
    analyzer = EdgeCaseAnalyzer()
    edge_cases = analyzer.analyze_edge_cases(modules)
    recommendations = analyzer.generate_recommendations(modules)
    
    if not edge_cases and not recommendations:
        return ""
    
    output = []
    output.append("# ⚠️  EDGE CASES & BOUNDARY CONDITIONS")
    output.append("=" * 80)
    output.append("")
    output.append("Understanding how the system handles edge cases and special scenarios.")
    output.append("")
    
    # Documented edge cases
    if edge_cases:
        output.append("## Handled Edge Cases")
        output.append("")
        output.append("The codebase explicitly handles the following edge cases:")
        output.append("")
        
        for category, cases in sorted(edge_cases.items()):
            if not cases:
                continue
            
            category_name = analyzer.categories.get(category, category.replace('_', ' ').title())
            output.append(f"### {category_name}")
            output.append("")
            
            for location, summary, detail in cases[:5]:  # Limit per category
                output.append(f"**`{location}`**")
                output.append(f"  - {summary}")
                if detail and detail != summary:
                    output.append(f"  - {detail}")
                output.append("")
    
    # Recommendations
    if recommendations:
        output.append("")
        output.append("## Recommended Edge Case Handling")
        output.append("")
        output.append("Consider adding edge case handling for:")
        output.append("")
        
        for location, recommendation in recommendations:
            output.append(f"- **`{location}`**: {recommendation}")
    
    # General guidance
    output.append("")
    output.append("## General Edge Case Guidelines")
    output.append("")
    output.append("When working with this codebase, always consider:")
    output.append("")
    output.append("1. **Empty Collections**: What happens if a list/dict is empty?")
    output.append("2. **None Values**: Does your function handle None gracefully?")
    output.append("3. **Boundary Values**: Test with 0, -1, maximum values")
    output.append("4. **Type Safety**: Validate input types early")
    output.append("5. **Resource Limits**: Consider memory/time constraints")
    output.append("6. **Concurrent Access**: Is thread safety needed?")
    output.append("")
    
    return "\n".join(output)
