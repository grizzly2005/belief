"""Performance hotspot identification."""

from typing import List, Dict, Tuple
from dataclasses import dataclass
from .models import ModuleInfo, FunctionInfo


@dataclass
class PerformanceHotspot:
    """Identified performance concern."""
    location: str
    pattern: str
    severity: str  # 'high', 'medium', 'low'
    description: str
    suggestion: str


class PerformanceAnalyzer:
    """Identifies performance hotspots through static analysis."""
    
    # Known slow patterns (language-agnostic)
    SLOW_PATTERNS = {
        'nested_loops': ('Nested loops detected', 'Consider flattening loops or algorithm optimization'),
        'string_concat': ('String concatenation in loop', 'Use efficient string building'),
        'list_append_loop': ('Array operations in tight loop', 'Consider batch operations or better data structures'),
        'deep_recursion': ('Deep recursion possible', 'Consider iterative approach or memoization'),
        'inefficient_search': ('Linear search pattern', 'Use hash tables/maps for O(1) lookups'),
        'sync_io': ('Synchronous I/O operations', 'Use async/await for better concurrency'),
        'dom_manipulation': ('Frequent DOM manipulation', 'Batch DOM updates or use virtual DOM'),
        'unnecessary_rerender': ('Component may re-render excessively', 'Use memoization or shouldComponentUpdate'),
    }
    
    def analyze_performance(self, modules: List[ModuleInfo]) -> List[PerformanceHotspot]:
        """Analyze modules for performance hotspots."""
        hotspots = []
        
        for module in modules:
            # Analyze functions
            for func in module.functions:
                hotspots.extend(self._analyze_function(func, module.name))
            
            # Analyze methods
            for cls in module.classes:
                for method in cls.methods:
                    hotspots.extend(self._analyze_function(method, f"{module.name}.{cls.name}"))
        
        return hotspots
    
    def _analyze_function(self, func: FunctionInfo, context: str) -> List[PerformanceHotspot]:
        """Analyze single function for performance issues."""
        hotspots = []
        location = f"{context}.{func.name}"
        is_js_ts = any(loc in func.location.file_path for loc in ['.js', '.ts', '.jsx', '.tsx'])
        
        # High complexity indicates potential performance issues
        if func.complexity > 20:
            hotspots.append(PerformanceHotspot(
                location=location,
                pattern='high_complexity',
                severity='high',
                description=f'Very high complexity ({func.complexity}) suggests nested logic',
                suggestion='Refactor to reduce branching and improve performance'
            ))
        
        # Check function name for clues
        func_lower = func.name.lower()
        
        if 'recursive' in func_lower or func_lower.startswith('_rec'):
            hotspots.append(PerformanceHotspot(
                location=location,
                pattern='deep_recursion',
                severity='medium',
                description=self.SLOW_PATTERNS['deep_recursion'][0],
                suggestion=self.SLOW_PATTERNS['deep_recursion'][1]
            ))
        
        if 'search' in func_lower or 'find' in func_lower:
            lang_specific_tip = 'Use Map/Set for O(1) lookups' if is_js_ts else 'Use dict/set for O(1) lookups'
            hotspots.append(PerformanceHotspot(
                location=location,
                pattern='inefficient_search',
                severity='medium',
                description=self.SLOW_PATTERNS['inefficient_search'][0],
                suggestion=lang_specific_tip
            ))
        
        # Check for nested loops (complexity > 10 is a rough indicator)
        if func.complexity > 10:
            hotspots.append(PerformanceHotspot(
                location=location,
                pattern='nested_loops',
                severity='high' if func.complexity > 15 else 'medium',
                description=self.SLOW_PATTERNS['nested_loops'][0],
                suggestion=self.SLOW_PATTERNS['nested_loops'][1]
            ))
        
        # JS/TS specific patterns
        if is_js_ts:
            # Check for synchronous operations in async functions
            if func.is_async and not any(call.startswith('await') for call in func.calls):
                hotspots.append(PerformanceHotspot(
                    location=location,
                    pattern='sync_io',
                    severity='medium',
                    description='Async function without await calls - may block event loop',
                    suggestion='Use await for async operations or make function synchronous'
                ))
            
            # React component performance
            if 'render' in func_lower or 'component' in context.lower():
                hotspots.append(PerformanceHotspot(
                    location=location,
                    pattern='unnecessary_rerender',
                    severity='medium',
                    description=self.SLOW_PATTERNS['unnecessary_rerender'][0],
                    suggestion='Use React.memo, useMemo, or useCallback to prevent unnecessary renders'
                ))
            
            # DOM manipulation in loops
            if 'dom' in func_lower or 'element' in func_lower:
                if func.complexity > 5:  # Likely has loops
                    hotspots.append(PerformanceHotspot(
                        location=location,
                        pattern='dom_manipulation',
                        severity='high',
                        description=self.SLOW_PATTERNS['dom_manipulation'][0],
                        suggestion='Use DocumentFragment or batch updates to minimize reflows'
                    ))
        
        return hotspots


def format_performance_report(modules: List[ModuleInfo]) -> str:
    """Format performance analysis report."""
    analyzer = PerformanceAnalyzer()
    hotspots = analyzer.analyze_performance(modules)
    
    if not hotspots:
        return ""
    
    output = []
    output.append("# ⚡ PERFORMANCE HOTSPOTS")
    output.append("=" * 80)
    output.append("")
    
    output.append(f"**Total Hotspots Identified**: {len(hotspots)}")
    output.append("")
    
    # Group by severity
    by_severity = {'high': [], 'medium': [], 'low': []}
    for h in hotspots:
        by_severity[h.severity].append(h)
    
    # High severity first
    for severity in ['high', 'medium', 'low']:
        items = by_severity[severity]
        if not items:
            continue
        
        emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}[severity]
        output.append(f"## {emoji} {severity.title()} Priority ({len(items)} items)")
        output.append("")
        
        for hotspot in items[:10]:  # Limit per severity
            output.append(f"### `{hotspot.location}`")
            output.append(f"**Pattern**: {hotspot.pattern}")
            output.append(f"**Issue**: {hotspot.description}")
            output.append(f"**Suggestion**: {hotspot.suggestion}")
            output.append("")
    
    # General recommendations (language-specific)
    has_python = any(not any(ext in h.location for ext in ['.js', '.ts']) for h in hotspots)
    has_js_ts = any(any(ext in h.location for ext in ['.js', '.ts']) for h in hotspots)
    
    output.append("## 💡 General Performance Tips")
    output.append("")
    
    if has_python:
        output.append("### Python")
        output.append("1. **Profile before optimizing**: Use `cProfile` to find real bottlenecks")
        output.append("2. **Use appropriate data structures**: dict/set for lookups, deque for queues")
        output.append("3. **Lazy evaluation**: Use generators for large datasets")
        output.append("4. **Caching**: Use `@lru_cache` for expensive repeated calls")
        output.append("5. **Vectorization**: Use numpy/pandas for numerical operations")
        output.append("")
    
    if has_js_ts:
        output.append("### JavaScript/TypeScript")
        output.append("1. **Use browser dev tools**: Profile with Chrome/Firefox DevTools")
        output.append("2. **Async patterns**: Use Promises and async/await to avoid blocking")
        output.append("3. **Debounce/throttle**: Limit expensive event handlers")
        output.append("4. **Web Workers**: Move heavy computation off main thread")
        output.append("5. **Code splitting**: Lazy load modules to reduce initial bundle size")
        output.append("6. **Memoization**: Cache expensive function results (React.memo, useMemo)")
        output.append("")
    
    return "\n".join(output)
