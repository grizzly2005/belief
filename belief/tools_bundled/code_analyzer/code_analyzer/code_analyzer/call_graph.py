"""Call graph generation for onboarding documentation."""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
from .models import ModuleInfo, FunctionInfo


class CallGraphBuilder:
    """Builds call graphs showing function relationships."""
    
    def __init__(self, modules: List[ModuleInfo]):
        self.modules = modules
        self.call_map: Dict[str, List[str]] = defaultdict(list)
        self.entry_points: Set[str] = set()
        self._build_graph()
    
    def _build_graph(self):
        """Build the complete call graph."""
        for module in self.modules:
            # Add functions
            for func in module.functions:
                func_name = f"{module.name}.{func.name}"
                self.call_map[func_name] = [
                    call for call in func.calls if not call.startswith('_')
                ]
                
                # Detect entry points (main, CLI commands)
                if func.name == 'main' or func.name in ['analyze', 'report', 'anonymize']:
                    self.entry_points.add(func_name)
            
            # Add class methods
            for cls in module.classes:
                for method in cls.methods:
                    method_name = f"{module.name}.{cls.name}.{method.name}"
                    self.call_map[method_name] = [
                        call for call in method.calls if not call.startswith('_')
                    ]
    
    def generate_call_tree(self, entry_point: str, max_depth: int = 4) -> List[str]:
        """Generate ASCII call tree from an entry point."""
        lines = []
        visited = set()
        
        def traverse(func_name: str, depth: int, prefix: str, is_last: bool):
            if depth > max_depth or func_name in visited:
                return
            
            visited.add(func_name)
            
            # Format the line
            if depth == 0:
                lines.append(f"Entry Point: {func_name}")
            else:
                branch = "└─>" if is_last else "├─>"
                lines.append(f"{prefix}{branch} {func_name}")
            
            # Get callees
            callees = self.call_map.get(func_name, [])
            if not callees:
                return
            
            # Update prefix for children
            if depth == 0:
                child_prefix = "    "
            else:
                child_prefix = prefix + ("    " if is_last else "│   ")
            
            # Recurse into callees
            for i, callee in enumerate(callees[:8]):  # Limit to 8 per level
                is_last_child = (i == len(callees) - 1)
                traverse(callee, depth + 1, child_prefix, is_last_child)
        
        traverse(entry_point, 0, "", True)
        return lines
    
    def generate_flow_diagram(self) -> List[str]:
        """Generate overall system flow diagram."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                    SYSTEM CALL FLOW                          │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        
        # Group by module
        module_funcs = defaultdict(list)
        for func_name in self.call_map.keys():
            module = func_name.split('.')[0]
            module_funcs[module].append(func_name)
        
        # Show main modules
        main_modules = sorted(module_funcs.keys())[:10]
        for module in main_modules:
            lines.append(f"┌─── {module}")
            funcs = sorted(module_funcs[module])[:5]
            for i, func in enumerate(funcs):
                is_last = (i == len(funcs) - 1)
                symbol = "└──" if is_last else "├──"
                func_short = func.split('.')[-1]
                lines.append(f"│   {symbol} {func_short}()")
            lines.append("│")
        
        lines.append("└─────────────────────────────────────────────────────────────┘")
        return lines
    
    def find_hot_paths(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Find most-called functions (hotspots)."""
        call_counts = defaultdict(int)
        
        for callees in self.call_map.values():
            for callee in callees:
                call_counts[callee] += 1
        
        # Sort by call count
        sorted_funcs = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_funcs[:top_n]
    
    def generate_data_flow_diagram(self) -> List[str]:
        """Generate data flow diagram showing how data moves through the system."""
        lines = []
        lines.append("┌──────────────────────────────────────────────────────────┐")
        lines.append("│                    DATA FLOW                              │")
        lines.append("└──────────────────────────────────────────────────────────┘")
        lines.append("")
        lines.append("  Python Files")
        lines.append("       │")
        lines.append("       ├──> AST Parser (ast.parse)")
        lines.append("       │         │")
        lines.append("       │         └──> ModuleInfo")
        lines.append("       │                  │")
        lines.append("       ├──> Analyzer")
        lines.append("       │         │")
        lines.append("       │         ├──> Issue Detection")
        lines.append("       │         ├──> Complexity Analysis (radon)")
        lines.append("       │         └──> Pattern Matching")
        lines.append("       │")
        lines.append("       └──> AnalysisResult")
        lines.append("                 │")
        lines.append("                 ├──> Logseq Documentation")
        lines.append("                 ├──> Trends Database (SQLite)")
        lines.append("                 ├──> Auto-Fix Suggestions")
        lines.append("                 └──> JSON Report")
        lines.append("")
        return lines
    
    def generate_module_dependencies(self) -> List[str]:
        """Generate module dependency diagram."""
        lines = []
        lines.append("Module Dependencies:")
        lines.append("")
        
        # Extract module-to-module dependencies
        module_deps = defaultdict(set)
        for func_name, callees in self.call_map.items():
            source_module = func_name.split('.')[0]
            for callee in callees:
                target_module = callee.split('.')[0]
                if target_module != source_module and target_module in [m.name for m in self.modules]:
                    module_deps[source_module].add(target_module)
        
        # Show as list
        for source, targets in sorted(module_deps.items())[:15]:
            if targets:
                lines.append(f"{source}")
                for target in sorted(targets)[:5]:
                    lines.append(f"  └─> {target}")
                lines.append("")
        
        return lines


def generate_workflow_diagram(workflow_name: str, steps: List[Tuple[str, str]]) -> List[str]:
    """Generate a workflow diagram for common developer tasks."""
    lines = []
    lines.append(f"## Workflow: {workflow_name}")
    lines.append("")
    lines.append("```")
    
    for i, (step, description) in enumerate(steps, 1):
        lines.append(f"{i}. {step}")
        if description:
            lines.append(f"   │ {description}")
        if i < len(steps):
            lines.append("   ↓")
    
    lines.append("```")
    lines.append("")
    return lines
