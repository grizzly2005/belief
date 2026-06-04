"""Generate enhanced ASCII architecture diagrams."""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
from .models import ModuleInfo


class ArchitectureDiagramGenerator:
    """Generate comprehensive architecture diagrams."""
    
    def __init__(self, modules: List[ModuleInfo]):
        self.modules = modules
        self.module_map = {m.name: m for m in modules}
        
    def generate_layered_architecture(self) -> List[str]:
        """Generate layered architecture diagram showing application layers."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                  LAYERED ARCHITECTURE                        │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        
        # Categorize modules by layer
        layers = self._categorize_by_layer()
        
        layer_order = ['presentation', 'application', 'domain', 'infrastructure', 'utilities']
        layer_symbols = {
            'presentation': '🖥️ ',
            'application': '⚙️ ',
            'domain': '🏢',
            'infrastructure': '🗄️ ',
            'utilities': '🔧'
        }
        
        for layer_name in layer_order:
            if layer_name in layers and layers[layer_name]:
                symbol = layer_symbols.get(layer_name, '📦')
                title = layer_name.replace('_', ' ').title()
                lines.append(f"{symbol} {title} Layer")
                lines.append("─" * 60)
                
                for module in sorted(layers[layer_name])[:8]:  # Limit to 8 per layer
                    lines.append(f"  • {module}")
                
                lines.append("")
                if layer_name != 'utilities':
                    lines.append("         ↓")
                    lines.append("")
        
        return lines
    
    def generate_component_diagram(self) -> List[str]:
        """Generate component interaction diagram."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                COMPONENT INTERACTIONS                        │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        
        # Find key components (modules with many classes or dependencies)
        components = self._identify_key_components()
        
        for comp_name, comp_info in components[:10]:  # Top 10 components
            lines.append(f"┌─ {comp_name}")
            lines.append(f"│  Classes: {comp_info['classes']}")
            lines.append(f"│  Functions: {comp_info['functions']}")
            lines.append(f"│  Complexity: {comp_info['complexity']}")
            
            if comp_info['dependencies']:
                lines.append("│  Depends on:")
                for dep in comp_info['dependencies'][:5]:
                    lines.append(f"│    ├─> {dep}")
            
            lines.append("│")
        
        lines.append("└" + "─" * 59)
        
        return lines
    
    def generate_package_structure(self) -> List[str]:
        """Generate package/namespace structure diagram."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                   PACKAGE STRUCTURE                          │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        
        # Build package tree
        packages = defaultdict(list)
        for module in self.modules:
            # Extract package from path
            parts = module.file_path.split('/')
            if len(parts) > 1:
                package = '/'.join(parts[:-1])
                packages[package].append(module.name)
            else:
                packages['root'].append(module.name)
        
        # Display tree
        for package in sorted(packages.keys())[:15]:  # Limit to 15 packages
            lines.append(f"📁 {package}/")
            for module in sorted(packages[package])[:8]:  # 8 modules per package
                lines.append(f"   ├─ {module}")
            lines.append("")
        
        return lines
    
    def generate_dependency_graph(self) -> List[str]:
        """Generate dependency relationships diagram."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                  DEPENDENCY GRAPH                            │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        
        # Calculate dependencies
        deps = self._calculate_dependencies()
        
        # Find modules with most dependencies
        sorted_deps = sorted(deps.items(), key=lambda x: len(x[1]), reverse=True)
        
        for module_name, dependencies in sorted_deps[:12]:  # Top 12
            if dependencies:
                lines.append(f"{module_name}")
                for i, dep in enumerate(sorted(dependencies)[:6]):  # Max 6 deps
                    is_last = (i == len(list(sorted(dependencies)[:6])) - 1)
                    connector = "└──>" if is_last else "├──>"
                    lines.append(f"  {connector} {dep}")
                lines.append("")
        
        return lines
    
    def generate_complexity_heatmap(self) -> List[str]:
        """Generate ASCII complexity heatmap."""
        lines = []
        lines.append("┌─────────────────────────────────────────────────────────────┐")
        lines.append("│                 COMPLEXITY HEATMAP                           │")
        lines.append("└─────────────────────────────────────────────────────────────┘")
        lines.append("")
        lines.append("Legend: 🟢 Simple  🟡 Moderate  🟠 Complex  🔴 Very Complex")
        lines.append("")
        
        # Sort by complexity
        sorted_modules = sorted(self.modules, key=lambda m: m.complexity, reverse=True)
        
        for module in sorted_modules[:20]:  # Top 20
            # Determine color
            if module.complexity < 5:
                indicator = "🟢"
            elif module.complexity < 10:
                indicator = "🟡"
            elif module.complexity < 20:
                indicator = "🟠"
            else:
                indicator = "🔴"
            
            # Create bar
            bar_length = min(int(module.complexity / 2), 25)
            bar = "█" * bar_length
            
            lines.append(f"{indicator} {module.name:30s} │{bar}│ {module.complexity}")
        
        lines.append("")
        
        return lines
    
    def _categorize_by_layer(self) -> Dict[str, List[str]]:
        """Categorize modules by architectural layer."""
        layers = defaultdict(list)
        
        for module in self.modules:
            name_lower = module.name.lower()
            path_lower = module.file_path.lower()
            
            # Presentation layer
            if any(x in name_lower for x in ['cli', 'ui', 'view', 'frontend', 'template']):
                layers['presentation'].append(module.name)
            # Application layer
            elif any(x in name_lower for x in ['service', 'controller', 'handler', 'api', 'workflow']):
                layers['application'].append(module.name)
            # Domain layer
            elif any(x in name_lower for x in ['model', 'entity', 'domain', 'business']):
                layers['domain'].append(module.name)
            # Infrastructure layer
            elif any(x in name_lower for x in ['database', 'repository', 'dao', 'integration', 'client']):
                layers['infrastructure'].append(module.name)
            # Utilities
            elif any(x in name_lower for x in ['util', 'helper', 'common', 'tool', 'config']):
                layers['utilities'].append(module.name)
            # Default to domain
            else:
                layers['domain'].append(module.name)
        
        return layers
    
    def _identify_key_components(self) -> List[Tuple[str, Dict]]:
        """Identify key components by importance."""
        components = []
        
        for module in self.modules:
            # Calculate importance score
            score = (
                len(module.classes) * 3 +
                len(module.functions) * 1 +
                module.complexity * 0.5
            )
            
            comp_info = {
                'classes': len(module.classes),
                'functions': len(module.functions),
                'complexity': module.complexity,
                'dependencies': self._get_module_dependencies(module)
            }
            
            components.append((module.name, comp_info))
        
        # Sort by score
        components.sort(key=lambda x: (
            x[1]['classes'] * 3 + 
            x[1]['functions'] + 
            x[1]['complexity'] * 0.5
        ), reverse=True)
        
        return components
    
    def _get_module_dependencies(self, module: ModuleInfo) -> List[str]:
        """Get dependencies for a module."""
        deps = set()
        
        # Get imports that are internal to the project
        for imp in module.imports:
            if imp.startswith('.') or imp in self.module_map:
                deps.add(imp)
        
        return sorted(list(deps))[:5]  # Limit to 5
    
    def _calculate_dependencies(self) -> Dict[str, Set[str]]:
        """Calculate all module dependencies."""
        deps = defaultdict(set)
        
        for module in self.modules:
            for imp in module.imports:
                # Check if it's an internal import
                if imp in self.module_map or imp.startswith('.'):
                    deps[module.name].add(imp)
        
        return deps


def format_architecture_diagrams(modules: List[ModuleInfo]) -> str:
    """Generate all architecture diagrams."""
    generator = ArchitectureDiagramGenerator(modules)
    sections = []
    
    sections.append("# 🏛️ ARCHITECTURE DIAGRAMS")
    sections.append("=" * 80)
    sections.append("")
    sections.append("Visual representation of the system architecture.")
    sections.append("")
    
    # Layered architecture
    sections.append("## Layered Architecture")
    sections.append("")
    sections.extend(generator.generate_layered_architecture())
    sections.append("")
    
    # Component diagram
    sections.append("## Component Interactions")
    sections.append("")
    sections.extend(generator.generate_component_diagram())
    sections.append("")
    
    # Package structure
    sections.append("## Package Structure")
    sections.append("")
    sections.extend(generator.generate_package_structure())
    sections.append("")
    
    # Dependency graph
    sections.append("## Dependency Relationships")
    sections.append("")
    sections.extend(generator.generate_dependency_graph())
    sections.append("")
    
    # Complexity heatmap
    sections.append("## Complexity Distribution")
    sections.append("")
    sections.extend(generator.generate_complexity_heatmap())
    sections.append("")
    
    return "\n".join(sections)
