"""Onboarding insights to help new developers understand codebases quickly."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import re

from .models import ModuleInfo, FunctionInfo, ClassInfo
from .language_detection import LanguageDetector


@dataclass
class ProjectOverview:
    """High-level overview of the project."""
    name: str
    purpose: Optional[str] = None
    description: Optional[str] = None
    main_technologies: List[str] = field(default_factory=list)
    key_dependencies: List[str] = field(default_factory=list)
    total_files: int = 0
    total_lines: int = 0
    estimated_complexity: str = "Unknown"


@dataclass
class LearningPath:
    """Suggested order to read/understand the code."""
    entry_points: List[Tuple[str, str]] = field(default_factory=list)  # (file, reason)
    core_modules: List[Tuple[str, str]] = field(default_factory=list)  # (file, role)
    utility_modules: List[Tuple[str, str]] = field(default_factory=list)  # (file, purpose)
    test_modules: List[Tuple[str, str]] = field(default_factory=list)  # (file, what it tests)
    recommended_order: List[str] = field(default_factory=list)


@dataclass
class CodeSnapshot:
    """Code snapshot with location info."""
    file_path: str
    line_start: int
    line_end: int
    code: str
    context: str  # What this code does
    entity_type: str  # 'class', 'function', 'pattern'
    entity_name: str


@dataclass
class KeyConcepts:
    """Important concepts and patterns in the codebase."""
    main_classes: List[Tuple[str, str, CodeSnapshot]] = field(default_factory=list)  # (class, purpose, snapshot)
    core_functions: List[Tuple[str, str, CodeSnapshot]] = field(default_factory=list)  # (func, role, snapshot)
    design_patterns: List[str] = field(default_factory=list)
    architectural_style: Optional[str] = None
    data_flow: List[str] = field(default_factory=list)
    architecture_diagram: List[str] = field(default_factory=list)  # ASCII art or description
    module_interactions: List[Tuple[str, str, str]] = field(default_factory=list)  # (from, to, purpose)


@dataclass
class OnboardingInsights:
    """Complete onboarding information for new developers."""
    overview: ProjectOverview
    learning_path: LearningPath
    key_concepts: KeyConcepts
    quick_start_tips: List[str] = field(default_factory=list)
    common_pitfalls: List[str] = field(default_factory=list)
    helpful_commands: List[Tuple[str, str]] = field(default_factory=list)  # (command, purpose)


class OnboardingAnalyzer:
    """Analyzes code to generate onboarding insights."""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.project_name = project_path.name
        self.language_detector = LanguageDetector()
        self.primary_language = None
    
    def generate_insights(self, modules: List[ModuleInfo]) -> OnboardingInsights:
        """Generate comprehensive onboarding insights."""
        # Detect primary language
        self.primary_language = self._detect_primary_language(modules)
        
        overview = self._analyze_project_overview(modules)
        learning_path = self._generate_learning_path(modules)
        key_concepts = self._identify_key_concepts(modules)
        quick_start = self._generate_quick_start_tips(modules)
        pitfalls = self._identify_common_pitfalls(modules)
        commands = self._suggest_helpful_commands(modules)
        
        return OnboardingInsights(
            overview=overview,
            learning_path=learning_path,
            key_concepts=key_concepts,
            quick_start_tips=quick_start,
            common_pitfalls=pitfalls,
            helpful_commands=commands
        )
    
    def _detect_primary_language(self, modules: List[ModuleInfo]) -> str:
        """Detect the primary programming language from modules."""
        if not modules:
            return 'python'
        
        # Count files by extension
        lang_counts = {}
        for module in modules:
            lang = self.language_detector.get_language_for_file(Path(module.file_path))
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        
        # Return most common language
        if lang_counts:
            return max(lang_counts.items(), key=lambda x: x[1])[0]
        return 'python'
    
    def _analyze_project_overview(self, modules: List[ModuleInfo]) -> ProjectOverview:
        """Extract high-level project information."""
        total_files = len(modules)
        total_lines = sum(m.lines_of_code for m in modules)
        
        # Detect main technologies from imports
        all_imports = set()
        for module in modules:
            all_imports.update(module.imports)
        
        # Categorize common frameworks/libraries
        technologies = []
        
        # Python frameworks
        if any('django' in imp for imp in all_imports):
            technologies.append('Django (web framework)')
        if any('flask' in imp for imp in all_imports):
            technologies.append('Flask (web framework)')
        if any('fastapi' in imp for imp in all_imports):
            technologies.append('FastAPI (web framework)')
        if any('click' in imp for imp in all_imports):
            technologies.append('Click (CLI framework)')
        if any('pytest' in imp for imp in all_imports):
            technologies.append('pytest (testing)')
        if any('numpy' in imp or 'pandas' in imp for imp in all_imports):
            technologies.append('Data Science (numpy/pandas)')
        if any('requests' in imp or 'httpx' in imp for imp in all_imports):
            technologies.append('HTTP client')
        if any('sqlalchemy' in imp for imp in all_imports):
            technologies.append('SQLAlchemy (database ORM)')
        
        # JavaScript/TypeScript frameworks
        if any('react' in imp for imp in all_imports):
            technologies.append('React (UI library)')
        if any('vue' in imp for imp in all_imports):
            technologies.append('Vue.js (framework)')
        if any('angular' in imp for imp in all_imports):
            technologies.append('Angular (framework)')
        if any('express' in imp for imp in all_imports):
            technologies.append('Express.js (web framework)')
        if any('next' in imp for imp in all_imports):
            technologies.append('Next.js (React framework)')
        if any('jest' in imp or 'vitest' in imp for imp in all_imports):
            technologies.append('Jest/Vitest (testing)')
        if any('axios' in imp or 'fetch' in imp for imp in all_imports):
            technologies.append('HTTP client (axios/fetch)')
        if any('redux' in imp or 'zustand' in imp for imp in all_imports):
            technologies.append('State management')
        
        # Estimate complexity
        avg_lines_per_file = total_lines / max(total_files, 1)
        if avg_lines_per_file < 100:
            complexity = "Simple"
        elif avg_lines_per_file < 300:
            complexity = "Moderate"
        elif avg_lines_per_file < 500:
            complexity = "Complex"
        else:
            complexity = "Very Complex"
        
        # Try to get description from main module
        description = None
        for module in modules:
            if module.name in ['__init__', '__main__', self.project_name]:
                if module.docstring:
                    description = module.docstring.split('\n')[0]
                    break
        
        # Extract key dependencies (most commonly imported)
        external_deps = [imp for imp in all_imports if not imp.startswith('.')]
        dep_counts = {}
        for dep in external_deps:
            # Get top-level package name
            top_level = dep.split('.')[0]
            dep_counts[top_level] = dep_counts.get(top_level, 0) + 1
        
        # Get top 5 dependencies
        key_deps = sorted(dep_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        key_dependencies = [dep for dep, _ in key_deps]
        
        return ProjectOverview(
            name=self.project_name,
            purpose=None,  # Will be extracted from README if available
            description=description,
            main_technologies=technologies,
            key_dependencies=key_dependencies,
            total_files=total_files,
            total_lines=total_lines,
            estimated_complexity=complexity
        )
    
    def _generate_learning_path(self, modules: List[ModuleInfo]) -> LearningPath:
        """Suggest order to read the code."""
        entry_points = []
        core_modules = []
        utility_modules = []
        test_modules = []
        
        for module in modules:
            # Identify entry points (language-specific)
            if any(func.name == 'main' for func in module.functions):
                entry_points.append((module.file_path, "Has main() function - application entry point"))
            elif '__main__' in module.name:
                entry_points.append((module.file_path, "Main module - run with 'python -m'"))
            elif 'cli' in module.name.lower():
                entry_points.append((module.file_path, "Command-line interface"))
            # JS/TS entry points
            elif 'index' in module.name.lower() or 'main' in module.name.lower():
                entry_points.append((module.file_path, "Main entry file"))
            elif 'app' in module.name.lower() and len(module.classes) > 0:
                entry_points.append((module.file_path, "Application root component"))
            elif 'server' in module.name.lower():
                entry_points.append((module.file_path, "Server entry point"))
            
            # Identify test modules
            if 'test' in module.name.lower() or 'tests' in module.file_path:
                test_name = module.name.replace('test_', '').replace('_test', '')
                test_modules.append((module.file_path, f"Tests for {test_name}"))
            
            # Identify utility modules
            elif any(name in module.name.lower() for name in ['util', 'helper', 'tool', 'common']):
                utility_modules.append((module.file_path, "Helper functions and utilities"))
            
            # Core modules (has classes or many functions)
            elif len(module.classes) > 0 or len(module.functions) > 5:
                purpose = self._infer_module_purpose(module)
                core_modules.append((module.file_path, purpose))
        
        # Recommended reading order
        recommended_order = []
        recommended_order.append("1. Start with README.md to understand the project's purpose")
        
        if entry_points:
            recommended_order.append(f"2. Read entry points to see how the application starts:")
            for file_path, _ in entry_points[:3]:
                recommended_order.append(f"   - {file_path}")
        
        if core_modules:
            recommended_order.append("3. Study core modules to understand main functionality:")
            for file_path, purpose in core_modules[:5]:
                recommended_order.append(f"   - {file_path} ({purpose})")
        
        if utility_modules:
            recommended_order.append("4. Review utility modules for common helpers")
        
        if test_modules:
            recommended_order.append("5. Read tests to understand expected behavior")
        
        return LearningPath(
            entry_points=entry_points,
            core_modules=core_modules,
            utility_modules=utility_modules,
            test_modules=test_modules,
            recommended_order=recommended_order
        )
    
    def _infer_module_purpose(self, module: ModuleInfo) -> str:
        """Infer the purpose of a module from its name and contents."""
        name_lower = module.name.lower()
        
        # Check module name patterns
        if 'model' in name_lower:
            return "Data models and structures"
        elif 'view' in name_lower or 'template' in name_lower:
            return "User interface views"
        elif 'controller' in name_lower or 'handler' in name_lower:
            return "Request handling and business logic"
        elif 'service' in name_lower:
            return "Business logic and services"
        elif 'repository' in name_lower or 'dao' in name_lower:
            return "Data access layer"
        elif 'api' in name_lower:
            return "API endpoints and routing"
        elif 'config' in name_lower or 'settings' in name_lower:
            return "Configuration and settings"
        elif 'database' in name_lower or 'db' in name_lower:
            return "Database operations"
        elif 'parser' in name_lower:
            return "Parsing and data extraction"
        elif 'analyzer' in name_lower or 'analyse' in name_lower:
            return "Analysis and processing"
        
        # Check based on content
        if module.docstring:
            return module.docstring.split('\n')[0][:50]
        
        # Default based on class/function count
        if len(module.classes) > 3:
            return f"Contains {len(module.classes)} classes"
        elif len(module.functions) > 10:
            return f"Contains {len(module.functions)} functions"
        else:
            return "Supporting module"
    
    def _extract_code_snapshot(self, module: ModuleInfo, cls: ClassInfo = None, func: FunctionInfo = None) -> Optional[CodeSnapshot]:
        """Extract code snapshot with context."""
        try:
            file_path = self.project_path / module.file_path
            if not file_path.exists():
                return None
            
            source = file_path.read_text()
            lines = source.splitlines()
            
            if cls:
                # Extract class definition (up to 20 lines)
                start = cls.location.line_start - 1
                end = min(start + 20, len(lines), cls.location.line_end)
                code = '\n'.join(lines[start:end])
                context = cls.docstring.split('\n')[0] if cls.docstring else f"Class with {len(cls.methods)} methods"
                entity_name = cls.name
                entity_type = "class"
            elif func:
                # Extract function definition (up to 15 lines)
                start = func.location.line_start - 1
                end = min(start + 15, len(lines), func.location.line_end)
                code = '\n'.join(lines[start:end])
                context = func.docstring.split('\n')[0] if func.docstring else "Function"
                entity_name = func.name
                entity_type = "function"
            else:
                return None
            
            return CodeSnapshot(
                file_path=module.file_path,
                line_start=start + 1,
                line_end=end,
                code=code,
                context=context,
                entity_type=entity_type,
                entity_name=entity_name
            )
        except Exception:
            return None
    
    def _identify_key_concepts(self, modules: List[ModuleInfo]) -> KeyConcepts:
        """Identify important concepts and patterns."""
        main_classes = []
        core_functions = []
        design_patterns = []
        data_flow = []
        
        # Find main classes (large or important ones) with code snapshots
        for module in modules:
            for cls in module.classes:
                # Skip test classes
                if 'test' in module.name.lower():
                    continue
                
                # Important if it has many methods or is in a core module
                if len(cls.methods) > 5:
                    purpose = cls.docstring.split('\n')[0] if cls.docstring else f"{len(cls.methods)} methods"
                    snapshot = self._extract_code_snapshot(module, cls=cls)
                    if snapshot:
                        main_classes.append((f"{module.name}.{cls.name}", purpose, snapshot))
        
        # Find core functions (called often or complex) with code snapshots
        for module in modules:
            for func in module.functions:
                if func.complexity > 8 or len(func.called_by) > 3:
                    role = func.docstring.split('\n')[0] if func.docstring else "Core function"
                    snapshot = self._extract_code_snapshot(module, func=func)
                    if snapshot:
                        core_functions.append((f"{module.name}.{func.name}", role, snapshot))
        
        # Detect design patterns
        class_names = []
        for module in modules:
            class_names.extend([cls.name for cls in module.classes])
        
        # Common pattern indicators
        if any('Factory' in name for name in class_names):
            design_patterns.append("Factory Pattern - Object creation")
        if any('Builder' in name for name in class_names):
            design_patterns.append("Builder Pattern - Complex object construction")
        if any('Singleton' in name for name in class_names):
            design_patterns.append("Singleton Pattern - Single instance")
        if any('Observer' in name or 'Listener' in name for name in class_names):
            design_patterns.append("Observer Pattern - Event handling")
        if any('Adapter' in name for name in class_names):
            design_patterns.append("Adapter Pattern - Interface adaptation")
        if any('Strategy' in name for name in class_names):
            design_patterns.append("Strategy Pattern - Pluggable algorithms")
        
        # Detect architectural style
        has_models = any('model' in m.name.lower() for m in modules)
        has_views = any('view' in m.name.lower() for m in modules)
        has_controllers = any('controller' in m.name.lower() for m in modules)
        has_api = any('api' in m.name.lower() for m in modules)
        
        if has_models and has_views and has_controllers:
            arch_style = "MVC (Model-View-Controller)"
        elif has_models and has_api:
            arch_style = "REST API with data models"
        elif any('cli' in m.name.lower() for m in modules):
            arch_style = "Command-Line Application"
        else:
            arch_style = "Modular Python Application"
        
        # Describe data flow
        if any('pipeline' in m.name.lower() for m in modules):
            data_flow.append("Data pipeline architecture - processes data in stages")
        if any('queue' in m.name.lower() or 'worker' in m.name.lower() for m in modules):
            data_flow.append("Async task processing with queues")
        if any('stream' in m.name.lower() for m in modules):
            data_flow.append("Streaming data processing")
        
        # Sort by importance
        main_classes.sort(key=lambda x: len(x[1]), reverse=True)
        core_functions.sort(key=lambda x: len(x[1]), reverse=True)
        
        return KeyConcepts(
            main_classes=main_classes[:10],  # Top 10
            core_functions=core_functions[:10],  # Top 10
            design_patterns=design_patterns,
            architectural_style=arch_style,
            data_flow=data_flow
        )
    
    def _generate_quick_start_tips(self, modules: List[ModuleInfo]) -> List[str]:
        """Generate quick start tips for developers."""
        tips = []
        is_python = self.primary_language == 'python'
        is_js_ts = self.primary_language in ['javascript', 'typescript']
        
        # Language-specific setup instructions
        if is_python:
            setup_files = ['setup.py', 'pyproject.toml', 'requirements.txt']
            for module in modules:
                if any(sf in module.file_path for sf in setup_files):
                    tips.append("Install dependencies: pip install -r requirements.txt or pip install -e .")
                    break
        elif is_js_ts:
            tips.append("Install dependencies: npm install or yarn install")
            tips.append("Check package.json for available scripts (npm run <script>)")
        
        # Look for configuration
        if any('config' in m.name.lower() or 'settings' in m.name.lower() for m in modules):
            tips.append("Review configuration files before running - may need environment setup")
        
        # Look for tests
        if any('test' in m.name.lower() for m in modules):
            if is_python:
                tips.append("Run tests: pytest or python -m pytest")
            elif is_js_ts:
                tips.append("Run tests: npm test or yarn test")
        
        # Look for CLI
        if any('cli' in m.name.lower() for m in modules):
            tips.append("Try CLI commands with --help to explore functionality")
        
        # Look for examples
        if any('example' in m.name.lower() or 'demo' in m.name.lower() for m in modules):
            tips.append("Check examples/ directory for usage demonstrations")
        
        # Look for documentation
        docs_modules = [m for m in modules if 'doc' in m.file_path.lower()]
        if docs_modules:
            tips.append("Read docs/ directory for detailed documentation")
        
        # Generic tips
        if is_python:
            tips.append("Start by reading docstrings in main classes and functions")
        elif is_js_ts:
            tips.append("Start by reading JSDoc comments in main components and functions")
        tips.append("Use an IDE with 'go to definition' to navigate the codebase")
        
        return tips
    
    def _identify_common_pitfalls(self, modules: List[ModuleInfo]) -> List[str]:
        """Identify potential pitfalls for new developers."""
        pitfalls = []
        is_python = self.primary_language == 'python'
        is_js_ts = self.primary_language in ['javascript', 'typescript']
        
        # Check complexity
        high_complexity_modules = [m for m in modules if m.complexity > 20]
        if high_complexity_modules:
            pitfalls.append(f"{len(high_complexity_modules)} modules have high complexity - start with simpler ones")
        
        # Check for deep nesting
        total_files = len(modules)
        if total_files > 50:
            pitfalls.append("Large codebase - don't try to understand everything at once")
        
        # Check for many dependencies
        all_imports = set()
        for module in modules:
            all_imports.update(module.imports)
        if len(all_imports) > 30:
            pitfalls.append("Many dependencies - make sure you understand the core ones first")
        
        # Check for async code
        has_async = any(
            any(func.is_async for func in m.functions)
            for m in modules
        )
        if has_async:
            if is_python:
                pitfalls.append("Contains async/await code - understand Python asyncio first")
            elif is_js_ts:
                pitfalls.append("Contains async/await code - understand Promises and async patterns")
        
        # Language-specific pitfalls
        if is_python:
            for module in modules:
                if any('meta' in cls.name.lower() for cls in module.classes):
                    pitfalls.append("Uses metaprogramming - advanced Python concepts")
                    break
        elif is_js_ts:
            # Check for React hooks patterns
            all_imports_str = ' '.join(all_imports)
            if 'react' in all_imports_str.lower():
                pitfalls.append("Uses React - understand hooks (useState, useEffect) and component lifecycle")
            # Check for TypeScript
            if any(m.file_path.endswith(('.ts', '.tsx')) for m in modules):
                pitfalls.append("Uses TypeScript - understand type system and interfaces")
        
        return pitfalls
    
    def _suggest_helpful_commands(self, modules: List[ModuleInfo]) -> List[Tuple[str, str]]:
        """Suggest helpful commands for exploring the codebase."""
        commands = []
        is_python = self.primary_language == 'python'
        is_js_ts = self.primary_language in ['javascript', 'typescript']
        
        # Standard exploration commands
        commands.append(("tree -L 2", "View project structure"))
        
        if is_python:
            commands.append(("find . -name '*.py' | wc -l", "Count Python files"))
            commands.append(("grep -r 'class ' --include='*.py' | wc -l", "Count classes"))
        elif is_js_ts:
            commands.append(("find . -name '*.js' -o -name '*.ts' | wc -l", "Count JS/TS files"))
            commands.append(("grep -r 'class ' --include='*.js' --include='*.ts' | wc -l", "Count classes"))
        
        # Test commands
        if any('test' in m.name.lower() for m in modules):
            if is_python:
                commands.append(("pytest -v", "Run tests with verbose output"))
                commands.append(("pytest --cov", "Run tests with coverage"))
            elif is_js_ts:
                commands.append(("npm test", "Run tests"))
                commands.append(("npm run test:coverage", "Run tests with coverage"))
        
        # CLI commands
        if any('cli' in m.name.lower() for m in modules):
            if is_python:
                cli_modules = [m for m in modules if 'cli' in m.name.lower()]
                if cli_modules:
                    module_name = cli_modules[0].name.replace('.', '/')
                    commands.append((f"python -m {module_name} --help", "View CLI help"))
        
        # Build/development commands
        if is_js_ts:
            commands.append(("npm run dev", "Start development server"))
            commands.append(("npm run build", "Build for production"))
        
        # Code quality
        if is_python:
            commands.append(("pylint *.py", "Check code quality"))
            commands.append(("radon cc . -a", "Calculate cyclomatic complexity"))
            commands.append(("pydoc <module>", "View module documentation"))
        elif is_js_ts:
            commands.append(("npm run lint", "Check code quality"))
            commands.append(("npm run type-check", "TypeScript type checking"))
        
        return commands


def format_onboarding_report(insights: OnboardingInsights) -> str:
    """Format onboarding insights as a human-readable report."""
    lines = []
    
    lines.append("=" * 80)
    lines.append(f"ONBOARDING GUIDE: {insights.overview.name}")
    lines.append("=" * 80)
    lines.append("")
    
    # Overview
    lines.append("📋 PROJECT OVERVIEW")
    lines.append("-" * 80)
    if insights.overview.description:
        lines.append(f"Description: {insights.overview.description}")
    lines.append(f"Complexity: {insights.overview.estimated_complexity}")
    lines.append(f"Size: {insights.overview.total_files} files, {insights.overview.total_lines:,} lines")
    lines.append("")
    
    if insights.overview.main_technologies:
        lines.append("Technologies:")
        for tech in insights.overview.main_technologies:
            lines.append(f"  • {tech}")
        lines.append("")
    
    if insights.overview.key_dependencies:
        lines.append("Key Dependencies:")
        for dep in insights.overview.key_dependencies:
            lines.append(f"  • {dep}")
        lines.append("")
    
    # Learning Path
    lines.append("🗺️  LEARNING PATH")
    lines.append("-" * 80)
    for step in insights.learning_path.recommended_order:
        lines.append(step)
    lines.append("")
    
    # Key Concepts
    lines.append("🔑 KEY CONCEPTS")
    lines.append("-" * 80)
    if insights.key_concepts.architectural_style:
        lines.append(f"Architecture: {insights.key_concepts.architectural_style}")
        lines.append("")
    
    if insights.key_concepts.design_patterns:
        lines.append("Design Patterns:")
        for pattern in insights.key_concepts.design_patterns:
            lines.append(f"  • {pattern}")
        lines.append("")
    
    if insights.key_concepts.main_classes:
        lines.append("Main Classes (Top 5):")
        for cls_name, purpose in insights.key_concepts.main_classes[:5]:
            lines.append(f"  • {cls_name}: {purpose}")
        lines.append("")
    
    # Quick Start
    lines.append("🚀 QUICK START TIPS")
    lines.append("-" * 80)
    for i, tip in enumerate(insights.quick_start_tips, 1):
        lines.append(f"{i}. {tip}")
    lines.append("")
    
    # Pitfalls
    if insights.common_pitfalls:
        lines.append("⚠️  COMMON PITFALLS")
        lines.append("-" * 80)
        for pitfall in insights.common_pitfalls:
            lines.append(f"  ⚠️  {pitfall}")
        lines.append("")
    
    # Helpful Commands
    lines.append("💻 HELPFUL COMMANDS")
    lines.append("-" * 80)
    for cmd, purpose in insights.helpful_commands:
        lines.append(f"  {cmd}")
        lines.append(f"    → {purpose}")
        lines.append("")
    
    lines.append("=" * 80)
    lines.append("Good luck! 🎉")
    lines.append("=" * 80)
    
    return "\n".join(lines)
