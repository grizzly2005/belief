"""Core code analyzer implementation using AST."""

import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Optional
from datetime import datetime
from radon.complexity import cc_visit
from radon.metrics import mi_visit
from tqdm import tqdm

from .models import (
    AnalysisResult, ModuleInfo, FunctionInfo, ClassInfo, CodeLocation,
    Issue, IssueType, IssueSeverity, CriticalSection, AnalysisMetrics
)
from .important_sections import ImportantSectionIdentifier
from .improvement_detector import ImprovementDetector
from .plugins import PluginManager
from .code_library import CodeLibrary, PatternMatcher, create_default_library
from .base_analyzer import LanguageAnalyzer
from .js_analyzer import JavaScriptAnalyzer
from .language_detection import LanguageDetector


class CodeAnalyzer:
    """Main code analyzer that supports multiple programming languages."""
    
    def __init__(self, project_path: str, ignore_patterns: Optional[List[str]] = None,
                 plugin_dir: Optional[Path] = None, code_library_path: Optional[Path] = None,
                 languages: Optional[List[str]] = None):
        """Initialize analyzer with project path."""
        self.project_path = Path(project_path).resolve()
        self.ignore_patterns = ignore_patterns or [
            "*/venv/*", "*/env/*", "*/.venv/*", "*/node_modules/*",
            "*/migrations/*", "*/build/*", "*/dist/*",
            "*/.git/*", "*/__pycache__/*", "*.egg-info/*"
        ]
        self.modules: List[ModuleInfo] = []
        self.issues: List[Issue] = []
        self.critical_sections: List[CriticalSection] = []
        self.call_graph: Dict[str, Set[str]] = {}
        
        # Language detection and analyzers
        self.language_detector = LanguageDetector()
        self.language_analyzers: Dict[str, LanguageAnalyzer] = {}
        self.enabled_languages = languages or ['python', 'javascript', 'typescript']  # Default enabled
        
        # Register language analyzers
        self._register_language_analyzers()
        
        # Plugin system
        self.plugin_manager = PluginManager()
        if plugin_dir:
            print(f"📦 Loading plugins from {plugin_dir}")
            self.plugin_manager.load_plugins_from_directory(plugin_dir)
        
        # Code library
        self.code_library: Optional[CodeLibrary] = None
        self.pattern_matcher: Optional[PatternMatcher] = None
        if code_library_path:
            print(f"📚 Loading code library from {code_library_path}")
            self.code_library = CodeLibrary(code_library_path)
            self.pattern_matcher = PatternMatcher(self.code_library)
        elif code_library_path is not None:  # Path specified but doesn't exist, use defaults
            print(f"📚 Creating default code library")
            self.code_library = create_default_library()
            self.pattern_matcher = PatternMatcher(self.code_library)
    
    def _register_language_analyzers(self):
        """Register available language analyzers."""
        # JavaScript/TypeScript analyzer
        if any(lang in self.enabled_languages for lang in ['javascript', 'typescript']):
            js_analyzer = JavaScriptAnalyzer()
            for ext in js_analyzer.get_supported_extensions():
                self.language_analyzers[ext] = js_analyzer
        
        # Python analyzer is handled separately (legacy code)
        # Future: refactor to use LanguageAnalyzer interface
    
    def _get_analyzer_for_file(self, file_path: Path) -> Optional[LanguageAnalyzer]:
        """Get the appropriate analyzer for a file based on its extension."""
        ext = file_path.suffix
        return self.language_analyzers.get(ext)
        
    def analyze(self, depth: str = "deep") -> AnalysisResult:
        """
        Analyze the entire project.
        
        Args:
            depth: Analysis depth - 'shallow', 'medium', or 'deep'
            
        Returns:
            AnalysisResult with complete analysis data
        """
        print(f"🔍 Analyzing project: {self.project_path}")
        print(f"   Depth: {depth}")
        print(f"   Languages: {', '.join(self.enabled_languages)}")
        
        # Find all source files (all languages)
        source_files = self._find_source_files()
        print(f"   Found {len(source_files)} source files")
        
        # Run pre-analysis hooks
        self.plugin_manager.run_pre_analysis_hooks([])
        
        # Analyze each file with progress bar
        for file_path in tqdm(source_files, desc="📄 Analyzing files", unit="file"):
            try:
                module_info = self._analyze_any_file(file_path)
                if module_info:
                    self.modules.append(module_info)
            except Exception as e:
                tqdm.write(f"   ⚠️  Error analyzing {file_path}: {e}")
        
        # Build call graph
        self._build_call_graph()
        
        # Identify critical sections
        self._identify_critical_sections()
        
        # Detect issues based on depth
        if depth in ["medium", "deep"]:
            self._detect_complexity_issues()
            self._detect_unused_code()
            self._detect_code_smells()
        
        if depth == "deep":
            self._detect_security_issues()
            self._detect_conceptual_issues()
        
        # Calculate metrics
        metrics = self._calculate_metrics()
        
        # Identify entry points
        entry_points = self._identify_entry_points()
        
        # Build dependency graph
        dependency_graph = self._build_dependency_graph()
        
        # Identify important sections
        important_identifier = ImportantSectionIdentifier()
        important_sections = important_identifier.identify_important_sections(self.modules)
        
        # Detect improvement opportunities
        improvement_detector = ImprovementDetector()
        improvements = improvement_detector.detect_improvements(self.modules)
        
        # Run plugins
        if self.plugin_manager.plugins:
            print(f"🔌 Running {len(self.plugin_manager.plugins)} plugin(s)")
            plugin_issues = self.plugin_manager.run_analysis(self.modules)
            self.issues.extend(plugin_issues)
        
        # Run pattern matching against code library
        library_matches = []
        if self.pattern_matcher:
            for module in tqdm(self.modules, desc="📚 Pattern matching", unit="module"):
                matches = self.pattern_matcher.find_matches(module)
                library_matches.extend(matches)
            
            # Generate issues from bad/smelly patterns
            library_issues = self.pattern_matcher.generate_issues_from_matches(library_matches)
            self.issues.extend(library_issues)
            if library_matches:
                print(f"   Found {len(library_matches)} pattern matches ({len(library_issues)} issues)")
        
        # Run post-analysis hooks
        self.plugin_manager.run_post_analysis_hooks(self.modules, self.issues)
        
        # Generate custom findings from plugins
        custom_findings = self.plugin_manager.generate_custom_findings(self.modules)
        
        print(f"✅ Analysis complete:")
        print(f"   Modules: {len(self.modules)}")
        print(f"   Issues: {len(self.issues)}")
        print(f"   Critical sections: {len(self.critical_sections)}")
        print(f"   Important sections: {len(important_sections)}")
        print(f"   Improvement opportunities: {len(improvements)}")
        if library_matches:
            print(f"   Code library matches: {len(library_matches)}")
        
        return AnalysisResult(
            project_path=str(self.project_path),
            analysis_date=datetime.now(),
            modules=self.modules,
            issues=self.issues,
            critical_sections=self.critical_sections,
            metrics=metrics,
            dependency_graph=dependency_graph,
            entry_points=entry_points,
            important_sections=important_sections,
            improvements=improvements
        )
    
    def _find_source_files(self) -> List[Path]:
        """Find all source files for enabled languages in the project."""
        source_files = []
        
        # Build list of extensions to search for
        extensions = ['.py', '.pyi']  # Always include Python
        for analyzer in self.language_analyzers.values():
            extensions.extend(analyzer.get_supported_extensions())
        extensions = list(set(extensions))  # Remove duplicates
        
        for root, dirs, files in os.walk(self.project_path):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore(Path(root) / d)]
            
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix in extensions and not self._should_ignore(file_path):
                    source_files.append(file_path)
        
        return source_files
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files in the project (legacy method)."""
        python_files = []
        for root, dirs, files in os.walk(self.project_path):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if not self._should_ignore(Path(root) / d)]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    if not self._should_ignore(file_path):
                        python_files.append(file_path)
        return python_files
    
    def _analyze_any_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Route file to appropriate analyzer based on extension."""
        # Check if it's a Python file (use legacy analyzer)
        if file_path.suffix in ['.py', '.pyi']:
            return self._analyze_file(file_path)
        
        # Use language-specific analyzer
        analyzer = self._get_analyzer_for_file(file_path)
        if analyzer:
            return analyzer.analyze_file(file_path)
        
        return None
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored."""
        path_str = str(path)
        
        # Check if any part of the path matches ignore patterns
        for pattern in self.ignore_patterns:
            # Remove leading */ for proper matching
            clean_pattern = pattern.lstrip('*/')
            
            # Check if pattern exists anywhere in the path
            if f'/{clean_pattern}/' in path_str or path_str.endswith(f'/{clean_pattern}'):
                return True
            
            # Also check directory names directly
            parts = Path(path_str).parts
            if clean_pattern.rstrip('/*') in parts:
                return True
        
        return False
    
    def _analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a single Python file."""
        try:
            # Try UTF-8 first, then fall back to latin-1
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Try latin-1 as fallback
                try:
                    with open(file_path, 'r', encoding='latin-1') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    # Skip files with encoding issues
                    return None
            
            tree = ast.parse(content, filename=str(file_path))
            
            # Extract module information
            module_name = self._get_module_name(file_path)
            docstring = ast.get_docstring(tree)
            
            module_info = ModuleInfo(
                name=module_name,
                file_path=str(file_path.resolve().relative_to(self.project_path.resolve())),
                docstring=docstring,
                lines_of_code=len(content.splitlines())
            )
            
            # Analyze imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module_info.imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_info.imports.append(node.module)
            
            # Analyze classes and functions
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._analyze_class(node, file_path)
                    module_info.classes.append(class_info)
                elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                    # Only top-level functions
                    if self._is_top_level(node, tree):
                        func_info = self._analyze_function(node, file_path)
                        module_info.functions.append(func_info)
            
            # Calculate complexity
            try:
                complexity_results = cc_visit(content)
                module_info.complexity = sum(r.complexity for r in complexity_results)
            except:
                pass
            
            return module_info
            
        except SyntaxError as e:
            # Skip files with syntax errors (might be Python 2 or invalid)
            return None
        except Exception as e:
            # Log but don't crash on unexpected errors
            return None
    
    def _get_module_name(self, file_path: Path) -> str:
        """Get module name from file path."""
        # Resolve both paths to handle symlinks
        resolved_file = file_path.resolve()
        resolved_project = self.project_path.resolve()
        rel_path = resolved_file.relative_to(resolved_project)
        parts = list(rel_path.parts[:-1]) + [rel_path.stem]
        if parts[-1] == '__init__':
            parts = parts[:-1]
        return '.'.join(parts) if parts else '__main__'
    
    def _is_top_level(self, node: ast.AST, tree: ast.Module) -> bool:
        """Check if node is at module level."""
        for item in tree.body:
            if item == node:
                return True
        return False
    
    def _analyze_class(self, node: ast.ClassDef, file_path: Path) -> ClassInfo:
        """Analyze a class definition."""
        location = CodeLocation(
            file_path=str(file_path.resolve().relative_to(self.project_path.resolve())),
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            class_name=node.name
        )
        
        bases = [self._get_name(base) for base in node.bases]
        docstring = ast.get_docstring(node)
        
        class_info = ClassInfo(
            name=node.name,
            location=location,
            bases=bases,
            docstring=docstring
        )
        
        # Analyze methods
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_info = self._analyze_function(item, file_path, class_name=node.name)
                class_info.methods.append(method_info)
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                class_info.attributes.append(item.target.id)
        
        # Check if abstract
        for decorator in node.decorator_list:
            if self._get_name(decorator) in ['abstractmethod', 'ABC']:
                class_info.is_abstract = True
        
        return class_info
    
    def _analyze_function(self, node: ast.FunctionDef, file_path: Path, 
                         class_name: Optional[str] = None) -> FunctionInfo:
        """Analyze a function definition."""
        location = CodeLocation(
            file_path=str(file_path.resolve().relative_to(self.project_path.resolve())),
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            function_name=node.name,
            class_name=class_name
        )
        
        # Extract parameters
        params = [arg.arg for arg in node.args.args]
        
        # Extract return type
        return_type = None
        if node.returns:
            return_type = self._get_name(node.returns)
        
        # Get docstring
        docstring = ast.get_docstring(node)
        
        # Calculate complexity
        complexity = 1  # Base complexity
        for _ in ast.walk(node):
            if isinstance(_, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
        
        # Find function calls
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_name(child.func)
                if call_name:
                    calls.append(call_name)
        
        # Extract decorators
        decorators = []
        for decorator in node.decorator_list:
            decorator_name = self._get_name(decorator)
            if decorator_name:
                decorators.append(decorator_name)
        
        is_async = isinstance(node, ast.AsyncFunctionDef)
        is_generator = any(isinstance(n, ast.Yield) for n in ast.walk(node))
        
        return FunctionInfo(
            name=node.name,
            location=location,
            parameters=params,
            return_type=return_type,
            docstring=docstring,
            complexity=complexity,
            is_async=is_async,
            is_generator=is_generator,
            calls=calls,
            decorators=decorators
        )
    
    def _get_name(self, node: ast.AST) -> str:
        """Extract name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value = self._get_name(node.value)
            return f"{value}.{node.attr}" if value else node.attr
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        return ""
    
    def _build_call_graph(self):
        """Build call graph from analyzed functions."""
        # Create mapping of function names to modules
        func_map = {}
        for module in self.modules:
            for func in module.functions:
                full_name = f"{module.name}.{func.name}"
                func_map[func.name] = full_name
                self.call_graph[full_name] = set(func.calls)
            
            for cls in module.classes:
                for method in cls.methods:
                    full_name = f"{module.name}.{cls.name}.{method.name}"
                    func_map[method.name] = full_name
                    self.call_graph[full_name] = set(method.calls)
        
        # Update called_by relationships
        for module in self.modules:
            for func in module.functions:
                full_name = f"{module.name}.{func.name}"
                for call in func.calls:
                    if call in func_map:
                        called_name = func_map[call]
                        # Find the called function and update its called_by list
                        for m in self.modules:
                            for f in m.functions + [mth for cls in m.classes for mth in cls.methods]:
                                if f"{m.name}.{f.name}" == called_name or \
                                   any(f"{m.name}.{cls.name}.{f.name}" == called_name 
                                       for cls in m.classes):
                                    f.called_by.append(full_name)
    
    def _identify_critical_sections(self):
        """Identify critical sections of code."""
        for module in self.modules:
            # High complexity functions are critical
            for func in module.functions:
                if func.complexity > 10:
                    self.critical_sections.append(CriticalSection(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        reason=f"High complexity ({func.complexity})",
                        risk_level=IssueSeverity.HIGH if func.complexity > 15 else IssueSeverity.MEDIUM,
                        dependencies=func.calls
                    ))
            
            # Classes with many methods
            for cls in module.classes:
                if len(cls.methods) > 15:
                    self.critical_sections.append(CriticalSection(
                        name=f"{module.name}.{cls.name}",
                        location=cls.location,
                        reason=f"Large class ({len(cls.methods)} methods)",
                        risk_level=IssueSeverity.MEDIUM
                    ))
            
            # Entry points (main, if __name__ == "__main__")
            if any(func.name == "main" for func in module.functions):
                func = next(f for f in module.functions if f.name == "main")
                self.critical_sections.append(CriticalSection(
                    name=f"{module.name}.main",
                    location=func.location,
                    reason="Application entry point",
                    risk_level=IssueSeverity.HIGH,
                    impact_areas=["startup", "initialization"]
                ))
    
    def _detect_complexity_issues(self):
        """Detect complexity-related issues."""
        for module in self.modules:
            for func in module.functions + [m for cls in module.classes for m in cls.methods]:
                if func.complexity > 15:
                    self.issues.append(Issue(
                        issue_type=IssueType.COMPLEXITY,
                        severity=IssueSeverity.HIGH,
                        title=f"High complexity in {func.name}",
                        description=f"Function has cyclomatic complexity of {func.complexity}",
                        location=func.location,
                        recommendation="Consider breaking this function into smaller, more focused functions",
                        metadata={"complexity": func.complexity}
                    ))
                elif func.complexity > 10:
                    self.issues.append(Issue(
                        issue_type=IssueType.COMPLEXITY,
                        severity=IssueSeverity.MEDIUM,
                        title=f"Moderate complexity in {func.name}",
                        description=f"Function has cyclomatic complexity of {func.complexity}",
                        location=func.location,
                        recommendation="Consider simplifying this function",
                        metadata={"complexity": func.complexity}
                    ))
    
    def _has_framework_decorators(self, func: FunctionInfo) -> bool:
        """Check if function has decorators that indicate external usage."""
        framework_decorators = [
            # Click (CLI framework)
            'click.command', 'click.group', 'command', 'group',
            # Pytest (testing framework)
            'pytest.fixture', 'fixture',
            # Flask/FastAPI (web frameworks)
            'app.route', 'route', 'get', 'post', 'put', 'delete',
            'app.get', 'app.post', 'app.put', 'app.delete',
            # Django
            'require_http_methods', 'login_required',
            # Celery (task queue)
            'task', 'shared_task',
            # Property decorators
            'property', 'staticmethod', 'classmethod',
        ]
        
        for decorator in func.decorators:
            # Check for exact match or if it's a method call (e.g., app.route())
            decorator_lower = decorator.lower()
            for framework_dec in framework_decorators:
                if framework_dec in decorator_lower:
                    return True
        
        return False
    
    def _is_public_api(self, func: FunctionInfo, module: ModuleInfo) -> bool:
        """Check if function appears to be part of public API."""
        # Functions in __init__.py are likely public API
        if '__init__' in module.file_path:
            return True
        
        # Functions starting with underscore are private
        if func.name.startswith('_'):
            return False
        
        # If module has __all__, check if function is in it
        # (We'd need to parse __all__ from the AST, but this is a simple heuristic)
        # For now, assume non-private functions in certain directories are public
        public_dirs = ['api', 'public', 'interface', 'facade']
        for dir_name in public_dirs:
            if dir_name in module.file_path:
                return True
        
        return False
    
    def _detect_unused_code(self):
        """Detect potentially unused code."""
        # Find functions that are never called
        all_functions = set()
        called_functions = set()
        
        for module in self.modules:
            for func in module.functions:
                func_name = f"{module.name}.{func.name}"
                all_functions.add(func_name)
                if func.called_by:
                    called_functions.add(func_name)
        
        unused = all_functions - called_functions
        for func_name in unused:
            # Skip special methods and common entry points
            if func_name.endswith(('__init__', '__main__', 'main', '__str__', '__repr__')):
                continue
            
            # Find the function to get its location and decorators
            for module in self.modules:
                for func in module.functions:
                    if f"{module.name}.{func.name}" == func_name:
                        # Skip if it has framework decorators that make it used externally
                        if self._has_framework_decorators(func):
                            continue
                        
                        # Skip if it's in __init__.py (likely part of public API)
                        if module.file_path.endswith('__init__.py'):
                            continue
                        
                        # Skip if function name suggests it's a public API
                        if self._is_public_api(func, module):
                            continue
                        
                        self.issues.append(Issue(
                            issue_type=IssueType.UNUSED_CODE,
                            severity=IssueSeverity.LOW,
                            title=f"Potentially unused function: {func.name}",
                            description="This function is not called anywhere in the codebase",
                            location=func.location,
                            recommendation="Consider removing if truly unused, or document its external usage"
                        ))
    
    def _detect_code_smells(self):
        """Detect code smells and anti-patterns."""
        for module in self.modules:
            # Long parameter lists
            for func in module.functions + [m for cls in module.classes for m in cls.methods]:
                if len(func.parameters) > 5:
                    self.issues.append(Issue(
                        issue_type=IssueType.CODE_SMELL,
                        severity=IssueSeverity.MEDIUM,
                        title=f"Long parameter list in {func.name}",
                        description=f"Function has {len(func.parameters)} parameters",
                        location=func.location,
                        recommendation="Consider using a configuration object or builder pattern"
                    ))
            
            # Missing docstrings
            for func in module.functions:
                if not func.docstring and not func.name.startswith('_'):
                    self.issues.append(Issue(
                        issue_type=IssueType.DOCUMENTATION,
                        severity=IssueSeverity.LOW,
                        title=f"Missing docstring: {func.name}",
                        description="Public function lacks documentation",
                        location=func.location,
                        recommendation="Add a docstring describing purpose, parameters, and return value"
                    ))
    
    def _detect_security_issues(self):
        """Detect potential security issues."""
        # This is a simplified version - in production, use bandit or similar
        for module in self.modules:
            # Check for dangerous imports
            dangerous_imports = ['pickle', 'marshal', 'shelve']
            for imp in module.imports:
                if any(danger in imp for danger in dangerous_imports):
                    self.issues.append(Issue(
                        issue_type=IssueType.SECURITY,
                        severity=IssueSeverity.MEDIUM,
                        title=f"Potentially dangerous import: {imp}",
                        description=f"Module imports {imp} which can be unsafe",
                        location=CodeLocation(
                            file_path=module.file_path,
                            line_start=1,
                            line_end=1
                        ),
                        recommendation="Ensure proper input validation when using this module"
                    ))
    
    def _detect_conceptual_issues(self):
        """Detect conceptual and architectural issues."""
        # God classes (too many responsibilities)
        for module in self.modules:
            for cls in module.classes:
                if len(cls.methods) > 20:
                    self.issues.append(Issue(
                        issue_type=IssueType.CONCEPTUAL,
                        severity=IssueSeverity.HIGH,
                        title=f"God class: {cls.name}",
                        description=f"Class has {len(cls.methods)} methods, indicating too many responsibilities",
                        location=cls.location,
                        recommendation="Consider splitting into smaller, more focused classes following SRP"
                    ))
    
    def _calculate_metrics(self) -> AnalysisMetrics:
        """Calculate overall project metrics."""
        metrics = AnalysisMetrics()
        
        metrics.total_files = len(self.modules)
        metrics.total_lines = sum(m.lines_of_code for m in self.modules)
        metrics.total_classes = sum(len(m.classes) for m in self.modules)
        metrics.total_functions = sum(
            len(m.functions) + sum(len(c.methods) for c in m.classes)
            for m in self.modules
        )
        metrics.total_issues = len(self.issues)
        
        # Group issues by severity
        for issue in self.issues:
            severity_key = issue.severity.value
            metrics.issues_by_severity[severity_key] = \
                metrics.issues_by_severity.get(severity_key, 0) + 1
        
        # Group issues by type
        for issue in self.issues:
            type_key = issue.issue_type.value
            metrics.issues_by_type[type_key] = \
                metrics.issues_by_type.get(type_key, 0) + 1
        
        # Calculate complexity metrics
        all_complexities = []
        for module in self.modules:
            for func in module.functions + [m for cls in module.classes for m in cls.methods]:
                all_complexities.append(func.complexity)
        
        if all_complexities:
            metrics.average_complexity = sum(all_complexities) / len(all_complexities)
            metrics.max_complexity = max(all_complexities)
        
        return metrics
    
    def _identify_entry_points(self) -> List[str]:
        """Identify application entry points."""
        entry_points = []
        
        for module in self.modules:
            # Look for main functions
            if any(f.name == "main" for f in module.functions):
                entry_points.append(f"{module.name}.main")
            
            # Look for CLI entry points
            if any(f.name in ["cli", "run", "start", "execute"] for f in module.functions):
                entry_points.append(module.name)
        
        return entry_points
    
    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """Build module dependency graph."""
        dep_graph = {}
        
        for module in self.modules:
            # Filter to internal dependencies only
            internal_deps = [
                imp for imp in module.imports
                if any(imp.startswith(m.name.split('.')[0]) for m in self.modules)
            ]
            dep_graph[module.name] = internal_deps
        
        return dep_graph
