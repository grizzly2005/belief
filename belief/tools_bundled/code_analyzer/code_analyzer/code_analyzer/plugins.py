"""Plugin system for custom code analyzers.

Allows users to add custom analysis logic and findings generation.
"""

from typing import List, Dict, Any, Optional, Callable
from abc import ABC, abstractmethod
from pathlib import Path
import importlib.util
import inspect

from .models import ModuleInfo, Issue, IssueType, IssueSeverity, CodeLocation


class AnalyzerPlugin(ABC):
    """Base class for analyzer plugins.
    
    Users can subclass this to add custom analysis logic.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Plugin version."""
        pass
    
    @abstractmethod
    def analyze_module(self, module: ModuleInfo) -> List[Issue]:
        """
        Analyze a module and return issues found.
        
        Args:
            module: Module to analyze
            
        Returns:
            List of issues found
        """
        pass
    
    def pre_analysis_hook(self, modules: List[ModuleInfo]) -> None:
        """
        Called before analysis begins.
        
        Args:
            modules: All modules to be analyzed
        """
        pass
    
    def post_analysis_hook(self, modules: List[ModuleInfo], all_issues: List[Issue]) -> None:
        """
        Called after analysis completes.
        
        Args:
            modules: All analyzed modules
            all_issues: All issues found
        """
        pass
    
    def generate_custom_findings(self, modules: List[ModuleInfo]) -> Dict[str, Any]:
        """
        Generate custom findings/metrics.
        
        Args:
            modules: All analyzed modules
            
        Returns:
            Dictionary of custom findings
        """
        return {}


class CustomRulePlugin(AnalyzerPlugin):
    """Plugin for adding custom rules.
    
    Example:
        class MyCustomRules(CustomRulePlugin):
            name = "my-rules"
            version = "1.0.0"
            
            def add_rules(self):
                self.add_rule(
                    name="no-print-statements",
                    check=lambda func: "print" in str(func.calls),
                    severity=IssueSeverity.LOW,
                    message="Avoid print statements, use logging instead"
                )
    """
    
    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
    
    def add_rule(self, 
                 name: str,
                 check: Callable,
                 severity: IssueSeverity,
                 message: str,
                 recommendation: Optional[str] = None):
        """
        Add a custom rule.
        
        Args:
            name: Rule name
            check: Function that takes a module/function/class and returns True if rule violated
            severity: Issue severity
            message: Issue message
            recommendation: Optional recommendation
        """
        self.rules.append({
            'name': name,
            'check': check,
            'severity': severity,
            'message': message,
            'recommendation': recommendation
        })
    
    def analyze_module(self, module: ModuleInfo) -> List[Issue]:
        """Apply all custom rules to module."""
        issues = []
        
        for rule in self.rules:
            # Check module-level
            if rule['check'](module):
                issues.append(Issue(
                    issue_type=IssueType.CODE_SMELL,
                    severity=rule['severity'],
                    title=f"Custom rule violated: {rule['name']}",
                    description=rule['message'],
                    location=CodeLocation(
                        file_path=module.file_path,
                        line_start=1,
                        line_end=1
                    ),
                    recommendation=rule['recommendation']
                ))
            
            # Check functions
            for func in module.functions:
                if rule['check'](func):
                    issues.append(Issue(
                        issue_type=IssueType.CODE_SMELL,
                        severity=rule['severity'],
                        title=f"Custom rule violated: {rule['name']}",
                        description=rule['message'],
                        location=func.location,
                        recommendation=rule['recommendation']
                    ))
            
            # Check classes
            for cls in module.classes:
                if rule['check'](cls):
                    issues.append(Issue(
                        issue_type=IssueType.CODE_SMELL,
                        severity=rule['severity'],
                        title=f"Custom rule violated: {rule['name']}",
                        description=rule['message'],
                        location=cls.location,
                        recommendation=rule['recommendation']
                    ))
        
        return issues


class PluginManager:
    """Manages analyzer plugins."""
    
    def __init__(self):
        self.plugins: List[AnalyzerPlugin] = []
        self.plugin_dir: Optional[Path] = None
    
    def register_plugin(self, plugin: AnalyzerPlugin):
        """Register a plugin instance."""
        self.plugins.append(plugin)
        print(f"   Registered plugin: {plugin.name} v{plugin.version}")
    
    def load_plugins_from_directory(self, plugin_dir: Path):
        """
        Load plugins from directory.
        
        Args:
            plugin_dir: Directory containing plugin files
        """
        self.plugin_dir = plugin_dir
        
        if not plugin_dir.exists():
            return
        
        for plugin_file in plugin_dir.glob("*.py"):
            if plugin_file.name.startswith("_"):
                continue
            
            try:
                # Load module
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, 
                    plugin_file
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find plugin classes
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, AnalyzerPlugin) and obj != AnalyzerPlugin:
                            plugin_instance = obj()
                            self.register_plugin(plugin_instance)
            
            except Exception as e:
                print(f"   ⚠️  Failed to load plugin {plugin_file}: {e}")
    
    def run_pre_analysis_hooks(self, modules: List[ModuleInfo]):
        """Run pre-analysis hooks for all plugins."""
        for plugin in self.plugins:
            try:
                plugin.pre_analysis_hook(modules)
            except Exception as e:
                print(f"   ⚠️  Plugin {plugin.name} pre-analysis hook failed: {e}")
    
    def run_analysis(self, modules: List[ModuleInfo]) -> List[Issue]:
        """Run all plugins and collect issues."""
        all_issues = []
        
        for plugin in self.plugins:
            try:
                for module in modules:
                    issues = plugin.analyze_module(module)
                    all_issues.extend(issues)
            except Exception as e:
                print(f"   ⚠️  Plugin {plugin.name} analysis failed: {e}")
        
        return all_issues
    
    def run_post_analysis_hooks(self, modules: List[ModuleInfo], all_issues: List[Issue]):
        """Run post-analysis hooks for all plugins."""
        for plugin in self.plugins:
            try:
                plugin.post_analysis_hook(modules, all_issues)
            except Exception as e:
                print(f"   ⚠️  Plugin {plugin.name} post-analysis hook failed: {e}")
    
    def generate_custom_findings(self, modules: List[ModuleInfo]) -> Dict[str, Any]:
        """Generate custom findings from all plugins."""
        findings = {}
        
        for plugin in self.plugins:
            try:
                plugin_findings = plugin.generate_custom_findings(modules)
                if plugin_findings:
                    findings[plugin.name] = plugin_findings
            except Exception as e:
                print(f"   ⚠️  Plugin {plugin.name} findings generation failed: {e}")
        
        return findings


# Example built-in plugins

class NamingConventionPlugin(CustomRulePlugin):
    """Plugin to enforce naming conventions."""
    
    @property
    def name(self) -> str:
        return "naming-conventions"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def __init__(self):
        super().__init__()
        
        # Add naming rules
        self.add_rule(
            name="class-name-pascal-case",
            check=lambda obj: hasattr(obj, 'name') and obj.name[0].islower() if hasattr(obj, 'name') else False,
            severity=IssueSeverity.LOW,
            message="Class names should use PascalCase",
            recommendation="Rename class to start with uppercase letter"
        )
        
        self.add_rule(
            name="no-single-letter-vars",
            check=lambda obj: hasattr(obj, 'name') and len(obj.name) == 1 and obj.name not in ['i', 'j', 'k', 'x', 'y', 'z'],
            severity=IssueSeverity.LOW,
            message="Avoid single-letter variable names (except loop counters)",
            recommendation="Use descriptive variable names"
        )


class LoggingBestPracticesPlugin(CustomRulePlugin):
    """Plugin to enforce logging best practices."""
    
    @property
    def name(self) -> str:
        return "logging-practices"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def __init__(self):
        super().__init__()
        
        self.add_rule(
            name="use-logging-not-print",
            check=lambda func: hasattr(func, 'calls') and 'print' in str(func.calls),
            severity=IssueSeverity.LOW,
            message="Use logging module instead of print statements",
            recommendation="Import logging and use logger.info(), logger.debug(), etc."
        )
