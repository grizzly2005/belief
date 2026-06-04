"""Identifies and documents important sections of code.

This module analyzes code to find:
- Design patterns
- Architectural patterns
- Entry points
- Configuration handlers
- API endpoints
- Database models
- Important business logic
"""

import ast
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, field
from pathlib import Path

from .models import CodeLocation, ModuleInfo, FunctionInfo, ClassInfo


@dataclass
class ImportantSection:
    """Represents an important section of code."""
    name: str
    location: CodeLocation
    category: str  # pattern, entry_point, api, data_model, config, etc.
    importance: str  # critical, high, medium
    description: str
    pattern_type: Optional[str] = None  # e.g., "Singleton", "Factory", "Observer"
    related_sections: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    documentation: Optional[str] = None
    usage_examples: List[str] = field(default_factory=list)


class ImportantSectionIdentifier:
    """Identifies important sections and patterns in code."""
    
    def __init__(self):
        self.important_sections: List[ImportantSection] = []
        self.patterns_found: Dict[str, List[str]] = {}
        
    def identify_important_sections(self, modules: List[ModuleInfo]) -> List[ImportantSection]:
        """
        Identify all important sections in the codebase.
        
        Args:
            modules: List of analyzed modules
            
        Returns:
            List of identified important sections
        """
        self.important_sections = []
        
        for module in modules:
            # Identify entry points
            self._identify_entry_points(module)
            
            # Identify design patterns
            self._identify_design_patterns(module)
            
            # Identify API endpoints
            self._identify_api_endpoints(module)
            
            # Identify data models
            self._identify_data_models(module)
            
            # Identify configuration handlers
            self._identify_config_handlers(module)
            
            # Identify core business logic
            self._identify_business_logic(module)
            
            # Identify database operations
            self._identify_database_operations(module)
            
            # Identify external integrations
            self._identify_integrations(module)
        
        return self.important_sections
    
    def _identify_entry_points(self, module: ModuleInfo):
        """Identify application entry points."""
        # Main function
        for func in module.functions:
            if func.name == "main":
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="entry_point",
                    importance="critical",
                    description="Application main entry point",
                    documentation=func.docstring or "Main entry point - starts the application"
                ))
            
            # CLI commands
            if func.name in ["cli", "run", "start", "execute", "app"]:
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="entry_point",
                    importance="high",
                    description=f"CLI entry point: {func.name}",
                    documentation=func.docstring
                ))
        
        # Check for __main__ block
        if module.name.endswith("__main__") or "main" in module.name.lower():
            for func in module.functions:
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="entry_point",
                    importance="high",
                    description="Module entry point function"
                ))
    
    def _identify_design_patterns(self, module: ModuleInfo):
        """Identify common design patterns."""
        for cls in module.classes:
            # Singleton pattern
            if self._is_singleton(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="high",
                    description="Singleton pattern implementation",
                    pattern_type="Singleton",
                    documentation=cls.docstring or "Singleton class - only one instance exists"
                ))
            
            # Factory pattern
            if self._is_factory(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="high",
                    description="Factory pattern implementation",
                    pattern_type="Factory",
                    documentation=cls.docstring or "Factory class - creates objects"
                ))
            
            # Builder pattern
            if self._is_builder(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="medium",
                    description="Builder pattern implementation",
                    pattern_type="Builder",
                    documentation=cls.docstring or "Builder class - constructs complex objects"
                ))
            
            # Observer pattern
            if self._is_observer(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="high",
                    description="Observer pattern implementation",
                    pattern_type="Observer",
                    documentation=cls.docstring or "Observer class - notifies subscribers of changes"
                ))
            
            # Strategy pattern
            if self._is_strategy(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="medium",
                    description="Strategy pattern implementation",
                    pattern_type="Strategy",
                    documentation=cls.docstring or "Strategy class - encapsulates algorithms"
                ))
            
            # Adapter pattern
            if self._is_adapter(cls):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="pattern",
                    importance="medium",
                    description="Adapter pattern implementation",
                    pattern_type="Adapter",
                    documentation=cls.docstring or "Adapter class - adapts interfaces"
                ))
    
    def _identify_api_endpoints(self, module: ModuleInfo):
        """Identify API endpoints and routes."""
        # Flask/FastAPI decorators
        for func in module.functions:
            # Check for common API decorators in calls
            api_indicators = ['route', 'get', 'post', 'put', 'delete', 'patch', 'api']
            
            if any(indicator in str(func.calls).lower() for indicator in api_indicators):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="api",
                    importance="high",
                    description=f"API endpoint handler: {func.name}",
                    documentation=func.docstring or f"Handles {func.name.replace('_', ' ')} requests"
                ))
        
        # Check for API-related classes
        for cls in module.classes:
            if any(keyword in cls.name.lower() for keyword in ['api', 'endpoint', 'route', 'handler', 'controller']):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="api",
                    importance="high",
                    description=f"API handler class: {cls.name}",
                    documentation=cls.docstring or "API endpoint handler class"
                ))
    
    def _identify_data_models(self, module: ModuleInfo):
        """Identify data models and schemas."""
        for cls in module.classes:
            # ORM models (SQLAlchemy, Django, etc.)
            orm_bases = ['Model', 'Base', 'Document', 'Entity']
            if any(base in cls.bases for base in orm_bases):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="data_model",
                    importance="critical",
                    description=f"Database model: {cls.name}",
                    pattern_type="ORM Model",
                    documentation=cls.docstring or f"Represents {cls.name} in database"
                ))
            
            # Dataclasses
            if 'dataclass' in module.imports or cls.name.endswith('Data'):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="data_model",
                    importance="high",
                    description=f"Data structure: {cls.name}",
                    pattern_type="Dataclass",
                    documentation=cls.docstring or f"Data structure for {cls.name.replace('Data', '')}"
                ))
            
            # Pydantic models
            if 'BaseModel' in cls.bases or 'pydantic' in module.imports:
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="data_model",
                    importance="high",
                    description=f"Validation model: {cls.name}",
                    pattern_type="Pydantic Model",
                    documentation=cls.docstring or "Data validation model"
                ))
    
    def _identify_config_handlers(self, module: ModuleInfo):
        """Identify configuration handlers."""
        config_keywords = ['config', 'settings', 'configuration', 'options']
        
        # Configuration classes
        for cls in module.classes:
            if any(keyword in cls.name.lower() for keyword in config_keywords):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="config",
                    importance="high",
                    description=f"Configuration handler: {cls.name}",
                    documentation=cls.docstring or "Application configuration"
                ))
        
        # Configuration functions
        for func in module.functions:
            if any(keyword in func.name.lower() for keyword in config_keywords + ['load', 'parse']):
                if any(keyword in func.name.lower() for keyword in config_keywords):
                    self.important_sections.append(ImportantSection(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="config",
                        importance="medium",
                        description=f"Configuration function: {func.name}",
                        documentation=func.docstring or "Loads/parses configuration"
                    ))
    
    def _identify_business_logic(self, module: ModuleInfo):
        """Identify core business logic."""
        business_keywords = ['process', 'calculate', 'compute', 'analyze', 'validate', 'transform']
        
        for func in module.functions:
            # Complex functions with business logic
            if func.complexity > 8 and any(keyword in func.name.lower() for keyword in business_keywords):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{func.name}",
                    location=func.location,
                    category="business_logic",
                    importance="high",
                    description=f"Core business logic: {func.name}",
                    documentation=func.docstring or f"Business logic for {func.name.replace('_', ' ')}"
                ))
        
        # Service classes
        for cls in module.classes:
            if any(keyword in cls.name.lower() for keyword in ['service', 'manager', 'handler', 'processor']):
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="business_logic",
                    importance="high",
                    description=f"Business logic class: {cls.name}",
                    documentation=cls.docstring or "Core business logic implementation"
                ))
    
    def _identify_database_operations(self, module: ModuleInfo):
        """Identify database operations."""
        db_keywords = ['query', 'insert', 'update', 'delete', 'save', 'fetch', 'find']
        
        for func in module.functions:
            if any(keyword in func.name.lower() for keyword in db_keywords):
                # Check if it's likely a database operation
                db_indicators = ['db', 'database', 'sql', 'query', 'session', 'connection']
                if any(indicator in func.name.lower() or indicator in str(func.calls).lower() 
                       for indicator in db_indicators):
                    self.important_sections.append(ImportantSection(
                        name=f"{module.name}.{func.name}",
                        location=func.location,
                        category="database",
                        importance="high",
                        description=f"Database operation: {func.name}",
                        documentation=func.docstring or f"Database {func.name.split('_')[0]} operation"
                    ))
        
        # Repository pattern
        for cls in module.classes:
            if 'repository' in cls.name.lower() or 'dao' in cls.name.lower():
                self.important_sections.append(ImportantSection(
                    name=f"{module.name}.{cls.name}",
                    location=cls.location,
                    category="database",
                    importance="high",
                    description=f"Data access layer: {cls.name}",
                    pattern_type="Repository",
                    documentation=cls.docstring or "Data access repository"
                ))
    
    def _identify_integrations(self, module: ModuleInfo):
        """Identify external integrations."""
        integration_keywords = ['client', 'api', 'integration', 'adapter', 'connector']
        
        for cls in module.classes:
            if any(keyword in cls.name.lower() for keyword in integration_keywords):
                # Check if it integrates with external services
                if any(svc in module.imports for svc in ['requests', 'httpx', 'aiohttp', 'boto3']):
                    self.important_sections.append(ImportantSection(
                        name=f"{module.name}.{cls.name}",
                        location=cls.location,
                        category="integration",
                        importance="high",
                        description=f"External integration: {cls.name}",
                        documentation=cls.docstring or "External service integration"
                    ))
    
    # Pattern detection helpers
    
    def _is_singleton(self, cls: ClassInfo) -> bool:
        """Check if class implements Singleton pattern."""
        # Check for __new__ method or _instance attribute
        has_new = any(m.name == "__new__" for m in cls.methods)
        has_instance = "_instance" in cls.attributes
        has_get_instance = any(m.name in ["get_instance", "getInstance"] for m in cls.methods)
        
        return (has_new and has_instance) or has_get_instance or 'singleton' in cls.name.lower()
    
    def _is_factory(self, cls: ClassInfo) -> bool:
        """Check if class implements Factory pattern."""
        factory_indicators = [
            'factory' in cls.name.lower(),
            any(m.name.startswith('create_') or m.name.startswith('make_') for m in cls.methods),
            any(m.name in ['create', 'build', 'make'] for m in cls.methods)
        ]
        return any(factory_indicators)
    
    def _is_builder(self, cls: ClassInfo) -> bool:
        """Check if class implements Builder pattern."""
        builder_indicators = [
            'builder' in cls.name.lower(),
            any(m.name == 'build' for m in cls.methods),
            len([m for m in cls.methods if m.name.startswith('with_') or m.name.startswith('set_')]) >= 3
        ]
        return any(builder_indicators)
    
    def _is_observer(self, cls: ClassInfo) -> bool:
        """Check if class implements Observer pattern."""
        observer_indicators = [
            'observer' in cls.name.lower() or 'listener' in cls.name.lower(),
            any(m.name in ['subscribe', 'unsubscribe', 'notify', 'update'] for m in cls.methods),
            any(m.name.startswith('on_') for m in cls.methods)
        ]
        return any(observer_indicators)
    
    def _is_strategy(self, cls: ClassInfo) -> bool:
        """Check if class implements Strategy pattern."""
        strategy_indicators = [
            'strategy' in cls.name.lower(),
            cls.is_abstract and len(cls.methods) <= 3,
            any(m.name in ['execute', 'perform', 'apply'] for m in cls.methods)
        ]
        return any(strategy_indicators)
    
    def _is_adapter(self, cls: ClassInfo) -> bool:
        """Check if class implements Adapter pattern."""
        adapter_indicators = [
            'adapter' in cls.name.lower() or 'wrapper' in cls.name.lower(),
            len(cls.attributes) >= 1 and any('_adapted' in attr or '_wrapped' in attr for attr in cls.attributes)
        ]
        return any(adapter_indicators)
    
    def generate_documentation(self, important_sections: List[ImportantSection]) -> str:
        """
        Generate documentation for important sections.
        
        Args:
            important_sections: List of identified important sections
            
        Returns:
            Formatted documentation string
        """
        doc = ["# Important Code Sections\n\n"]
        
        # Group by category
        by_category = {}
        for section in important_sections:
            if section.category not in by_category:
                by_category[section.category] = []
            by_category[section.category].append(section)
        
        # Sort categories by importance
        category_order = [
            "entry_point", "data_model", "api", "business_logic",
            "pattern", "config", "database", "integration"
        ]
        
        category_titles = {
            "entry_point": "🚀 Entry Points",
            "data_model": "📊 Data Models",
            "api": "🌐 API Endpoints",
            "business_logic": "💼 Business Logic",
            "pattern": "🎨 Design Patterns",
            "config": "⚙️ Configuration",
            "database": "🗄️ Database Operations",
            "integration": "🔌 External Integrations"
        }
        
        for category in category_order:
            if category in by_category:
                sections = by_category[category]
                doc.append(f"\n## {category_titles.get(category, category.title())}\n\n")
                
                # Sort by importance
                sections.sort(key=lambda s: {"critical": 0, "high": 1, "medium": 2}.get(s.importance, 3))
                
                for section in sections:
                    importance_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(section.importance, "⚪")
                    
                    doc.append(f"### {importance_emoji} {section.name}\n\n")
                    doc.append(f"**Location**: `{section.location}`\n\n")
                    doc.append(f"**Importance**: {section.importance.upper()}\n\n")
                    doc.append(f"**Description**: {section.description}\n\n")
                    
                    if section.pattern_type:
                        doc.append(f"**Pattern**: {section.pattern_type}\n\n")
                    
                    if section.documentation:
                        doc.append(f"**Documentation**:\n```\n{section.documentation}\n```\n\n")
                    
                    if section.dependencies:
                        doc.append(f"**Dependencies**: {', '.join(f'`{d}`' for d in section.dependencies)}\n\n")
                    
                    doc.append("---\n\n")
        
        return ''.join(doc)
