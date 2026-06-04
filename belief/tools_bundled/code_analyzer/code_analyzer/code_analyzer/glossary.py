"""Glossary generator - extracts and explains key technical terms and domain concepts."""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
import re
from .models import ModuleInfo


class GlossaryGenerator:
    """Generates glossary of technical terms and domain concepts."""
    
    def __init__(self):
        # Common tech terms we should explain
        self.tech_terms = {
            'api': 'Application Programming Interface - defines how software components interact',
            'cli': 'Command Line Interface - text-based interface for user interaction',
            'orm': 'Object-Relational Mapping - translates between database and objects',
            'async': 'Asynchronous - operations that run without blocking execution',
            'decorator': 'Python syntax (@) to modify function/class behavior',
            'context manager': 'Python construct using "with" for resource management',
            'generator': 'Function that yields values lazily, saving memory',
            'metaclass': 'Class that defines the behavior of other classes',
            'singleton': 'Design pattern ensuring only one instance exists',
            'factory': 'Design pattern for creating objects without specifying exact class',
            'mixin': 'Class providing methods to other classes via inheritance',
            'dependency injection': 'Providing dependencies from outside rather than creating internally',
        }
    
    def generate_glossary(self, modules: List[ModuleInfo], project_name: str) -> Dict[str, str]:
        """Generate glossary from code analysis."""
        glossary = {}
        
        # Extract domain terms from class/function names
        domain_terms = self._extract_domain_terms(modules)
        glossary.update(domain_terms)
        
        # Add technical terms found in code
        tech_terms_found = self._find_tech_terms(modules)
        glossary.update(tech_terms_found)
        
        # Extract terms from docstrings
        docstring_terms = self._extract_from_docstrings(modules)
        glossary.update(docstring_terms)
        
        return glossary
    
    def _extract_domain_terms(self, modules: List[ModuleInfo]) -> Dict[str, str]:
        """Extract domain-specific terms from class and function names."""
        terms = {}
        
        # Collect all significant names
        for module in modules:
            # Classes
            for cls in module.classes:
                term = self._camel_to_words(cls.name)
                if self._is_significant_term(term):
                    purpose = cls.docstring.split('\n')[0] if cls.docstring else f"Core class in {module.name}"
                    terms[term.lower()] = purpose
            
            # Functions
            for func in module.functions:
                if func.name.startswith('_'):  # Skip private
                    continue
                term = self._snake_to_words(func.name)
                if self._is_significant_term(term) and len(term.split()) <= 3:
                    purpose = func.docstring.split('\n')[0] if func.docstring else f"Function in {module.name}"
                    terms[term.lower()] = purpose
        
        return terms
    
    def _find_tech_terms(self, modules: List[ModuleInfo]) -> Dict[str, str]:
        """Find technical terms used in the codebase."""
        found_terms = {}
        
        for module in modules:
            # Check imports
            for imp in module.imports:
                for term, definition in self.tech_terms.items():
                    if term in imp.lower():
                        found_terms[term] = definition
            
            # Check module names
            module_name_lower = module.name.lower()
            for term, definition in self.tech_terms.items():
                if term in module_name_lower:
                    found_terms[term] = definition
        
        return found_terms
    
    def _extract_from_docstrings(self, modules: List[ModuleInfo]) -> Dict[str, str]:
        """Extract terms and definitions from docstrings."""
        terms = {}
        
        for module in modules:
            # Module docstring
            if module.docstring:
                extracted = self._parse_docstring_definitions(module.docstring)
                terms.update(extracted)
            
            # Class docstrings
            for cls in module.classes:
                if cls.docstring:
                    extracted = self._parse_docstring_definitions(cls.docstring)
                    terms.update(extracted)
        
        return terms
    
    def _parse_docstring_definitions(self, docstring: str) -> Dict[str, str]:
        """Parse docstring for term definitions (e.g., 'Term: definition')."""
        terms = {}
        
        # Look for patterns like "Term: definition" or "- Term: definition"
        pattern = r'(?:^|\n)\s*-?\s*([A-Z][a-zA-Z\s]+?):\s*(.+?)(?=\n|$)'
        matches = re.finditer(pattern, docstring)
        
        for match in matches:
            term = match.group(1).strip().lower()
            definition = match.group(2).strip()
            if len(term.split()) <= 4 and len(definition) > 10:
                terms[term] = definition
        
        return terms
    
    def _camel_to_words(self, name: str) -> str:
        """Convert CamelCase to words."""
        # Insert space before uppercase letters
        result = re.sub(r'([A-Z])', r' \1', name)
        return result.strip()
    
    def _snake_to_words(self, name: str) -> str:
        """Convert snake_case to words."""
        return name.replace('_', ' ')
    
    def _is_significant_term(self, term: str) -> bool:
        """Check if term is significant enough to include."""
        # Filter out common programming terms
        common = ['get', 'set', 'init', 'main', 'run', 'test', 'create', 'update', 'delete']
        words = term.lower().split()
        
        # Must be multi-word or not in common list
        return len(words) > 1 or (len(words) == 1 and words[0] not in common)


def format_glossary(modules: List[ModuleInfo], project_name: str) -> str:
    """Format glossary section for onboarding document."""
    generator = GlossaryGenerator()
    glossary = generator.generate_glossary(modules, project_name)
    
    if not glossary:
        return ""
    
    output = []
    output.append("# 📖 GLOSSARY & KEY CONCEPTS")
    output.append("=" * 80)
    output.append("")
    output.append("Quick reference for technical terms and domain concepts used in this project.")
    output.append("")
    
    # Sort alphabetically
    sorted_terms = sorted(glossary.items())
    
    # Group by letter
    current_letter = None
    for term, definition in sorted_terms:
        first_letter = term[0].upper()
        if first_letter != current_letter:
            if current_letter is not None:
                output.append("")
            output.append(f"## {first_letter}")
            output.append("")
            current_letter = first_letter
        
        output.append(f"**{term.title()}**")
        output.append(f"  {definition}")
        output.append("")
    
    return "\n".join(output)
