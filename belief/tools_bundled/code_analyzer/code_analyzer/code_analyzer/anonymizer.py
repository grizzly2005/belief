"""Code anonymization for safe external analysis."""

import ast
import hashlib
from pathlib import Path
from typing import Dict, Set, Optional
import re


class CodeAnonymizer:
    """Anonymizes code for external LLM analysis while preserving structure."""
    
    def __init__(self, preserve_stdlib: bool = True):
        """
        Initialize anonymizer.
        
        Args:
            preserve_stdlib: Whether to keep standard library names
        """
        self.preserve_stdlib = preserve_stdlib
        self.name_mapping: Dict[str, str] = {}
        self.counter = 0
        self.stdlib_modules = {
            'os', 'sys', 'json', 'yaml', 're', 'math', 'datetime',
            'pathlib', 'collections', 'itertools', 'functools',
            'typing', 'dataclasses', 'enum', 'abc', 'ast'
        }
    
    def anonymize_project(self, source_path: Path, output_path: Path):
        """
        Anonymize entire project.
        
        Args:
            source_path: Source project directory
            output_path: Output directory for anonymized code
        """
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Write mapping file
        mapping_file = output_path / "ANONYMIZATION_MAP.txt"
        
        # Find and anonymize all Python files
        for py_file in source_path.rglob("*.py"):
            if self._should_skip(py_file):
                continue
            
            rel_path = py_file.relative_to(source_path)
            output_file = output_path / rel_path
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            anonymized = self.anonymize_file(py_file)
            output_file.write_text(anonymized)
        
        # Save mapping
        self._save_mapping(mapping_file)
        
        print(f"✅ Anonymized {len(self.name_mapping)} identifiers")
        print(f"   Output: {output_path}")
        print(f"   Mapping: {mapping_file}")
    
    def anonymize_file(self, file_path: Path) -> str:
        """
        Anonymize a single Python file.
        
        Args:
            file_path: Path to file to anonymize
            
        Returns:
            Anonymized code as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Collect all identifiers
            identifiers = self._collect_identifiers(tree)
            
            # Create anonymization mapping
            for identifier in identifiers:
                if identifier not in self.name_mapping:
                    if self._should_preserve(identifier):
                        self.name_mapping[identifier] = identifier
                    else:
                        self.name_mapping[identifier] = self._generate_anonymous_name(identifier)
            
            # Replace identifiers in code
            anonymized = content
            # Sort by length (longest first) to avoid partial replacements
            for original, anonymous in sorted(
                self.name_mapping.items(),
                key=lambda x: len(x[0]),
                reverse=True
            ):
                if original != anonymous:
                    # Use word boundaries to avoid partial replacements
                    pattern = r'\b' + re.escape(original) + r'\b'
                    anonymized = re.sub(pattern, anonymous, anonymized)
            
            return anonymized
            
        except Exception as e:
            print(f"Error anonymizing {file_path}: {e}")
            return content
    
    def _collect_identifiers(self, tree: ast.AST) -> Set[str]:
        """Collect all identifiers from AST."""
        identifiers = set()
        
        for node in ast.walk(tree):
            # Function and class names
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                identifiers.add(node.name)
            
            # Variable names
            elif isinstance(node, ast.Name):
                identifiers.add(node.id)
            
            # Attribute names
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            
            # Parameter names
            elif isinstance(node, ast.arg):
                identifiers.add(node.arg)
        
        return identifiers
    
    def _should_preserve(self, identifier: str) -> bool:
        """Check if identifier should be preserved."""
        # Preserve dunder methods
        if identifier.startswith('__') and identifier.endswith('__'):
            return True
        
        # Preserve single-letter variables (common conventions)
        if len(identifier) == 1:
            return True
        
        # Preserve common Python keywords/builtins
        python_builtins = {
            'True', 'False', 'None', 'self', 'cls',
            'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
            'len', 'range', 'enumerate', 'zip', 'map', 'filter',
            'print', 'open', 'type', 'isinstance', 'hasattr'
        }
        if identifier in python_builtins:
            return True
        
        # Preserve stdlib module names if configured
        if self.preserve_stdlib and identifier in self.stdlib_modules:
            return True
        
        return False
    
    def _generate_anonymous_name(self, original: str) -> str:
        """Generate an anonymous name."""
        # Use hash-based naming for consistency
        hash_obj = hashlib.md5(original.encode())
        hash_hex = hash_obj.hexdigest()[:8]
        
        # Preserve some semantic info through prefixes
        prefix = ""
        if original[0].isupper():
            prefix = "Class"
        elif original.startswith('_'):
            prefix = "private"
        else:
            prefix = "var"
        
        self.counter += 1
        return f"{prefix}_{hash_hex}_{self.counter}"
    
    def _should_skip(self, path: Path) -> bool:
        """Check if file should be skipped."""
        skip_patterns = [
            '__pycache__', '.git', 'venv', 'env', '.venv',
            'build', 'dist', '.egg-info', 'migrations'
        ]
        return any(pattern in str(path) for pattern in skip_patterns)
    
    def _save_mapping(self, mapping_file: Path):
        """Save anonymization mapping to file."""
        with open(mapping_file, 'w') as f:
            f.write("# Code Anonymization Mapping\n")
            f.write("# KEEP THIS FILE SECURE - IT CONTAINS ORIGINAL NAMES\n\n")
            
            for original, anonymous in sorted(self.name_mapping.items()):
                if original != anonymous:
                    f.write(f"{original} -> {anonymous}\n")
    
    def create_structure_summary(self, source_path: Path) -> str:
        """
        Create a structure summary that can be safely shared.
        
        Returns high-level structure without sensitive names.
        """
        summary = []
        summary.append("# Anonymized Code Structure Summary\n")
        summary.append("## Project Metrics\n")
        
        # Count files and LOC
        py_files = list(source_path.rglob("*.py"))
        total_lines = sum(
            len(f.read_text().splitlines())
            for f in py_files
            if not self._should_skip(f)
        )
        
        summary.append(f"- Total Python files: {len(py_files)}\n")
        summary.append(f"- Total lines of code: {total_lines}\n")
        summary.append(f"- Anonymized identifiers: {len(self.name_mapping)}\n")
        
        return ''.join(summary)
