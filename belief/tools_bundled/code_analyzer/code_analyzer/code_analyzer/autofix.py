"""Automatic code fix generation for common issues."""

import ast
import re
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from .models import Issue, IssueType


@dataclass
class CodeFix:
    """Represents a code fix."""
    issue: Issue
    file_path: str
    original_code: str
    fixed_code: str
    description: str
    confidence: str  # 'high', 'medium', 'low'
    
    def generate_diff(self) -> str:
        """Generate unified diff for preview."""
        import difflib
        
        original_lines = self.original_code.splitlines(keepends=True)
        fixed_lines = self.fixed_code.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{self.file_path}",
            tofile=f"b/{self.file_path}",
            lineterm=''
        )
        
        return ''.join(diff)


class UnusedImportRemover(ast.NodeTransformer):
    """Remove unused imports from AST."""
    
    def __init__(self, used_names: set):
        self.used_names = used_names
        self.removed_imports = []
    
    def visit_Import(self, node):
        """Remove unused import statements."""
        new_names = []
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            if name in self.used_names or name.split('.')[0] in self.used_names:
                new_names.append(alias)
            else:
                self.removed_imports.append(alias.name)
        
        if new_names:
            node.names = new_names
            return node
        return None  # Remove entire import statement
    
    def visit_ImportFrom(self, node):
        """Remove unused from-imports."""
        new_names = []
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            if name in self.used_names:
                new_names.append(alias)
            else:
                self.removed_imports.append(f"{node.module}.{alias.name}")
        
        if new_names:
            node.names = new_names
            return node
        return None


class AutoFixGenerator:
    """Generate automatic fixes for common code issues."""
    
    def __init__(self):
        self.fixes: List[CodeFix] = []
    
    def generate_fixes(self, issues: List[Issue], project_path: Path) -> List[CodeFix]:
        """Generate fixes for all applicable issues."""
        self.fixes = []
        
        for issue in issues:
            fix = self._generate_fix_for_issue(issue, project_path)
            if fix:
                self.fixes.append(fix)
        
        return self.fixes
    
    def _generate_fix_for_issue(self, issue: Issue, project_path: Path) -> Optional[CodeFix]:
        """Generate fix for a single issue."""
        # Parse file path from location
        file_path = issue.location.file_path
        full_path = project_path / file_path
        
        if not full_path.exists():
            return None
        
        try:
            original_code = full_path.read_text()
        except Exception:
            return None
        
        # Route to specific fix generator based on issue type
        if issue.issue_type == IssueType.UNUSED_CODE:
            if "unused import" in issue.title.lower():
                return self._fix_unused_import(issue, file_path, original_code)
            elif "unused variable" in issue.title.lower():
                return self._fix_unused_variable(issue, file_path, original_code)
        
        elif issue.issue_type == IssueType.DOCUMENTATION:
            if "missing docstring" in issue.title.lower():
                return self._fix_missing_docstring(issue, file_path, original_code)
        
        elif issue.issue_type == IssueType.CODE_SMELL:
            if "simplify" in issue.description.lower():
                return self._fix_simple_smell(issue, file_path, original_code)
        
        return None
    
    def _fix_unused_import(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Fix unused import by removing it."""
        try:
            tree = ast.parse(original_code)
            
            # Collect all used names
            used_names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    used_names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name):
                        used_names.add(node.value.id)
            
            # Remove unused imports
            remover = UnusedImportRemover(used_names)
            new_tree = remover.visit(tree)
            ast.fix_missing_locations(new_tree)
            
            if remover.removed_imports:
                fixed_code = ast.unparse(new_tree)
                
                return CodeFix(
                    issue=issue,
                    file_path=file_path,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    description=f"Removed unused imports: {', '.join(remover.removed_imports)}",
                    confidence='high'
                )
        except Exception as e:
            # If AST manipulation fails, try simple regex for single-line imports
            return self._fix_unused_import_regex(issue, file_path, original_code)
        
        return None
    
    def _fix_unused_import_regex(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Fallback: use regex to remove single-line unused imports."""
        # Extract import statement from issue description
        import_pattern = r'^(import\s+\w+|from\s+\w+\s+import\s+\w+)'
        
        lines = original_code.splitlines(keepends=True)
        line_start = issue.location.line_start - 1
        
        if 0 <= line_start < len(lines):
            line = lines[line_start]
            if re.search(import_pattern, line.strip()):
                # Remove this line
                new_lines = lines[:line_start] + lines[line_start+1:]
                fixed_code = ''.join(new_lines)
                
                return CodeFix(
                    issue=issue,
                    file_path=file_path,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    description=f"Removed unused import at line {issue.location.line_start}",
                    confidence='medium'
                )
        
        return None
    
    def _fix_unused_variable(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Fix unused variable by adding underscore prefix."""
        lines = original_code.splitlines(keepends=True)
        line_idx = issue.location.line_start - 1
        
        if 0 <= line_idx < len(lines):
            line = lines[line_idx]
            
            # Find variable name in issue title/description
            var_match = re.search(r"variable[:\s]+['\"]?(\w+)['\"]?", issue.description)
            if var_match:
                var_name = var_match.group(1)
                
                # Replace first occurrence on that line with underscore prefix
                if re.search(rf'\b{var_name}\b', line):
                    new_line = re.sub(rf'\b{var_name}\b', f'_{var_name}', line, count=1)
                    new_lines = lines[:line_idx] + [new_line] + lines[line_idx+1:]
                    fixed_code = ''.join(new_lines)
                    
                    return CodeFix(
                        issue=issue,
                        file_path=file_path,
                        original_code=original_code,
                        fixed_code=fixed_code,
                        description=f"Prefixed unused variable '{var_name}' with underscore",
                        confidence='high'
                    )
        
        return None
    
    def _fix_missing_docstring(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Add missing docstring to function or class."""
        try:
            tree = ast.parse(original_code)
            lines = original_code.splitlines(keepends=True)
            
            # Find the function/class at the issue location
            target_line = issue.location.line_start
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
                    if node.lineno == target_line:
                        # Generate docstring
                        indent = self._get_indent(lines[node.lineno])
                        
                        if isinstance(node, ast.ClassDef):
                            docstring = f'{indent}    """TODO: Document this class."""\n'
                        else:
                            docstring = f'{indent}    """TODO: Document this function."""\n'
                        
                        # Insert after function/class definition line
                        insert_line = node.lineno  # Insert after the def/class line
                        new_lines = lines[:insert_line] + [docstring] + lines[insert_line:]
                        fixed_code = ''.join(new_lines)
                        
                        return CodeFix(
                            issue=issue,
                            file_path=file_path,
                            original_code=original_code,
                            fixed_code=fixed_code,
                            description=f"Added placeholder docstring to {node.name}",
                            confidence='medium'
                        )
        except Exception:
            pass
        
        return None
    
    def _fix_simple_smell(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Fix simple code smells."""
        # Check for specific patterns
        if "if True:" in issue.description or "if False:" in issue.description:
            return self._fix_constant_condition(issue, file_path, original_code)
        
        return None
    
    def _fix_constant_condition(self, issue: Issue, file_path: str, original_code: str) -> Optional[CodeFix]:
        """Remove if statements with constant conditions."""
        lines = original_code.splitlines(keepends=True)
        line_idx = issue.location.line_start - 1
        
        if 0 <= line_idx < len(lines):
            line = lines[line_idx]
            
            if "if True:" in line:
                # Remove the if statement, keep the body (simplified)
                indent = len(line) - len(line.lstrip())
                new_line = ' ' * indent + '# Fixed: removed redundant "if True:"\n'
                new_lines = lines[:line_idx] + [new_line] + lines[line_idx+1:]
                fixed_code = ''.join(new_lines)
                
                return CodeFix(
                    issue=issue,
                    file_path=file_path,
                    original_code=original_code,
                    fixed_code=fixed_code,
                    description="Removed redundant constant condition",
                    confidence='low'
                )
        
        return None
    
    def _get_indent(self, line: str) -> str:
        """Get indentation from a line."""
        return line[:len(line) - len(line.lstrip())]
    
    def apply_fixes(self, fixes: List[CodeFix], project_path: Path) -> Dict[str, int]:
        """Apply fixes to files."""
        stats = {'applied': 0, 'failed': 0}
        
        # Group fixes by file
        fixes_by_file: Dict[str, List[CodeFix]] = {}
        for fix in fixes:
            if fix.file_path not in fixes_by_file:
                fixes_by_file[fix.file_path] = []
            fixes_by_file[fix.file_path].append(fix)
        
        # Apply fixes file by file
        for file_path, file_fixes in fixes_by_file.items():
            # Sort by confidence and apply highest confidence fix for each file
            file_fixes.sort(key=lambda f: {'high': 0, 'medium': 1, 'low': 2}[f.confidence])
            
            best_fix = file_fixes[0]
            full_path = project_path / file_path
            
            try:
                full_path.write_text(best_fix.fixed_code)
                stats['applied'] += 1
            except Exception:
                stats['failed'] += 1
        
        return stats
