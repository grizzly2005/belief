"""JavaScript/TypeScript code analyzer."""

import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass

from .models import ModuleInfo, FunctionInfo, ClassInfo, Issue, IssueSeverity, CodeLocation
from .base_analyzer import LanguageAnalyzer


@dataclass
class JSFunction:
    """JavaScript/TypeScript function information."""
    name: str
    line_start: int
    line_end: int
    is_async: bool = False
    is_arrow: bool = False
    is_export: bool = False
    parameters: List[str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []


@dataclass
class JSClass:
    """JavaScript/TypeScript class information."""
    name: str
    line_start: int
    line_end: int
    is_export: bool = False
    methods: List[JSFunction] = None
    extends: Optional[str] = None
    
    def __post_init__(self):
        if self.methods is None:
            self.methods = []


class JavaScriptAnalyzer(LanguageAnalyzer):
    """Analyze JavaScript/TypeScript code."""
    
    def __init__(self):
        # Regex patterns
        self.function_pattern = re.compile(
            r'(export\s+)?(async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE
        )
        self.arrow_function_pattern = re.compile(
            r'(export\s+)?(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\(([^)]*)\)\s*=>',
            re.MULTILINE
        )
        self.class_pattern = re.compile(
            r'(export\s+)?(default\s+)?class\s+(\w+)(\s+extends\s+(\w+))?',
            re.MULTILINE
        )
        self.method_pattern = re.compile(
            r'(async\s+)?(\w+)\s*\(([^)]*)\)\s*{',
            re.MULTILINE
        )
        self.import_pattern = re.compile(
            r"import\s+(?:(?:\{[^}]+\}|\w+|\*\s+as\s+\w+)(?:\s*,\s*(?:\{[^}]+\}|\w+))?\s+from\s+)?['\"]([^'\"]+)['\"]",
            re.MULTILINE
        )
        self.require_pattern = re.compile(
            r"require\s*\(['\"]([^'\"]+)['\"]\)",
            re.MULTILINE
        )
    
    def analyze_file(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a JavaScript/TypeScript file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return None
        
        lines = content.split('\n')
        self.file_content = content  # Store for complexity calculation
        
        # Extract module name from file path
        module_name = file_path.stem
        
        # Extract imports
        imports = self._extract_imports(content)
        
        # Extract classes
        classes = self._extract_classes(content, lines)
        
        # Extract functions (excluding methods)
        functions = self._extract_functions(content, lines, classes)
        
        # Convert to ModuleInfo format
        module_info = ModuleInfo(
            name=module_name,
            file_path=str(file_path),
            lines_of_code=len(lines),
            docstring=self._extract_file_comment(lines),
            imports=imports,
            classes=[self._convert_class(cls, file_path) for cls in classes],
            functions=[self._convert_function(func, file_path) for func in functions]
        )
        
        return module_info
    
    def _extract_imports(self, content: str) -> List[str]:
        """Extract import statements."""
        imports = set()
        
        # ES6 imports
        for match in self.import_pattern.finditer(content):
            imports.add(match.group(1))
        
        # CommonJS requires
        for match in self.require_pattern.finditer(content):
            imports.add(match.group(1))
        
        return sorted(imports)
    
    def _extract_classes(self, content: str, lines: List[str]) -> List[JSClass]:
        """Extract class definitions."""
        classes = []
        
        for match in self.class_pattern.finditer(content):
            is_export = bool(match.group(1))
            class_name = match.group(3)
            extends = match.group(5)
            
            # Find class body
            class_start = content[:match.start()].count('\n') + 1
            class_end = self._find_block_end(content, match.end())
            
            # Extract methods
            class_body = content[match.end():class_end]
            methods = self._extract_methods(class_body, class_start)
            
            classes.append(JSClass(
                name=class_name,
                line_start=class_start,
                line_end=class_end,
                is_export=is_export,
                methods=methods,
                extends=extends
            ))
        
        return classes
    
    def _extract_methods(self, class_body: str, class_start: int) -> List[JSFunction]:
        """Extract methods from class body."""
        methods = []
        
        for match in self.method_pattern.finditer(class_body):
            is_async = bool(match.group(1))
            method_name = match.group(2)
            params_str = match.group(3)
            
            # Skip constructor-like patterns
            if method_name in ['if', 'for', 'while', 'switch']:
                continue
            
            line_num = class_start + class_body[:match.start()].count('\n')
            
            parameters = [p.strip().split('=')[0].strip() 
                         for p in params_str.split(',') if p.strip()]
            
            methods.append(JSFunction(
                name=method_name,
                line_start=line_num,
                line_end=line_num + 10,  # Approximate
                is_async=is_async,
                parameters=parameters
            ))
        
        return methods
    
    def _extract_functions(self, content: str, lines: List[str], classes: List[JSClass]) -> List[JSFunction]:
        """Extract top-level functions."""
        functions = []
        
        # Regular functions
        for match in self.function_pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            
            # Skip if inside a class
            if any(cls.line_start <= line_num <= cls.line_end for cls in classes):
                continue
            
            is_export = bool(match.group(1))
            is_async = bool(match.group(2))
            func_name = match.group(3)
            params_str = match.group(4)
            
            parameters = [p.strip().split('=')[0].strip().split(':')[0].strip()
                         for p in params_str.split(',') if p.strip()]
            
            functions.append(JSFunction(
                name=func_name,
                line_start=line_num,
                line_end=line_num + 10,
                is_async=is_async,
                is_export=is_export,
                parameters=parameters
            ))
        
        # Arrow functions
        for match in self.arrow_function_pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            
            # Skip if inside a class
            if any(cls.line_start <= line_num <= cls.line_end for cls in classes):
                continue
            
            is_export = bool(match.group(1))
            func_name = match.group(3)
            is_async = bool(match.group(4))
            params_str = match.group(5)
            
            parameters = [p.strip().split('=')[0].strip().split(':')[0].strip()
                         for p in params_str.split(',') if p.strip()]
            
            functions.append(JSFunction(
                name=func_name,
                line_start=line_num,
                line_end=line_num + 10,
                is_async=is_async,
                is_arrow=True,
                is_export=is_export,
                parameters=parameters
            ))
        
        return functions
    
    def _find_block_end(self, content: str, start_pos: int) -> int:
        """Find the end of a code block (matching braces)."""
        brace_count = 0
        in_string = False
        string_char = None
        
        for i, char in enumerate(content[start_pos:], start=start_pos):
            if char in ['"', "'", '`'] and not in_string:
                in_string = True
                string_char = char
            elif in_string and char == string_char:
                in_string = False
            elif not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        return i
        
        return len(content)
    
    def _extract_file_comment(self, lines: List[str]) -> Optional[str]:
        """Extract top-level file comment."""
        comment_lines = []
        in_block_comment = False
        
        for line in lines[:20]:  # Check first 20 lines
            stripped = line.strip()
            
            if stripped.startswith('/**'):
                in_block_comment = True
                comment_lines.append(stripped[3:])
            elif in_block_comment:
                if stripped.endswith('*/'):
                    comment_lines.append(stripped[:-2])
                    break
                else:
                    comment_lines.append(stripped.lstrip('* '))
            elif stripped.startswith('//'):
                comment_lines.append(stripped[2:].strip())
            elif stripped and not stripped.startswith('import'):
                break
        
        return '\n'.join(comment_lines).strip() if comment_lines else None
    
    def _convert_function(self, func: JSFunction, file_path: Path) -> FunctionInfo:
        """Convert JSFunction to FunctionInfo."""
        return FunctionInfo(
            name=func.name,
            location=CodeLocation(
                file_path=str(file_path),
                line_start=func.line_start,
                line_end=func.line_end
            ),
            parameters=func.parameters,
            return_type=None,  # TypeScript return types could be parsed
            docstring=None,
            complexity=self._estimate_complexity(func),
            is_async=func.is_async
        )
    
    def _convert_class(self, cls: JSClass, file_path: Path) -> ClassInfo:
        """Convert JSClass to ClassInfo."""
        return ClassInfo(
            name=cls.name,
            location=CodeLocation(
                file_path=str(file_path),
                line_start=cls.line_start,
                line_end=cls.line_end,
                class_name=cls.name
            ),
            bases=[cls.extends] if cls.extends else [],
            docstring=None,
            methods=[self._convert_function(m, file_path) for m in cls.methods]
        )
    
    def _estimate_complexity(self, func: JSFunction) -> int:
        """Calculate cyclomatic complexity by counting decision points."""
        # Start with base complexity of 1
        complexity = 1
        
        # Try to extract function body from file content
        if hasattr(self, 'file_content'):
            func_body = self._extract_function_body(func)
            if func_body:
                # Count decision points (cyclomatic complexity)
                # Each of these adds one to complexity:
                complexity += func_body.count('if ')
                complexity += func_body.count('else if')
                complexity += func_body.count('} else ')
                complexity += func_body.count('for ')
                complexity += func_body.count('for(')
                complexity += func_body.count('while ')
                complexity += func_body.count('while(')
                complexity += func_body.count('case ')
                complexity += func_body.count(' && ')  # Logical AND
                complexity += func_body.count(' || ')  # Logical OR
                complexity += func_body.count('catch ')
                complexity += func_body.count('catch(')
                complexity += func_body.count(' ? ')  # Ternary operator
                
                return max(1, complexity)
        
        # Fallback: rough estimate based on parameters
        complexity += len(func.parameters) // 3
        return max(1, complexity)
    
    def _extract_function_body(self, func: JSFunction) -> Optional[str]:
        """Extract the body of a function from file content."""
        if not hasattr(self, 'file_content'):
            return None
        
        lines = self.file_content.split('\n')
        if func.line_start > len(lines):
            return None
        
        # Get the function definition line
        start_line = func.line_start - 1
        
        # Find the opening brace
        brace_line = start_line
        while brace_line < len(lines) and '{' not in lines[brace_line]:
            brace_line += 1
        
        if brace_line >= len(lines):
            return None
        
        # Find matching closing brace
        full_text = '\n'.join(lines[start_line:])
        brace_start = full_text.index('{') if '{' in full_text else -1
        
        if brace_start == -1:
            return None
        
        # Extract body between braces
        brace_end = self._find_matching_brace(full_text, brace_start)
        if brace_end > brace_start:
            return full_text[brace_start:brace_end + 1]
        
        return None
    
    def _find_matching_brace(self, text: str, start: int) -> int:
        """Find the matching closing brace for an opening brace."""
        if start >= len(text) or text[start] != '{':
            return -1
        
        brace_count = 0
        in_string = False
        string_char = None
        in_comment = False
        
        i = start
        while i < len(text):
            char = text[i]
            
            # Handle strings
            if char in ['"', "'", '`'] and not in_comment:
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
            # Handle comments
            elif not in_string:
                if i + 1 < len(text) and text[i:i+2] == '//':
                    # Single line comment - skip to end of line
                    while i < len(text) and text[i] != '\n':
                        i += 1
                    continue
                elif i + 1 < len(text) and text[i:i+2] == '/*':
                    # Multi-line comment
                    in_comment = True
                    i += 2
                    continue
                elif in_comment and i + 1 < len(text) and text[i:i+2] == '*/':
                    in_comment = False
                    i += 2
                    continue
                elif not in_comment:
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            return i
            
            i += 1
        
        return -1
    
    def get_supported_extensions(self) -> List[str]:
        """Return JavaScript/TypeScript file extensions."""
        return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']
    
    def get_language_name(self) -> str:
        """Return language name."""
        return 'JavaScript/TypeScript'


def analyze_js_project(project_path: Path) -> List[ModuleInfo]:
    """Analyze all JavaScript/TypeScript files in a project."""
    analyzer = JavaScriptAnalyzer()
    modules = []
    
    # Find all JS/TS files
    patterns = ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx']
    ignore_dirs = {'node_modules', '.git', 'dist', 'build', 'coverage'}
    
    for pattern in patterns:
        for file_path in project_path.glob(pattern):
            # Skip if in ignore directory
            if any(ignore_dir in file_path.parts for ignore_dir in ignore_dirs):
                continue
            
            module = analyzer.analyze_file(file_path)
            if module:
                modules.append(module)
    
    return modules
