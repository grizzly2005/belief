"""Generate troubleshooting playbook from detected issues."""

from typing import List, Dict
from collections import defaultdict
from .models import Issue


class TroubleshootingPlaybook:
    """Generate troubleshooting guides based on detected issues."""
    
    def __init__(self, issues: List[Issue]):
        self.issues = issues
        self.issue_patterns = self._categorize_issues()
        
    def _categorize_issues(self) -> Dict[str, List[Issue]]:
        """Categorize issues by type."""
        patterns = defaultdict(list)
        
        for issue in self.issues:
            # Categorize by description patterns
            desc_lower = issue.description.lower()
            
            if 'complexity' in desc_lower:
                patterns['high_complexity'].append(issue)
            elif 'unused' in desc_lower:
                patterns['unused_code'].append(issue)
            elif 'import' in desc_lower:
                patterns['import_issues'].append(issue)
            elif 'error handling' in desc_lower or 'exception' in desc_lower:
                patterns['error_handling'].append(issue)
            elif 'security' in desc_lower or 'vulnerable' in desc_lower:
                patterns['security'].append(issue)
            elif 'god class' in desc_lower or 'too many' in desc_lower:
                patterns['design_issues'].append(issue)
            elif 'duplicate' in desc_lower:
                patterns['duplication'].append(issue)
            elif 'naming' in desc_lower or 'name' in desc_lower:
                patterns['naming'].append(issue)
            else:
                patterns['other'].append(issue)
        
        return patterns
    
    def generate_playbook(self) -> List[str]:
        """Generate complete troubleshooting playbook."""
        sections = []
        
        sections.append("# 🔧 TROUBLESHOOTING PLAYBOOK")
        sections.append("=" * 80)
        sections.append("")
        sections.append("Common problems, their causes, and solutions.")
        sections.append("")
        
        # Generate sections for each issue type
        if self.issue_patterns['high_complexity']:
            sections.extend(self._section_high_complexity())
            sections.append("")
        
        if self.issue_patterns['unused_code']:
            sections.extend(self._section_unused_code())
            sections.append("")
        
        if self.issue_patterns['import_issues']:
            sections.extend(self._section_import_issues())
            sections.append("")
        
        if self.issue_patterns['error_handling']:
            sections.extend(self._section_error_handling())
            sections.append("")
        
        if self.issue_patterns['security']:
            sections.extend(self._section_security())
            sections.append("")
        
        if self.issue_patterns['design_issues']:
            sections.extend(self._section_design_issues())
            sections.append("")
        
        # General troubleshooting tips
        sections.extend(self._general_tips())
        
        return sections
    
    def _section_high_complexity(self) -> List[str]:
        """High complexity troubleshooting."""
        lines = []
        lines.append("## 🔴 High Complexity Functions")
        lines.append("")
        lines.append("**Problem**: Functions or methods are too complex to understand and maintain.")
        lines.append("")
        lines.append("**Symptoms**:")
        lines.append("- Difficulty understanding code flow")
        lines.append("- Hard to test thoroughly")
        lines.append("- Frequent bugs in the same area")
        lines.append("- New team members struggle with the code")
        lines.append("")
        lines.append("**Common Causes**:")
        lines.append("- Too many responsibilities in one function")
        lines.append("- Deeply nested conditionals")
        lines.append("- Long parameter lists")
        lines.append("- Missing abstractions")
        lines.append("")
        lines.append("**Solutions**:")
        lines.append("1. **Extract Methods**: Break complex logic into smaller functions")
        lines.append("   ```python")
        lines.append("   # Before")
        lines.append("   def process_data(data):")
        lines.append("       # 100 lines of complex logic")
        lines.append("   ")
        lines.append("   # After")
        lines.append("   def process_data(data):")
        lines.append("       validated = validate_data(data)")
        lines.append("       transformed = transform_data(validated)")
        lines.append("       return save_data(transformed)")
        lines.append("   ```")
        lines.append("")
        lines.append("2. **Use Guard Clauses**: Reduce nesting with early returns")
        lines.append("   ```python")
        lines.append("   def process(item):")
        lines.append("       if not item:")
        lines.append("           return None  # Early exit")
        lines.append("       if not item.is_valid():")
        lines.append("           return None  # Early exit")
        lines.append("       # Main logic here")
        lines.append("   ```")
        lines.append("")
        lines.append("3. **Introduce Strategy Pattern**: Replace complex conditionals")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['high_complexity'])} instance(s) in this project.**")
        
        return lines
    
    def _section_unused_code(self) -> List[str]:
        """Unused code troubleshooting."""
        lines = []
        lines.append("## 🟡 Unused Code")
        lines.append("")
        lines.append("**Problem**: Code that is defined but never used.")
        lines.append("")
        lines.append("**Why It Matters**:")
        lines.append("- Increases codebase size unnecessarily")
        lines.append("- Confuses developers about what's active")
        lines.append("- May indicate incomplete refactoring")
        lines.append("")
        lines.append("**Safe Removal Steps**:")
        lines.append("1. **Verify it's truly unused**: Search the entire codebase")
        lines.append("   ```bash")
        lines.append("   grep -r \"function_name\" .")
        lines.append("   ```")
        lines.append("")
        lines.append("2. **Check for dynamic usage**: String-based imports or reflection")
        lines.append("   - Look for `__import__()`, `getattr()`, `eval()`")
        lines.append("   - Check config files and plugin systems")
        lines.append("")
        lines.append("3. **Remove incrementally**: One item at a time, test after each")
        lines.append("")
        lines.append("4. **Use version control**: Easy to restore if needed")
        lines.append("   ```bash")
        lines.append("   git commit -m 'Remove unused function X'")
        lines.append("   # If needed later: git revert <commit>")
        lines.append("   ```")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['unused_code'])} instance(s) in this project.**")
        
        return lines
    
    def _section_import_issues(self) -> List[str]:
        """Import issues troubleshooting."""
        lines = []
        lines.append("## 📦 Import Issues")
        lines.append("")
        lines.append("**Problem**: Import-related problems (unused, circular, missing).")
        lines.append("")
        lines.append("**Common Issues & Fixes**:")
        lines.append("")
        lines.append("**1. Unused Imports**")
        lines.append("- **Fix**: Remove them to keep code clean")
        lines.append("- **Auto-fix**: Use `autoflake` or IDE cleanup")
        lines.append("")
        lines.append("**2. Circular Imports**")
        lines.append("- **Symptom**: `ImportError: cannot import name 'X'`")
        lines.append("- **Fix**: Move import inside function, or restructure modules")
        lines.append("  ```python")
        lines.append("  # Instead of top-level import")
        lines.append("  def function():")
        lines.append("      from module import something  # Local import")
        lines.append("  ```")
        lines.append("")
        lines.append("**3. Import Order Issues**")
        lines.append("- **Fix**: Use standard order: stdlib, third-party, local")
        lines.append("- **Auto-fix**: Use `isort` to organize imports")
        lines.append("  ```bash")
        lines.append("  isort --profile black .")
        lines.append("  ```")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['import_issues'])} instance(s) in this project.**")
        
        return lines
    
    def _section_error_handling(self) -> List[str]:
        """Error handling troubleshooting."""
        lines = []
        lines.append("## ⚠️ Error Handling")
        lines.append("")
        lines.append("**Problem**: Missing or inadequate error handling.")
        lines.append("")
        lines.append("**Best Practices**:")
        lines.append("")
        lines.append("1. **Catch Specific Exceptions**")
        lines.append("   ```python")
        lines.append("   # Bad")
        lines.append("   try:")
        lines.append("       risky_operation()")
        lines.append("   except:  # Too broad!")
        lines.append("       pass")
        lines.append("   ")
        lines.append("   # Good")
        lines.append("   try:")
        lines.append("       risky_operation()")
        lines.append("   except FileNotFoundError:")
        lines.append("       logger.error('File not found')")
        lines.append("       raise")
        lines.append("   ```")
        lines.append("")
        lines.append("2. **Don't Silence Errors**")
        lines.append("   - Log before swallowing exceptions")
        lines.append("   - Re-raise if you can't handle it")
        lines.append("")
        lines.append("3. **Use Context Managers**")
        lines.append("   ```python")
        lines.append("   with open('file.txt') as f:  # Auto-closes")
        lines.append("       data = f.read()")
        lines.append("   ```")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['error_handling'])} instance(s) in this project.**")
        
        return lines
    
    def _section_security(self) -> List[str]:
        """Security issues troubleshooting."""
        lines = []
        lines.append("## 🔒 Security Issues")
        lines.append("")
        lines.append("**Problem**: Potential security vulnerabilities detected.")
        lines.append("")
        lines.append("**Immediate Actions**:")
        lines.append("")
        lines.append("1. **Never use `eval()` on user input**")
        lines.append("   - Use `ast.literal_eval()` for safe evaluation")
        lines.append("")
        lines.append("2. **Sanitize all inputs**")
        lines.append("   - Validate, escape, and whitelist")
        lines.append("   - Never trust user-provided data")
        lines.append("")
        lines.append("3. **Use parameterized queries**")
        lines.append("   ```python")
        lines.append("   # Bad - SQL injection risk")
        lines.append("   query = f\"SELECT * FROM users WHERE id = {user_id}\"")
        lines.append("   ")
        lines.append("   # Good - parameterized")
        lines.append("   query = \"SELECT * FROM users WHERE id = ?\"")
        lines.append("   cursor.execute(query, (user_id,))")
        lines.append("   ```")
        lines.append("")
        lines.append("4. **Keep dependencies updated**")
        lines.append("   ```bash")
        lines.append("   pip list --outdated")
        lines.append("   pip install --upgrade package-name")
        lines.append("   ```")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['security'])} instance(s) in this project.**")
        
        return lines
    
    def _section_design_issues(self) -> List[str]:
        """Design issues troubleshooting."""
        lines = []
        lines.append("## 🏗️ Design Issues")
        lines.append("")
        lines.append("**Problem**: God classes, poor separation of concerns, or architectural issues.")
        lines.append("")
        lines.append("**Refactoring Strategies**:")
        lines.append("")
        lines.append("1. **Split God Classes**")
        lines.append("   - Identify distinct responsibilities")
        lines.append("   - Extract each into its own class")
        lines.append("   - Use composition to connect them")
        lines.append("")
        lines.append("2. **Apply SOLID Principles**")
        lines.append("   - **S**ingle Responsibility: One reason to change")
        lines.append("   - **O**pen/Closed: Open for extension, closed for modification")
        lines.append("   - **L**iskov Substitution: Subtypes must be substitutable")
        lines.append("   - **I**nterface Segregation: Many specific interfaces")
        lines.append("   - **D**ependency Inversion: Depend on abstractions")
        lines.append("")
        lines.append("3. **Introduce Design Patterns**")
        lines.append("   - Factory: For object creation")
        lines.append("   - Strategy: For algorithm selection")
        lines.append("   - Observer: For event handling")
        lines.append("")
        lines.append(f"**Found {len(self.issue_patterns['design_issues'])} instance(s) in this project.**")
        
        return lines
    
    def _general_tips(self) -> List[str]:
        """General troubleshooting tips."""
        lines = []
        lines.append("## 💡 General Troubleshooting Tips")
        lines.append("")
        lines.append("### When Issues Occur")
        lines.append("")
        lines.append("1. **Read the Error Message Carefully**")
        lines.append("   - Note the file, line number, and exception type")
        lines.append("   - Search for the exact error message")
        lines.append("")
        lines.append("2. **Use the Debugger**")
        lines.append("   ```python")
        lines.append("   import pdb; pdb.set_trace()  # Set breakpoint")
        lines.append("   # Or use your IDE's debugger")
        lines.append("   ```")
        lines.append("")
        lines.append("3. **Check Recent Changes**")
        lines.append("   ```bash")
        lines.append("   git diff HEAD~5  # Last 5 commits")
        lines.append("   git log --oneline -10  # Recent history")
        lines.append("   ```")
        lines.append("")
        lines.append("4. **Verify Dependencies**")
        lines.append("   ```bash")
        lines.append("   pip list  # Check installed packages")
        lines.append("   pip check  # Verify compatibility")
        lines.append("   ```")
        lines.append("")
        lines.append("5. **Isolate the Problem**")
        lines.append("   - Create minimal reproduction")
        lines.append("   - Comment out code until it works")
        lines.append("   - Add print statements to trace execution")
        lines.append("")
        lines.append("### Prevention")
        lines.append("")
        lines.append("- **Write tests**: Catch issues early")
        lines.append("- **Use linters**: `pylint`, `flake8`, `mypy`")
        lines.append("- **Code reviews**: Get fresh eyes on changes")
        lines.append("- **CI/CD**: Automate checks before merge")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("**Remember**: Most issues have been solved before. Search GitHub issues,")
        lines.append("Stack Overflow, and documentation before implementing complex workarounds.")
        
        return lines


def format_troubleshooting_playbook(issues: List[Issue]) -> str:
    """Generate troubleshooting playbook from issues."""
    if not issues:
        return "# 🔧 TROUBLESHOOTING PLAYBOOK\n\nNo issues detected - no troubleshooting needed!"
    
    playbook = TroubleshootingPlaybook(issues)
    sections = playbook.generate_playbook()
    
    return "\n".join(sections)
