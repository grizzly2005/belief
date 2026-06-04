"""Generate common developer workflow documentation."""

from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path


@dataclass
class WorkflowStep:
    """A single step in a workflow."""
    title: str
    description: str
    code: Optional[str] = None
    file_to_edit: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class Workflow:
    """A complete developer workflow."""
    name: str
    description: str
    estimated_time: str
    steps: List[WorkflowStep]
    prerequisites: List[str] = None


class WorkflowsGenerator:
    """Generate common developer workflows based on project structure."""
    
    def __init__(self, project_name: str, modules: list):
        self.project_name = project_name
        self.modules = modules
        self.module_names = [m.name for m in modules]
    
    def generate_workflows(self) -> List[Workflow]:
        """Generate all relevant workflows for this project."""
        workflows = []
        
        # Detect project patterns
        has_analyzer = any('analyzer' in m.name.lower() for m in self.modules)
        has_tests = any('test' in m.name.lower() for m in self.modules)
        has_issues = any('issue' in m.name.lower() or 'models' in m.name.lower() for m in self.modules)
        has_plugins = any('plugin' in m.name.lower() for m in self.modules)
        
        # Generate relevant workflows
        if has_analyzer:
            workflows.append(self._workflow_add_analyzer())
        
        if has_issues:
            workflows.append(self._workflow_add_issue_type())
        
        if has_plugins:
            workflows.append(self._workflow_create_plugin())
        
        if has_tests:
            workflows.append(self._workflow_add_tests())
        
        # Always include these
        workflows.append(self._workflow_debug_issue())
        workflows.append(self._workflow_first_contribution())
        
        return workflows
    
    def _workflow_add_analyzer(self) -> Workflow:
        """Workflow for adding a new analyzer."""
        return Workflow(
            name="Add a New Code Analyzer",
            description="How to extend the analyzer with new detection logic",
            estimated_time="30-60 minutes",
            prerequisites=[
                "Familiarity with Python AST module",
                "Understanding of the issue you want to detect"
            ],
            steps=[
                WorkflowStep(
                    title="1. Define your detection logic",
                    description="Decide what pattern or issue you want to detect",
                    notes="Example: detecting unused imports, missing type hints, security vulnerabilities"
                ),
                WorkflowStep(
                    title="2. Locate the analyzer module",
                    description="Find where analysis logic lives",
                    file_to_edit="code_analyzer/analyzer.py",
                    notes="Look for the _analyze_file() or _analyze_function() methods"
                ),
                WorkflowStep(
                    title="3. Add detection method",
                    description="Create a new method for your detection logic",
                    code="""def _detect_your_issue(self, node: ast.Node) -> List[Issue]:
    \"\"\"Detect your specific issue.\"\"\"
    issues = []
    
    # Your detection logic here
    if some_condition(node):
        issues.append(Issue(
            severity='medium',
            category='code-quality',
            description='Description of the issue',
            file_path=self.current_file,
            line_number=node.lineno
        ))
    
    return issues""",
                    file_to_edit="code_analyzer/analyzer.py"
                ),
                WorkflowStep(
                    title="4. Integrate into analysis flow",
                    description="Call your new method during file analysis",
                    code="""# In _analyze_file() or similar
new_issues = self._detect_your_issue(tree)
issues.extend(new_issues)"""
                ),
                WorkflowStep(
                    title="5. Write tests",
                    description="Add test cases for your new analyzer",
                    code="""def test_detect_your_issue():
    analyzer = CodeAnalyzer('test_project')
    code = '''
    # Code that should trigger your detection
    '''
    issues = analyzer._detect_your_issue(ast.parse(code))
    assert len(issues) == 1
    assert 'your expected message' in issues[0].description""",
                    file_to_edit="tests/test_analyzer.py"
                ),
                WorkflowStep(
                    title="6. Run tests",
                    description="Verify your analyzer works correctly",
                    code="pytest tests/test_analyzer.py -v",
                    notes="Fix any failures before committing"
                ),
                WorkflowStep(
                    title="7. Update documentation",
                    description="Document the new detection capability",
                    notes="Add to README.md or docs/ explaining what you detect"
                )
            ]
        )
    
    def _workflow_add_issue_type(self) -> Workflow:
        """Workflow for adding a new issue type."""
        return Workflow(
            name="Add a New Issue Type",
            description="How to create a new category of issues the tool can report",
            estimated_time="20-30 minutes",
            prerequisites=["Understanding of the models module"],
            steps=[
                WorkflowStep(
                    title="1. Define issue category",
                    description="Decide the category and severity for your new issue type",
                    notes="Common categories: security, performance, maintainability, code-quality, documentation"
                ),
                WorkflowStep(
                    title="2. Locate the Issue model",
                    description="Find where Issue is defined",
                    file_to_edit="code_analyzer/models.py",
                    notes="Look for the Issue dataclass or class definition"
                ),
                WorkflowStep(
                    title="3. Add to severity/category enums",
                    description="If using enums, add your new type",
                    code="""# If there's a Severity enum
class Severity(Enum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'  # Your new severity

# If there's a Category enum
class IssueCategory(Enum):
    SECURITY = 'security'
    YOUR_CATEGORY = 'your-category'  # Add here"""
                ),
                WorkflowStep(
                    title="4. Create Issue instances",
                    description="In your analyzer code, create issues with your new type",
                    code="""Issue(
    severity='your-severity',
    category='your-category',
    description='Clear description of what was detected',
    file_path=file_path,
    line_number=line_num,
    suggestion='How to fix this issue'
)"""
                ),
                WorkflowStep(
                    title="5. Test the new issue type",
                    description="Verify issues are created and reported correctly",
                    code="""def test_new_issue_type():
    # Create a test that triggers your new issue
    result = analyzer.analyze('test_code.py')
    assert any(i.category == 'your-category' for i in result.issues)"""
                )
            ]
        )
    
    def _workflow_create_plugin(self) -> Workflow:
        """Workflow for creating a plugin."""
        return Workflow(
            name="Create a Custom Plugin",
            description="How to extend functionality with a plugin",
            estimated_time="45-90 minutes",
            prerequisites=["Understanding of plugin architecture"],
            steps=[
                WorkflowStep(
                    title="1. Create plugin file",
                    description="Create a new Python file in plugins directory",
                    code="touch plugins/my_plugin.py"
                ),
                WorkflowStep(
                    title="2. Implement plugin interface",
                    description="Define your plugin class with required methods",
                    code="""class MyPlugin:
    \"\"\"Custom plugin for X functionality.\"\"\"
    
    def __init__(self):
        self.name = 'my_plugin'
    
    def analyze(self, module_info):
        \"\"\"Analyze a module and return issues.\"\"\"
        issues = []
        # Your plugin logic here
        return issues
    
    def should_run(self, file_path):
        \"\"\"Determine if plugin should run on this file.\"\"\"
        return file_path.endswith('.py')""",
                    file_to_edit="plugins/my_plugin.py"
                ),
                WorkflowStep(
                    title="3. Register the plugin",
                    description="Make the plugin discoverable",
                    notes="Check if there's a plugin registry or config file"
                ),
                WorkflowStep(
                    title="4. Test your plugin",
                    description="Write tests for plugin functionality",
                    code="""def test_my_plugin():
    plugin = MyPlugin()
    # Test plugin logic
    assert plugin.should_run('test.py')
    issues = plugin.analyze(test_module)
    assert len(issues) >= 0"""
                )
            ]
        )
    
    def _workflow_add_tests(self) -> Workflow:
        """Workflow for adding tests."""
        return Workflow(
            name="Add Tests for New Features",
            description="How to write and run tests",
            estimated_time="20-40 minutes",
            prerequisites=["pytest installed", "Understanding of the feature to test"],
            steps=[
                WorkflowStep(
                    title="1. Create or locate test file",
                    description="Find the appropriate test file for your feature",
                    notes="tests/test_<module>.py for module tests"
                ),
                WorkflowStep(
                    title="2. Write test function",
                    description="Create a test function with descriptive name",
                    code="""def test_my_feature_handles_edge_case():
    \"\"\"Test that my feature works with edge case.\"\"\"
    # Arrange: Set up test data
    input_data = create_test_input()
    
    # Act: Run the code
    result = my_feature(input_data)
    
    # Assert: Verify expectations
    assert result.status == 'success'
    assert len(result.items) == 5"""
                ),
                WorkflowStep(
                    title="3. Run tests locally",
                    description="Execute pytest to verify tests pass",
                    code="pytest tests/ -v"
                ),
                WorkflowStep(
                    title="4. Check coverage",
                    description="Ensure your new code is covered",
                    code="pytest --cov=code_analyzer --cov-report=html",
                    notes="Aim for >80% coverage on new code"
                )
            ]
        )
    
    def _workflow_debug_issue(self) -> Workflow:
        """Workflow for debugging an issue."""
        return Workflow(
            name="Debug a Reported Issue",
            description="Step-by-step process for investigating and fixing bugs",
            estimated_time="30-90 minutes",
            steps=[
                WorkflowStep(
                    title="1. Reproduce the issue",
                    description="Create a minimal test case that triggers the bug",
                    code="""# Create test file that reproduces issue
def test_reproduce_bug():
    # Minimal code that shows the problem
    result = buggy_function(test_input)
    # This should fail initially
    assert result == expected"""
                ),
                WorkflowStep(
                    title="2. Add debug logging",
                    description="Insert print statements or use debugger",
                    code="""import pdb; pdb.set_trace()  # Breakpoint
# Or use logging
import logging
logging.debug(f"Variable state: {variable}")"""
                ),
                WorkflowStep(
                    title="3. Identify root cause",
                    description="Use debugger to step through and find where it breaks",
                    notes="Check: variable values, control flow, function call order"
                ),
                WorkflowStep(
                    title="4. Fix the bug",
                    description="Make the minimal change to fix the issue",
                    notes="Avoid over-engineering - fix the specific problem"
                ),
                WorkflowStep(
                    title="5. Verify the fix",
                    description="Run the reproduction test - it should now pass",
                    code="pytest tests/test_reproduce_bug.py -v"
                ),
                WorkflowStep(
                    title="6. Run full test suite",
                    description="Ensure the fix didn't break anything else",
                    code="pytest tests/ -v"
                ),
                WorkflowStep(
                    title="7. Clean up debug code",
                    description="Remove print statements and pdb calls",
                    notes="Leave useful logging at appropriate levels"
                )
            ]
        )
    
    def _workflow_first_contribution(self) -> Workflow:
        """Workflow for making first contribution."""
        return Workflow(
            name="Make Your First Contribution",
            description="Complete guide from fork to pull request",
            estimated_time="60-90 minutes",
            steps=[
                WorkflowStep(
                    title="1. Find something to work on",
                    description="Look for issues labeled 'good first issue' or 'help wanted'",
                    notes="Or fix a bug you found, or add a feature you need"
                ),
                WorkflowStep(
                    title="2. Create a branch",
                    description="Branch from main with descriptive name",
                    code="""git checkout main
git pull origin main
git checkout -b feature/my-improvement"""
                ),
                WorkflowStep(
                    title="3. Make your changes",
                    description="Write code following the project style",
                    notes="Keep changes focused - one feature/fix per PR"
                ),
                WorkflowStep(
                    title="4. Test thoroughly",
                    description="Run tests and add new ones if needed",
                    code="pytest tests/ -v --cov=code_analyzer"
                ),
                WorkflowStep(
                    title="5. Commit with clear message",
                    description="Write a descriptive commit message",
                    code="""git add .
git commit -m "feat: Add new analyzer for detecting X

- Implements detection logic for X
- Adds tests for edge cases
- Updates documentation
"""
                ),
                WorkflowStep(
                    title="6. Push and create PR",
                    description="Push your branch and open a pull request",
                    code="""git push origin feature/my-improvement
# Then open PR on GitHub/GitLab""",
                    notes="Fill out the PR template completely"
                ),
                WorkflowStep(
                    title="7. Respond to review feedback",
                    description="Address reviewer comments and update PR",
                    notes="Be receptive to feedback - it makes the code better!"
                )
            ]
        )


def format_workflow(workflow: Workflow) -> List[str]:
    """Format a workflow as markdown."""
    output = []
    
    output.append(f"## {workflow.name}")
    output.append("")
    output.append(f"**Description**: {workflow.description}")
    output.append(f"**Estimated Time**: {workflow.estimated_time}")
    output.append("")
    
    if workflow.prerequisites:
        output.append("**Prerequisites**:")
        for prereq in workflow.prerequisites:
            output.append(f"- {prereq}")
        output.append("")
    
    output.append("**Steps**:")
    output.append("")
    
    for step in workflow.steps:
        output.append(f"### {step.title}")
        output.append(step.description)
        output.append("")
        
        if step.file_to_edit:
            output.append(f"📝 **File**: `{step.file_to_edit}`")
            output.append("")
        
        if step.code:
            output.append("```python" if '.py' in str(step.file_to_edit or '') or 'import' in step.code else "```bash")
            output.append(step.code)
            output.append("```")
            output.append("")
        
        if step.notes:
            output.append(f"💡 *{step.notes}*")
            output.append("")
    
    output.append("---")
    output.append("")
    
    return output
