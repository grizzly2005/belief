"""Build Logseq graph programmatically using graph-as-code approach."""

from pathlib import Path
from typing import List
from datetime import datetime

try:
    from logseq_py.builders import PageBuilder, TaskBuilder, BlockBuilder
    HAS_BUILDERS = True
except ImportError:
    HAS_BUILDERS = False


class LogseqGraphBuilder:
    """Build complete Logseq graphs programmatically."""
    
    def __init__(self, graph_path: Path):
        self.graph_path = Path(graph_path)
        self.pages = []
        self.journals = []
        
    def create_onboarding_page(self, project_name: str, onboarding_content: str) -> 'LogseqGraphBuilder':
        """Create onboarding page using builder DSL."""
        if not HAS_BUILDERS:
            # Fallback to file creation
            self._create_page_file(f"{project_name}/Onboarding", onboarding_content)
            return self
        
        # Convert markdown to Logseq bullet format
        page = (PageBuilder(f"{project_name}/Onboarding")
                .tags("onboarding", "documentation", "engineering")
                .created()
                .page_type("documentation"))
        
        # Add content as bullets
        for line in onboarding_content.split('\n'):
            if line.strip():
                # Convert markdown headings to bullets with formatting
                if line.startswith('# '):
                    page.add(BlockBuilder(line.replace('# ', '')))
                elif line.startswith('## '):
                    page.add(BlockBuilder(line.replace('## ', '')))
                elif line.startswith('### '):
                    page.add(BlockBuilder(line.replace('### ', '')))
                elif line.startswith('- '):
                    page.add(BlockBuilder(line[2:]))
                else:
                    page.add(BlockBuilder(line))
        
        content = page.build()
        self._write_page(f"{project_name}_Onboarding.md", content)
        self.pages.append(f"{project_name}_Onboarding.md")
        return self
    
    def create_issues_page(self, project_name: str, severity: str, issues: List) -> 'LogseqGraphBuilder':
        """Create issues page for a specific severity."""
        if not HAS_BUILDERS:
            # Fallback
            self._create_issues_file_simple(project_name, severity, issues)
            return self
        
        page = (PageBuilder(f"{project_name}/Issues/{severity}")
                .tags("issues", severity.lower(), "code-quality")
                .created()
                .page_type("issue-tracker"))
        
        page.heading(1, f"{severity} Priority Issues")
        page.text(f"Found {len(issues)} {severity.lower()}-priority issues that need attention.")
        page.empty_line()
        
        for issue in issues[:20]:  # Limit to 20
            # Create task for each issue
            task = (TaskBuilder(issue.description)
                    .todo()
                    .property("file", issue.file_path)
                    .property("line", str(issue.line_number))
                    .property("category", issue.category))
            
            if severity.lower() == 'high':
                task.high_priority()
            elif severity.lower() == 'medium':
                task.medium_priority()
            
            page.add(task)
        
        content = page.build()
        self._write_page(f"{project_name}_Issues_{severity}.md", content)
        self.pages.append(f"{project_name}_Issues_{severity}.md")
        return self
    
    def create_modules_page(self, project_name: str, modules: List) -> 'LogseqGraphBuilder':
        """Create modules documentation page."""
        if not HAS_BUILDERS:
            self._create_modules_file_simple(project_name, modules)
            return self
        
        page = (PageBuilder(f"{project_name}/Modules")
                .tags("modules", "code-structure", "architecture")
                .created()
                .page_type("documentation"))
        
        page.heading(1, "Module Documentation")
        page.text(f"Total modules analyzed: **{len(modules)}**")
        page.empty_line()
        
        for module in modules[:30]:  # Limit to 30
            page.heading(2, module.name)
            page.add(BlockBuilder(f"**Path**: `{module.file_path}`"))
            page.add(BlockBuilder(f"**Lines of Code**: {module.lines_of_code}"))
            page.add(BlockBuilder(f"**Classes**: {len(module.classes)}"))
            page.add(BlockBuilder(f"**Functions**: {len(module.functions)}"))
            
            if module.docstring:
                page.add(BlockBuilder(f"**Description**: {module.docstring[:200]}..."))
            
            page.empty_line()
        
        content = page.build()
        self._write_page(f"{project_name}_Modules.md", content)
        self.pages.append(f"{project_name}_Modules.md")
        return self
    
    def create_journal_entry(self, project_name: str, analysis_result) -> 'LogseqGraphBuilder':
        """Create journal entry with analysis results."""
        if not HAS_BUILDERS:
            self._create_journal_file_simple(project_name, analysis_result)
            return self
        
        today = datetime.now()
        page = (PageBuilder(f"Journal/{today.strftime('%Y_%m_%d')}")
                .created())
        
        # Analysis header
        page.heading(2, f"🔍 Code Analysis: [[{project_name}]]")
        page.add(BlockBuilder(f"**Time**: {today.strftime('%H:%M')}"))
        page.add(BlockBuilder(f"**Status**: #code-analysis/identified"))
        
        # Count issues by severity
        issues_by_severity = {}
        for issue in analysis_result.issues:
            issues_by_severity[issue.severity] = issues_by_severity.get(issue.severity, 0) + 1
        
        page.add(BlockBuilder(f"**Issues Found**: {len(analysis_result.issues)}"))
        
        severity_line = " | ".join([
            f"**{sev.title()}**: {count}" 
            for sev, count in sorted(issues_by_severity.items())
        ])
        page.add(BlockBuilder(severity_line))
        page.empty_line()
        
        # Top issues
        page.heading(3, "🎯 Top Issues to Address:")
        high_issues = [i for i in analysis_result.issues if i.severity == 'high'][:5]
        
        for issue in high_issues:
            task = (TaskBuilder(issue.description)
                    .todo()
                    .property("file", issue.file_path)
                    .property("line", str(issue.line_number)))
            page.add(task)
            page.add(BlockBuilder("  TODO Mark as #issue/resolved when fixed"))
        
        page.empty_line()
        
        # Quick wins
        improvements = [i for i in analysis_result.improvement_opportunities 
                       if 'risky' in i.description.lower()][:3]
        if improvements:
            page.heading(3, f"💡 Quick Wins ({len(improvements)} available):")
            for imp in improvements:
                task = (TaskBuilder(imp.description)
                        .property("file", imp.file_path)
                        .property("type", "improvement"))
                page.add(task)
        
        page.empty_line()
        page.add(BlockBuilder(f"📊 **Full Analysis**: [[{project_name}/Top Findings]]"))
        page.empty_line()
        page.separator()
        
        content = page.build()
        
        # Ensure journals directory exists
        journals_dir = self.graph_path / "journals"
        journals_dir.mkdir(parents=True, exist_ok=True)
        
        journal_file = journals_dir / f"{today.strftime('%Y_%m_%d')}.md"
        with open(journal_file, 'w') as f:
            f.write(content)
        
        self.journals.append(journal_file.name)
        return self
    
    def create_metrics_page(self, project_name: str, analysis_result) -> 'LogseqGraphBuilder':
        """Create project metrics page."""
        if not HAS_BUILDERS:
            return self
        
        page = (PageBuilder(f"{project_name}/Metrics")
                .tags("metrics", "statistics", "analytics")
                .created())
        
        page.heading(1, "Project Metrics")
        page.empty_line()
        
        # Stats table
        page.heading(2, "Code Statistics")
        table = page.table()
        table.headers("Metric", "Value")
        table.row("Total Files", str(len(analysis_result.modules)))
        table.row("Total Lines", f"{sum(m.lines_of_code for m in analysis_result.modules):,}")
        table.row("Total Classes", str(sum(len(m.classes) for m in analysis_result.modules)))
        table.row("Total Functions", str(sum(len(m.functions) for m in analysis_result.modules)))
        table.row("Issues Found", str(len(analysis_result.issues)))
        
        page.empty_line()
        
        # Complexity metrics
        if analysis_result.modules:
            avg_complexity = sum(m.complexity for m in analysis_result.modules) / len(analysis_result.modules)
            max_complexity = max(m.complexity for m in analysis_result.modules)
            
            page.heading(2, "Complexity")
            page.add(BlockBuilder(f"**Average**: {avg_complexity:.2f}"))
            page.add(BlockBuilder(f"**Maximum**: {max_complexity}"))
        
        content = page.build()
        self._write_page(f"{project_name}_Metrics.md", content)
        self.pages.append(f"{project_name}_Metrics.md")
        return self
    
    def build(self) -> dict:
        """Build and return graph info."""
        return {
            'graph_path': str(self.graph_path),
            'pages_created': len(self.pages),
            'journals_created': len(self.journals),
            'pages': self.pages,
            'journals': self.journals
        }
    
    def _write_page(self, filename: str, content: str):
        """Write page file to graph directory."""
        self.graph_path.mkdir(parents=True, exist_ok=True)
        page_file = self.graph_path / filename
        with open(page_file, 'w') as f:
            f.write(content)
    
    def _create_page_file(self, title: str, content: str):
        """Fallback method to create page without builders."""
        filename = title.replace('/', '_') + '.md'
        self._write_page(filename, content)
        self.pages.append(filename)
    
    def _create_issues_file_simple(self, project_name: str, severity: str, issues: List):
        """Fallback for issues page."""
        content = f"- # {severity} Priority Issues\n"
        content += f"- Found {len(issues)} issues\n"
        for issue in issues[:10]:
            content += f"- TODO {issue.description}\n"
            content += f"  - file:: {issue.file_path}\n"
        
        self._write_page(f"{project_name}_Issues_{severity}.md", content)
        self.pages.append(f"{project_name}_Issues_{severity}.md")
    
    def _create_modules_file_simple(self, project_name: str, modules: List):
        """Fallback for modules page."""
        content = f"- # Module Documentation\n"
        content += f"- Total: {len(modules)}\n"
        for module in modules[:10]:
            content += f"- ## {module.name}\n"
            content += f"  - Path: {module.file_path}\n"
        
        self._write_page(f"{project_name}_Modules.md", content)
        self.pages.append(f"{project_name}_Modules.md")
    
    def _create_journal_file_simple(self, project_name: str, analysis_result):
        """Fallback for journal entry."""
        today = datetime.now()
        content = f"- ## Code Analysis: [[{project_name}]]\n"
        content += f"  - Time: {today.strftime('%H:%M')}\n"
        content += f"  - Issues: {len(analysis_result.issues)}\n"
        
        journals_dir = self.graph_path / "journals"
        journals_dir.mkdir(parents=True, exist_ok=True)
        journal_file = journals_dir / f"{today.strftime('%Y_%m_%d')}.md"
        with open(journal_file, 'w') as f:
            f.write(content)
        
        self.journals.append(journal_file.name)
