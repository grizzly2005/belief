"""Logseq integration for documentation generation."""

import sys
import os
import json
from pathlib import Path
from datetime import datetime
from typing import List, Set, Dict

# Add logseq-python to path
sys.path.insert(0, "/Volumes/Projects/logseq-python")

try:
    from logseq_py import LogseqClient
except ImportError:
    print("Warning: logseq-py not found. Install with: pip install logseq-py")
    LogseqClient = None

from .models import AnalysisResult, Issue, CriticalSection, IssueSeverity, IssueType
from .top_findings import TopFindingsGenerator


class LogseqDocGenerator:
    """Generates documentation in Logseq format."""
    
    def __init__(self, logseq_graph_path: str):
        """
        Initialize Logseq documentation generator.
        
        Args:
            logseq_graph_path: Path to Logseq graph directory
        """
        self.graph_path = Path(logseq_graph_path)
        if LogseqClient:
            self.client = LogseqClient(str(self.graph_path))
        else:
            self.client = None
            print("⚠️  Logseq client not available. Documentation will be generated as markdown only.")
    
    def generate_documentation(self, result: AnalysisResult, project_name: str, onboarding_path: Path = None):
        """
        Generate complete documentation for analysis results.
        
        Args:
            result: Analysis result to document
            project_name: Name of the project being analyzed
            onboarding_path: Optional path to ONBOARDING.md file to include
        """
        print(f"📚 Generating Logseq documentation for {project_name}...")
        
        # Create main project page
        self._create_project_overview(result, project_name)
        
        # Create metrics page
        self._create_metrics_page(result, project_name)
        
        # Create critical sections page
        self._create_critical_sections_page(result, project_name)
        
        # Create issues page with categorization
        self._create_issues_pages(result, project_name)
        
        # Create module documentation
        self._create_module_docs(result, project_name)
        
        # Create dependency graph page
        self._create_dependency_graph(result, project_name)
        
        # Create important sections page
        self._create_important_sections_page(result, project_name)
        
        # Create improvements page
        self._create_improvements_page(result, project_name)
        
        # Create top findings page (summary)
        self._create_top_findings_page(result, project_name)
        
        # Create onboarding page if available
        if onboarding_path and onboarding_path.exists():
            self._create_onboarding_page(project_name, onboarding_path)
        
        # Create journal entry for tracking
        self._create_journal_entry(result, project_name)
        
        print(f"✅ Documentation generated in {self.graph_path}")
    
    def _create_project_overview(self, result: AnalysisResult, project_name: str):
        """Create main project overview page."""
        page_title = f"Code Analysis: {project_name}"
        
        content = f"""# Code Analysis: {project_name}

## Overview
- **Analysis Date**: {result.analysis_date.strftime('%Y-%m-%d %H:%M')}
- **Project Path**: `{result.project_path}`
- **Status**: #code-analysis/complete

## Quick Stats
- **Modules**: {result.metrics.total_files}
- **Lines of Code**: {result.metrics.total_lines:,}
- **Classes**: {result.metrics.total_classes}
- **Functions**: {result.metrics.total_functions}
- **Issues Found**: {result.metrics.total_issues}
- **Critical Sections**: {len(result.critical_sections)}

## Analysis Sections
- [[{project_name}/Top Findings]] 🎯 **START HERE**
- [[{project_name}/Onboarding]] 🚀 **New Developer Guide**
- [[{project_name}/Metrics]]
- [[{project_name}/Critical Sections]]
- [[{project_name}/Important Sections]] ⭐
- [[{project_name}/Improvement Opportunities]] 💡
- [[{project_name}/Issues]]
- [[{project_name}/Modules]]
- [[{project_name}/Dependencies]]

## Issue Summary by Severity
"""
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = result.metrics.issues_by_severity.get(severity, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                        'low': '🔵', 'info': '⚪'}[severity]
                content += f"- {emoji} **{severity.upper()}**: {count}\n"
        
        content += "\n## Issue Summary by Type\n"
        for issue_type, count in result.metrics.issues_by_type.items():
            content += f"- **{issue_type.replace('_', ' ').title()}**: {count}\n"
        
        content += f"\n## Complexity Analysis\n"
        content += f"- **Average Complexity**: {result.metrics.average_complexity:.2f}\n"
        content += f"- **Maximum Complexity**: {result.metrics.max_complexity}\n"
        
        if result.entry_points:
            content += f"\n## Entry Points\n"
            for ep in result.entry_points:
                content += f"- `{ep}`\n"
        
        self._write_page(page_title, content)
    
    def _create_metrics_page(self, result: AnalysisResult, project_name: str):
        """Create detailed metrics page."""
        page_title = f"{project_name}/Metrics"
        
        content = f"""# Metrics: {project_name}

## Codebase Metrics
- **Total Files**: {result.metrics.total_files}
- **Total Lines**: {result.metrics.total_lines:,}
- **Average Lines per File**: {result.metrics.total_lines // result.metrics.total_files if result.metrics.total_files > 0 else 0}

## Structure Metrics
- **Total Classes**: {result.metrics.total_classes}
- **Total Functions**: {result.metrics.total_functions}
- **Functions per File**: {result.metrics.total_functions / result.metrics.total_files if result.metrics.total_files > 0 else 0:.1f}

## Complexity Metrics
- **Average Cyclomatic Complexity**: {result.metrics.average_complexity:.2f}
- **Maximum Cyclomatic Complexity**: {result.metrics.max_complexity}
- **High Complexity Functions**: {sum(1 for m in result.modules for f in m.functions if f.complexity > 10)}

## Quality Metrics
- **Total Issues**: {result.metrics.total_issues}
- **Issue Density**: {result.metrics.total_issues / result.metrics.total_lines * 1000 if result.metrics.total_lines > 0 else 0:.2f} per 1000 LOC
- **Critical Sections**: {len(result.critical_sections)}

## Issues Distribution
"""
        
        for severity, count in sorted(result.metrics.issues_by_severity.items()):
            percentage = (count / result.metrics.total_issues * 100) if result.metrics.total_issues > 0 else 0
            content += f"- **{severity.upper()}**: {count} ({percentage:.1f}%)\n"
        
        self._write_page(page_title, content)
    
    def _create_critical_sections_page(self, result: AnalysisResult, project_name: str):
        """Create critical sections documentation."""
        page_title = f"{project_name}/Critical Sections"
        
        content = f"""# Critical Sections: {project_name}

Critical sections are parts of the code that require extra attention due to:
- High complexity
- Entry points
- Large scope
- High impact on system

## Summary
- **Total Critical Sections**: {len(result.critical_sections)}

"""
        
        # Group by risk level
        by_risk = {}
        for cs in result.critical_sections:
            risk = cs.risk_level.value
            if risk not in by_risk:
                by_risk[risk] = []
            by_risk[risk].append(cs)
        
        for risk_level in ['critical', 'high', 'medium', 'low']:
            sections = by_risk.get(risk_level, [])
            if sections:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}[risk_level]
                content += f"## {emoji} {risk_level.upper()} Risk ({len(sections)})\n\n"
                
                for cs in sections:
                    content += f"### `{cs.name}`\n"
                    content += f"- **Location**: `{cs.location}`\n"
                    content += f"- **Reason**: {cs.reason}\n"
                    if cs.dependencies:
                        content += f"- **Dependencies**: {', '.join(f'`{d}`' for d in cs.dependencies[:5])}\n"
                    if cs.impact_areas:
                        content += f"- **Impact Areas**: {', '.join(cs.impact_areas)}\n"
                    content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_issues_pages(self, result: AnalysisResult, project_name: str):
        """Create issues documentation organized by severity and type."""
        page_title = f"{project_name}/Issues"
        
        content = f"""# Issues: {project_name}

## Overview
Total issues found: **{len(result.issues)}**

## By Severity
"""
        
        for severity in [IssueSeverity.CRITICAL, IssueSeverity.HIGH, IssueSeverity.MEDIUM, IssueSeverity.LOW]:
            issues = result.get_issues_by_severity(severity)
            if issues:
                content += f"- [[{project_name}/Issues/{severity.value.title()}]] ({len(issues)} issues)\n"
                self._create_issues_by_severity_page(project_name, severity, issues)
        
        content += "\n## By Type\n"
        for issue_type in IssueType:
            issues = result.get_issues_by_type(issue_type)
            if issues:
                type_name = issue_type.value.replace('_', ' ').title()
                content += f"- [[{project_name}/Issues/{type_name}]] ({len(issues)} issues)\n"
                self._create_issues_by_type_page(project_name, issue_type, issues)
        
        self._write_page(page_title, content)
    
    def _create_issues_by_severity_page(self, project_name: str, severity: IssueSeverity, issues: List[Issue]):
        """Create page for issues of a specific severity."""
        page_title = f"{project_name}/Issues/{severity.value.title()}"
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}[severity.value]
        
        content = f"""# {emoji} {severity.value.upper()} Severity Issues

Total: **{len(issues)}** issues

"""
        
        for i, issue in enumerate(issues, 1):
            content += f"## {i}. {issue.title}\n"
            content += f"- **Type**: #{issue.issue_type.value}\n"
            content += f"- **Location**: `{issue.location}`\n"
            content += f"- **Description**: {issue.description}\n"
            if issue.recommendation:
                content += f"- **Recommendation**: {issue.recommendation}\n"
            if issue.code_snippet:
                content += f"```python\n{issue.code_snippet}\n```\n"
            content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_issues_by_type_page(self, project_name: str, issue_type: IssueType, issues: List[Issue]):
        """Create page for issues of a specific type."""
        type_name = issue_type.value.replace('_', ' ').title()
        page_title = f"{project_name}/Issues/{type_name}"
        
        content = f"""# {type_name} Issues

Total: **{len(issues)}** issues

"""
        
        for i, issue in enumerate(issues, 1):
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 
                            'low': '🔵', 'info': '⚪'}[issue.severity.value]
            content += f"## {severity_emoji} {i}. {issue.title}\n"
            content += f"- **Severity**: {issue.severity.value.upper()}\n"
            content += f"- **Location**: `{issue.location}`\n"
            content += f"- **Description**: {issue.description}\n"
            if issue.recommendation:
                content += f"- **Recommendation**: {issue.recommendation}\n"
            content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_module_docs(self, result: AnalysisResult, project_name: str):
        """Create module documentation."""
        page_title = f"{project_name}/Modules"
        
        content = f"""# Modules: {project_name}

Total modules analyzed: **{len(result.modules)}**

"""
        
        for module in sorted(result.modules, key=lambda m: m.name):
            content += f"## `{module.name}`\n"
            content += f"- **File**: `{module.file_path}`\n"
            content += f"- **Lines of Code**: {module.lines_of_code}\n"
            content += f"- **Complexity**: {module.complexity}\n"
            content += f"- **Classes**: {len(module.classes)}\n"
            content += f"- **Functions**: {len(module.functions)}\n"
            
            if module.docstring:
                content += f"- **Description**: {module.docstring.split(chr(10))[0]}\n"
            
            if module.imports:
                content += f"- **Key Imports**: {', '.join(f'`{imp}`' for imp in module.imports[:5])}\n"
            
            content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_dependency_graph(self, result: AnalysisResult, project_name: str):
        """Create dependency graph documentation."""
        page_title = f"{project_name}/Dependencies"
        
        content = f"""# Dependencies: {project_name}

## Internal Dependencies

"""
        
        for module, deps in sorted(result.dependency_graph.items()):
            if deps:
                content += f"### `{module}`\n"
                content += "Depends on:\n"
                for dep in deps:
                    content += f"- `{dep}`\n"
                content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_important_sections_page(self, result: AnalysisResult, project_name: str):
        """Create important sections documentation."""
        page_title = f"{project_name}/Important Sections"
        
        content = f"""# Important Sections: {project_name}

This page documents the most important parts of the codebase:
- Entry points and main functions
- Design patterns implementations
- Core business logic
- API endpoints
- Data models
- Configuration handlers

## Summary
- **Total Important Sections**: {len(result.important_sections)}

"""
        
        if not result.important_sections:
            content += "No important sections identified.\n"
            self._write_page(page_title, content)
            return
        
        # Group by category
        by_category = {}
        for section in result.important_sections:
            if section.category not in by_category:
                by_category[section.category] = []
            by_category[section.category].append(section)
        
        # Define category order and titles
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
                content += f"\n## {category_titles.get(category, category.title())} ({len(sections)})\n\n"
                
                # Sort by importance
                sections.sort(key=lambda s: {"critical": 0, "high": 1, "medium": 2}.get(s.importance, 3))
                
                for section in sections:
                    importance_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(section.importance, "⚪")
                    
                    content += f"### {importance_emoji} `{section.name}`\n"
                    content += f"- **Location**: `{section.location}`\n"
                    content += f"- **Importance**: {section.importance.upper()}\n"
                    content += f"- **Description**: {section.description}\n"
                    
                    if hasattr(section, 'pattern_type') and section.pattern_type:
                        content += f"- **Pattern**: {section.pattern_type}\n"
                    
                    if hasattr(section, 'documentation') and section.documentation:
                        # Truncate long documentation
                        doc = section.documentation[:200] + "..." if len(section.documentation) > 200 else section.documentation
                        content += f"- **Documentation**: {doc}\n"
                    
                    content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_improvements_page(self, result: AnalysisResult, project_name: str):
        """Create improvement opportunities page."""
        page_title = f"{project_name}/Improvement Opportunities"
        
        content = f"""# 💡 Improvement Opportunities: {project_name}

Code sections that need updates, refactoring, or enhancements.

## Summary
- **Total Opportunities**: {len(result.improvements)}

"""
        
        if not result.improvements:
            content += "No improvement opportunities identified.\n"
            self._write_page(page_title, content)
            return
        
        # Group by category
        by_category = {}
        for imp in result.improvements:
            if imp.category not in by_category:
                by_category[imp.category] = []
            by_category[imp.category].append(imp)
        
        category_titles = {
            "refactoring": "♻️ Refactoring Needed",
            "configuration": "⚙️ Configuration",
            "error_handling": "⚠️ Error Handling",
            "validation": "✔️ Validation",
            "testing": "🧪 Testing",
            "performance": "⚡ Performance",
            "scalability": "📈 Scalability"
        }
        
        for category, title in category_titles.items():
            if category in by_category:
                items = by_category[category]
                content += f"\n## {title} ({len(items)})\n\n"
                
                # Sort by priority
                items.sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.priority, 4))
                
                for imp in items[:10]:  # Max 10 per category
                    priority_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(imp.priority, '⚪')
                    
                    content += f"### {priority_emoji} {imp.issue}\n"
                    content += f"- **Location**: `{imp.location}`\n"
                    content += f"- **Priority**: {imp.priority.upper()}\n"
                    content += f"- **Effort**: {imp.effort.title()} | **Impact**: {imp.impact.title()}\n"
                    content += f"- **Suggestion**: {imp.suggestion}\n"
                    
                    if imp.examples:
                        content += f"- **Example**:\n```python\n{chr(10).join(imp.examples[:5])}\n```\n"
                    
                    content += "\n"
        
        self._write_page(page_title, content)
    
    def _create_top_findings_page(self, result: AnalysisResult, project_name: str):
        """Create top findings summary page."""
        page_title = f"{project_name}/Top Findings"
        
        # Generate top findings
        top_gen = TopFindingsGenerator()
        top_findings = top_gen.generate_top_findings(result, n=15)
        
        content = top_gen.generate_summary_markdown(top_findings, project_name)
        
        # Add quick wins section
        quick_wins = top_gen.generate_quick_wins(result.improvements)
        if quick_wins:
            content += "\n\n## ⚡ Quick Wins (Small Effort, High Impact)\n\n"
            content += "These improvements can be completed quickly but provide significant value:\n\n"
            
            for i, qw in enumerate(quick_wins[:5], 1):
                content += f"{i}. **{qw['issue']}** at `{qw['name']}`\n"
                content += f"   - {qw['suggestion']}\n"
                content += f"   - Location: `{qw['location']}`\n\n"
        
        self._write_page(page_title, content)
    
    def _create_onboarding_page(self, project_name: str, onboarding_path: Path):
        """Create onboarding guide page from ONBOARDING.md."""
        page_title = f"{project_name}/Onboarding"
        
        try:
            onboarding_content = onboarding_path.read_text()
            
            # Convert to Logseq format (add bullet points)
            lines = onboarding_content.split('\n')
            formatted_lines = []
            
            for line in lines:
                if line.strip():
                    # Headers
                    if line.startswith('#'):
                        # Convert markdown headers to Logseq format
                        level = len(line) - len(line.lstrip('#'))
                        text = line.lstrip('#').strip()
                        formatted_lines.append('- ' + '#' * level + ' ' + text)
                    # Horizontal rules
                    elif line.strip().startswith('---') or line.strip().startswith('==='):
                        formatted_lines.append('')
                    # List items (already have bullets or numbers)
                    elif line.strip().startswith(('-', '*', '\u2022')) or (len(line) > 0 and line.strip()[0].isdigit() and '.' in line[:5]):
                        formatted_lines.append('  ' + line.strip())
                    # Regular text
                    else:
                        formatted_lines.append('- ' + line.strip())
                else:
                    formatted_lines.append('')
            
            content = '\n'.join(formatted_lines)
            self._write_page(page_title, content)
            
        except Exception as e:
            print(f"   ⚠️  Could not create onboarding page: {e}")
    
    def _write_page(self, title: str, content: str):
        """Write a page to Logseq."""
        if self.client:
            try:
                self.client.create_page(title, content)
                print(f"   ✅ Created page: {title}")
            except Exception as e:
                print(f"   ⚠️  Error creating page {title}: {e}")
                # Fallback to file write
                self._write_markdown_file(title, content)
        else:
            self._write_markdown_file(title, content)
    
    def _write_markdown_file(self, title: str, content: str):
        """Fallback: write as markdown file."""
        pages_dir = self.graph_path / "pages"
        pages_dir.mkdir(parents=True, exist_ok=True)
        
        # Convert title to filename
        filename = title.replace("/", "___").replace(" ", "_") + ".md"
        file_path = pages_dir / filename
        
        file_path.write_text(content)
        print(f"   📝 Wrote markdown: {file_path}")
    
    def _load_previous_analysis(self, project_path: str) -> Set[str]:
        """Load fingerprints from previous analysis."""
        analysis_file = Path(project_path) / ".code-analyzer" / "analysis.json"
        if not analysis_file.exists():
            print(f"   📝 No previous analysis found")
            return set()
        
        try:
            with open(analysis_file, 'r') as f:
                data = json.load(f)
                issues = data.get('issues', [])
                fingerprints = {issue.get('fingerprint') for issue in issues if 'fingerprint' in issue}
                print(f"   📊 Loaded {len(fingerprints)} previous issue fingerprints")
                return fingerprints
        except Exception as e:
            print(f"   ⚠️  Could not load previous analysis: {e}")
            return set()
    
    def _find_resolved_issues(self, result: AnalysisResult, previous_fingerprints: Set[str]) -> List[Dict[str, str]]:
        """Find issues that were resolved since last analysis."""
        current_fingerprints = {issue.fingerprint() for issue in result.issues}
        resolved_fingerprints = previous_fingerprints - current_fingerprints
        
        # We don't have the full issue details for resolved issues,
        # so we just return the count and fingerprints
        return [{"fingerprint": fp} for fp in resolved_fingerprints]
    
    def _create_journal_entry(self, result: AnalysisResult, project_name: str):
        """Create a journal entry for tracking issues over time."""
        # Get today's date
        today = datetime.now()
        journal_date = today.strftime('%Y_%m_%d')
        
        # Load previous analysis to detect resolved issues
        previous_fingerprints = self._load_previous_analysis(result.project_path)
        resolved_issues = self._find_resolved_issues(result, previous_fingerprints)
        if resolved_issues:
            print(f"   ✅ Detected {len(resolved_issues)} resolved issue(s)")
        
        # Create journal directory if it doesn't exist
        journals_dir = self.graph_path / "journals"
        journals_dir.mkdir(parents=True, exist_ok=True)
        
        # Create journal file path
        journal_file = journals_dir / f"{journal_date}.md"
        
        # Create journal content
        content = f"""- ## 🔍 Code Analysis: [[{project_name}]]
  - **Time**: {today.strftime('%H:%M')}
  - **Status**: #code-analysis/identified
  - **Issues Found**: {result.metrics.total_issues}
  - **Critical**: {result.metrics.issues_by_severity.get('critical', 0)} | **High**: {result.metrics.issues_by_severity.get('high', 0)} | **Medium**: {result.metrics.issues_by_severity.get('medium', 0)} | **Low**: {result.metrics.issues_by_severity.get('low', 0)}
  - 
  - ### 🎯 Top Issues to Address:
"""
        
        # Add top 5 high/critical issues
        high_issues = [i for i in result.issues if i.severity.value in ['critical', 'high']]
        for i, issue in enumerate(high_issues[:5], 1):
            severity_emoji = '🔴' if issue.severity.value == 'critical' else '🟠'
            content += f"  - {severity_emoji} **{issue.title}** at `{issue.location}` #issue/open\n"
            content += f"    - TODO Mark as #issue/resolved when fixed\n"
        
        if not high_issues:
            content += "  - ✅ No high/critical issues found!\n"
        
        # Add resolved issues section if any
        if resolved_issues:
            content += f"  - \n  - ### ✅ Resolved Since Last Analysis ({len(resolved_issues)}):\n"
            content += f"  - {len(resolved_issues)} issue(s) were fixed or removed! #code-analysis/progress\n"
        
        # Add summary of improvement opportunities
        if result.improvements:
            content += f"  - \n  - ### 💡 Quick Wins ({len([i for i in result.improvements if i.effort == 'small' and i.impact == 'high'])} available):\n"
            quick_wins = [i for i in result.improvements if i.effort == 'small' and i.impact == 'high']
            for qw in quick_wins[:3]:
                content += f"  - [ ] {qw.issue} at `{qw.location}` #improvement\n"
        
        # Add link to full analysis
        content += f"  - \n  - 📊 **Full Analysis**: [[{project_name}/Top Findings]]\n"
        content += f"  - \n  - ---\n"
        
        # Append to existing journal or create new
        if journal_file.exists():
            existing_content = journal_file.read_text()
            content = existing_content + "\n" + content
        
        journal_file.write_text(content)
        print(f"   ✅ Created journal entry: {journal_file.name}")
