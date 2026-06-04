"""Repo-tickets integration for automated issue tracking."""

import sys
import subprocess
from pathlib import Path
from typing import List, Dict
from datetime import datetime

# Add repo-tickets to path
sys.path.insert(0, "/Volumes/Projects/repo-tickets")

from .models import AnalysisResult, Issue, IssueSeverity, IssueType


class TicketsManager:
    """Manages ticket creation for discovered issues."""
    
    def __init__(self, repo_path: str):
        """
        Initialize tickets manager.
        
        Args:
            repo_path: Path to repository root
        """
        self.repo_path = Path(repo_path)
        self._check_tickets_initialized()
    
    def _check_tickets_initialized(self):
        """Check if repo-tickets is initialized."""
        tickets_dir = self.repo_path / ".tickets"
        if not tickets_dir.exists():
            print("⚠️  Repo-tickets not initialized. Run: tickets init")
            self.initialized = False
        else:
            self.initialized = True
    
    def create_epic_and_tickets(self, result: AnalysisResult, project_name: str):
        """
        Create epic and tickets for analysis results.
        
        Args:
            result: Analysis result
            project_name: Name of project
        """
        if not self.initialized:
            print("❌ Cannot create tickets: repo-tickets not initialized")
            return
        
        print(f"🎫 Creating epic and tickets for {project_name}...")
        
        # Create main epic
        epic_id = self._create_main_epic(result, project_name)
        
        if not epic_id:
            print("❌ Failed to create epic")
            return
        
        # Create tickets by severity
        critical_issues = result.get_issues_by_severity(IssueSeverity.CRITICAL)
        high_issues = result.get_issues_by_severity(IssueSeverity.HIGH)
        medium_issues = result.get_issues_by_severity(IssueSeverity.MEDIUM)
        
        ticket_ids = []
        
        # Create tickets for critical issues (always create)
        for issue in critical_issues:
            ticket_id = self._create_ticket(issue, epic_id, "critical")
            if ticket_id:
                ticket_ids.append(ticket_id)
        
        # Create tickets for high severity issues
        for issue in high_issues:
            ticket_id = self._create_ticket(issue, epic_id, "high")
            if ticket_id:
                ticket_ids.append(ticket_id)
        
        # Sample medium issues (create max 10)
        for issue in medium_issues[:10]:
            ticket_id = self._create_ticket(issue, epic_id, "medium")
            if ticket_id:
                ticket_ids.append(ticket_id)
        
        # Create summary ticket
        self._create_summary_ticket(result, epic_id)
        
        print(f"✅ Created epic {epic_id} with {len(ticket_ids)} tickets")
    
    def _create_main_epic(self, result: AnalysisResult, project_name: str) -> str:
        """Create main epic for code analysis."""
        title = f"Code Quality Improvements: {project_name}"
        description = f"""Code analysis completed on {result.analysis_date.strftime('%Y-%m-%d %H:%M')}

## Analysis Summary
- **Total Issues**: {result.metrics.total_issues}
- **Critical**: {result.metrics.issues_by_severity.get('critical', 0)}
- **High**: {result.metrics.issues_by_severity.get('high', 0)}
- **Medium**: {result.metrics.issues_by_severity.get('medium', 0)}
- **Low**: {result.metrics.issues_by_severity.get('low', 0)}

## Code Metrics
- **Files Analyzed**: {result.metrics.total_files}
- **Total Lines**: {result.metrics.total_lines:,}
- **Average Complexity**: {result.metrics.average_complexity:.2f}
- **Max Complexity**: {result.metrics.max_complexity}

## Goals
- Address all critical and high-severity issues
- Reduce average complexity below 10
- Improve code documentation
- Enhance test coverage
"""
        
        cmd = [
            "tickets", "epic", "create", title,
            "--description", description,
            "--priority", "high",
            "--status", "active"
        ]
        
        try:
            result_run = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result_run.returncode == 0:
                # Extract epic ID from output
                output = result_run.stdout
                # Parse epic ID (format: EPIC-xxx)
                import re
                match = re.search(r'(EPIC-\w+)', output)
                if match:
                    epic_id = match.group(1)
                    print(f"   ✅ Created epic: {epic_id}")
                    return epic_id
            else:
                print(f"   ⚠️  Error creating epic: {result_run.stderr}")
                return None
        except Exception as e:
            print(f"   ❌ Failed to create epic: {e}")
            return None
    
    def _create_ticket(self, issue: Issue, epic_id: str, priority: str) -> str:
        """Create a ticket for an issue."""
        title = issue.title
        
        description = f"""{issue.description}

**Location**: `{issue.location}`

**Type**: {issue.issue_type.value}

**Recommendation**: {issue.recommendation or 'Manual review required'}

**Metadata**:
{self._format_metadata(issue.metadata)}
"""
        
        if issue.code_snippet:
            description += f"\n\n**Code Snippet**:\n```python\n{issue.code_snippet}\n```"
        
        # Map issue type to labels
        labels = [issue.issue_type.value, f"severity-{issue.severity.value}", "code-analysis"]
        
        cmd = [
            "tickets", "create", title,
            "--description", description,
            "--priority", priority,
            "--labels", ",".join(labels)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Extract ticket ID
                import re
                match = re.search(r'(\w+-\d+)', result.stdout)
                if match:
                    ticket_id = match.group(1)
                    
                    # Add to epic
                    self._add_ticket_to_epic(epic_id, ticket_id)
                    
                    print(f"   ✅ Created ticket: {ticket_id} - {title[:50]}...")
                    return ticket_id
            else:
                print(f"   ⚠️  Error creating ticket: {result.stderr}")
                return None
        except Exception as e:
            print(f"   ❌ Failed to create ticket: {e}")
            return None
    
    def _add_ticket_to_epic(self, epic_id: str, ticket_id: str):
        """Add ticket to epic."""
        cmd = ["tickets", "epic", "add-ticket", epic_id, ticket_id]
        
        try:
            subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
        except Exception as e:
            print(f"   ⚠️  Failed to add ticket {ticket_id} to epic: {e}")
    
    def _create_summary_ticket(self, result: AnalysisResult, epic_id: str):
        """Create a summary ticket with overall findings."""
        title = "Code Analysis Summary and Action Plan"
        
        description = f"""# Code Analysis Summary

## Key Findings

### Issues by Type
"""
        
        for issue_type, count in sorted(
            result.metrics.issues_by_type.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            description += f"- **{issue_type.replace('_', ' ').title()}**: {count}\n"
        
        description += "\n### Critical Sections\n"
        for cs in result.critical_sections[:5]:
            description += f"- `{cs.name}`: {cs.reason}\n"
        
        description += "\n### Recommended Actions\n"
        description += "1. Address all critical severity issues immediately\n"
        description += "2. Refactor high-complexity functions\n"
        description += "3. Add documentation to undocumented code\n"
        description += "4. Review and remove unused code\n"
        description += "5. Improve test coverage\n"
        
        description += f"\n### Metrics\n"
        description += f"- Average Complexity: {result.metrics.average_complexity:.2f}\n"
        description += f"- Max Complexity: {result.metrics.max_complexity}\n"
        description += f"- Issue Density: {result.metrics.total_issues / result.metrics.total_lines * 1000:.2f} per 1000 LOC\n"
        
        cmd = [
            "tickets", "create", title,
            "--description", description,
            "--priority", "high",
            "--labels", "summary,code-analysis,action-plan"
        ]
        
        try:
            result_run = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            
            if result_run.returncode == 0:
                import re
                match = re.search(r'(\w+-\d+)', result_run.stdout)
                if match:
                    ticket_id = match.group(1)
                    self._add_ticket_to_epic(epic_id, ticket_id)
                    print(f"   ✅ Created summary ticket: {ticket_id}")
        except Exception as e:
            print(f"   ⚠️  Failed to create summary ticket: {e}")
    
    def _format_metadata(self, metadata: Dict) -> str:
        """Format metadata for display."""
        if not metadata:
            return "None"
        
        lines = []
        for key, value in metadata.items():
            lines.append(f"- {key}: {value}")
        return "\n".join(lines)
