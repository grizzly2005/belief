"""Extract 'Why this exists' documentation from git history."""

import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from collections import defaultdict
import re


@dataclass
class ComponentHistory:
    """History and rationale for a component."""
    component_name: str
    file_path: str
    why_it_exists: str  # Problem it solves
    initial_commit_message: str
    major_changes: List[Tuple[str, str]] = field(default_factory=list)  # (date, reason)
    design_decisions: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)


class WhyDocsExtractor:
    """Extract rationale and history from git commits."""
    
    def __init__(self, project_path: Path):
        self.project_path = Path(project_path)
    
    def extract_component_history(self, file_path: str) -> Optional[ComponentHistory]:
        """Extract the history and rationale for a specific file/component."""
        try:
            # Get initial commit for this file
            initial_commit = self._get_initial_commit(file_path)
            if not initial_commit:
                return None
            
            # Get commit message
            initial_message = self._get_commit_message(initial_commit['hash'])
            
            # Extract "why" from commit message
            why_it_exists = self._extract_why_from_message(initial_message)
            
            # Get major changes/refactors
            major_changes = self._get_major_changes(file_path)
            
            # Get authors
            authors = self._get_file_authors(file_path)
            
            # Extract design decisions from commits
            design_decisions = self._extract_design_decisions(file_path)
            
            component_name = Path(file_path).stem
            
            return ComponentHistory(
                component_name=component_name,
                file_path=file_path,
                why_it_exists=why_it_exists or "Implements core functionality",
                initial_commit_message=initial_message,
                major_changes=major_changes[:5],  # Top 5
                design_decisions=design_decisions[:3],  # Top 3
                authors=authors[:3]  # Top 3 contributors
            )
        
        except Exception as e:
            # If git history unavailable, return None
            return None
    
    def _get_initial_commit(self, file_path: str) -> Optional[Dict[str, str]]:
        """Get the first commit that introduced this file."""
        try:
            cmd = [
                'git', '--no-pager', 'log', '--follow', '--diff-filter=A',
                '--format=%H|%ai|%an', '--', file_path
            ]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                if lines:
                    # Get last line (oldest commit)
                    parts = lines[-1].split('|')
                    if len(parts) >= 3:
                        return {
                            'hash': parts[0],
                            'date': parts[1],
                            'author': parts[2]
                        }
            return None
        except Exception:
            return None
    
    def _get_commit_message(self, commit_hash: str) -> str:
        """Get the full commit message for a commit."""
        try:
            cmd = ['git', '--no-pager', 'log', '-1', '--format=%B', commit_hash]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except Exception:
            return ""
    
    def _extract_why_from_message(self, commit_message: str) -> str:
        """Extract the 'why' from a commit message."""
        # Look for patterns like:
        # - "Add X to solve Y"
        # - "Implement X for Y"
        # - "Why: ..."
        # - Lines after "Motivation:", "Rationale:", etc.
        
        lines = commit_message.split('\n')
        
        # Check for explicit "why" indicators
        for i, line in enumerate(lines):
            lower = line.lower().strip()
            if any(keyword in lower for keyword in ['why:', 'motivation:', 'rationale:', 'reason:', 'problem:']):
                # Return next few lines
                why_lines = []
                for j in range(i, min(i + 3, len(lines))):
                    if lines[j].strip():
                        # Remove the keyword prefix
                        clean = re.sub(r'^(why|motivation|rationale|reason|problem):\s*', '', 
                                     lines[j], flags=re.IGNORECASE)
                        why_lines.append(clean.strip())
                if why_lines:
                    return ' '.join(why_lines)
        
        # Look for "to solve", "to fix", "to handle", "to support"
        for line in lines:
            match = re.search(r'to (solve|fix|handle|support|enable|allow|provide)\s+(.+)', 
                            line, re.IGNORECASE)
            if match:
                return f"Created to {match.group(1).lower()} {match.group(2)}"
        
        # Look for "for X" patterns
        for line in lines:
            match = re.search(r'(implement|add|create)\s+\w+\s+for\s+(.+)', 
                            line, re.IGNORECASE)
            if match:
                return f"Provides {match.group(2)}"
        
        # Fallback: use first line of commit
        if lines:
            first_line = lines[0].strip()
            # Remove conventional commit prefixes
            first_line = re.sub(r'^(feat|fix|docs|style|refactor|test|chore)(\(.+?\))?:\s*', 
                              '', first_line, flags=re.IGNORECASE)
            return first_line
        
        return "Core functionality"
    
    def _get_major_changes(self, file_path: str) -> List[Tuple[str, str]]:
        """Get major changes/refactors to this file."""
        try:
            # Get commits with significant changes (>20 lines changed)
            cmd = [
                'git', '--no-pager', 'log', '--follow', '--oneline', 
                '--format=%ai|%s', '--numstat', '--', file_path
            ]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return []
            
            changes = []
            lines = result.stdout.split('\n')
            current_commit = None
            
            for line in lines:
                if '|' in line and not '\t' in line:
                    # Commit line
                    current_commit = line
                elif '\t' in line and current_commit:
                    # Stat line: added  deleted  filename
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        try:
                            added = int(parts[0]) if parts[0].isdigit() else 0
                            deleted = int(parts[1]) if parts[1].isdigit() else 0
                            total = added + deleted
                            
                            if total >= 20:  # Significant change
                                date, message = current_commit.split('|', 1)
                                date = date.split()[0]  # Just the date
                                changes.append((date, message.strip()))
                                current_commit = None  # Avoid duplicates
                        except (ValueError, IndexError):
                            continue
            
            return changes[:5]
        
        except Exception:
            return []
    
    def _get_file_authors(self, file_path: str) -> List[str]:
        """Get main contributors to this file."""
        try:
            cmd = [
                'git', '--no-pager', 'log', '--follow', '--format=%an', '--', file_path
            ]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                authors = result.stdout.strip().split('\n')
                # Count occurrences
                author_counts = defaultdict(int)
                for author in authors:
                    author_counts[author] += 1
                
                # Sort by contribution count
                sorted_authors = sorted(author_counts.items(), 
                                      key=lambda x: x[1], reverse=True)
                return [author for author, _ in sorted_authors[:3]]
            
            return []
        except Exception:
            return []
    
    def _extract_design_decisions(self, file_path: str) -> List[str]:
        """Extract design decisions from commit messages."""
        try:
            cmd = [
                'git', '--no-pager', 'log', '--follow', '--format=%B', '--', file_path
            ]
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return []
            
            decisions = []
            commit_messages = result.stdout
            
            # Look for decision indicators
            decision_patterns = [
                r'decided?\s+to\s+(.+)',
                r'chose\s+(.+)',
                r'using\s+(.+)\s+because\s+(.+)',
                r'switched\s+to\s+(.+)',
                r'(use|uses|using)\s+(\w+)\s+(instead of|over|rather than)\s+(.+)'
            ]
            
            for line in commit_messages.split('\n'):
                for pattern in decision_patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        decision = match.group(0).strip()
                        if len(decision) > 10 and decision not in decisions:
                            decisions.append(decision)
                            if len(decisions) >= 3:
                                return decisions
            
            return decisions
        
        except Exception:
            return []


def format_why_section(history: ComponentHistory) -> List[str]:
    """Format a component's history as markdown."""
    output = []
    
    output.append(f"### {history.component_name}")
    output.append(f"**File**: `{history.file_path}`")
    output.append("")
    output.append(f"**Why It Exists**: {history.why_it_exists}")
    output.append("")
    
    if history.authors:
        output.append(f"**Main Contributors**: {', '.join(history.authors)}")
        output.append("")
    
    if history.design_decisions:
        output.append("**Design Decisions**:")
        for decision in history.design_decisions:
            output.append(f"- {decision}")
        output.append("")
    
    if history.major_changes:
        output.append("**Evolution**:")
        for date, change in history.major_changes:
            output.append(f"- `{date}` - {change}")
        output.append("")
    
    return output
