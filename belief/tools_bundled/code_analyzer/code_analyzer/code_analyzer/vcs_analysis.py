"""VCS history analysis for code quality insights."""

import subprocess
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class FileChurn:
    """Represents churn metrics for a file."""
    file_path: str
    total_commits: int
    total_changes: int  # Lines added + deleted
    lines_added: int
    lines_deleted: int
    last_modified: datetime
    authors: Set[str] = field(default_factory=set)
    churn_score: float = 0.0  # Normalized churn metric
    
    def calculate_churn_score(self, max_changes: int):
        """Calculate normalized churn score."""
        if max_changes > 0:
            self.churn_score = self.total_changes / max_changes


@dataclass
class CommitInfo:
    """Information about a commit."""
    hash: str
    author: str
    date: datetime
    message: str
    files_changed: List[str]
    insertions: int
    deletions: int


@dataclass
class AuthorStats:
    """Statistics about an author."""
    name: str
    email: str
    total_commits: int
    total_lines_added: int
    total_lines_deleted: int
    files_touched: Set[str] = field(default_factory=set)
    first_commit: Optional[datetime] = None
    last_commit: Optional[datetime] = None


@dataclass
class VCSInsights:
    """VCS analysis results."""
    repo_path: str
    total_commits: int
    authors: Dict[str, AuthorStats]
    file_churn: Dict[str, FileChurn]
    hotspots: List[Tuple[str, float]]  # (file_path, hotspot_score)
    recent_activity: List[CommitInfo]
    commit_frequency: Dict[str, int]  # date -> count
    branch_name: str = "main"


class VCSAnalyzer:
    """Analyze version control history for insights."""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.is_git_repo = (repo_path / ".git").exists()
    
    def analyze(self, since_days: int = 90, include_branches: bool = False) -> Optional[VCSInsights]:
        """Analyze VCS history."""
        if not self.is_git_repo:
            return None
        
        since_date = datetime.now() - timedelta(days=since_days)
        
        # Get current branch
        branch = self._get_current_branch()
        
        # Analyze commits
        commits = self._get_commits(since_date)
        
        # Analyze file churn
        file_churn = self._analyze_file_churn(since_date)
        
        # Analyze authors
        authors = self._analyze_authors(commits)
        
        # Calculate commit frequency
        commit_freq = self._calculate_commit_frequency(commits)
        
        # Identify hotspots (high churn files)
        hotspots = self._identify_hotspots(file_churn)
        
        # Get recent activity
        recent = commits[:20] if commits else []
        
        return VCSInsights(
            repo_path=str(self.repo_path),
            total_commits=len(commits),
            authors=authors,
            file_churn=file_churn,
            hotspots=hotspots,
            recent_activity=recent,
            commit_frequency=commit_freq,
            branch_name=branch
        )
    
    def _get_current_branch(self) -> str:
        """Get current git branch name."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"
    
    def _get_commits(self, since_date: datetime) -> List[CommitInfo]:
        """Get commits since date."""
        try:
            # Format: hash|author|date|message
            result = subprocess.run(
                [
                    "git", "log",
                    f"--since={since_date.strftime('%Y-%m-%d')}",
                    "--pretty=format:%H|%an|%ai|%s",
                    "--numstat"
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return []
            
            commits = []
            lines = result.stdout.split('\n')
            i = 0
            
            while i < len(lines):
                line = lines[i].strip()
                if not line:
                    i += 1
                    continue
                
                if '|' in line:
                    parts = line.split('|', 3)
                    if len(parts) == 4:
                        commit_hash, author, date_str, message = parts
                        
                        # Parse date
                        try:
                            date = datetime.fromisoformat(date_str.replace(' ', 'T').split('+')[0].split('-')[0])
                        except Exception:
                            date = datetime.now()
                        
                        # Collect file changes
                        files_changed = []
                        insertions = 0
                        deletions = 0
                        i += 1
                        
                        while i < len(lines) and lines[i].strip() and '|' not in lines[i]:
                            stat_line = lines[i].strip()
                            if stat_line:
                                parts = stat_line.split('\t')
                                if len(parts) == 3:
                                    added, deleted, filepath = parts
                                    files_changed.append(filepath)
                                    try:
                                        insertions += int(added) if added != '-' else 0
                                        deletions += int(deleted) if deleted != '-' else 0
                                    except ValueError:
                                        pass
                            i += 1
                        
                        commits.append(CommitInfo(
                            hash=commit_hash,
                            author=author,
                            date=date,
                            message=message,
                            files_changed=files_changed,
                            insertions=insertions,
                            deletions=deletions
                        ))
                        continue
                
                i += 1
            
            return commits
        except Exception as e:
            print(f"Error getting commits: {e}")
            return []
    
    def _analyze_file_churn(self, since_date: datetime) -> Dict[str, FileChurn]:
        """Analyze file change frequency."""
        churn_data = {}
        
        try:
            # Get file change stats
            result = subprocess.run(
                [
                    "git", "log",
                    f"--since={since_date.strftime('%Y-%m-%d')}",
                    "--pretty=format:%H|%an|%ai",
                    "--numstat"
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return churn_data
            
            current_commit = None
            current_author = None
            current_date = None
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) == 3:
                        current_commit = parts[0]
                        current_author = parts[1]
                        try:
                            current_date = datetime.fromisoformat(parts[2].replace(' ', 'T').split('+')[0].split('-')[0])
                        except Exception:
                            current_date = datetime.now()
                else:
                    # File stat line
                    parts = line.split('\t')
                    if len(parts) == 3:
                        added, deleted, filepath = parts
                        
                        # Only track Python files
                        if not filepath.endswith('.py'):
                            continue
                        
                        if filepath not in churn_data:
                            churn_data[filepath] = FileChurn(
                                file_path=filepath,
                                total_commits=0,
                                total_changes=0,
                                lines_added=0,
                                lines_deleted=0,
                                last_modified=current_date or datetime.now(),
                                authors=set()
                            )
                        
                        churn = churn_data[filepath]
                        churn.total_commits += 1
                        
                        try:
                            added_int = int(added) if added != '-' else 0
                            deleted_int = int(deleted) if deleted != '-' else 0
                            churn.lines_added += added_int
                            churn.lines_deleted += deleted_int
                            churn.total_changes += added_int + deleted_int
                        except ValueError:
                            pass
                        
                        if current_author:
                            churn.authors.add(current_author)
                        
                        if current_date and current_date > churn.last_modified:
                            churn.last_modified = current_date
            
            # Calculate churn scores
            max_changes = max((c.total_changes for c in churn_data.values()), default=1)
            for churn in churn_data.values():
                churn.calculate_churn_score(max_changes)
            
        except Exception as e:
            print(f"Error analyzing file churn: {e}")
        
        return churn_data
    
    def _analyze_authors(self, commits: List[CommitInfo]) -> Dict[str, AuthorStats]:
        """Analyze author contributions."""
        authors: Dict[str, AuthorStats] = {}
        
        for commit in commits:
            if commit.author not in authors:
                authors[commit.author] = AuthorStats(
                    name=commit.author,
                    email="",  # Would need separate git command
                    total_commits=0,
                    total_lines_added=0,
                    total_lines_deleted=0
                )
            
            author = authors[commit.author]
            author.total_commits += 1
            author.total_lines_added += commit.insertions
            author.total_lines_deleted += commit.deletions
            author.files_touched.update(commit.files_changed)
            
            if author.first_commit is None or commit.date < author.first_commit:
                author.first_commit = commit.date
            if author.last_commit is None or commit.date > author.last_commit:
                author.last_commit = commit.date
        
        return authors
    
    def _calculate_commit_frequency(self, commits: List[CommitInfo]) -> Dict[str, int]:
        """Calculate commits per day."""
        frequency = defaultdict(int)
        
        for commit in commits:
            date_key = commit.date.strftime('%Y-%m-%d')
            frequency[date_key] += 1
        
        return dict(frequency)
    
    def _identify_hotspots(self, file_churn: Dict[str, FileChurn], top_n: int = 20) -> List[Tuple[str, float]]:
        """Identify files with highest churn (maintenance hotspots)."""
        # Sort by churn score
        sorted_files = sorted(
            file_churn.items(),
            key=lambda x: (x[1].churn_score, x[1].total_commits),
            reverse=True
        )
        
        hotspots = [(path, churn.churn_score) for path, churn in sorted_files[:top_n]]
        return hotspots
    
    def get_file_authors(self, file_path: str) -> List[Tuple[str, int]]:
        """Get authors who modified a file and their contribution."""
        try:
            result = subprocess.run(
                ["git", "log", "--follow", "--pretty=format:%an", file_path],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                authors = defaultdict(int)
                for author in result.stdout.split('\n'):
                    if author:
                        authors[author] += 1
                
                return sorted(authors.items(), key=lambda x: x[1], reverse=True)
        except Exception:
            pass
        
        return []
    
    def get_recent_changes(self, file_path: str, n: int = 5) -> List[CommitInfo]:
        """Get recent commits affecting a file."""
        try:
            result = subprocess.run(
                [
                    "git", "log",
                    f"-n{n}",
                    "--pretty=format:%H|%an|%ai|%s",
                    "--", file_path
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                commits = []
                for line in result.stdout.split('\n'):
                    if line and '|' in line:
                        parts = line.split('|', 3)
                        if len(parts) == 4:
                            commit_hash, author, date_str, message = parts
                            try:
                                date = datetime.fromisoformat(date_str.replace(' ', 'T').split('+')[0].split('-')[0])
                            except Exception:
                                date = datetime.now()
                            
                            commits.append(CommitInfo(
                                hash=commit_hash,
                                author=author,
                                date=date,
                                message=message,
                                files_changed=[file_path],
                                insertions=0,
                                deletions=0
                            ))
                return commits
        except Exception:
            pass
        
        return []
