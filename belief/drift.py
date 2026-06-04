"""
BELIEF — Temporal drift detector.

Analyzes git history to find beliefs whose scope has changed without
revalidation of justification. Detects both passive drift (context changed,
code unchanged) and active drift (code changed, contracts not updated).

Pure CPU, no LLM needed.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .models import Belief, DriftEvent, DriftType

logger = logging.getLogger("belief.drift")


@dataclass
class GitCommit:
    """A parsed git commit."""

    hash: str
    author: str
    date: str
    message: str
    files_changed: list[str]
    additions: int = 0
    deletions: int = 0


class DriftDetector:
    """
    Detect temporal belief drift by analyzing git history.

    Passive drift: a function's callers changed but the function didn't.
    Active drift: a function changed but its callers' assumptions didn't.
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        if not (self.repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {repo_path}")

    def detect_passive_drift(
        self,
        beliefs: list[Belief],
        lookback_commits: int = 200,
    ) -> list[DriftEvent]:
        """
        Find beliefs whose scope expanded without revalidation.

        Passive drift: the function itself didn't change, but new callers
        appeared or the call context changed.
        """
        events = []
        commits = self._get_recent_commits(lookback_commits)

        # Group beliefs by file
        beliefs_by_file: dict[str, list[Belief]] = {}
        for b in beliefs:
            beliefs_by_file.setdefault(b.scope.file_path, []).append(b)

        for commit in commits:
            for changed_file in commit.files_changed:
                # Check if any belief's callers are in the changed file
                # but the belief's own file was NOT changed
                for file_path, file_beliefs in beliefs_by_file.items():
                    if file_path == changed_file:
                        continue  # Skip files that changed themselves

                    for belief in file_beliefs:
                        # Check if the changed file might contain callers
                        if self._file_references_function(
                            changed_file,
                            belief.scope.function_name or "",
                            commit.hash,
                        ):
                            event = DriftEvent(
                                belief=belief,
                                drift_type=DriftType.PASSIVE,
                                commit_hash=commit.hash,
                                commit_message=commit.message,
                                commit_date=commit.date,
                                old_scope_description=(
                                    f"Before {commit.hash[:8]}: "
                                    f"function {belief.scope.function_name} "
                                    f"had established call context"
                                ),
                                new_scope_description=(
                                    f"After {commit.hash[:8]}: "
                                    f"{changed_file} was modified and may "
                                    f"have added/changed a call to "
                                    f"{belief.scope.function_name}"
                                ),
                                risk_assessment=(
                                    f"Belief '{belief.predicate.expression}' "
                                    f"({belief.justification.value}) may no longer "
                                    f"hold in the new call context"
                                ),
                            )
                            events.append(event)

        return events

    def detect_active_drift(
        self,
        beliefs: list[Belief],
        lookback_commits: int = 200,
    ) -> list[DriftEvent]:
        """
        Find beliefs whose code changed but callers' assumptions didn't.

        Active drift: the function was refactored/modified but its callers
        still assume the old behavior.
        """
        events = []
        commits = self._get_recent_commits(lookback_commits)

        beliefs_by_file: dict[str, list[Belief]] = {}
        for b in beliefs:
            beliefs_by_file.setdefault(b.scope.file_path, []).append(b)

        for commit in commits:
            for changed_file in commit.files_changed:
                if changed_file not in beliefs_by_file:
                    continue

                # The file containing beliefs changed
                # Check if the change is significant (not just whitespace/comments)
                if not self._is_significant_change(changed_file, commit.hash):
                    continue

                for belief in beliefs_by_file[changed_file]:
                    # Check if the specific function was modified
                    if belief.scope.function_name and self._function_changed(
                        changed_file,
                        belief.scope.function_name,
                        commit.hash,
                    ):
                        event = DriftEvent(
                            belief=belief,
                            drift_type=DriftType.ACTIVE,
                            commit_hash=commit.hash,
                            commit_message=commit.message,
                            commit_date=commit.date,
                            old_scope_description=(
                                f"Function {belief.scope.function_name} "
                                f"was modified in {commit.hash[:8]}"
                            ),
                            new_scope_description=(
                                f"Callers of {belief.scope.function_name} "
                                f"may still assume the old contract"
                            ),
                            risk_assessment=(
                                f"Belief '{belief.predicate.expression}' "
                                f"may have changed meaning after refactoring. "
                                f"Commit message: '{commit.message}'"
                            ),
                        )
                        events.append(event)

        return events

    def find_security_fixes(self, lookback_commits: int = 500) -> list[GitCommit]:
        """
        Find commits that look like silent security fixes (no CVE assigned).
        These are useful for retrospective evaluation.
        """
        commits = self._get_recent_commits(lookback_commits)
        security_keywords = [
            "fix", "security", "overflow", "sanitize", "validate",
            "escape", "inject", "xss", "csrf", "auth", "permission",
            "bounds", "check", "null", "crash", "vuln", "exploit",
            "patch", "safe", "unsafe", "trust", "untrust",
        ]

        results = []
        for c in commits:
            msg_lower = c.message.lower()
            if any(kw in msg_lower for kw in security_keywords):
                results.append(c)

        return results

    # ── Git operations ──

    def _get_recent_commits(self, n: int) -> list[GitCommit]:
        n = min(n, 1000)  # Cap to prevent OOM on huge repos
        try:
            result = subprocess.run(
                [
                    "git", "log", f"-{n}",
                    "--pretty=format:%H|%an|%aI|%s",
                    "--name-only",
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        if result.returncode != 0:
            return []

        commits = []
        current_commit = None

        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line:
                if current_commit:
                    commits.append(current_commit)
                    current_commit = None
                continue

            if "|" in line and len(line.split("|")) >= 4:
                parts = line.split("|", 3)
                current_commit = GitCommit(
                    hash=parts[0],
                    author=parts[1],
                    date=parts[2],
                    message=parts[3],
                    files_changed=[],
                )
            elif current_commit:
                current_commit.files_changed.append(line)

        if current_commit:
            commits.append(current_commit)

        return commits

    def _file_references_function(
        self, file_path: str, function_name: str, commit_hash: str
    ) -> bool:
        """Check if a file references a function name at a specific commit."""
        if not function_name:
            return False
        try:
            result = subprocess.run(
                ["git", "show", f"{commit_hash}:{file_path}"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return function_name in result.stdout
        except Exception:
            return False

    def _is_significant_change(self, file_path: str, commit_hash: str) -> bool:
        """Check if a change is significant (not just whitespace/comments)."""
        try:
            result = subprocess.run(
                ["git", "diff", f"{commit_hash}~1", commit_hash, "--", file_path],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            diff = result.stdout
            # Count non-whitespace, non-comment changes
            significant_lines = 0
            for line in diff.split("\n"):
                if line.startswith("+") or line.startswith("-"):
                    stripped = line[1:].strip()
                    if stripped and not stripped.startswith("#") and not stripped.startswith("//"):
                        significant_lines += 1
            return significant_lines > 2
        except Exception:
            return False

    def _function_changed(
        self, file_path: str, function_name: str, commit_hash: str
    ) -> bool:
        """Check if a specific function was modified in a commit."""
        try:
            result = subprocess.run(
                [
                    "git", "diff", f"{commit_hash}~1", commit_hash,
                    "--", file_path,
                ],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return function_name in result.stdout
        except Exception:
            return False
