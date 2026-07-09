"""
belief/cognitive/drift_detector.py — historical drift detection via git.

Phase 6 of the audit roadmap: detects when a belief's surrounding code
has changed across commits, signaling that previously-valid invariants
may no longer hold.

No pydriller dependency — uses subprocess + `git log --follow` + `git blame`
so BELIEF stays install-free on Kali/WSL. If the user later installs
pydriller for richer parsing, we can swap backends without breaking the API.

Two flavors of drift:
  - PREDICATE_VIOLATED: the line(s) the belief anchors to have been
                        modified recently (≥ 1 commit since belief extraction)
  - SCOPE_EXPANDED:     the enclosing function has grown or been renamed

Usage:
    det = GitDriftDetector(project_path="/path/to/repo")
    drift = det.check_belief(belief, since_days=90)
    if drift:
        print(f"Belief {belief.id} drifted: {drift.drift_type}")
"""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("belief.cognitive.drift_detector")


# ─────────────────────────────────────────────────────────────────

@dataclass
class DriftSignal:
    belief_id: str
    drift_type: str  # "predicate_violated" | "scope_expanded" | "none"
    last_commit: str = ""
    last_commit_date: str = ""
    last_author: str = ""
    lines_changed: List[int] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "belief_id": self.belief_id,
            "drift_type": self.drift_type,
            "last_commit": self.last_commit,
            "last_commit_date": self.last_commit_date,
            "last_author": self.last_author,
            "lines_changed": self.lines_changed,
            "explanation": self.explanation,
        }


# ─────────────────────────────────────────────────────────────────

class GitDriftDetector:
    """Subprocess-based git-log / git-blame analyzer."""

    def __init__(self, project_path: str, git_timeout_s: int = 10):
        self.project_path = Path(project_path).resolve()
        self.timeout = git_timeout_s
        self._is_repo = self._check_repo()

    def _git(self, *args: str) -> Optional[str]:
        """Run a git subcommand under self.project_path. Returns stdout
        or None on error/timeout. Never raises."""
        if not self._is_repo:
            return None
        cmd = ["git", "-C", str(self.project_path), *args]
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, timeout=self.timeout,
            )
            return out.decode("utf-8", errors="replace")
        except (subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                FileNotFoundError):
            return None

    def _check_repo(self) -> bool:
        """Is this directory inside a git repo?"""
        try:
            out = subprocess.check_output(
                ["git", "-C", str(self.project_path), "rev-parse", "--is-inside-work-tree"],
                stderr=subprocess.DEVNULL, timeout=self.timeout,
            )
            return out.decode().strip() == "true"
        except Exception:
            return False

    # ── public API ──────────────────────────────────────────────

    def check_belief(self, belief, since_days: int = 90) -> Optional[DriftSignal]:
        """Check if a belief has drifted in the last `since_days` days.

        Returns None if no drift detected, else a DriftSignal with type.
        """
        if not self._is_repo:
            return None

        file_path = belief.scope.file_path
        if not file_path:
            return None

        # Make the path relative to repo root if needed
        rel = self._relative(file_path)
        if rel is None:
            return None

        since = (datetime.now(timezone.utc)
                 - timedelta(days=since_days)).strftime("%Y-%m-%d")

        # 1) Has the file been touched?
        log = self._git(
            "log", f"--since={since}", "--format=%H|%ai|%an", "--", rel
        )
        if not log or not log.strip():
            return None  # file untouched in window

        recent_commits = [l for l in log.strip().split("\n") if l]
        first = recent_commits[0]  # most recent
        try:
            sha, date, author = first.split("|", 2)
        except ValueError:
            sha, date, author = first, "", ""

        # 2) Precision check: did the belief's line range change?
        ls = belief.scope.line_start
        le = belief.scope.line_end or ls
        lines_changed: List[int] = []
        if ls:
            lines_changed = self._lines_changed_since(rel, ls, le or ls, since)

        if lines_changed:
            return DriftSignal(
                belief_id=belief.id,
                drift_type="predicate_violated",
                last_commit=sha,
                last_commit_date=date,
                last_author=author,
                lines_changed=lines_changed,
                explanation=(
                    f"{len(lines_changed)} line(s) in belief scope "
                    f"{rel}:{ls}-{le} modified since {since} "
                    f"(last commit {sha[:8]})"
                ),
            )

        # 3) Coarser check: function size changed?
        if belief.scope.function_name:
            expanded = self._function_expanded(
                rel, belief.scope.function_name, since
            )
            if expanded:
                return DriftSignal(
                    belief_id=belief.id,
                    drift_type="scope_expanded",
                    last_commit=sha,
                    last_commit_date=date,
                    last_author=author,
                    explanation=(
                        f"Function {belief.scope.function_name} in {rel} "
                        f"was modified since {since} (last commit {sha[:8]}). "
                        f"Invariants may have changed."
                    ),
                )

        return None

    def check_beliefs(self, beliefs: list, since_days: int = 90) -> List[DriftSignal]:
        """Batch variant. Skips beliefs in files we can't find."""
        out: List[DriftSignal] = []
        for b in beliefs:
            try:
                sig = self.check_belief(b, since_days=since_days)
                if sig:
                    out.append(sig)
            except Exception as e:
                logger.debug(f"Drift check failed for {b.id}: {e}")
        return out

    def introducing_commit(self, file_path: str, line: int) -> Optional[Dict[str, str]]:
        """Who introduced this line? Uses git blame -L.
        Returns {'sha', 'author', 'date'} or None."""
        if not self._is_repo:
            return None
        rel = self._relative(file_path)
        if rel is None:
            return None
        out = self._git(
            "blame", "-L", f"{line},{line}", "--porcelain", "--", rel
        )
        if not out:
            return None
        lines = out.split("\n")
        if not lines:
            return None
        header = lines[0].split(" ", 1)
        sha = header[0] if header else ""
        author = ""
        date = ""
        for l in lines[1:]:
            if l.startswith("author "):
                author = l[len("author "):].strip()
            elif l.startswith("author-time "):
                try:
                    ts = int(l[len("author-time "):].strip())
                    date = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                except Exception:
                    pass
            elif l.startswith("\t"):
                break
        return {"sha": sha, "author": author, "date": date}

    # ── internals ──────────────────────────────────────────────

    def _relative(self, file_path: str) -> Optional[str]:
        """Express file_path relative to repo root, or None if outside."""
        p = Path(file_path)
        if not p.is_absolute():
            # Assume relative to project_path
            candidate = self.project_path / p
            if candidate.exists():
                return str(p)
            return None
        try:
            return str(p.resolve().relative_to(self.project_path))
        except ValueError:
            return None

    def _lines_changed_since(self, rel_path: str, line_start: int,
                             line_end: int, since: str) -> List[int]:
        """Return which lines in [line_start, line_end] were modified
        since `since` date. Uses git log -L."""
        if line_start <= 0:
            return []
        # -L :<file>,<s>,<e> isn't quite right; -L <s>,<e>:<file> is.
        spec = f"{line_start},{line_end}:{rel_path}"
        out = self._git("log", f"--since={since}", "-L", spec,
                        "--format=%H", "-s")
        if not out or not out.strip():
            return []
        # We don't have exact line diffs here (would need `--no-abbrev` parsing);
        # having SOME commit that touched this range is enough to flag drift.
        return list(range(line_start, min(line_end, line_start + 50) + 1))

    def _function_expanded(self, rel_path: str, function_name: str,
                           since: str) -> bool:
        """Heuristic: did any commit since `since` touch this function?
        Uses `-L :<fn>:<file>`."""
        if not function_name:
            return False
        spec = f":{function_name}:{rel_path}"
        out = self._git("log", f"--since={since}", "-L", spec,
                        "--format=%H", "-s")
        return bool(out and out.strip())


__all__ = ["GitDriftDetector", "DriftSignal"]
