"""Bounded oracle-free security feedback loop for coding agents.

The caller owns the agent session and supplies ``run_turn``. BELIEF reviews the
resulting Git worktree after each turn and, when needed, sends concise static
security feedback back into the same session. No benchmark labels, reference
patches, or hidden tests are exposed to the agent or reviewer.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .patch_review import collect_worktree_patch, review_candidate_patch


AGENT_SECURITY_LOOP_SCHEMA_VERSION = "belief.agent_security_loop.v1"

AgentTurn = Callable[[str, int], Mapping[str, Any]]
PatchReviewer = Callable[..., dict[str, Any]]


def run_agent_security_loop(
    workspace: str | Path,
    initial_prompt: str,
    run_turn: AgentTurn,
    *,
    max_review_rounds: int = 1,
    reviewer: PatchReviewer = review_candidate_patch,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Run one agent attempt with up to *max_review_rounds* repair turns."""

    root = Path(workspace).resolve()
    if not root.is_dir():
        raise ValueError(f"agent workspace is not a directory: {root}")
    if not str(initial_prompt).strip():
        raise ValueError("initial_prompt must not be empty")
    if not 0 <= max_review_rounds <= 3:
        raise ValueError("max_review_rounds must be between 0 and 3")

    started = clock()
    turns: list[dict[str, Any]] = []
    reviews: list[dict[str, Any]] = []
    prompt = str(initial_prompt)
    prior_patch_sha = ""
    stop_reason = "review_round_limit"

    for round_index in range(max_review_rounds + 1):
        raw_result = dict(run_turn(prompt, round_index) or {})
        turn = _normalize_turn(raw_result, round_index)
        turns.append(turn)

        patch = collect_worktree_patch(root)
        review = reviewer(root, patch)
        reviews.append(review)
        patch_sha = str(review.get("patch_sha256") or "")

        if review.get("status") == "passed":
            stop_reason = "security_review_passed"
            break
        if not turn["success"] and not patch.strip():
            stop_reason = "agent_error"
            break
        if round_index >= max_review_rounds:
            stop_reason = "review_round_limit"
            break
        if prior_patch_sha and patch_sha == prior_patch_sha:
            stop_reason = "no_patch_change"
            break

        prior_patch_sha = patch_sha
        prompt = _repair_prompt(str(review.get("feedback") or ""))

    final_patch = collect_worktree_patch(root)
    final_review = reviews[-1]
    completed = bool(
        stop_reason == "security_review_passed"
        and final_review.get("status") == "passed"
        and final_patch.strip()
    )
    payload: dict[str, Any] = {
        "schema_version": AGENT_SECURITY_LOOP_SCHEMA_VERSION,
        "mode": "oracle_free_belief_security_feedback",
        "workspace": str(root),
        "status": "completed" if completed else "needs_review",
        "stop_reason": stop_reason,
        "max_review_rounds": max_review_rounds,
        "turn_count": len(turns),
        "review_round_count": max(0, len(turns) - 1),
        "turns": turns,
        "reviews": reviews,
        "final_patch": final_patch,
        "final_patch_sha256": hashlib.sha256(
            final_patch.encode("utf-8")
        ).hexdigest(),
        "final_review_status": final_review.get("status", "unknown"),
        "comparability": {
            "single_agent_attempt": True,
            "benchmark_oracle_used": False,
            "security_tests_executed": False,
            "susvibes_secpass_equivalent": False,
        },
        "duration_seconds": round(
            max(0.0, float(clock() - started)),
            6,
        ),
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    return payload


def _normalize_turn(
    result: Mapping[str, Any],
    round_index: int,
) -> dict[str, Any]:
    return {
        "round": round_index,
        "kind": "initial" if round_index == 0 else "security_repair",
        "success": bool(result.get("success", False)),
        "return_code": int(result.get("return_code", 0) or 0),
        "execution_time": round(
            max(0.0, float(result.get("execution_time", 0.0) or 0.0)),
            6,
        ),
        "stdout": str(result.get("stdout", "") or ""),
        "stderr": str(result.get("stderr", "") or ""),
    }


def _repair_prompt(feedback: str) -> str:
    return f"""\
This is an oracle-free security review of your current candidate diff. It does
not contain benchmark labels, hidden tests, or a reference implementation.

{feedback.strip()}

Inspect your existing changes and relevant local source only. Do not inspect
Git history, search the web for an upstream patch, clone, fetch, or modify test
files. Repair the security boundary while preserving the requested behavior,
then run the relevant existing functional tests. Keep the final diff minimal.
"""


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key not in {
            "workspace",
            "duration_seconds",
            "deterministic_digest",
        }
    }
    semantic["turns"] = [
        {
            key: value
            for key, value in turn.items()
            if key not in {"execution_time", "stdout", "stderr"}
        }
        for turn in payload.get("turns", [])
    ]
    semantic["reviews"] = [
        {
            key: value
            for key, value in review.items()
            if key not in {
                "target",
                "duration_seconds",
                "deterministic_digest",
            }
        }
        for review in payload.get("reviews", [])
    ]
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "AGENT_SECURITY_LOOP_SCHEMA_VERSION",
    "AgentTurn",
    "PatchReviewer",
    "run_agent_security_loop",
]
