#!/usr/bin/env python3
"""Claude Code command hook entry point for BELIEF security feedback."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.claude_hooks import handle_claude_hook  # noqa: E402


def main() -> int:
    try:
        event = json.load(sys.stdin)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            decision = handle_claude_hook(
                event,
                max_stop_blocks=int(
                    os.environ.get("BELIEF_STOP_HOOK_MAX_BLOCKS", "1")
                ),
                state_dir=(
                    os.environ.get("BELIEF_HOOK_STATE_DIR") or None
                ),
                report_dir=(
                    os.environ.get("BELIEF_HOOK_REPORT_DIR") or None
                ),
            )
    except Exception as exc:
        decision = {
            "systemMessage": (
                "BELIEF hook failed open so the agent session can finish: "
                f"{type(exc).__name__}: {exc}"
            )
        }
    sys.stdout.write(json.dumps(decision, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
