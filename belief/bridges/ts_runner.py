"""
ts_runner — execute TypeScript modules from Python, without translating them.

Why: the Claude Code codebase (src/*) contains TypeScript patterns we want
reuse verbatim — token counting, retry logic, MCP client, AgentTool
spawning. Translating them to Python is lossy and slow. Instead, we run
them with Node + tsx and talk JSON over stdio.

Approach:
1. Each TypeScript "capability" exposes a default export: an async
   function that takes a JSON payload and returns JSON.
2. This Python bridge spawns `npx tsx <capability>.ts` and communicates
   line-delimited JSON on stdin/stdout.
3. Result is handed back as a Python dict.

Requirements on the system:
- Node.js 18+
- `npx` available
- `tsx` package (or the user installs it in the project's node_modules)

Gracefully returns a BridgeResult with an error if node/tsx are missing,
so the rest of BELIEF still works.

Security note: we do NOT copy Claude Code source verbatim. The user
provides TypeScript files (either their own, or open-source ports).
This bridge is a PATTERN, not a bundler.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from . import BridgeResult

logger = logging.getLogger("belief.bridges.ts")


def has_node() -> bool:
    return shutil.which("node") is not None and shutil.which("npx") is not None


def run_typescript(
    *,
    script_path: str,
    payload: Optional[Dict[str, Any]] = None,
    cwd: Optional[str] = None,
    timeout_s: int = 60,
) -> BridgeResult:
    """Run a TypeScript file via tsx, passing JSON payload on stdin.
    The script must write a single JSON object to stdout as its result."""
    t0 = time.time()
    result = BridgeResult(source="ts_runner")

    if not has_node():
        result.errors.append(
            "Node.js not installed. `apt install nodejs npm` (and `npx tsx` "
            "in your project) to enable TS interop."
        )
        result.elapsed_s = time.time() - t0
        return result

    script = Path(script_path)
    if not script.exists():
        result.errors.append(f"TS script not found: {script_path}")
        result.elapsed_s = time.time() - t0
        return result

    cmd = ["npx", "--yes", "tsx", str(script)]
    payload_bytes = (json.dumps(payload or {}) + "\n").encode("utf-8")

    try:
        proc = subprocess.run(
            cmd,
            input=payload_bytes,
            capture_output=True,
            timeout=timeout_s,
            cwd=cwd or str(script.parent),
            env={**os.environ, "NODE_NO_WARNINGS": "1"},
        )
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            result.errors.append(
                f"tsx exited {proc.returncode}. stderr={proc.stderr.decode('utf-8', errors='replace')[:500]}"
            )
        # Use LAST JSON line (tsx logs to stderr usually, but if stdout is chatty,
        # the last newline-delimited JSON is the result)
        if out:
            lines = out.splitlines()
            parsed = None
            for line in reversed(lines):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        parsed = json.loads(line)
                        break
                    except json.JSONDecodeError:
                        continue
            if parsed is not None:
                result.findings = [parsed]
            else:
                result.errors.append(f"No JSON line in TS stdout. Raw: {out[:300]}")
    except subprocess.TimeoutExpired:
        result.errors.append(f"TS script timed out after {timeout_s}s")
    except Exception as e:
        result.errors.append(f"TS runner failed: {type(e).__name__}: {e}")

    result.elapsed_s = time.time() - t0
    return result


def count_tokens_precise(
    *,
    messages: list,
    model: str = "claude-sonnet-4-5",
    api_key: Optional[str] = None,
) -> int:
    """Port of src/services/tokenEstimation.ts: call Anthropic's count_tokens API
    for precise counts. Falls back to len/3 heuristic if:
    - No network
    - No ANTHROPIC_API_KEY
    - API error

    This replaces belief.llm_client.estimate_tokens where accuracy matters
    (i.e. when deciding whether to skip or chunk a prompt)."""
    # Heuristic baseline: ~3.5 chars per token for English code
    def _heuristic(msgs):
        total_chars = 0
        for m in msgs:
            content = m.get("content", m) if isinstance(m, dict) else m
            if isinstance(content, str):
                total_chars += len(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        total_chars += len(str(block.get("text", "")))
        return max(1, total_chars // 3)

    api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _heuristic(messages)

    try:
        import httpx
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages/count_tokens",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": model, "messages": messages},
            timeout=10.0,
        )
        if resp.status_code == 200:
            return int(resp.json().get("input_tokens", _heuristic(messages)))
    except Exception as e:
        logger.debug(f"count_tokens API failed: {e}")
    return _heuristic(messages)


def register(registry) -> None:
    registry.register("ts_runner", run_typescript)
