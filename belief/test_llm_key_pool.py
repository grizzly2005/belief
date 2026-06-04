"""
Quick sanity-check for the Groq key rotation pool.

Auto-loads .env from the project root if python-dotenv is installed.

Run with:
    python3 -m belief.test_llm_key_pool

Does NOT make any API call — it only tests the local pool logic.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _autoload_dotenv() -> str:
    """Try to load .env from project root. Returns a status string."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return "python-dotenv not installed (pip install python-dotenv)"

    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        env = parent / ".env"
        if env.is_file():
            load_dotenv(env, override=False)
            return f"loaded {env}"
    return "no .env found in parent directories"


def main() -> None:
    status = _autoload_dotenv()
    print(f"[env] {status}")

    visible = []
    for name in ["GROQ_API_KEY"] + [f"GROQ_API_KEY_{i}" for i in range(2, 11)]:
        v = os.getenv(name)
        if v:
            visible.append(f"{name}={v[:6]}...{v[-4:]}")
    if not visible:
        print("[FAIL] No GROQ_API_KEY* variables visible in os.environ.")
        print("       Either your .env is not being loaded, or the key names")
        print("       in .env don't match (expected: GROQ_API_KEY, "
              "GROQ_API_KEY_2, ...).")
        print("       Quick bypass: "
              "export $(grep -v '^#' .env | grep -v '^$' | xargs)")
        sys.exit(1)
    print(f"[env] visible vars: {', '.join(visible)}")

    from belief.llm_key_pool import GroqKeyPool, _mask, classify_error

    try:
        pool = GroqKeyPool()
    except RuntimeError as e:
        print(f"[FAIL] {e}")
        sys.exit(1)

    print(f"\n[OK] Discovered {pool.size()} key(s)")
    for row in pool.status():
        print(f"      {row}")

    print("\n[Test 1] round-robin rotation (6 gets):")
    for i in range(6):
        k = pool.get()
        print(f"  get #{i + 1} -> {_mask(k)}")

    if pool.size() >= 2:
        print("\n[Test 2] penalizing 2nd key for 30s and re-cycling:")
        second = pool.keys[1]
        pool.penalize(second, seconds=30)
        hits = {_mask(k): 0 for k in pool.keys}
        for _ in range(pool.size() * 3):
            k = pool.get()
            hits[_mask(k)] += 1
        print("  hits:", hits)
        assert hits[_mask(second)] == 0, "Penalized key should be skipped"
        print("  [OK] penalized key correctly skipped")

    print("\n[Test 3] all keys in cooldown -> should still return something:")
    for k in pool.keys:
        pool.penalize(k, seconds=5)
    k = pool.get()
    idx = pool.keys.index(k)
    remaining = pool.status()[idx]['cooldown_remaining_s']
    print(f"  get -> {_mask(k)} (cooldown remaining: {remaining}s)")
    assert k is not None

    print("\n[Test 4] classify_error smoke test:")

    class _Err(Exception):
        def __init__(self, msg, status=None):
            super().__init__(msg)
            self.status_code = status

    samples = [
        _Err("Rate limit exceeded for model", 429),
        _Err("Invalid API key", 401),
        _Err("Internal server error", 500),
        _Err("Connection timeout"),
        _Err("Unexpected payload"),
    ]
    for e in samples:
        print(f"  {e!r:55s} -> {classify_error(e)}")

    print("\n[All tests passed]")


if __name__ == "__main__":
    main()
