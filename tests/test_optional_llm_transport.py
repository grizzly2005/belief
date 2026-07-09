"""The static CLI remains importable without the optional LLM transport."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_core_imports_without_site_packages_or_httpx():
    code = f"""
import importlib.util
import sys

sys.path.insert(0, {str(ROOT)!r})
assert importlib.util.find_spec('httpx') is None

import belief
from belief.config import BeliefConfig
from belief.llm_client import LLMClient, LLMDependencyError

try:
    LLMClient(BeliefConfig.default())
except LLMDependencyError as exc:
    assert 'httpx' in str(exc)
else:
    raise AssertionError('LLMClient should require httpx when LLM features are requested')
"""
    result = subprocess.run(
        [sys.executable, "-S", "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
