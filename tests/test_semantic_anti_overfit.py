"""Reject benchmark-specific shortcuts in production semantic primitives."""

from __future__ import annotations

import re
from pathlib import Path

import pytest


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
SEMANTIC_ROOT = ROOT / "belief" / "semantic"

FORBIDDEN_LITERALS = {
    "canary",
    "golden_patch",
    "holdout",
    "instance_id",
    "mask_patch",
    "security_patch",
    "susvibes",
    "task_patch",
    "belief-rd",
    "rdiffweb",
    "tensorflow",
    "vyperlang",
}


def test_semantic_primitives_have_no_benchmark_special_cases():
    violations = []
    sha_pattern = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
    cve_pattern = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)

    for path in sorted(SEMANTIC_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8").lower()
        for token in sorted(FORBIDDEN_LITERALS):
            if token.lower() in source:
                violations.append(f"{path.name}: literal {token}")
        if sha_pattern.search(source):
            violations.append(f"{path.name}: commit-shaped literal")
        if cve_pattern.search(source):
            violations.append(f"{path.name}: CVE-shaped literal")
        if re.search(r"[a-z]:[\\/].*(?:results|belief-rd)", source):
            violations.append(f"{path.name}: local result path")

    assert not violations, "\n".join(violations)
