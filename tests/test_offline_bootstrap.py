from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = ROOT / "requirements-offline-test.lock"
BOOTSTRAP = ROOT / "scripts" / "bootstrap_offline.ps1"
DOCS = ROOT / "docs" / "OFFLINE_REPRODUCIBILITY.md"
INVALID_HASH_FIXTURE = ROOT / "tests" / "fixtures" / "offline" / "invalid-hash.lock"
LOCK_ENTRY = re.compile(
    r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.!+]+ --hash=sha256:[0-9a-f]{64}"
)


def test_offline_lock_has_exact_versions_and_sha256_hashes():
    entries = [
        line
        for line in LOCK_FILE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]

    assert entries
    assert all(LOCK_ENTRY.fullmatch(entry) for entry in entries)


def test_offline_lock_contains_jsonschema_validation_closure():
    distribution_names = {
        entry.split("==", maxsplit=1)[0].lower().replace("_", "-").replace(".", "-")
        for entry in LOCK_FILE.read_text(encoding="utf-8").splitlines()
        if entry and not entry.startswith("#")
    }

    assert {
        "attrs",
        "jsonschema",
        "jsonschema-specifications",
        "referencing",
        "rpds-py",
        "typing-extensions",
    } <= distribution_names


def test_bootstrap_remains_fresh_and_hermetic():
    script = BOOTSTRAP.read_text(encoding="utf-8")

    assert '[string]$VenvDir = ".venv-offline"' in script
    assert "Offline bootstrap requires a fresh virtual environment" in script
    assert "Assert-Cpython312x64" in script
    assert "Assert-WheelhouseMatchesLock" in script
    assert '"$Role:' not in script
    for option in (
        "--isolated",
        "--no-index",
        "--require-hashes",
        "--only-binary=:all:",
        "--no-build-isolation",
        "--no-deps",
    ):
        assert option in script


def test_offline_bootstrap_docs_state_the_supply_chain_boundary():
    docs = DOCS.read_text(encoding="utf-8")

    for phrase in (
        "Windows CPython 3.12 x64",
        "must not exist",
        "PIP_*",
        "Third-party dependencies are installed only as locked wheels",
        "explicit editable BELIEF",
        "checkout, using its declared PEP 517 backend",
    ):
        assert phrase in docs


def test_invalid_hash_fixture_remains_a_valid_lock_entry():
    entry = INVALID_HASH_FIXTURE.read_text(encoding="utf-8").splitlines()[-1]

    assert LOCK_ENTRY.fullmatch(entry)
    assert entry.endswith("0" * 64)
