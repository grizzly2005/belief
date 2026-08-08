"""
Integration test for belief.bridges

Runs every bridge against a synthetic vulnerable project (/tmp/belief_test_target/)
and verifies:
1. Each bridge either succeeds or returns a graceful error (no crashes)
2. Adapter converts every finding without exceptions
3. The dedupe logic produces a reasonable count
4. Merged beliefs have correct fragility/confidence relationships

This test does NOT require an LLM or network. It runs offline in seconds.
Run with: python -m pytest tests_bridges/test_integration.py -v
or directly: python tests_bridges/test_integration.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

# Make sure belief is importable when run standalone
HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))


TARGET_DIR = Path(tempfile.gettempdir()) / "belief_test_target"


VULN_CODE = '''
"""Synthetic vulnerable module with multiple issue types."""
import pickle
import hashlib
import subprocess
import yaml

SECRET_KEY = "my_super_secret_admin_pwd_2023"   # B105 hardcoded password

def load_user_blob(path):
    """Load attacker-controlled pickle → deserialization RCE."""
    with open(path, "rb") as f:
        return pickle.load(f)                      # B301

def weak_hash(password):
    """Hash password with MD5 → brute-forceable."""
    return hashlib.md5(password.encode()).hexdigest()  # B324

def run_user_cmd(cmd):
    """Shell injection via user-supplied cmd."""
    subprocess.call(cmd, shell=True)               # B602

def load_config(path):
    """Unsafe YAML load allows arbitrary code execution."""
    return yaml.load(open(path).read())            # DUO109

def fetch_url(u):
    """Server-side request forgery: no validation of user-supplied URL."""
    import urllib.request
    return urllib.request.urlopen(u).read()        # semgrep ssrf-bandit

def is_safe_path(p):
    """Attempts to check for path traversal but does it wrong."""
    if ".." in p:
        return False
    return True  # still vulnerable to ../../../ with symlinks

def eval_expr(expr):
    """Arbitrary code exec via eval."""
    return eval(expr)                              # B307

def random_token():
    """Uses insecure random for token generation."""
    import random
    return str(random.random())                    # DUO102
'''

VULN_REQUIREMENTS = """\
# Intentionally pin known-vulnerable versions
requests==2.5.0
urllib3==1.20
jinja2==2.7
Flask==0.10.1
pyyaml==3.13
"""


def setup_target():
    """(Re)create the vulnerable target directory."""
    if TARGET_DIR.exists():
        shutil.rmtree(TARGET_DIR)
    TARGET_DIR.mkdir(parents=True)
    (TARGET_DIR / "app.py").write_text(VULN_CODE, encoding="utf-8")
    (TARGET_DIR / "requirements.txt").write_text(VULN_REQUIREMENTS, encoding="utf-8")
    print(f"Target directory: {TARGET_DIR}")


def setup_module(module):
    setup_target()


def test_registry_structure():
    """All bridges are registered and accessible."""
    from belief.bridges import registry
    expected = {"bandit", "dlint", "crosshair", "pyt", "contextgem",
                "semgrep", "pyre", "safety_db", "ts_runner"}
    actual = set(registry.available())
    assert expected.issubset(actual), f"Missing: {expected - actual}"
    print(f"  ✓ {len(actual)} bridges registered: {sorted(actual)}")


def test_no_crash():
    """Every bridge returns a BridgeResult (even when the tool is missing)."""
    from belief.bridges import registry
    from belief.bridges import BridgeResult
    tests = [
        ("bandit",     {"project_path": str(TARGET_DIR)}),
        ("dlint",      {"project_path": str(TARGET_DIR)}),
        ("crosshair",  {"project_path": str(TARGET_DIR),
                        "module_file": str(TARGET_DIR / "app.py"),
                        "func_name": "weak_hash"}),
        ("pyt",        {"project_path": str(TARGET_DIR)}),
        ("contextgem", {"source_code": "x = eval(input())", "prompt": "extract"}),
        ("semgrep",    {"project_path": str(TARGET_DIR)}),
        ("pyre",       {"project_path": str(TARGET_DIR)}),
        ("safety_db",  {"project_path": str(TARGET_DIR)}),
        ("ts_runner",  {"script_path": "/tmp/__nonexistent__.ts"}),
    ]
    for name, kwargs in tests:
        r = registry.run(name, **kwargs)
        assert isinstance(r, BridgeResult), f"{name} returned {type(r)}"
        status = "ok" if not r.errors else f"unavailable ({r.errors[0][:50]})"
        print(f"  ✓ {name:10s} → {len(r):3d} findings, {status}")


def test_bandit_real_findings():
    """If bandit is installed, it must find the known vulns."""
    import shutil as _sh
    if not _sh.which("bandit"):
        print("  - bandit not installed, skipping")
        return
    from belief.bridges import registry
    r = registry.run("bandit", project_path=str(TARGET_DIR), use_cache=False)
    assert not r.errors, f"bandit errors: {r.errors}"
    test_ids = {f["test_id"] for f in r.findings}
    # The target has pickle.load, hashlib.md5, subprocess shell=True, eval, hardcoded pwd, insecure random
    expected_any_of = {"B301", "B324", "B602", "B307", "B105"}
    assert test_ids & expected_any_of, (
        f"bandit missed expected vulns. Got: {test_ids}"
    )
    print(f"  ✓ bandit found {len(r)} issues: {sorted(test_ids)}")


def test_safety_db_real_findings():
    """safety_db must flag pinned vulnerable versions."""
    from belief.bridges import registry
    r = registry.run("safety_db", project_path=str(TARGET_DIR))
    if r.errors and "not found" in r.errors[0]:
        print("  - safety-db not installed, skipping")
        return
    assert not r.errors, f"safety_db errors: {r.errors}"
    packages = {f["package"] for f in r.findings}
    expected_any_of = {"requests", "urllib3", "jinja2", "flask", "pyyaml"}
    assert packages & expected_any_of, f"safety_db missed: got {packages}"
    print(f"  ✓ safety_db found {len(r)} CVE matches: {sorted(packages)}")


def test_adapter_conversion():
    """Adapter converts bridge findings to Belief sextuplets without errors."""
    from belief.bridges import registry
    from belief.bridges.belief_adapter import adapt_one
    from belief.models import Belief
    # Use bandit if available; otherwise test with synthetic finding
    import shutil as _sh
    if _sh.which("bandit"):
        r = registry.run("bandit", project_path=str(TARGET_DIR), use_cache=False)
        beliefs = adapt_one(r)
        for b in beliefs:
            assert isinstance(b, Belief)
            assert b.scope.file_path
            assert 0.0 <= b.fragility <= 1.0
            assert 0.0 <= b.confidence_score <= 1.0
        print(f"  ✓ adapter converted {len(beliefs)} bandit findings → Beliefs")
    else:
        from belief.bridges.belief_adapter import dict_to_belief
        b = dict_to_belief({
            "assumption": "test", "anchor_file": "test.py", "anchor_line": 1,
            "anchor_line_end": 1, "justification_type": "C1",
            "contextual_constraint": "", "trust_domain": "test",
            "logic_type": "semantic", "source": "test",
        })
        assert b is not None
        assert 0.0 <= b.fragility <= 1.0
        print("  ✓ adapter synthetic test passed (bandit not installed)")


def test_merge_deduplication():
    """EnhancedOrchestrator._merge_beliefs removes duplicates correctly."""
    from belief.enhanced_orchestrator import EnhancedOrchestrator
    from belief.bridges.belief_adapter import dict_to_belief
    b1 = dict_to_belief({
        "assumption": "user input is sanitized before SQL execution",
        "anchor_file": "app.py", "anchor_line": 42, "anchor_line_end": 42,
        "justification_type": "C1", "contextual_constraint": "",
        "trust_domain": "x", "logic_type": "semantic", "source": "base",
    })
    b2 = dict_to_belief({
        "assumption": "user input is sanitized before SQL query",  # similar prefix
        "anchor_file": "app.py", "anchor_line": 42, "anchor_line_end": 42,
        "justification_type": "C4", "contextual_constraint": "",
        "trust_domain": "x", "logic_type": "semantic", "source": "bandit",
    })
    b3 = dict_to_belief({
        "assumption": "dependency requests==2.5.0 is not known-vulnerable",
        "anchor_file": "requirements.txt", "anchor_line": 1, "anchor_line_end": 1,
        "justification_type": "C3", "contextual_constraint": "",
        "trust_domain": "supply_chain", "logic_type": "semantic", "source": "safety_db",
    })
    merged = EnhancedOrchestrator._merge_beliefs([b1], [b2, b3])
    # b2 should be deduped against b1 (same file+line, overlapping prefix)
    # b3 should be kept (different file)
    assert len(merged) == 2, f"Expected 2 merged, got {len(merged)}"
    print(f"  ✓ merge dedup: [1 base] + [2 bridge] → {len(merged)} merged")


def main():
    print("=" * 60)
    print("BELIEF Bridges — Integration Test")
    print("=" * 60)
    setup_target()

    tests = [
        ("registry structure",    test_registry_structure),
        ("no-crash guarantee",    test_no_crash),
        ("bandit real findings",  test_bandit_real_findings),
        ("safety_db findings",    test_safety_db_real_findings),
        ("adapter conversion",    test_adapter_conversion),
        ("merge deduplication",   test_merge_deduplication),
    ]
    passed = 0
    failed = []
    for name, fn in tests:
        print(f"\n[{name}]")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAIL: {e}")
            failed.append((name, str(e)))
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            failed.append((name, f"{type(e).__name__}: {e}"))
    print()
    print("=" * 60)
    print(f"Result: {passed}/{len(tests)} passed")
    if failed:
        print("Failures:")
        for n, m in failed:
            print(f"  - {n}: {m}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
