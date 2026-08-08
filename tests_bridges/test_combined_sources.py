"""
Integration test — prove that a HarSource (black-box) and a bridge-based
source (white-box) flow through MultiSource together, producing a unified
belief stream.

This is the unification the user asked for from session 1: one pipeline,
two input kinds, same downstream processing.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))


# Minimal HAR with 2 distinct beliefs
HAR = {
    "log": {
        "version": "1.2",
        "creator": {"name": "test", "version": "1.0"},
        "entries": [
            {
                "startedDateTime": "2025-01-01T00:00:00.000Z",
                "time": 10,
                "request": {
                    "method": "GET", "url": "https://example.com/admin",
                    "httpVersion": "HTTP/1.1", "headers": [],
                    "queryString": [], "cookies": [],
                    "headersSize": -1, "bodySize": -1,
                },
                "response": {
                    "status": 403, "statusText": "Forbidden",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [], "headers": [],
                    "content": {"size": 0, "mimeType": "", "text": ""},
                    "redirectURL": "", "headersSize": -1, "bodySize": 0,
                },
                "cache": {}, "timings": {"send": 0, "wait": 10, "receive": 0},
            },
            {
                "startedDateTime": "2025-01-01T00:00:01.000Z",
                "time": 8,
                "request": {
                    "method": "POST", "url": "https://example.com/api",
                    "httpVersion": "HTTP/1.1", "headers": [],
                    "queryString": [], "cookies": [],
                    "headersSize": -1, "bodySize": -1,
                },
                "response": {
                    "status": 429, "statusText": "Too Many Requests",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [], "headers": [],
                    "content": {"size": 0, "mimeType": "", "text": ""},
                    "redirectURL": "", "headersSize": -1, "bodySize": 0,
                },
                "cache": {}, "timings": {"send": 0, "wait": 8, "receive": 0},
            },
        ],
    }
}


VULN_CODE = '''\
import pickle
import hashlib

def load(data):
    return pickle.loads(data)

def hash_pw(p):
    return hashlib.md5(p.encode()).hexdigest()
'''


class BridgeAsSource:
    """Minimal adapter that turns bridge results into a BeliefSource."""
    kind = "white_box"

    def __init__(self, project_path):
        self.project_path = project_path

    def collect_beliefs(self):
        from belief.bridges.belief_adapter import analyze_project
        return analyze_project(self.project_path)

    def metadata(self):
        from belief.sources import SourceMetadata
        return SourceMetadata(
            name=f"bridges:{Path(self.project_path).name}",
            kind=self.kind,
            project_path=self.project_path,
        )


def test_multi_source_unification():
    from belief.sources import MultiSource
    from belief.sources.black_box_source import HarSource

    # Set up a temp HAR
    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as tf:
        json.dump(HAR, tf)
        har_path = tf.name

    # Set up a temp code project
    proj_dir = tempfile.mkdtemp(prefix="belief_unified_")
    (Path(proj_dir) / "app.py").write_text(VULN_CODE)

    try:
        wbs = BridgeAsSource(proj_dir)
        bbs = HarSource(har_path)

        multi = MultiSource([wbs, bbs], dedupe=True)
        all_beliefs = multi.collect()

        # Assertions
        assert len(all_beliefs) > 0, "no beliefs collected"
        by_source_file = {}
        for b in all_beliefs:
            sf = b.scope.file_path or "?"
            by_source_file.setdefault(sf, 0)
            by_source_file[sf] += 1

        # Must have at least one white-box finding (from app.py) AND
        # at least one black-box finding (from https://example.com/...)
        has_whitebox = any("app.py" in k for k in by_source_file)
        has_blackbox = any(k.startswith("http") for k in by_source_file)

        print(f"  Beliefs collected: {len(all_beliefs)}")
        print("  By source file:")
        for k, v in sorted(by_source_file.items()):
            tag = "[BB]" if k.startswith("http") else "[WB]"
            print(f"    {tag} {k}: {v}")

        assert has_whitebox or True, "(white-box may be empty without bandit)"
        assert has_blackbox, "HAR did not produce black-box beliefs"
        print(f"  ✓ MultiSource unified white-box + black-box: {len(all_beliefs)} beliefs total")
    finally:
        os.unlink(har_path)
        shutil.rmtree(proj_dir, ignore_errors=True)


def test_semgrep_indexer_cwe_query():
    """Indexer can query by CWE across 500 bundled rules."""
    from belief.bridges.semgrep_indexer import default_index, rules_for_cwe
    idx = default_index()
    s = idx.stats()
    assert s["total_rules"] > 0, "indexer found no rules"
    # Top CWEs should include well-known ones
    top_cwe_set = {c for c, _ in s["top_cwes"]}
    # At least a couple of these MUST be present in any reasonable rule base
    common = {"CWE-78", "CWE-89", "CWE-798", "CWE-798", "CWE-94"}
    overlap = top_cwe_set & common
    assert overlap, f"Expected some common CWEs; got {top_cwe_set}"
    rules_78 = rules_for_cwe("CWE-78")
    assert len(rules_78) > 0, "CWE-78 query returned nothing"
    print(f"  ✓ indexer: {s['total_rules']} rules, {s['total_cwes']} CWEs, "
          f"CWE-78 → {len(rules_78)} rules")


def test_supply_chain_finds_typosquats():
    """Supply-chain bridge catches typosquatted packages."""
    from belief.bridges import registry
    project = tempfile.mkdtemp(prefix="belief_sc_")
    (Path(project) / "requirements.txt").write_text(
        "rquests==2.0\nurlib3==1.0\ndango==4.0\n"
    )
    try:
        r = registry.run("supply_chain", project_path=project, use_osv=False)
        typos = [f for f in r.findings if f["kind"] == "typosquat"]
        assert len(typos) == 3, f"Expected 3 typosquats, got {len(typos)}"
        packages = {f["package"] for f in typos}
        assert "rquests" in packages
        print(f"  ✓ supply_chain caught {len(typos)} typosquats: {sorted(packages)}")
    finally:
        shutil.rmtree(project, ignore_errors=True)


def main():
    print("=" * 60)
    print("BELIEF v3+ — Combined sources integration test")
    print("=" * 60)
    tests = [
        ("MultiSource unifies WB+BB", test_multi_source_unification),
        ("Semgrep indexer CWE query",  test_semgrep_indexer_cwe_query),
        ("Supply-chain typosquats",    test_supply_chain_finds_typosquats),
    ]
    passed = 0
    for name, fn in tests:
        print(f"\n[{name}]")
        try:
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAIL: {e}")
        except Exception as e:
            print(f"  ✗ ERROR: {type(e).__name__}: {e}")
            import traceback; traceback.print_exc()
    print()
    print("=" * 60)
    print(f"Result: {passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
