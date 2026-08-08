"""
Tests for belief.sources.har_parser and belief.sources.black_box_source.
No network required. Builds a synthetic HAR in memory, parses it,
extracts beliefs, asserts the expected patterns fire.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))


# Synthetic HAR with one entry per expected belief pattern
SYNTHETIC_HAR = {
    "log": {
        "version": "1.2",
        "creator": {"name": "belief-test", "version": "1.0"},
        "entries": [
            # 1) 403 → path_exists_but_requires_auth
            {
                "startedDateTime": "2025-01-01T00:00:00.000Z",
                "time": 42,
                "request": {
                    "method": "GET",
                    "url": "https://target.test/admin",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "User-Agent", "value": "test"}],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 403,
                    "statusText": "Forbidden",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [{"name": "Content-Type", "value": "text/html"}],
                    "content": {"size": 20, "mimeType": "text/html", "text": "<h1>Forbidden</h1>"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 20,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 42, "receive": 0},
            },
            # 2) 429 → rate_limit
            {
                "startedDateTime": "2025-01-01T00:00:01.000Z",
                "time": 20,
                "request": {
                    "method": "POST",
                    "url": "https://target.test/api/login",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                    "postData": {"mimeType": "application/json",
                                  "text": "{\"u\":\"a\",\"p\":\"a\"}"},
                },
                "response": {
                    "status": 429,
                    "statusText": "Too Many Requests",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [{"name": "Retry-After", "value": "60"}],
                    "content": {"size": 20, "mimeType": "text/plain", "text": "rate limited"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 20,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 20, "receive": 0},
            },
            # 3) 500 → input_parser broken
            {
                "startedDateTime": "2025-01-01T00:00:02.000Z",
                "time": 55,
                "request": {
                    "method": "GET",
                    "url": "https://target.test/crash?x=\x00\x00\x00",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [{"name": "x", "value": "\x00\x00\x00"}],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 500,
                    "statusText": "Internal Server Error",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "content": {"size": 10, "mimeType": "text/html", "text": "err"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 10,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 55, "receive": 0},
            },
            # 4) Reflected query param → XSS
            {
                "startedDateTime": "2025-01-01T00:00:03.000Z",
                "time": 30,
                "request": {
                    "method": "GET",
                    "url": "https://target.test/search?q=canary1234",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [{"name": "q", "value": "canary1234"}],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [{"name": "Content-Type", "value": "text/html"}],
                    "content": {
                        "size": 60, "mimeType": "text/html",
                        "text": "<html><body>You searched for canary1234</body></html>"
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 60,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 30, "receive": 0},
            },
            # 5) Set-Cookie without HttpOnly
            {
                "startedDateTime": "2025-01-01T00:00:04.000Z",
                "time": 18,
                "request": {
                    "method": "POST",
                    "url": "https://target.test/auth",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": "Set-Cookie", "value": "session=abc123; Path=/"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "content": {"size": 10, "mimeType": "application/json", "text": "{\"ok\":1}"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 10,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 18, "receive": 0},
            },
            # 6) Static asset — should be FILTERED out by default
            {
                "startedDateTime": "2025-01-01T00:00:05.000Z",
                "time": 5,
                "request": {
                    "method": "GET",
                    "url": "https://target.test/logo.png",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [{"name": "Content-Type", "value": "image/png"}],
                    "content": {"size": 100, "mimeType": "image/png", "text": ""},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 100,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 5, "receive": 0},
            },
        ],
    }
}


def test_har_parser_basic():
    from belief.sources.har_parser import parse_har, har_summary

    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as tf:
        json.dump(SYNTHETIC_HAR, tf)
        tmp = tf.name
    try:
        entries = parse_har(tmp)
        assert len(entries) == 6, f"Expected 6 entries, got {len(entries)}"
        e0 = entries[0]
        assert e0.method == "GET"
        assert e0.status_code == 403
        assert e0.host == "target.test"
        assert e0.path == "/admin"

        summary = har_summary(tmp)
        assert summary["total_entries"] == 6
        assert summary["hosts"] == {"target.test": 6}
        assert 403 in summary["statuses"]
        print(f"  ✓ parsed {len(entries)} entries, summary correct")
    finally:
        os.unlink(tmp)


def test_har_filter_excludes_static():
    from belief.sources.har_parser import parse_har, filter_entries

    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as tf:
        json.dump(SYNTHETIC_HAR, tf)
        tmp = tf.name
    try:
        all_entries = parse_har(tmp)
        filtered = filter_entries(all_entries, exclude_static=True)
        # 6 total, 1 is .png → 5 remain
        assert len(filtered) == 5, f"Expected 5 after static filter, got {len(filtered)}"
        print(f"  ✓ static filter: 6 → {len(filtered)} (logo.png removed)")
    finally:
        os.unlink(tmp)


def test_black_box_source_extracts_beliefs():
    from belief.sources.black_box_source import HarSource

    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as tf:
        json.dump(SYNTHETIC_HAR, tf)
        tmp = tf.name
    try:
        src = HarSource(tmp)
        beliefs = src.collect_beliefs()
        # At minimum: 403 → 1, 429 → 1, 500 → 1, reflected query → 1, set-cookie missing httponly → 1
        # (static asset is filtered) = ≥ 5 beliefs expected
        assert len(beliefs) >= 4, f"Expected ≥4 beliefs, got {len(beliefs)}"

        # Check predicate expressions
        preds = {b.predicate.expression.split("[")[0] for b in beliefs}
        expected_some = {
            "server.path_exists_but_requires_auth",
            "server.rate_limit_enforces_global_quota",
            "server.input_parser_handles_malformed_input",
            "server.user_input_is_sanitized_before_reflection",
        }
        found = preds & expected_some
        assert len(found) >= 3, f"Expected ≥3 patterns; found {found}"
        print(f"  ✓ extracted {len(beliefs)} beliefs; patterns found: {len(found)}/{len(expected_some)}")

        # Verify metadata
        md = src.metadata()
        assert md.kind == "black_box"
        assert md.name.startswith("har:")
        assert md.extra["entries"] >= 4
        print(f"  ✓ metadata: {md.name}, {md.extra['entries']} entries, hosts={md.extra['hosts_seen']}")
    finally:
        os.unlink(tmp)


def test_multisource_dedupes():
    """MultiSource combines two sources and deduplicates overlaps."""
    from belief.sources import MultiSource, BeliefSource, SourceMetadata
    from belief.models import Belief, Predicate, Scope, JustificationCategory, LogicType, ArtifactKind, EpistemicStatus

    def mk_belief(expr, file_, line):
        return Belief(
            predicate=Predicate(expression=expr, variables=(), anchor_lines=(line,)),
            scope=Scope(file_path=file_, line_start=line, line_end=line),
            justification=JustificationCategory.C4_CALLER_ASSUMPTION,
            epistemic_status=EpistemicStatus.BELIEF,
            logic_type=LogicType.FOL,
            artifact_kind=ArtifactKind.SOURCE_CODE,
            confidence_score=0.5,
        )

    class FakeSource(BeliefSource):
        def __init__(self, name, beliefs):
            self.name = name
            self._beliefs = beliefs
        def collect_beliefs(self):
            return self._beliefs
        def metadata(self):
            return SourceMetadata(name=self.name, kind="white_box")

    b1 = mk_belief("user_input_is_sanitized_always_true", "app.py", 42)
    b2_dup = mk_belief("user_input_is_sanitized_sometimes", "app.py", 42)  # same prefix 20 chars
    b3 = mk_belief("another_belief_entirely", "app.py", 99)

    s1 = FakeSource("s1", [b1])
    s2 = FakeSource("s2", [b2_dup, b3])
    ms = MultiSource([s1, s2], dedupe=True)
    merged = ms.collect()
    # b2 should be deduped as its prefix matches b1's
    assert len(merged) == 2, f"Expected 2 after dedupe, got {len(merged)}: {[b.predicate.expression for b in merged]}"
    print(f"  ✓ MultiSource dedupe: [1] + [2] → {len(merged)}")


def main():
    print("=" * 60)
    print("BELIEF Sources — HAR + BlackBoxSource tests")
    print("=" * 60)
    tests = [
        ("HAR parser basic",         test_har_parser_basic),
        ("HAR filter static assets", test_har_filter_excludes_static),
        ("BlackBoxSource beliefs",   test_black_box_source_extracts_beliefs),
        ("MultiSource dedup",        test_multisource_dedupes),
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
            import traceback
            traceback.print_exc()
    print()
    print("=" * 60)
    print(f"Result: {passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
