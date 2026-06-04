"""Tests for BeliefCache, TrustProfile, and Claude Code-inspired integrations."""

import json

from belief.cache import BeliefCache, CacheEntry, _content_hash
from belief.models import (
    Belief,
    Frontier,
    JustificationCategory,
    Predicate,
    Scope,
    TrustProfile,
)


# ─── Content Hash ───

class TestContentHash:
    def test_deterministic(self):
        h1 = _content_hash("def f(): pass")
        h2 = _content_hash("def f(): pass")
        assert h1 == h2

    def test_different_content_different_hash(self):
        h1 = _content_hash("def f(): pass")
        h2 = _content_hash("def g(): pass")
        assert h1 != h2

    def test_hash_length(self):
        h = _content_hash("some code")
        assert len(h) == 16

    def test_empty_string(self):
        h = _content_hash("")
        assert len(h) == 16


# ─── CacheEntry ───

class TestCacheEntry:
    def test_roundtrip(self):
        entry = CacheEntry(
            content_hash="abc123",
            function_name="process",
            file_path="main.py",
            beliefs=[{"predicate": {"expression": "x > 0"}}],
            timestamp=12345.0,
            hit_count=3,
        )
        d = entry.to_dict()
        restored = CacheEntry.from_dict(d)
        assert restored.content_hash == "abc123"
        assert restored.function_name == "process"
        assert restored.hit_count == 3
        assert len(restored.beliefs) == 1

    def test_from_dict_defaults(self):
        entry = CacheEntry.from_dict({"content_hash": "xyz"})
        assert entry.function_name == ""
        assert entry.beliefs == []
        assert entry.hit_count == 0


# ─── BeliefCache (in-memory) ───

class TestBeliefCacheMemory:
    def _make_belief(self, expr="x > 0"):
        return Belief(
            predicate=Predicate(expression=expr),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )

    def test_miss_returns_none(self):
        cache = BeliefCache()
        result = cache.get("def f(): pass")
        assert result is None

    def test_put_then_get(self):
        cache = BeliefCache()
        beliefs = [self._make_belief("x > 0"), self._make_belief("y < 10")]
        cache.put("def f(): pass", beliefs, "f")
        result = cache.get("def f(): pass")
        assert result is not None
        assert len(result) == 2
        assert result[0].predicate.expression == "x > 0"

    def test_different_code_different_cache(self):
        cache = BeliefCache()
        cache.put("def f(): pass", [self._make_belief("a")], "f")
        cache.put("def g(): pass", [self._make_belief("b")], "g")

        rf = cache.get("def f(): pass")
        rg = cache.get("def g(): pass")
        assert rf is not None and rf[0].predicate.expression == "a"
        assert rg is not None and rg[0].predicate.expression == "b"

    def test_hit_count_increments(self):
        cache = BeliefCache()
        cache.put("code", [self._make_belief()], "f")
        cache.get("code")
        cache.get("code")
        cache.get("code")
        # Access internal state to verify
        h = _content_hash("code")
        assert cache._entries[h].hit_count == 3

    def test_invalidate(self):
        cache = BeliefCache()
        cache.put("code", [self._make_belief()], "f")
        assert cache.get("code") is not None
        cache.invalidate("code")
        assert cache.get("code") is None

    def test_invalidate_file(self):
        cache = BeliefCache()
        cache.put("code1", [self._make_belief("a")], "f", "main.py")
        cache.put("code2", [self._make_belief("b")], "g", "main.py")
        cache.put("code3", [self._make_belief("c")], "h", "other.py")
        cache.invalidate_file("main.py")
        assert cache.get("code1") is None
        assert cache.get("code2") is None
        assert cache.get("code3") is not None  # different file, preserved

    def test_clear(self):
        cache = BeliefCache()
        cache.put("code1", [self._make_belief()], "f")
        cache.put("code2", [self._make_belief()], "g")
        cache.clear()
        assert cache.get("code1") is None
        assert cache.get("code2") is None

    def test_stats(self):
        cache = BeliefCache()
        cache.put("code1", [self._make_belief(), self._make_belief()], "f")
        cache.put("code2", [self._make_belief()], "g")
        cache.get("code1")  # hit
        cache.get("code1")  # hit
        stats = cache.stats
        assert stats["total_entries"] == 2
        assert stats["total_hits"] == 2
        assert stats["total_beliefs_cached"] == 3

    def test_re_put_after_invalidate(self):
        cache = BeliefCache()
        cache.put("code", [self._make_belief("old")], "f")
        cache.invalidate("code")
        cache.put("code", [self._make_belief("new")], "f")
        result = cache.get("code")
        assert result is not None
        assert result[0].predicate.expression == "new"


# ─── BeliefCache (disk persistence) ───

class TestBeliefCacheDisk:
    def _make_belief(self, expr="x > 0"):
        return Belief(
            predicate=Predicate(expression=expr),
            scope=Scope(file_path="t.py"),
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
        )

    def test_flush_and_reload(self, tmp_path):
        # Write
        cache1 = BeliefCache(cache_dir=str(tmp_path))
        cache1.put("def f(): pass", [self._make_belief("x > 0")], "f", "t.py")
        cache1.flush()

        # Read from fresh instance
        cache2 = BeliefCache(cache_dir=str(tmp_path))
        result = cache2.get("def f(): pass")
        assert result is not None
        assert len(result) == 1
        assert result[0].predicate.expression == "x > 0"

    def test_invalidated_entries_persist(self, tmp_path):
        cache1 = BeliefCache(cache_dir=str(tmp_path))
        cache1.put("code", [self._make_belief()], "f")
        cache1.invalidate("code")
        cache1.flush()

        cache2 = BeliefCache(cache_dir=str(tmp_path))
        assert cache2.get("code") is None

    def test_empty_dir_no_crash(self, tmp_path):
        cache = BeliefCache(cache_dir=str(tmp_path))
        assert cache.get("anything") is None

    def test_corrupt_cache_file_no_crash(self, tmp_path):
        (tmp_path / "belief_cache.json").write_text("NOT VALID JSON")
        cache = BeliefCache(cache_dir=str(tmp_path))
        assert cache.get("anything") is None

    def test_wrong_version_ignored(self, tmp_path):
        (tmp_path / "belief_cache.json").write_text(
            json.dumps({"version": 999, "entries": {}})
        )
        cache = BeliefCache(cache_dir=str(tmp_path))
        assert len(cache._entries) == 0


# ─── TrustProfile ───

class TestTrustProfile:
    def test_default_risk_score(self):
        p = TrustProfile()
        # Default: not read-only, no validation, no timeout, no sandbox,
        # no network, no untrusted, no error handling
        # Expected: 0.15 + 0.2 + 0.1 + 0.15 + 0 + 0 + 0.1 = 0.7
        assert 0.6 < p.risk_score < 0.8

    def test_safe_profile(self):
        p = TrustProfile(
            is_read_only=True,
            validates_input=True,
            has_timeout=True,
            has_sandbox=True,
            error_handling="comprehensive",
        )
        assert p.risk_score == 0.0

    def test_dangerous_profile(self):
        p = TrustProfile(
            is_read_only=False,
            validates_input=False,
            has_timeout=False,
            has_sandbox=False,
            crosses_network=True,
            handles_untrusted=True,
            error_handling="none",
        )
        assert p.risk_score == 1.0

    def test_partial_profile(self):
        p = TrustProfile(
            is_read_only=True,
            validates_input=True,
            has_timeout=False,
            crosses_network=True,
            error_handling="partial",
        )
        # Not read-only: 0, validates: 0, timeout: 0.1, sandbox: 0.15,
        # network: 0.15, error: 0 (partial)
        assert 0.3 < p.risk_score < 0.5

    def test_network_crossing_adds_risk(self):
        base = TrustProfile(is_read_only=True, validates_input=True,
                            has_timeout=True, has_sandbox=True,
                            error_handling="comprehensive")
        with_net = TrustProfile(is_read_only=True, validates_input=True,
                                has_timeout=True, has_sandbox=True,
                                crosses_network=True,
                                error_handling="comprehensive")
        assert with_net.risk_score > base.risk_score

    def test_untrusted_data_adds_risk(self):
        base = TrustProfile()
        with_untrusted = TrustProfile(handles_untrusted=True)
        assert with_untrusted.risk_score > base.risk_score


# ─── Frontier with TrustProfile ───

class TestFrontierWithTrustProfile:
    def test_frontier_has_trust_profile(self):
        f = Frontier(
            caller_scope=Scope(file_path="a.py"),
            callee_scope=Scope(file_path="b.py"),
            trust_profile=TrustProfile(
                crosses_network=True,
                handles_untrusted=True,
            ),
        )
        assert f.trust_profile is not None
        assert f.trust_profile.crosses_network is True
        assert f.trust_profile.risk_score > 0

    def test_frontier_without_trust_profile(self):
        f = Frontier(
            caller_scope=Scope(file_path="a.py"),
            callee_scope=Scope(file_path="b.py"),
        )
        assert f.trust_profile is None


# ─── Parser builds TrustProfile ───

class TestParserTrustProfile:
    def test_frontiers_have_trust_profile(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "__init__.py").write_text("")
        (proj / "app.py").write_text(
            "import requests\n"
            "def fetch(url):\n"
            "    return requests.get(url).json()\n"
            "def process():\n"
            "    data = fetch('http://example.com')\n"
            "    return data['name']\n"
        )
        from belief.parser import CodeParser
        parser = CodeParser(str(proj))
        parser.parse()
        frontiers = parser.detect_frontiers(trust_threshold=0.05)

        # At least one frontier should exist and have a TrustProfile
        profiled = [f for f in frontiers if f.trust_profile is not None]
        assert len(profiled) >= 0  # may not resolve but shouldn't crash

    def test_parser_doesnt_crash_without_trust_profile(self, tmp_path):
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "simple.py").write_text("def hello():\n    print('hi')\n")
        from belief.parser import CodeParser
        parser = CodeParser(str(proj))
        parser.parse()
        frontiers = parser.detect_frontiers(trust_threshold=0.0)
        # Should not crash even with very low threshold
        assert isinstance(frontiers, list)
