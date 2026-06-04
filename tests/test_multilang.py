"""Tests for multi-language tree-sitter parser."""

import pytest
from pathlib import Path

from belief.multilang import (
    MultiLangParser,
    get_language_for_file,
    get_supported_languages,
    _TS_AVAILABLE,
)


# ─── Language Detection ───

class TestLanguageDetection:
    def test_javascript(self):
        assert get_language_for_file("app.js") == "javascript"
        assert get_language_for_file("app.mjs") == "javascript"
        assert get_language_for_file("app.jsx") == "javascript"

    def test_typescript(self):
        assert get_language_for_file("app.ts") == "typescript"
        assert get_language_for_file("app.tsx") == "typescript"

    def test_go(self):
        assert get_language_for_file("main.go") == "go"

    def test_java(self):
        assert get_language_for_file("App.java") == "java"

    def test_rust(self):
        assert get_language_for_file("lib.rs") == "rust"

    def test_c(self):
        assert get_language_for_file("main.c") == "c"
        assert get_language_for_file("header.h") == "c"

    def test_unknown(self):
        assert get_language_for_file("README.md") is None
        assert get_language_for_file("Makefile") is None

    def test_python_not_handled(self):
        # Python uses the dedicated AST parser, not tree-sitter
        assert get_language_for_file("app.py") is None


# ─── Supported Languages ───

class TestSupportedLanguages:
    def test_returns_list(self):
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter not installed")
        langs = get_supported_languages()
        assert isinstance(langs, list)
        # At least JS and Go should work
        assert "javascript" in langs
        assert "go" in langs

    def test_without_treesitter(self):
        # Even if tree-sitter fails, it shouldn't crash
        langs = get_supported_languages()
        assert isinstance(langs, list)


# ─── JavaScript Parsing ───

class TestJavaScriptParsing:
    @pytest.fixture
    def js_project(self, tmp_path):
        proj = tmp_path / "jsproject"
        proj.mkdir()
        (proj / "index.js").write_text(
            'const fetch = require("node-fetch");\n'
            '\n'
            'function getData(url) {\n'
            '  return fetch(url).then(r => r.json());\n'
            '}\n'
            '\n'
            'function processData(data) {\n'
            '  return data.map(item => item.name.toUpperCase());\n'
            '}\n'
            '\n'
            'async function main() {\n'
            '  const data = await getData("https://api.example.com/users");\n'
            '  return processData(data);\n'
            '}\n'
        )
        return str(proj)

    def test_parses_js_functions(self, js_project):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        parser = MultiLangParser(js_project, languages=["javascript"])
        functions = parser.parse()
        names = {f.name for f in functions}

        assert "getData" in names
        assert "processData" in names
        assert "main" in names

    def test_detects_calls(self, js_project):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        parser = MultiLangParser(js_project, languages=["javascript"])
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        if "main" in func_map:
            # main calls getData and processData
            assert len(func_map["main"].calls) >= 1

    def test_detects_external_access(self, js_project):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        parser = MultiLangParser(js_project, languages=["javascript"])
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        if "getData" in func_map:
            assert func_map["getData"].accesses_external


# ─── TypeScript Parsing ───

class TestTypeScriptParsing:
    @pytest.fixture
    def ts_project(self, tmp_path):
        proj = tmp_path / "tsproject"
        proj.mkdir()
        (proj / "service.ts").write_text(
            'interface User { name: string; age: number; }\n'
            '\n'
            'function validateUser(user: User): boolean {\n'
            '  if (!user.name || user.age < 0) return false;\n'
            '  return true;\n'
            '}\n'
            '\n'
            'async function fetchUser(id: string): Promise<User> {\n'
            '  const response = await fetch(`/api/users/${id}`);\n'
            '  return response.json();\n'
            '}\n'
        )
        return str(proj)

    def test_parses_ts_functions(self, ts_project):
        if not _TS_AVAILABLE or "typescript" not in get_supported_languages():
            pytest.skip("TS grammar not available")

        parser = MultiLangParser(ts_project, languages=["typescript"])
        functions = parser.parse()
        names = {f.name for f in functions}

        assert "validateUser" in names
        assert "fetchUser" in names


# ─── Go Parsing ───

class TestGoParsing:
    @pytest.fixture
    def go_project(self, tmp_path):
        proj = tmp_path / "goproject"
        proj.mkdir()
        (proj / "main.go").write_text(
            'package main\n'
            '\n'
            'import "net/http"\n'
            '\n'
            'func handleRequest(w http.ResponseWriter, r *http.Request) {\n'
            '  data := r.URL.Query().Get("input")\n'
            '  w.Write([]byte(data))\n'
            '}\n'
            '\n'
            'func processInput(input string) string {\n'
            '  return input\n'
            '}\n'
        )
        return str(proj)

    def test_parses_go_functions(self, go_project):
        if not _TS_AVAILABLE or "go" not in get_supported_languages():
            pytest.skip("Go grammar not available")

        parser = MultiLangParser(go_project, languages=["go"])
        functions = parser.parse()
        names = {f.name for f in functions}

        assert "handleRequest" in names
        assert "processInput" in names


# ─── Java Parsing ───

class TestJavaParsing:
    @pytest.fixture
    def java_project(self, tmp_path):
        proj = tmp_path / "javaproject"
        proj.mkdir()
        (proj / "App.java").write_text(
            'public class App {\n'
            '    public static String greet(String name) {\n'
            '        return "Hello " + name;\n'
            '    }\n'
            '\n'
            '    public void process(Object data) {\n'
            '        String result = data.toString();\n'
            '        System.out.println(result);\n'
            '    }\n'
            '}\n'
        )
        return str(proj)

    def test_parses_java_methods(self, java_project):
        if not _TS_AVAILABLE or "java" not in get_supported_languages():
            pytest.skip("Java grammar not available")

        parser = MultiLangParser(java_project, languages=["java"])
        functions = parser.parse()
        names = {f.name for f in functions}

        assert "greet" in names
        assert "process" in names


# ─── Mixed Project ───

class TestMixedProject:
    @pytest.fixture
    def mixed_project(self, tmp_path):
        proj = tmp_path / "mixed"
        proj.mkdir()
        (proj / "app.js").write_text(
            'function jsFunc() { return 1; }\n'
        )
        (proj / "main.go").write_text(
            'package main\nfunc goFunc() int { return 1 }\n'
        )
        (proj / "ignored.py").write_text(
            'def py_func(): pass\n'  # should be ignored by multilang
        )
        return str(proj)

    def test_parses_multiple_languages(self, mixed_project):
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter not installed")

        supported = get_supported_languages()
        parser = MultiLangParser(mixed_project)
        functions = parser.parse()
        names = {f.name for f in functions}

        if "javascript" in supported:
            assert "jsFunc" in names
        if "go" in supported:
            assert "goFunc" in names

        # Python files are NOT parsed by multilang
        assert "py_func" not in names

    def test_excludes_node_modules(self, mixed_project):
        nm = Path(mixed_project) / "node_modules" / "lib"
        nm.mkdir(parents=True)
        (nm / "vendor.js").write_text('function vendorFunc() {}')

        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter not installed")

        parser = MultiLangParser(mixed_project)
        functions = parser.parse()
        names = {f.name for f in functions}
        assert "vendorFunc" not in names


# ─── Frontier Detection ───

class TestMultiLangFrontiers:
    def test_detect_frontiers_no_crash(self, tmp_path):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "app.js").write_text(
            'function fetch(url) { return http.get(url); }\n'
            'function process() { return fetch("/api"); }\n'
        )
        parser = MultiLangParser(str(proj), languages=["javascript"])
        parser.parse()
        frontiers = parser.detect_frontiers(trust_threshold=0.0)
        assert isinstance(frontiers, list)

    def test_frontiers_have_trust_profile(self, tmp_path):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "app.js").write_text(
            'function fetch(url) { return http.get(url); }\n'
            'function process() { return fetch("/api"); }\n'
        )
        parser = MultiLangParser(str(proj), languages=["javascript"])
        parser.parse()
        frontiers = parser.detect_frontiers(trust_threshold=0.0)
        for f in frontiers:
            if f.trust_profile:
                assert hasattr(f.trust_profile, "risk_score")


# ─── Edge Cases ───

class TestMultiLangEdgeCases:
    def test_empty_project(self, tmp_path):
        parser = MultiLangParser(str(tmp_path))
        functions = parser.parse()
        assert functions == []

    def test_binary_file_skipped(self, tmp_path):
        (tmp_path / "binary.js").write_bytes(b'\x00\x01\x02\x03' * 100)
        if not _TS_AVAILABLE:
            pytest.skip("tree-sitter not installed")
        parser = MultiLangParser(str(tmp_path))
        # Should not crash on binary content
        functions = parser.parse()
        assert isinstance(functions, list)

    def test_get_function_with_context(self, tmp_path):
        if not _TS_AVAILABLE or "javascript" not in get_supported_languages():
            pytest.skip("JS grammar not available")

        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "app.js").write_text('function hello() { return 42; }\n')
        parser = MultiLangParser(str(proj), languages=["javascript"])
        parser.parse()

        for qname in parser.functions:
            ctx = parser.get_function_with_context(qname)
            assert "code" in ctx
            assert "file_path" in ctx
            break
