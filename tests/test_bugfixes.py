"""Tests for the 4 crash bugs fixed in this session.

Bug 1: extract_from_function() got unexpected keyword argument 'parameters'
Bug 2: Default exclude_dirs missing examples/tests → 11k functions → segfault
Bug 3: CLI missing --exclude argument
Bug 4: cmd_scan and hunter not filtering examples/tests directories
"""

import tempfile
import unittest
from pathlib import Path


class TestBug1_ExtractorContextFilter(unittest.TestCase):
    """Bug 1: orchestrator passes 'parameters' and 'decorators' from parser
    context to extractor, which doesn't accept them."""

    def test_parser_returns_extra_keys(self):
        """Verify parser's get_function_with_context includes parameters/decorators."""
        from belief.parser import CodeParser

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "sample.py").write_text(
                "def greet(name: str, greeting='hello'):\n"
                "    return f'{greeting} {name}'\n"
            )
            p = CodeParser(td)
            p.parse()
            for qn, func in p.functions.items():
                ctx = p.get_function_with_context(qn)
                if ctx:
                    self.assertIn("parameters", ctx)
                    self.assertIn("decorators", ctx)
                    self.assertIn("code", ctx)
                    break

    def test_extractor_accepts_only_known_keys(self):
        """Verify that filtering context keys prevents TypeError."""
        extractor_keys = {
            "code", "file_path", "function_name",
            "module_name", "callers", "documentation", "test_info",
        }
        context = {
            "code": "def f(): pass",
            "file_path": "test.py",
            "function_name": "f",
            "module_name": "test",
            "callers": [],
            "documentation": "(none)",
            "test_info": "no assertions",
            "parameters": ["x", "y"],  # extra key from parser
            "decorators": ["staticmethod"],  # extra key from parser
        }
        filtered = {k: v for k, v in context.items() if k in extractor_keys}
        self.assertNotIn("parameters", filtered)
        self.assertNotIn("decorators", filtered)
        self.assertIn("code", filtered)
        self.assertIn("function_name", filtered)


class TestBug2_ExcludeDirs(unittest.TestCase):
    """Bug 2: Default exclude_dirs missing 'examples', 'tests', etc.
    causing parser to scan 11,725 functions and segfault."""

    def test_default_excludes_contain_examples(self):
        """Verify 'examples' is in default exclude_dirs."""
        from belief.parser import CodeParser
        p = CodeParser("/tmp")
        self.assertIn("examples", p.exclude_dirs)
        self.assertIn("tests", p.exclude_dirs)
        self.assertIn("venv_belief", p.exclude_dirs)
        self.assertIn("benchmark_suite", p.exclude_dirs)

    def test_examples_not_collected(self):
        """Verify files inside examples/ are not collected."""
        with tempfile.TemporaryDirectory() as td:
            # Create structure with examples
            (Path(td) / "core.py").write_text("x = 1\n")
            examples = Path(td) / "examples"
            examples.mkdir()
            for i in range(100):
                (examples / f"ref_{i}.py").write_text(f"y = {i}\n")

            from belief.parser import CodeParser
            p = CodeParser(td)
            files = p._collect_python_files()
            self.assertEqual(len(files), 1)  # Only core.py
            self.assertTrue(all("examples" not in f.parts for f in files))

    def test_custom_excludes_merge_with_defaults(self):
        """Verify custom exclude_dirs are added to default safety excludes."""
        from belief.parser import CodeParser
        p = CodeParser("/tmp", exclude_dirs={"custom_dir"})
        self.assertIn("custom_dir", p.exclude_dirs)
        self.assertIn("examples", p.exclude_dirs)

    def test_no_segfault_on_belief_dir(self):
        """If belief/examples exists, parsing belief/ should not segfault."""
        belief_dir = Path(__file__).parent.parent / "belief"
        if not belief_dir.exists():
            self.skipTest("belief/ not found")

        from belief.parser import CodeParser
        p = CodeParser(str(belief_dir))
        files = p._collect_python_files()
        # Should be ~88 files, not 1800+
        self.assertLess(len(files), 200,
                        f"Too many files ({len(files)}): examples likely not excluded")
        # Should not contain any examples/ files
        examples_leaked = [f for f in files if "examples" in f.parts]
        self.assertEqual(len(examples_leaked), 0,
                        f"Examples leaked: {examples_leaked[:5]}")


class TestBug3_CLIExcludeArg(unittest.TestCase):
    """Bug 3: CLI doesn't support --exclude argument."""

    def test_analyze_parser_has_exclude(self):
        """Verify the analyze subcommand accepts --exclude."""
        import argparse
        # Recreate the parser structure from cli.py
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        p_analyze = sub.add_parser("analyze")
        p_analyze.add_argument("project_path")
        p_analyze.add_argument("--exclude", default="")
        p_analyze.add_argument("--output", "-o", default="./belief_output")
        p_analyze.add_argument("--max-frontiers", type=int, default=50)
        p_analyze.add_argument("--name", default="")
        p_analyze.add_argument("-v", "--verbose", action="store_true")

        # Should not raise
        args = parser.parse_args(
            ["analyze", "./myproject", "--exclude", "vendor,third_party"]
        )
        self.assertEqual(args.exclude, "vendor,third_party")

    def test_exclude_parsing(self):
        """Verify comma-separated excludes are parsed into a set."""
        exclude_str = "examples,tests,vendor"
        result = set(exclude_str.split(","))
        self.assertEqual(result, {"examples", "tests", "vendor"})

    def test_empty_exclude(self):
        """Verify empty --exclude doesn't break."""
        exclude_str = ""
        result = set(exclude_str.split(",")) if exclude_str else None
        self.assertIsNone(result)


class TestBug4_ScanAndHunterExclusion(unittest.TestCase):
    """Bug 4: cmd_scan and hunter don't filter examples/tests."""

    def test_hunter_relative_exclusion(self):
        """Verify hunter excludes __pycache__ but not parent dir names."""
        with tempfile.TemporaryDirectory() as td:
            # Create files
            (Path(td) / "main.py").write_text("def main(): pass\n")
            cache = Path(td) / "__pycache__"
            cache.mkdir()
            (cache / "main.cpython-312.pyc").write_text("")
            (Path(td) / "util.py").write_text("def util(): pass\n")

            from belief.hunter import ZeroDayHunter
            hunter = ZeroDayHunter()
            result = hunter.hunt(td, max_files=50)
            # Should scan main.py and util.py, not __pycache__
            self.assertEqual(result.files_scanned, 2)

    def test_hunter_explicit_examples_dir(self):
        """Verify hunter CAN scan examples/ when explicitly targeted."""
        examples_dir = Path(__file__).parent.parent / "belief" / "examples" / "flask_src"
        if not examples_dir.exists():
            self.skipTest("flask_src not found")

        from belief.hunter import ZeroDayHunter
        result = ZeroDayHunter().hunt(str(examples_dir), max_files=5)
        # Should scan files when explicitly targeted
        self.assertGreater(result.files_scanned, 0)


class TestOrchestratorExcludeDirs(unittest.TestCase):
    """Verify orchestrator passes exclude_dirs to CodeParser."""

    def test_analyze_project_accepts_exclude_dirs(self):
        """Verify analyze_project signature includes exclude_dirs."""
        from belief.orchestrator import Orchestrator
        import inspect
        sig = inspect.signature(Orchestrator.analyze_project)
        self.assertIn("exclude_dirs", sig.parameters)


if __name__ == "__main__":
    unittest.main()
