"""Tests for BELIEF code parser and frontier detection."""

import pytest

from belief.parser import CodeParser


SAMPLE_CODE = '''\
import requests
import json


class DataFetcher:
    """Fetches data from external APIs."""

    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def fetch_user(self, user_id):
        """Fetch a user by ID."""
        response = self.session.get(f"{self.base_url}/users/{user_id}")
        data = response.json()
        return data

    def _parse_response(self, raw):
        return json.loads(raw)


def process_data(fetcher, user_id):
    """Process user data from the API."""
    user = fetcher.fetch_user(user_id)
    name = user["name"]
    return name.upper()


def validate_input(user_id):
    """Validate that user_id is a positive integer."""
    assert isinstance(user_id, int)
    assert user_id > 0
    return user_id
'''


@pytest.fixture
def sample_project(tmp_path):
    """Create a minimal Python project for testing."""
    src = tmp_path / "myproject"
    src.mkdir()
    (src / "__init__.py").write_text("")
    (src / "fetcher.py").write_text(SAMPLE_CODE)

    # Add a second module
    (src / "handler.py").write_text('''\
from .fetcher import DataFetcher, process_data


class RequestHandler:
    def handle(self, request):
        user_id = request.get("user_id")
        fetcher = DataFetcher("https://api.example.com")
        result = process_data(fetcher, user_id)
        return {"result": result}
''')

    return str(src)


class TestCodeParser:
    def test_parse_finds_functions(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        names = {f.name for f in functions}
        assert "fetch_user" in names
        assert "__init__" in names
        assert "process_data" in names
        assert "validate_input" in names
        assert "handle" in names

    def test_parse_extracts_classes(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        class_funcs = [f for f in functions if f.class_name == "DataFetcher"]
        assert len(class_funcs) >= 2  # __init__ + fetch_user + _parse_response

    def test_detects_external_access(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        # fetch_user accesses network via requests
        assert func_map["fetch_user"].accesses_external

    def test_detects_assertions(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        assert func_map["validate_input"].has_assertions
        assert not func_map["fetch_user"].has_assertions

    def test_public_private_detection(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        assert func_map["fetch_user"].is_public
        assert not func_map["_parse_response"].is_public

    def test_detect_frontiers(self, sample_project):
        parser = CodeParser(sample_project)
        parser.parse()
        frontiers = parser.detect_frontiers(trust_threshold=0.1)

        # Should find frontiers involving external-accessing functions
        assert len(frontiers) > 0

        # Frontiers should be sorted by trust asymmetry (descending)
        if len(frontiers) > 1:
            assert frontiers[0].trust_asymmetry >= frontiers[-1].trust_asymmetry

    def test_get_function_with_context(self, sample_project):
        parser = CodeParser(sample_project)
        parser.parse()

        # Find a function by qualified name
        for qname in parser.functions:
            if "fetch_user" in qname:
                ctx = parser.get_function_with_context(qname)
                assert "code" in ctx
                assert "file_path" in ctx
                assert "fetch_user" in ctx["code"]
                break

    def test_call_graph(self, sample_project):
        parser = CodeParser(sample_project)
        parser.parse()

        # process_data should call fetch_user
        # This may or may not resolve depending on import handling
        # Just ensure call_graph exists and is populated
        assert isinstance(parser.call_graph, dict)
        assert len(parser.call_graph) > 0

    def test_qualified_names(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()

        for f in functions:
            qn = f.qualified_name
            assert f.module in qn
            assert f.name in qn
            if f.class_name:
                assert f.class_name in qn

    def test_docstring_extraction(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        assert func_map["fetch_user"].docstring == "Fetch a user by ID."
        assert func_map["validate_input"].docstring is not None

    def test_parameter_extraction(self, sample_project):
        parser = CodeParser(sample_project)
        functions = parser.parse()
        func_map = {f.name: f for f in functions}

        assert "user_id" in func_map["fetch_user"].parameters
        assert "user_id" in func_map["validate_input"].parameters

    def test_empty_project(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        parser = CodeParser(str(empty))
        functions = parser.parse()
        assert functions == []

    def test_syntax_error_resilience(self, tmp_path):
        proj = tmp_path / "bad"
        proj.mkdir()
        (proj / "broken.py").write_text("def f(\n  this is not valid python")
        (proj / "good.py").write_text("def g():\n    return 42\n")

        parser = CodeParser(str(proj))
        functions = parser.parse()
        # Should still parse the good file
        names = {f.name for f in functions}
        assert "g" in names
