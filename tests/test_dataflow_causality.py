"""Regression coverage for causal local dataflow and taint analysis."""

from __future__ import annotations

from pathlib import Path

from belief.dataflow import (
    analyze_source_dataflow,
    dataflow_for_finding,
    dataflow_paths_for_finding,
)
from belief.models import Finding
from belief.security_patterns import SecurityPatternExtractor
from belief.taint import TaintEngine, TaintSink, TaintSource


ROOT = Path(__file__).resolve().parents[1]


def test_source_after_sink_does_not_create_a_flow() -> None:
    source = """
def handler():
    filename = "safe.txt"
    open(filename)
    filename = request.args.get("file")
"""

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert TaintEngine().analyze(source, "app.py") == []


def test_ignored_sanitizer_result_does_not_sanitize_original_value() -> None:
    source = """
def handler():
    filename = request.args.get("file")
    sanitize(filename)
    open(filename)
"""

    dataflow_paths = analyze_source_dataflow(source, "app.py").paths
    taint_paths = TaintEngine().analyze(source, "app.py")

    assert len(dataflow_paths) == 1
    assert dataflow_paths[0].sanitized is False
    assert len(taint_paths) == 1
    assert taint_paths[0].sanitized is False


def test_local_constant_return_does_not_propagate_taint() -> None:
    source = """
def constant_filename(value):
    return "safe.txt"

def handler():
    untrusted = request.args.get("file")
    filename = constant_filename(untrusted)
    open(filename)
"""

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert TaintEngine().analyze(source, "app.py") == []


def test_used_sanitizer_result_is_causally_attached_to_the_sink_value() -> None:
    source = """
def handler():
    display_name = request.args.get("name")
    safe_name = escape(display_name)
    Markup(safe_name)
"""

    dataflow_path = analyze_source_dataflow(source, "app.py").paths[0]
    taint_path = TaintEngine().analyze(source, "app.py")[0]

    assert dataflow_path.sanitized is True
    assert taint_path.sanitized is True


def test_local_identity_return_preserves_taint() -> None:
    source = """
def identity(value):
    return value

def handler():
    untrusted = request.args.get("file")
    filename = identity(untrusted)
    open(filename)
"""

    assert len(analyze_source_dataflow(source, "app.py").paths) == 1
    assert len(TaintEngine().analyze(source, "app.py")) == 1


def test_unknown_transforming_method_propagates_receiver_taint() -> None:
    source = """
def handler():
    user_path = request.args.get("path")
    candidate = (BASE / user_path).resolve()
    open(candidate)
"""

    dataflow_paths = analyze_source_dataflow(source, "app.py").paths
    taint_paths = TaintEngine().analyze(source, "app.py")

    assert len(dataflow_paths) == 1
    assert dataflow_paths[0].source.expression == 'request.args.get("path")'
    assert dataflow_paths[0].sink.expression == "open(candidate)"
    assert "candidate" in dataflow_paths[0].intermediate_variables
    assert len(taint_paths) == 1
    assert "candidate" in taint_paths[0].intermediate_vars


def test_method_receiver_is_not_treated_as_a_sink_argument() -> None:
    source = """
def handler():
    stream = request.args.get("stream")
    result = stream.open()
    open(result)
"""

    taint_engine = TaintEngine(
        sources=[TaintSource("request.args", "user_input", "high")],
        sinks=[TaintSink("open", "file_write", "high", "CWE-73")],
    )

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert taint_engine.analyze(source, "app.py") == []


def test_method_receiver_is_not_used_by_a_local_constant_return_model() -> None:
    source = """
class Factory:
    def constant(self):
        return "safe.txt"

def handler():
    untrusted = request.args.get("file")
    filename = untrusted.constant()
    open(filename)
"""

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert TaintEngine().analyze(source, "app.py") == []


def test_guarantee_call_without_real_source_does_not_create_a_flow() -> None:
    source = """
def handler():
    filename = Storage.path("safe.txt")
    open(filename)
"""

    assert analyze_source_dataflow(source, "app.py").paths == []


def test_return_model_binds_keyword_arguments_by_parameter_name() -> None:
    source = """
def choose(x, y):
    return x

def handler():
    untrusted = request.args.get("file")
    filename = choose(y=untrusted, x="safe.txt")
    open(filename)
"""

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert TaintEngine().analyze(source, "app.py") == []


def test_return_model_follows_tainted_keyword_independent_of_keyword_order() -> None:
    source = """
def choose(x, y):
    return x

def handler():
    untrusted = request.args.get("file")
    filename = choose(y="safe.txt", x=untrusted)
    open(filename)
"""

    assert len(analyze_source_dataflow(source, "app.py").paths) == 1
    assert len(TaintEngine().analyze(source, "app.py")) == 1


def test_bound_method_return_model_does_not_count_self_as_an_argument() -> None:
    source = """
class Picker:
    def choose(self, x, y):
        return x

def handler():
    untrusted = request.args.get("file")
    filename = Picker().choose(untrusted, "safe.txt")
    open(filename)
"""

    assert len(analyze_source_dataflow(source, "app.py").paths) == 1
    assert len(TaintEngine().analyze(source, "app.py")) == 1


def test_protected_benchmark_path_has_causal_commonpath_guard() -> None:
    fixture = ROOT / "benchmark_static_analysis" / "path_traversal" / "protected.py"
    source = fixture.read_text(encoding="utf-8")

    paths = analyze_source_dataflow(source, fixture.as_posix()).paths
    path = next(item for item in paths if item.sink.expression == "open(candidate)")

    assert path.source.expression == 'request.args["path"]'
    assert path.function_name == "download_safe_file"
    assert [guard.expression for guard in path.guarantees] == [
        "path.is_within_store == true"
    ]
    assert path.guarantees[0].line < path.sink.line


def test_dataflow_nodes_include_execution_order_metadata() -> None:
    source = """
def handler():
    filename = request.args.get("file")
    open(filename)
"""

    path = analyze_source_dataflow(source, "app.py").paths[0]

    assert path.source.file_path == "app.py"
    assert path.source.function_name == "handler"
    assert path.source.column == 15
    assert path.source.statement_order is not None
    assert path.sink.file_path == "app.py"
    assert path.sink.function_name == "handler"
    assert path.sink.column == 4
    assert path.sink.statement_order is not None
    assert path.source.statement_order < path.sink.statement_order


def test_dataflow_edges_use_each_causal_target_location() -> None:
    source = """
def handler():
    filename = request.args.get("file")
    open(filename)
"""

    path = analyze_source_dataflow(source, "app.py").paths[0]

    assert [edge.line for edge in path.edges] == [3, 4]
    assert [edge.column for edge in path.edges] == [4, 4]
    assert [edge.statement_order for edge in path.edges] == [1, 2]
    assert all(edge.file_path == "app.py" for edge in path.edges)
    assert all(edge.function_name == "handler" for edge in path.edges)
    assert path.edges[0].to_dict() == {
        "source_id": path.nodes[0].node_id,
        "target_id": path.nodes[1].node_id,
        "kind": "flows_to",
        "line": 3,
        "file": "app.py",
        "column": 4,
        "function_name": "handler",
        "statement_order": 1,
    }


def test_analysis_limits_emit_explicit_diagnostics() -> None:
    source = """
def handler():
    filename = request.args.get("file")
    open(filename)
"""

    depth_summary = analyze_source_dataflow(source, "app.py", max_depth=0)
    node_summary = analyze_source_dataflow(source, "app.py", max_nodes=0)
    taint_engine = TaintEngine(max_nodes=0)
    taint_engine.analyze(source, "app.py")

    assert any(
        item["reason"] == "analysis_truncated_max_depth"
        for item in depth_summary.diagnostics
    )
    assert node_summary.diagnostics[0]["reason"] == "analysis_truncated_max_nodes"
    assert taint_engine.diagnostics[0]["reason"] == "analysis_truncated_max_nodes"


def test_recursive_local_return_models_report_cycle_detection() -> None:
    source = """
def first(value):
    return second(value)

def second(value):
    return first(value)

def handler():
    untrusted = request.args.get("file")
    filename = first(untrusted)
    open(filename)
"""

    summary = analyze_source_dataflow(source, "app.py")
    taint_engine = TaintEngine()
    taint_paths = taint_engine.analyze(source, "app.py")

    assert any(item["reason"] == "cycle_detected" for item in summary.diagnostics)
    assert any(item["reason"] == "cycle_detected" for item in taint_engine.diagnostics)
    assert summary.paths == []
    assert taint_paths == []


def test_truncated_local_return_model_depth_never_falls_back_to_identity() -> None:
    source = """
def first(value):
    return second(value)

def second(value):
    return third(value)

def third(value):
    return value

def handler(request):
    filename = first(request)
    open(filename)
"""

    summary = analyze_source_dataflow(source, "app.py", max_depth=1)
    taint_engine = TaintEngine(max_depth=1)
    taint_paths = taint_engine.analyze(source, "app.py")

    assert summary.paths == []
    assert taint_paths == []
    assert any(
        item["reason"] == "analysis_truncated_max_depth"
        for item in summary.diagnostics
    )
    assert any(
        item["reason"] == "analysis_truncated_max_depth"
        for item in taint_engine.diagnostics
    )


def test_truncated_local_return_model_node_budget_never_produces_a_path() -> None:
    source = """
def handler(request):
    filename = first(request)
    open(filename)

def first(value):
    return second(value)

def second(value):
    return value
"""

    summary = analyze_source_dataflow(source, "app.py", max_nodes=2)
    taint_engine = TaintEngine(max_nodes=4)
    taint_paths = taint_engine.analyze(source, "app.py")

    assert summary.paths == []
    assert taint_paths == []
    assert any(
        item["reason"] == "analysis_truncated_max_nodes"
        for item in summary.diagnostics
    )
    assert any(
        item["reason"] == "analysis_truncated_max_nodes"
        for item in taint_engine.diagnostics
    )


def test_finding_never_borrows_adjacent_function_protected_path() -> None:
    source = """
def safe():
    requested = request.args.get("file")
    filename = os.path.basename(requested)
    open(filename)

def vuln():
    filename = request.args.get("file")
    open(filename)
"""
    summary = analyze_source_dataflow(source, "app.py")
    findings = [
        Finding.from_belief(belief, source="security")
        for belief in SecurityPatternExtractor().extract(source, "app.py")
        if belief.cwe == "CWE-22"
    ]
    vuln_finding = next(
        finding
        for finding in findings
        if finding.metadata.get("function_name") == "vuln"
    )

    paths = dataflow_paths_for_finding(vuln_finding, {"app.py": summary})
    payload = dataflow_for_finding(vuln_finding, {"app.py": summary})

    assert paths
    assert all(path.function_name == "vuln" for path in paths)
    assert paths[0].sanitized is False
    assert payload is not None
    assert payload["function"] == "vuln"
    assert payload["sanitizers"] == []


def test_finding_evidence_sink_line_selects_exact_path_within_function() -> None:
    source = """
def mixed():
    requested = request.args.get("file")
    filename = os.path.basename(requested)
    open(filename)
    open(requested)
"""
    summary = analyze_source_dataflow(source, "app.py")
    findings = [
        Finding.from_belief(belief, source="security")
        for belief in SecurityPatternExtractor().extract(source, "app.py")
        if belief.cwe == "CWE-22"
    ]
    vulnerable_finding = next(
        finding for finding in findings if "line 6" in finding.evidence
    )

    paths = dataflow_paths_for_finding(vulnerable_finding, {"app.py": summary})

    assert paths[0].sink_line == 6
    assert paths[0].sanitized is False
    assert paths[0].sanitizers == ()


def test_same_sink_bypass_path_sorts_before_sanitized_argument_path() -> None:
    source = """
def handler():
    safe_id = os.path.basename(request.args.get("safe"))
    unsafe_id = request.args.get("unsafe")
    Document.query.filter_by(id=safe_id, object_id=unsafe_id)
"""
    summary = analyze_source_dataflow(source, "app.py")
    finding = Finding(
        source="test",
        rule_id="CWE-639",
        title="Unscoped object lookup",
        description="Externally controlled object lookup at line 5",
        file="app.py",
        line=5,
        cwe="CWE-639",
        severity="high",
        confidence=0.9,
        metadata={"function_name": "handler"},
    )

    paths = dataflow_paths_for_finding(finding, {"app.py": summary})
    payload = dataflow_for_finding(finding, {"app.py": summary}, show_dataflow=True)

    assert len(paths) == 2
    assert [path.sanitized for path in paths] == [False, True]
    assert paths[0].source.expression == 'request.args.get("unsafe")'
    assert payload is not None
    assert payload["source"] == 'request.args.get("unsafe")'
    assert payload["path_count"] == 2


def test_query_guard_without_real_source_never_creates_dataflow_path() -> None:
    source = """
def handler():
    return Document.query.filter_by(id=42, owner_id=current_user.id).first()
"""

    summary = analyze_source_dataflow(source, "app.py")

    assert summary.paths == []


def test_mutually_exclusive_source_and_sink_do_not_form_a_path() -> None:
    source = """
def handler(flag):
    if flag:
        filename = request.args.get("file")
    else:
        open(filename)
"""

    assert analyze_source_dataflow(source, "app.py").paths == []
    assert TaintEngine().analyze(source, "app.py") == []


def test_sanitizer_in_other_branch_does_not_protect_sink_path() -> None:
    source = """
def handler(flag):
    display_name = request.args.get("name")
    if flag:
        display_name = escape(display_name)
    else:
        Markup(display_name)
"""

    dataflow_path = analyze_source_dataflow(source, "app.py").paths[0]
    taint_path = TaintEngine().analyze(source, "app.py")[0]

    assert dataflow_path.sanitized is False
    assert taint_path.sanitized is False
