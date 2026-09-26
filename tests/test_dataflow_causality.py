"""Regression coverage for causal local dataflow and taint analysis."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from belief.audit_case import audit_case_from_finding
from belief.dataflow import (
    analyze_source_dataflow,
    attach_dataflow_to_findings,
    dataflow_for_finding,
    dataflow_paths_for_finding,
)
from belief.models import Finding
from belief.security_patterns import SecurityPatternExtractor
from belief.taint import TaintEngine, TaintSink, TaintSource


ROOT = Path(__file__).resolve().parents[1]


def _path_finding(**overrides) -> Finding:
    values = {
        "source": "test",
        "rule_id": "CWE-22",
        "title": "Path traversal candidate",
        "description": "Review this path operation.",
        "file": "app.py",
        "line": 3,
        "cwe": "CWE-22",
        "severity": "high",
        "confidence": 0.9,
    }
    values.update(overrides)
    return Finding(**values)


_PROVENANCE_SOURCE = (
    "def store():\n"
    "    folder = request.args.get('dir')\n"
    "    open(folder)\n"
)


def test_missing_context_does_not_borrow_a_distant_path_or_audit_sink() -> None:
    source = _PROVENANCE_SOURCE + "\n" * 40 + "def unrelated():\n    return 'safe'\n"
    summary = analyze_source_dataflow(source, "app.py")
    finding = _path_finding(line=len(source.splitlines()))

    assert summary.paths  # A real path exists, but belongs to another operation.
    assert dataflow_paths_for_finding(finding, [summary]) == []
    assert dataflow_for_finding(finding, [summary]) is None
    attach_dataflow_to_findings([finding], [summary])
    case = audit_case_from_finding(finding)
    assert case is not None
    assert case.source == case.sink == ""
    assert case.structured_dataflow == {}


@pytest.mark.parametrize("function_name", ["handle", "Beta.handle"])
def test_function_name_does_not_bind_a_sink_at_an_unrelated_location(function_name) -> None:
    source = (
        "class Beta:\n"
        "    def handle(self):\n"
        "        folder = request.args.get('dir')\n"
        "        open(folder)\n"
        "\n"
        "def handle():\n"
        "    return 'safe'\n"
    )
    summary = analyze_source_dataflow(source, "app.py")
    finding = _path_finding(line=7, metadata={"function_name": function_name})

    assert summary.paths
    assert dataflow_paths_for_finding(finding, [summary]) == []


@pytest.mark.parametrize(
    ("finding_file", "summary_files"),
    [
        ("pkg/a/app.py", ["pkg/b/app.py"]),
        ("pkg/a/app.py", ["pkg/b/app.py", "pkg/c/app.py"]),
        ("app.py", ["pkg/a/app.py", "pkg/b/app.py"]),
    ],
)
def test_file_provenance_rejects_unrelated_or_ambiguous_suffixes(
    finding_file, summary_files,
) -> None:
    summaries = [analyze_source_dataflow(_PROVENANCE_SOURCE, name) for name in summary_files]
    finding = _path_finding(file=finding_file)

    assert all(summary.paths for summary in summaries)
    assert dataflow_paths_for_finding(finding, summaries) == []


@pytest.mark.parametrize(
    ("finding_file", "summary_file"),
    [
        ("app.py", "pkg/app.py"),
        ("pkg/app.py", "workspace/pkg/app.py"),
        ("workspace/pkg/app.py", "pkg/app.py"),
        ("pkg\\app.py", "pkg/app.py"),
    ],
)
def test_unique_complete_path_suffix_keeps_exact_sink_provenance(
    finding_file, summary_file,
) -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, summary_file)
    paths = dataflow_paths_for_finding(_path_finding(file=finding_file), [summary])

    assert len(paths) == 1
    assert paths[0].file_path == summary_file
    assert paths[0].sink_line == 3


def test_exact_file_match_wins_over_other_files_with_the_same_basename() -> None:
    summaries = [
        analyze_source_dataflow(_PROVENANCE_SOURCE, name)
        for name in ("app.py", "pkg/app.py")
    ]
    paths = dataflow_paths_for_finding(_path_finding(), summaries)

    assert len(paths) == 1
    assert paths[0].file_path == "app.py"


def test_function_range_keeps_its_own_sink_without_treating_def_as_sink() -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "app.py")
    finding = _path_finding(line=1, end_line=3, metadata={"function_name": "store"})
    payload = dataflow_for_finding(finding, [summary])

    assert payload is not None
    assert payload["function"] == "store"
    assert payload["sink_line"] == 3
    assert finding.line == 1


def test_function_range_does_not_override_an_explicit_sink_location() -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "app.py")
    finding = _path_finding(
        line=1, end_line=10,
        metadata={"function_name": "store", "sink_line": 8},
    )

    assert dataflow_paths_for_finding(finding, [summary]) == []


def test_previous_enrichment_cannot_supply_its_own_location_evidence() -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "app.py")
    finding = _path_finding(line=40, metadata={"dataflow": {"sink_line": 3}})

    assert dataflow_paths_for_finding(finding, [summary]) == []


def test_summary_dictionary_key_cannot_disguise_a_different_file() -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "pkg/b/app.py")
    finding = _path_finding(file="pkg/a/app.py")

    assert dataflow_paths_for_finding(finding, {"pkg/a/app.py": summary}) == []


def test_summary_cannot_supply_a_path_from_another_file() -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "app.py")
    summary.paths = [replace(summary.paths[0], file_path="other.py")]

    assert dataflow_paths_for_finding(_path_finding(), [summary]) == []


@pytest.mark.parametrize("has_current_path", [False, True])
def test_refresh_invalidates_stale_enrichment_and_derived_hypothesis(has_current_path) -> None:
    summary = analyze_source_dataflow(_PROVENANCE_SOURCE, "app.py")
    stale = {"source": "old", "sink": "open(old)", "sink_line": 3}
    hypothesis = {"status": "strengthened", "dataflow": stale}
    finding = _path_finding(
        line=3 if has_current_path else 5132,
        metadata={"dataflow": stale, "hypothesis": hypothesis, "producer": "keep"},
    )

    attach_dataflow_to_findings([finding], [summary])
    case = audit_case_from_finding(finding)

    assert case is not None
    assert case.sink == ("open(folder)" if has_current_path else "")
    assert "hypothesis" not in finding.metadata
    assert finding.metadata["producer"] == "keep"
    assert hypothesis["dataflow"] is stale  # No mutation of shared producer metadata.
    if not has_current_path:
        assert "dataflow" not in finding.metadata


def test_refresh_preserves_hypothesis_without_dataflow_dependencies() -> None:
    finding = _path_finding(metadata={"hypothesis": {"status": "unproven"}})

    attach_dataflow_to_findings([finding], [])

    assert finding.metadata["hypothesis"] == {"status": "unproven"}


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
