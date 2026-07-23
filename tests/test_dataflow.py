"""Local dataflow coverage using annotated real-world snippets."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from belief.dataflow import (
    analyze_source_dataflow,
    dataflow_paths_to_beliefs,
    dataflow_paths_to_hypotheses,
    find_source_to_sink_paths,
)
from belief.hypothesis_engine import attach_hypotheses_to_findings
from belief.invariant_miner import InvariantMiner
from belief.models import Finding
from belief.security_patterns import SecurityPatternExtractor


SNIPPETS = Path(__file__).parent / "real_world_snippets"


def _snippet(name: str) -> str:
    return (SNIPPETS / name).read_text(encoding="utf-8")


def _summary(name: str, file_path: str | None = None):
    file_path = file_path or name
    return analyze_source_dataflow(_snippet(name), file_path)


def _security_findings(name: str, file_path: str) -> list[Finding]:
    beliefs = SecurityPatternExtractor().extract(_snippet(name), file_path)
    return [Finding.from_belief(belief, source="security") for belief in beliefs]


def _guarantees(*items: tuple[str, str]):
    miner = InvariantMiner()
    beliefs = []
    for name, path in items:
        beliefs.extend(miner.extract(_snippet(name), path))
    return beliefs


def test_securedrop_delete_reply_links_form_filename_to_scoped_query():
    path = "securedrop/source_app/main.py"
    summary = _summary("securedrop_source_app.py", path)
    query_paths = [item for item in summary.paths if item.sink_category == "query"]

    assert len(query_paths) == 1
    query = query_paths[0]
    assert query.source.expression == 'request.form["reply_filename"]'
    assert "filter_by" in query.sink.expression
    assert query.missing_sanitizers == ()
    assert any(
        node.expression == "query.scoped_to_current_source == true"
        for node in query.guarantees
    )

    finding = Finding(
        source="manual-real-snippet",
        rule_id="IDOR_QUERY_FILENAME",
        title="Reply filename query may be unscoped",
        description="Potential IDOR if filename lookup is not scoped to the logged-in source.",
        file=path,
        line=query.sink_line,
        cwe="CWE-639",
        severity="high",
        confidence=0.9,
        evidence=query.sink.expression,
    )
    attach_hypotheses_to_findings(
        [finding],
        _guarantees(("securedrop_source_app.py", path)),
        dataflow_summaries={path: summary},
        show_dataflow=True,
    )

    hypothesis = finding.metadata["hypothesis"]
    assert hypothesis["status"] in {"weakened", "contradicted"}
    assert hypothesis["status"] != "strengthened"
    assert hypothesis["dataflow"]["source"] == 'request.form["reply_filename"]'
    assert hypothesis["dataflow"]["guarantees"] == ["query.scoped_to_current_source == true"]


def test_securedrop_reply_path_keeps_storage_path_guarantee_before_open():
    path = "securedrop/source_app/main.py"
    summary = _summary("securedrop_source_app.py", path)
    open_paths = [
        item for item in summary.paths
        if item.sink_category == "path" and "open(" in item.sink.expression
    ]

    assert len(open_paths) == 1
    open_path = open_paths[0]
    assert open_path.source.expression == 'request.form["reply_filename"]'
    assert [item.expression for item in open_path.guarantees] == [
        "storage.path.enforces_store_boundary == true"
    ]
    assert open_path.missing_sanitizers == ()
    assert open_path.review_priority == "low"

    findings = [
        finding for finding in _security_findings("securedrop_source_app.py", path)
        if finding.cwe == "CWE-22"
    ]
    assert findings
    attach_hypotheses_to_findings(
        findings,
        _guarantees(
            ("securedrop_store.py", "securedrop/store.py"),
            ("securedrop_source_app.py", path),
        ),
        dataflow_summaries={path: summary},
    )

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["status"] in {"weakened", "contradicted"}
    assert hypothesis["dataflow"]["guarantees"] == ["storage.path.enforces_store_boundary == true"]


def test_securedrop_markup_escape_is_visible_before_markup_sink():
    path = "securedrop/journalist_app/main.py"
    summary = _summary("securedrop_journalist_app.py", path)
    markup_paths = [item for item in summary.paths if item.sink_category == "template"]

    assert len(markup_paths) == 1
    markup = markup_paths[0]
    assert markup.source.expression == "display_name"
    assert markup.missing_sanitizers == ()
    assert markup.sanitizers[0].expression == "escape(display_name)"

    findings = [
        finding for finding in _security_findings("securedrop_journalist_app.py", path)
        if finding.cwe == "CWE-79"
    ]
    assert findings
    attach_hypotheses_to_findings(
        findings,
        _guarantees(("securedrop_journalist_app.py", path)),
        dataflow_summaries={path: summary},
    )

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["status"] in {"weakened", "contradicted"}
    assert hypothesis["dataflow"]["sanitizers"] == ["escape(display_name)"]


def test_flask_caching_pickle_loads_remains_high_priority_without_sanitizer():
    path = "flask_caching/backends/filesystemcache.py"
    summary = _summary("flask_caching_pickle_backend.py", path)
    pickle_paths = [item for item in summary.paths if item.sink_category == "deserialization"]

    assert len(pickle_paths) == 1
    pickle_path = pickle_paths[0]
    assert pickle_path.source.expression == "cache_file.read()"
    assert pickle_path.sanitizers == ()
    assert pickle_path.guarantees == ()
    assert pickle_path.missing_sanitizers == ("deserialization.input_trusted",)
    assert pickle_path.review_priority == "high"

    findings = [
        finding for finding in _security_findings("flask_caching_pickle_backend.py", path)
        if finding.cwe == "CWE-502"
    ]
    assert findings
    attach_hypotheses_to_findings(
        findings,
        _guarantees(("flask_caching_pickle_backend.py", path)),
        dataflow_summaries={path: summary},
    )

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["status"] == "strengthened"
    assert hypothesis["dataflow"]["review_priority"] == "high"


def test_square_header_pattern_does_not_become_exploitable_dataflow_source():
    summary = _summary("square_sdk_headers.py", "square/client.py")
    assert summary.paths == []


def test_find_source_to_sink_paths_and_optional_belief_conversion_are_deterministic():
    source = _snippet("securedrop_source_direct_path.py")
    paths = find_source_to_sink_paths(
        __import__("ast").parse(source),
        filename="securedrop/source_app/main.py",
        source_code=source,
    )
    first = dataflow_paths_to_hypotheses(paths)
    second = dataflow_paths_to_hypotheses(paths)
    beliefs = dataflow_paths_to_beliefs(paths)

    assert first == second
    assert len(paths) == 2
    assert len(beliefs) == 2
    assert all(b.source_metadata["source"] == "dataflow" for b in beliefs)


def test_cli_scan_dataflow_exports_json_and_help(tmp_path):
    project = tmp_path / "project"
    (project / "securedrop" / "source_app").mkdir(parents=True)
    (project / "securedrop").mkdir(exist_ok=True)
    (project / "securedrop" / "store.py").write_text(
        _snippet("securedrop_store.py"),
        encoding="utf-8",
    )
    (project / "securedrop" / "source_app" / "main.py").write_text(
        _snippet("securedrop_source_app.py"),
        encoding="utf-8",
    )
    output = tmp_path / "scan.json"
    project_root = Path(__file__).resolve().parents[1]

    help_result = subprocess.run(
        [sys.executable, "-m", "belief", "scan", "--help"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--dataflow" in help_result.stdout
    assert "--show-dataflow" in help_result.stdout

    scan_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "scan",
            str(project),
            "--only",
            "security",
            "--hypotheses",
            "--dataflow",
            "--show-dataflow",
            "--json-output",
            str(output),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert scan_result.returncode == 0, scan_result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["filters"]["dataflow"] is True
    assert payload["filters"]["show_dataflow"] is True
    assert payload["dataflow"]["path_count"] >= 2
    assert any(
        path["source"] == 'request.form["reply_filename"]'
        and "query.scoped_to_current_source == true" in path["guarantees"]
        for path in payload["dataflow"]["paths"]
    )
    assert any("dataflow" in finding for finding in payload["findings"])
    assert any(
        "storage.path.enforces_store_boundary == true" in finding["dataflow"]["guarantees"]
        for finding in payload["findings"]
        if "dataflow" in finding
    )
