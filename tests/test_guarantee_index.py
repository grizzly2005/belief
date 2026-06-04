"""Cross-file guarantee propagation using annotated SecureDrop snippets."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.guarantee_index import (
    attach_called_function_guarantees,
    build_guarantee_index,
    lookup_guarantees_for_call,
)
from belief.hypothesis_engine import attach_hypotheses_to_findings
from belief.invariant_miner import InvariantMiner
from belief.models import Finding
from belief.security_patterns import SecurityPatternExtractor

pytestmark = pytest.mark.security

SNIPPETS = Path(__file__).parent / "real_world_snippets"


def _snippet(name: str) -> str:
    return (SNIPPETS / name).read_text(encoding="utf-8")


def _path_finding(source: str, file_path: str) -> Finding:
    beliefs = SecurityPatternExtractor().extract(source, file_path)
    findings = [Finding.from_belief(belief, source="security") for belief in beliefs]
    path_findings = [finding for finding in findings if finding.cwe == "CWE-22"]
    assert path_findings
    return path_findings[0]


def test_guarantee_index_detects_storage_path_guarantees_from_securedrop_store():
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
    })

    guarantees = lookup_guarantees_for_call("Storage.path", index)
    expressions = {belief.predicate.expression for belief in guarantees}

    assert "storage.path.enforces_store_boundary == true" in expressions
    assert "path.is_normalized == true" in expressions
    assert "path.is_within_store == true" in expressions
    assert "filename.matches_allowed_pattern == true" in expressions
    assert all((belief.source_metadata or {}).get("propagated") for belief in guarantees)


def test_chained_call_storage_get_default_path_matches_storage_path():
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
    })

    guarantees = lookup_guarantees_for_call("Storage.get_default().path", index)

    assert any(
        (belief.source_metadata or {}).get("registered_function") == "storage.path"
        for belief in guarantees
    )
    assert any(
        belief.predicate.expression == "storage.path.enforces_store_boundary == true"
        for belief in guarantees
    )


def test_reply_path_assignment_receives_storage_path_guarantees():
    source = _snippet("securedrop_source_app.py")
    finding = _path_finding(source, "source_app/main.py")
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
        "source_app/main.py": source,
    })

    guarantees = attach_called_function_guarantees(finding, source, index)
    expressions = {belief.predicate.expression for belief in guarantees}

    assert "storage.path.enforces_store_boundary == true" in expressions
    assert "path.is_within_store == true" in expressions
    assert all((belief.source_metadata or {}).get("propagated_to_finding_id") == finding.id for belief in guarantees)


def test_securedrop_reply_path_hypothesis_is_no_longer_strengthened():
    source = _snippet("securedrop_source_app.py")
    finding = _path_finding(source, "source_app/main.py")
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
        "source_app/main.py": source,
    })
    guarantees = InvariantMiner().extract(source, "source_app/main.py") + index.all_guarantees

    attach_hypotheses_to_findings(
        [finding],
        guarantees,
        show_proofs=True,
        guarantee_index=index,
        local_contexts={"source_app/main.py": source},
    )

    hypothesis = finding.metadata["hypothesis"]
    assert hypothesis["status"] in {"weakened", "contradicted"}
    assert len(hypothesis["guarantee_beliefs"]) > 0
    assert any(
        guarantee["registered_function"] == "storage.path"
        for guarantee in hypothesis["guarantee_beliefs"]
    )


def test_missing_storage_path_definition_keeps_reply_path_strengthened():
    source = _snippet("securedrop_source_app.py")
    finding = _path_finding(source, "source_app/main.py")
    index = build_guarantee_index({
        "source_app/main.py": source,
    })
    guarantees = InvariantMiner().extract(source, "source_app/main.py")

    attach_hypotheses_to_findings(
        [finding],
        guarantees,
        guarantee_index=index,
        local_contexts={"source_app/main.py": source},
    )

    hypothesis = finding.metadata["hypothesis"]
    assert hypothesis["status"] == "strengthened"
    assert hypothesis["guarantee_beliefs"] == []


def test_direct_open_storage_path_receives_propagated_guarantee():
    source = _snippet("securedrop_source_direct_path.py")
    finding = Finding(
        source="manual-real-snippet",
        rule_id="CWE-22",
        title="Potential path traversal",
        description="File operation with direct Storage.path call.",
        file="source_app/main.py",
        line=8,
        cwe="CWE-22",
        severity="high",
        confidence=0.88,
        evidence=source,
    )
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
        "source_app/main.py": source,
    })

    guarantees = attach_called_function_guarantees(finding, source, index)

    assert any(
        belief.predicate.expression == "storage.path.enforces_store_boundary == true"
        for belief in guarantees
    )


def test_cli_source_app_scan_resolves_parent_store_and_exports_propagated_json(tmp_path):
    project = tmp_path / "securedrop"
    source_app = project / "source_app"
    source_app.mkdir(parents=True)
    (project / "store.py").write_text(_snippet("securedrop_store.py"), encoding="utf-8")
    (source_app / "main.py").write_text(_snippet("securedrop_source_app.py"), encoding="utf-8")
    output = tmp_path / "scan.json"
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "scan",
            str(source_app),
            "--only",
            "security",
            "--hypotheses",
            "--show-proofs",
            "--json-output",
            str(output),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    path_findings = [
        finding for finding in payload["findings"]
        if finding.get("cwe") == "CWE-22" and finding.get("file") == "main.py"
    ]
    assert path_findings
    hypothesis = path_findings[0]["hypothesis"]
    assert hypothesis["status"] in {"weakened", "contradicted"}
    assert any(
        guarantee["propagated"]
        and guarantee["registered_function"] == "storage.path"
        for guarantee in hypothesis["guarantee_beliefs"]
    )


def test_propagated_guarantee_order_is_deterministic():
    source = _snippet("securedrop_source_app.py")
    finding = _path_finding(source, "source_app/main.py")
    index = build_guarantee_index({
        "store.py": _snippet("securedrop_store.py"),
        "source_app/main.py": source,
    })

    first = [
        belief.to_dict()
        for belief in attach_called_function_guarantees(finding, source, index)
    ]
    second = [
        belief.to_dict()
        for belief in attach_called_function_guarantees(finding, source, index)
    ]

    assert first == second
