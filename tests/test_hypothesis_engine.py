"""Hypothesis engine coverage using annotated real-world snippets."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.hypothesis_engine import (
    attach_hypotheses_to_findings,
    filter_findings_by_hypothesis_status,
)
from belief.invariant_miner import InvariantMiner
from belief.models import Finding
from belief.security_patterns import SecurityPatternExtractor

pytestmark = pytest.mark.security
pytest.importorskip("z3", reason="z3-solver is required for hypothesis counter-proof tests")

SNIPPETS = Path(__file__).parent / "real_world_snippets"


def _snippet(name: str) -> str:
    return (SNIPPETS / name).read_text(encoding="utf-8")


def _security_findings(name: str, file_path: str) -> list[Finding]:
    beliefs = SecurityPatternExtractor().extract(_snippet(name), file_path)
    return [Finding.from_belief(belief, source="security") for belief in beliefs]


def _guarantees(*items: tuple[str, str]):
    miner = InvariantMiner()
    mined = []
    for name, path in items:
        mined.extend(miner.extract(_snippet(name), path))
    return mined


def test_path_traversal_hypothesis_is_contradicted_by_securedrop_store_boundary():
    findings = [
        finding for finding in _security_findings(
            "securedrop_source_app.py",
            "securedrop/source_app/main.py",
        )
        if finding.cwe == "CWE-22"
    ]
    assert findings
    guarantees = _guarantees(
        ("securedrop_store.py", "securedrop/store.py"),
        ("securedrop_source_app.py", "securedrop/source_app/main.py"),
    )

    attach_hypotheses_to_findings(findings, guarantees, show_proofs=True)

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["hypothesis_type"] == "path_traversal_possible"
    assert hypothesis["status"] == "contradicted"
    assert hypothesis["z3"]["status"] == "unsat"
    assert any(
        guarantee["expression"] == "storage.path.enforces_store_boundary == true"
        for guarantee in hypothesis["guarantee_beliefs"]
    )


def test_xss_hypothesis_is_contradicted_by_escape_markup_pattern():
    findings = [
        finding for finding in _security_findings(
            "securedrop_journalist_app.py",
            "securedrop/journalist_app/main.py",
        )
        if finding.cwe == "CWE-79"
    ]
    assert findings
    guarantees = _guarantees(
        ("securedrop_journalist_app.py", "securedrop/journalist_app/main.py"),
    )

    attach_hypotheses_to_findings(findings, guarantees, show_proofs=True)

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["hypothesis_type"] == "xss_possible"
    assert hypothesis["status"] == "contradicted"
    assert hypothesis["z3"]["status"] == "unsat"
    assert hypothesis["missing_guarantees"] == []


def test_flask_caching_pickle_hypothesis_stays_strengthened_without_guarantee():
    findings = [
        finding for finding in _security_findings(
            "flask_caching_pickle_backend.py",
            "flask_caching/backends/filesystemcache.py",
        )
        if finding.cwe == "CWE-502"
    ]
    assert findings
    guarantees = _guarantees(
        ("flask_caching_pickle_backend.py", "flask_caching/backends/filesystemcache.py"),
    )

    attach_hypotheses_to_findings(findings, guarantees)

    hypothesis = findings[0].metadata["hypothesis"]
    assert hypothesis["hypothesis_type"] == "unsafe_deserialization_possible"
    assert hypothesis["status"] == "strengthened"
    assert "trusted deserialization boundary or safe loader proof" in hypothesis["missing_guarantees"]
    assert hypothesis["z3"]["checked"] is False


def test_square_sdk_hardcoded_credential_false_positive_is_weakened_by_header_context():
    snippet = _snippet("square_sdk_headers.py")
    assert "Authorization" in snippet
    finding = Finding(
        source="manual-real-snippet",
        rule_id="CWE-798",
        title="Hardcoded credential candidate",
        description="Square SDK Authorization header pattern looked like a credential.",
        file="square/client.py",
        line=4,
        cwe="CWE-798",
        severity="high",
        confidence=0.88,
        evidence=snippet,
    )
    guarantees = _guarantees(("square_sdk_headers.py", "square/client.py"))

    attach_hypotheses_to_findings([finding], guarantees)

    hypothesis = finding.metadata["hypothesis"]
    assert hypothesis["hypothesis_type"] == "hardcoded_credential_possible"
    assert hypothesis["status"] == "weakened"
    assert hypothesis["missing_guarantees"] == []
    assert any(
        guarantee["expression"] == "credential.value_is_header_name == true"
        for guarantee in hypothesis["guarantee_beliefs"]
    )


def test_filter_findings_by_hypothesis_status_is_deterministic():
    path_findings = [
        finding for finding in _security_findings(
            "securedrop_source_app.py",
            "securedrop/source_app/main.py",
        )
        if finding.cwe == "CWE-22"
    ]
    deser_findings = [
        finding for finding in _security_findings(
            "flask_caching_pickle_backend.py",
            "flask_caching/backends/filesystemcache.py",
        )
        if finding.cwe == "CWE-502"
    ]
    findings = path_findings[:1] + deser_findings[:1]
    guarantees = _guarantees(
        ("securedrop_store.py", "securedrop/store.py"),
        ("flask_caching_pickle_backend.py", "flask_caching/backends/filesystemcache.py"),
    )
    attach_hypotheses_to_findings(findings, guarantees)

    contradicted = filter_findings_by_hypothesis_status(findings, "contradicted")
    strengthened = filter_findings_by_hypothesis_status(findings, "strengthened")

    assert [finding.cwe for finding in contradicted] == ["CWE-22"]
    assert [finding.cwe for finding in strengthened] == ["CWE-502"]


def test_hypothesis_metadata_round_trips_in_finding_json():
    finding = _security_findings(
        "flask_caching_pickle_backend.py",
        "flask_caching/backends/filesystemcache.py",
    )[0]
    attach_hypotheses_to_findings([finding], [])

    encoded = finding.to_dict()
    decoded = Finding.from_dict(json.loads(json.dumps(encoded)))

    assert decoded.metadata["hypothesis"]["hypothesis_type"] == "unsafe_deserialization_possible"
    assert decoded.metadata["hypothesis"]["status"] == "strengthened"


def test_cli_scan_exports_top_level_hypothesis_json(tmp_path):
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

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "scan",
            str(project),
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
    assert payload["filters"]["hypotheses"] is True
    assert payload["filters"]["show_proofs"] is True
    assert any("hypothesis" in finding for finding in payload["findings"])
    assert any(
        finding["hypothesis"]["status"] == "contradicted"
        for finding in payload["findings"]
        if "hypothesis" in finding
    )
