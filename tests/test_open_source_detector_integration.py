from __future__ import annotations

import re
from pathlib import Path

import pytest

from belief import static_analysis_pipeline
from belief.bridges import (
    download_destination_bridge,
    orm_identifier_bridge,
    path_traversal_bridge,
)
from belief.benchmark.open_source_pairs import load_open_source_pairs_manifest
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target


pytestmark = pytest.mark.security

DETECTOR_SOURCES = {"download_destination", "orm_identifier", "path_boundary"}


def _analyze(tmp_path: Path, source: str):
    target = tmp_path / "module.py"
    target.write_text(source, encoding="utf-8")
    return analyze_static_target(
        tmp_path,
        StaticAnalysisOptions(
            selected_categories=frozenset({"security"}),
            include_audit_cases=True,
            audit_mode=True,
            reportability=True,
        ),
    )


@pytest.mark.parametrize(
    ("source", "detector", "case_type", "line"),
    [
        (
            '''
def build_path(input_value, trusted_root):
    leaf, fragment = derive_leaf(input_value)
    candidate = os.path.join(trusted_root, leaf)
    return candidate
''',
            "path_boundary",
            "path_traversal_possible",
            5,
        ),
        (
            '''
def aggregate(self, fields):
    actions = [
        FieldAction(field_name=value, model=self.model)
        for value in fields
    ]
    return [action.apply_func(sum) for action in actions]
''',
            "orm_identifier",
            "sql_injection_possible",
            7,
        ),
        (
            '''
def receive(resource, output_dir):
    local_name = resource.original_filename
    return queue_download((output_dir, local_name))
''',
            "download_destination",
            "path_traversal_possible",
            4,
        ),
    ],
)
def test_native_detectors_reach_pipeline_audit_cases(
    tmp_path: Path,
    source: str,
    detector: str,
    case_type: str,
    line: int,
) -> None:
    result = _analyze(tmp_path, source)

    findings = [
        finding for finding in result.findings if finding.source == detector
    ]
    cases = [
        case
        for case in result.audit_cases
        if case.case_type == case_type and case.line == line
    ]
    assert len(findings) == 1
    assert len(cases) == 1
    assert findings[0].metadata["dataflow"]["source"]
    assert findings[0].metadata["dataflow"]["sink"]
    assert findings[0].metadata["dataflow"]["guarantees"] == []
    assert findings[0].metadata["dataflow"]["sanitizers"] == []
    assert cases[0].source
    assert cases[0].sink
    assert cases[0].structured_dataflow["source"]["line"] is not None
    assert cases[0].structured_dataflow["sink"]["line"] == line
    assert cases[0].status in {"actionable", "needs_review"}


@pytest.mark.parametrize(
    ("source", "detector"),
    [
        (
            '''
def build_path(input_value, trusted_root):
    candidate = (Path(trusted_root) / input_value).resolve()
    if not candidate.is_relative_to(trusted_root):
        raise ValueError("outside root")
    return candidate
''',
            "path_boundary",
        ),
        (
            '''
def aggregate(self, fields):
    actions = [
        FieldAction(field_name=value, model=self.model)
        for value in fields
    ]
    if any(
        action.field_name not in action.target_model.model_fields
        for action in actions
    ):
        raise ValueError("unknown field")
    return [action.apply_func(sum) for action in actions]
''',
            "orm_identifier",
        ),
        (
            '''
def receive(resource, output_dir):
    remote_name = resource.original_filename
    local_name = os.path.basename(remote_name)
    return queue_download((output_dir, local_name))
''',
            "download_destination",
        ),
    ],
)
def test_effective_guards_suppress_only_the_matching_native_detector(
    tmp_path: Path,
    source: str,
    detector: str,
) -> None:
    result = _analyze(tmp_path, source)

    assert detector not in {finding.source for finding in result.findings}


def test_native_detector_output_is_semantically_deterministic(tmp_path: Path) -> None:
    source = '''
def receive(resource, output_dir):
    local_name = resource.original_filename
    return queue_download((output_dir, local_name))
'''

    first = _analyze(tmp_path, source).to_dict()
    second = _analyze(tmp_path, source).to_dict()

    assert first == second


def test_native_detector_provenance_is_authoritative_and_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spoofed = {
        "rule_id": "TEST-RULE",
        "title": "duplicate",
        "description": "duplicate",
        "file": "module.py",
        "line": 3,
        "source": "spoofed-source",
        "dedup_key": "same-native-finding",
        "metadata": {
            "category": "spoofed-category",
            "native_static_detector": "spoofed-detector",
        },
    }
    monkeypatch.setattr(
        download_destination_bridge,
        "scan_source",
        lambda _source, _file: [spoofed, dict(spoofed)],
    )
    monkeypatch.setattr(
        orm_identifier_bridge,
        "scan_source",
        lambda _source, _file: [],
    )
    monkeypatch.setattr(
        path_traversal_bridge,
        "scan_source",
        lambda _source, _file: [],
    )

    records, diagnostics = static_analysis_pipeline._native_security_records(
        "pass",
        "module.py",
    )

    assert diagnostics == []
    assert len(records) == 1
    assert records[0].category == "security"
    assert records[0].finding.source == "download_destination"
    assert records[0].finding.metadata["category"] == "security"
    assert (
        records[0].finding.metadata["native_static_detector"]
        == "download_destination"
    )


def test_native_detectors_do_not_change_the_historical_default_profile(
    tmp_path: Path,
) -> None:
    target = tmp_path / "module.py"
    target.write_text(
        """
import os

def read_asset(root, key):
    return open(os.path.join(root, key)).read()
""",
        encoding="utf-8",
    )

    result = analyze_static_target(
        target,
        StaticAnalysisOptions(selected_categories=frozenset({"security"})),
    )

    assert not ({finding.source for finding in result.findings} & DETECTOR_SOURCES)


def test_native_detector_failure_is_isolated_as_a_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(_source: str, _file: str) -> list[dict[str, object]]:
        raise IndexError("detector implementation detail")

    monkeypatch.setattr(download_destination_bridge, "scan_source", crash)
    monkeypatch.setattr(orm_identifier_bridge, "scan_source", lambda *_args: [])
    monkeypatch.setattr(path_traversal_bridge, "scan_source", lambda *_args: [])

    records, diagnostics = static_analysis_pipeline._native_security_records(
        "pass",
        "module.py",
    )

    assert records == []
    assert [item.to_dict() for item in diagnostics] == [
        {
            "code": "native_detector_failed",
            "message": "Native security detector failed: download_destination",
            "file": "module.py",
            "details": {
                "detector": "download_destination",
                "exception_type": "IndexError",
            },
        }
    ]


@pytest.mark.parametrize("malformed", [None, [None], [{"rule_id": "PARTIAL"}, None]])
def test_malformed_detector_output_is_discarded_without_losing_other_detectors(
    monkeypatch: pytest.MonkeyPatch,
    malformed: object,
) -> None:
    monkeypatch.setattr(download_destination_bridge, "scan_source", lambda *_: malformed)
    monkeypatch.setattr(
        orm_identifier_bridge,
        "scan_source",
        lambda *_: [{"rule_id": "SURVIVES", "file": "module.py", "line": 2}],
    )
    monkeypatch.setattr(path_traversal_bridge, "scan_source", lambda *_: [])

    records, diagnostics = static_analysis_pipeline._native_security_records("pass", "module.py")

    assert [record.finding.rule_id for record in records] == ["SURVIVES"]
    assert len(diagnostics) == 1
    assert diagnostics[0].code == "native_detector_failed"
    assert diagnostics[0].details == {
        "detector": "download_destination",
        "exception_type": "TypeError",
    }


def test_production_detectors_contain_no_benchmark_fingerprints() -> None:
    root = Path(__file__).resolve().parents[1]
    detector_paths = (
        root / "belief" / "bridges" / "download_destination_bridge.py",
        root / "belief" / "bridges" / "orm_identifier_bridge.py",
        root / "belief" / "bridges" / "path_traversal_bridge.py",
    )
    manifest = load_open_source_pairs_manifest(
        root / "benchmark_open_source_pairs" / "cases-recovery-v2.json"
    )
    forbidden_literals = {"github.com/advisories"}
    for case in manifest["cases"]:
        forbidden_literals.update({
            str(case["advisory_url"]).lower(),
            str(case["checkout_dir"]).lower(),
            str(case["cve_id"]).lower(),
            str(case["fixed_revision"]).lower(),
            str(case["id"]).lower(),
            str(case["project"]).lower(),
            str(case["vulnerable_revision"]).lower(),
        })
        for target in case["targets"]:
            target_path = str(target["path"]).lower()
            forbidden_literals.update({
                target_path,
                Path(target_path).name,
                str(target["fixed_sha256"]).lower(),
                str(target["vulnerable_sha256"]).lower(),
            })
    violations: list[str] = []
    for path in detector_paths:
        source = path.read_text(encoding="utf-8").lower()
        for token in sorted(forbidden_literals):
            if token in source:
                violations.append(f"{path.name}: literal {token}")
        if re.search(r"\bCVE-\d{4}-\d+\b", source, re.IGNORECASE):
            violations.append(f"{path.name}: CVE-shaped literal")
        if re.search(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", source):
            violations.append(f"{path.name}: commit-shaped literal")
        if re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", source):
            violations.append(f"{path.name}: digest-shaped literal")

    assert not violations, "\n".join(violations)
