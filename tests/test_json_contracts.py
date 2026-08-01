"""Strict interchange tests for model, importer, and tool trust boundaries."""

from __future__ import annotations

import json

import pytest

from belief.importers.bandit_json import import_bandit_json
from belief.json_contracts import (
    StrictJSONError,
    load_json_file,
    strict_json_dumps,
    strict_json_loads,
)
from belief.models import (
    AnalysisReport,
    Belief,
    Finding,
    JustificationCategory,
    ModelContractError,
    Predicate,
    Scope,
)
from belief.tools.errors import ToolManifestError
from belief.tools.manifest import manifest_from_dict
from belief.validation.models import ValidationResult


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_strict_json_rejects_nonfinite_constants(token):
    with pytest.raises(StrictJSONError, match="non-finite"):
        strict_json_loads(f'{{"value": {token}}}')


def test_strict_json_rejects_duplicate_keys():
    with pytest.raises(StrictJSONError, match="duplicate"):
        strict_json_loads('{"decision": "allow", "decision": "deny"}')


def test_strict_json_rejects_invalid_utf8():
    with pytest.raises(StrictJSONError, match="UTF-8"):
        strict_json_loads(b'{"value":"\xff"}')


def test_bounded_json_file_is_rejected_before_parse(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b'{"padding":"' + b"x" * 64 + b'"}')
    with pytest.raises(StrictJSONError, match="exceeds"):
        load_json_file(path, max_bytes=16)


def test_strict_json_dumps_rejects_nested_nan():
    with pytest.raises(StrictJSONError, match="non-finite"):
        strict_json_dumps({"nested": [float("nan")]})


def test_belief_rejects_nan_confidence():
    with pytest.raises(ModelContractError, match="finite"):
        Belief(
            predicate=Predicate(expression="x > 0"),
            scope=Scope(file_path="a.py"),
            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
            confidence_score=float("nan"),
        )


def test_finding_rejects_infinite_confidence():
    with pytest.raises(ModelContractError, match="finite"):
        Finding(confidence=float("inf"))


def test_validation_result_rejects_unknown_outcome_and_nan():
    with pytest.raises(ValueError, match="unsupported validation outcome"):
        ValidationResult(
            subject_id="case",
            subject_kind="audit_case",
            source="test",
            outcome="probably_safe",
        )
    with pytest.raises(ValueError, match="finite"):
        ValidationResult(
            subject_id="case",
            subject_kind="audit_case",
            source="test",
            outcome="unknown",
            confidence=float("nan"),
        )


def test_validation_result_does_not_coerce_string_booleans():
    with pytest.raises(ValueError, match="must be booleans"):
        ValidationResult.from_dict({
            "subject_id": "case",
            "subject_kind": "audit_case",
            "source": "test",
            "outcome": "unknown",
            "tested": "false",
        })


def test_unversioned_legacy_c1_migrates_to_runtime_guard():
    belief = Belief.from_dict({
        "predicate": {"expression": "x > 0"},
        "scope": {"file_path": "a.py"},
        "justification": "C1",
    })
    assert belief.justification is JustificationCategory.C3_EXPLICIT_RUNTIME_GUARD
    diagnostics = belief.source_metadata["deserialization_diagnostics"]
    assert diagnostics[0]["migration"] == "C1->C3_EXPLICIT_RUNTIME_GUARD"


def test_report_load_records_enum_abstention(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({
            "project_name": "strict",
            "beliefs": [
                {
                    "predicate": {"expression": "x > 0"},
                    "scope": {"file_path": "ok.py"},
                    "justification": "C5",
                },
                {
                    "predicate": {"expression": "y > 0"},
                    "scope": {"file_path": "bad.py"},
                    "justification": "NOT_A_CATEGORY",
                },
            ],
        }),
        encoding="utf-8",
    )
    report = AnalysisReport.load(str(path))
    assert len(report.beliefs) == 1
    assert report.run_metadata["load_diagnostics"][0]["code"] == (
        "belief_deserialization_abstained"
    )


def test_first_party_importer_rejects_nonfinite_json(tmp_path):
    path = tmp_path / "bandit.json"
    path.write_text('{"results": [], "generated_at": NaN}', encoding="utf-8")
    with pytest.raises(StrictJSONError, match="non-finite"):
        import_bandit_json(path)


def test_tool_manifest_rejects_unknown_execution_mode():
    with pytest.raises(ToolManifestError, match="unknown execution_mode"):
        manifest_from_dict({
            "tool_id": "bad",
            "name": "Bad",
            "description": "bad mode",
            "execution_mode": "run_anything",
            "risk": {},
        })


def test_tool_manifest_rejects_string_boolean():
    with pytest.raises(ToolManifestError, match="must be boolean"):
        manifest_from_dict({
            "tool_id": "bad",
            "name": "Bad",
            "description": "bad boolean",
            "execution_mode": "passive_import",
            "risk": {"network": "false"},
        })
