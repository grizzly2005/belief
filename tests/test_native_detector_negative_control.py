from __future__ import annotations

from pathlib import Path

import pytest

from belief.benchmark.native_negative_control import (
    NegativeControlLimits,
    evaluate_native_negative_control,
)


pytestmark = pytest.mark.security


def test_negative_control_passes_with_quiet_deterministic_detector(
    tmp_path: Path,
) -> None:
    (tmp_path / "quiet.py").write_text("value = 1\n", encoding="utf-8")

    result = evaluate_native_negative_control(
        tmp_path,
        detectors={"quiet": lambda _source, _file: []},
    )

    assert result["status"] == "PASS"
    assert result["file_count"] == 1
    assert result["metrics"] == {
        "corpus_error_count": 0,
        "crash_count": 0,
        "high_confidence_file_count": 0,
        "high_confidence_file_rate": 0.0,
    }
    assert "does not establish" in result["claim_boundary"]


def test_negative_control_fails_closed_on_crash_and_high_confidence_signal(
    tmp_path: Path,
) -> None:
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("value = 2\n", encoding="utf-8")

    def crashing(_source: str, filename: str):
        if filename == "a.py":
            raise IndexError("implementation detail")
        return [{"rule_id": "TEST", "line": 1, "confidence": 0.9}]

    result = evaluate_native_negative_control(
        tmp_path,
        detectors={"probe": crashing},
        limits=NegativeControlLimits(max_high_confidence_file_rate=0.0),
    )

    assert result["status"] == "FAIL"
    assert result["metrics"] == {
        "corpus_error_count": 0,
        "crash_count": 1,
        "high_confidence_file_count": 1,
        "high_confidence_file_rate": 0.5,
    }
    assert result["detectors"]["probe"]["samples"] == [
        {"file": "a.py", "kind": "crash", "exception_type": "IndexError"},
        {"file": "b.py", "kind": "finding", "line": 1, "rule_id": "TEST"},
    ]


def test_negative_control_rejects_empty_or_over_budget_corpus(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no Python files"):
        evaluate_native_negative_control(tmp_path, detectors={"quiet": lambda *_: []})

    (tmp_path / "one.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="max_files"):
        evaluate_native_negative_control(
            tmp_path,
            detectors={"quiet": lambda *_: []},
            limits=NegativeControlLimits(max_files=1),
        )
