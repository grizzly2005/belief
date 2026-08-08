"""Bandit informational-code filtering regressions.

These tests never invoke the bandit binary. They exercise the pure
classification and filtering surface so the behavior is pinned even on a
machine where the bridge reports `missing`.
"""

from __future__ import annotations

import pytest

from belief.bridges import BridgeResult
from belief.bridges.bandit_bridge import (
    BANDIT_INFORMATIONAL_TEST_IDS,
    _apply_informational_filter,
    is_informational,
    to_belief,
)

pytestmark = pytest.mark.security


def _finding(test_id: str, **overrides) -> dict:
    finding = {
        "test_id": test_id,
        "test_name": "sample",
        "issue_text": "sample issue",
        "issue_severity": "LOW",
        "issue_confidence": "HIGH",
        "filename": "app/service.py",
        "line_number": 12,
    }
    finding.update(overrides)
    return finding


def test_import_only_and_hygiene_codes_are_informational():
    assert is_informational(_finding("B101"))  # assert_used
    assert is_informational(_finding("B110"))  # try_except_pass
    assert is_informational(_finding("B404"))  # import_subprocess
    assert is_informational(_finding("B403"))  # import_pickle


def test_real_sinks_are_never_informational():
    for test_id in ("B301", "B307", "B310", "B602", "B603", "B607", "B608"):
        assert not is_informational(_finding(test_id)), test_id


def test_use_checks_are_kept_when_their_import_twin_is_dropped():
    """B403/B405-B411 are dropped; the matching use checks must survive."""
    for import_id, use_id in (
        ("B403", "B301"),  # import_pickle  -> pickle
        ("B405", "B313"),  # import_xml_etree -> xml_bad_cElementTree
        ("B406", "B317"),  # import_xml_sax -> xml_bad_sax
    ):
        assert is_informational(_finding(import_id))
        assert not is_informational(_finding(use_id))


def test_unknown_and_malformed_test_ids_are_kept():
    assert not is_informational(_finding("B999"))
    assert not is_informational({})
    assert not is_informational({"test_id": None})


def test_filter_drops_informational_and_reports_counts():
    result = BridgeResult(source="bandit")
    result.findings = [
        _finding("B101"),
        _finding("B404"),
        _finding("B608"),
    ]

    _apply_informational_filter(result, True)

    assert [f["test_id"] for f in result.findings] == ["B608"]
    assert result.metadata["informational_available"] == 2
    assert result.metadata["informational_dropped"] == 2
    assert result.metadata["informational_test_ids"] == ["B101", "B404"]


def test_filter_disabled_keeps_findings_but_still_accounts_for_them():
    result = BridgeResult(source="bandit")
    result.findings = [_finding("B101"), _finding("B608")]

    _apply_informational_filter(result, False)

    assert [f["test_id"] for f in result.findings] == ["B101", "B608"]
    assert result.metadata["informational_available"] == 1
    assert result.metadata["informational_dropped"] == 0


def test_filter_is_a_no_op_when_nothing_is_informational():
    result = BridgeResult(source="bandit")
    result.findings = [_finding("B608"), _finding("B310")]

    _apply_informational_filter(result, True)

    assert len(result.findings) == 2
    assert result.metadata["informational_available"] == 0
    assert result.metadata["informational_test_ids"] == []


def test_to_belief_labels_informational_findings():
    """A caller that bypasses run_bandit still learns the classification."""
    assert to_belief(_finding("B101"))["informational"] is True
    assert to_belief(_finding("B608"))["informational"] is False


def test_to_belief_still_maps_cwe_for_kept_sinks():
    assert to_belief(_finding("B608"))["cwe"] == "CWE-89"
    assert to_belief(_finding("B310"))["cwe"] == "CWE-918"


def test_informational_set_declares_no_cwe_bearing_sink():
    """Guard against an informational entry silently shadowing a CWE mapping."""
    for test_id in BANDIT_INFORMATIONAL_TEST_IDS:
        assert to_belief(_finding(test_id))["cwe"] == "", test_id
