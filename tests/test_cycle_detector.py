"""Call-graph cycle detector coverage."""

from __future__ import annotations

from belief.cycle_detector import (
    analyze_cycles,
    detect_cycles,
    cycles_to_findings,
    normalize_call_graph,
)
from belief.models import Finding
from belief.parser import CodeParser


def test_acyclic_graph_has_no_cycles():
    cycles = detect_cycles({
        "A": {"B"},
        "B": {"C"},
        "C": set(),
    })

    assert cycles == []


def test_self_cycle_is_detected_once():
    cycles = detect_cycles({"A": {"A"}})

    assert len(cycles) == 1
    assert cycles[0].nodes == ("A",)
    assert cycles[0].length == 1
    assert cycles[0].entry_node == "A"


def test_simple_two_node_cycle_is_canonicalized():
    cycles = detect_cycles({
        "A": {"B"},
        "B": {"A"},
    })

    assert len(cycles) == 1
    assert cycles[0].nodes == ("A", "B")


def test_three_node_cycle_is_detected():
    cycles = detect_cycles({
        "A": {"B"},
        "B": {"C"},
        "C": {"A"},
    })

    assert len(cycles) == 1
    assert cycles[0].nodes == ("A", "B", "C")
    assert cycles[0].fingerprint
    assert cycles[0].cycle_id.startswith("cycle-")


def test_rotation_duplicates_are_removed_from_edge_list():
    cycles = detect_cycles([
        ("A", "B"),
        ("B", "A"),
        ("B", "A"),
        {"caller": "B", "callee": "A"},
    ])

    assert len(cycles) == 1
    assert cycles[0].nodes == ("A", "B")


def test_two_distinct_cycles_are_returned():
    cycles = detect_cycles({
        "A": {"B"},
        "B": {"A", "C"},
        "C": {"D"},
        "D": {"C"},
    })

    assert [cycle.nodes for cycle in cycles] == [("A", "B"), ("C", "D")]


def test_output_order_is_deterministic():
    first = detect_cycles({
        "D": {"C"},
        "B": {"A", "C"},
        "C": {"D"},
        "A": {"B"},
    })
    second = detect_cycles([
        ("C", "D"),
        ("A", "B"),
        ("D", "C"),
        ("B", "C"),
        ("B", "A"),
    ])

    assert [cycle.to_dict() for cycle in first] == [cycle.to_dict() for cycle in second]


def test_normalize_call_graph_supports_missing_callee_nodes():
    graph = normalize_call_graph({"A": {"B"}})

    assert graph == {"A": {"B"}, "B": set()}


def test_cycles_to_findings_roundtrip():
    cycles = detect_cycles({"A": {"B"}, "B": {"A"}})
    findings = cycles_to_findings(cycles)

    assert len(findings) == 1
    assert findings[0].rule_id == "CALL_GRAPH_CYCLE"
    assert findings[0].severity == "info"
    assert findings[0].metadata["nodes"] == ["A", "B"]

    restored = Finding.from_dict(findings[0].to_dict())

    assert restored.fingerprint == findings[0].fingerprint
    assert restored.dedup_key == findings[0].dedup_key
    assert restored.metadata["cycle_id"] == cycles[0].cycle_id


def test_detect_cycles_accepts_code_parser_call_graph(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        """
def a():
    return b()

def b():
    return a()
""",
        encoding="utf-8",
    )
    parser = CodeParser(str(tmp_path))
    parser.parse()

    cycles = detect_cycles(parser.call_graph)

    assert len(cycles) == 1
    assert cycles[0].nodes == ("app.a", "app.b")


def test_analyze_cycles_reports_truncation_metadata():
    result = analyze_cycles({
        "A": {"B"},
        "B": {"A"},
        "C": {"D"},
        "D": {"C"},
    }, max_cycles=1)

    assert result.count == 1
    assert result.max_cycles == 1
    assert result.truncated is True
    assert result.to_metadata() == {
        "enabled": True,
        "count": 1,
        "max_cycles": 1,
        "truncated": True,
    }
