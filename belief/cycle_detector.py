"""Lightweight call-graph cycle detection for BELIEF v4.

Works directly on CodeParser.call_graph ({caller: {callees}}) or on a small
edge list. It deliberately does not depend on the legacy dep_graph graph_core
module.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .models import Finding


@dataclass(frozen=True)
class FunctionCycle:
    """A deterministic representation of one directed function cycle."""

    cycle_id: str
    nodes: tuple[str, ...]
    length: int
    entry_node: str | None
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "nodes": list(self.nodes),
            "length": self.length,
            "entry_node": self.entry_node,
            "fingerprint": self.fingerprint,
        }


@dataclass(frozen=True)
class CycleDetectionResult:
    """Cycle analysis output with deterministic truncation metadata."""

    cycles: tuple[FunctionCycle, ...]
    max_cycles: int
    truncated: bool

    @property
    def count(self) -> int:
        return len(self.cycles)

    def to_metadata(self, *, enabled: bool = True) -> dict[str, Any]:
        return {
            "enabled": enabled,
            "count": self.count,
            "max_cycles": self.max_cycles,
            "truncated": self.truncated,
        }


CallGraphInput = Mapping[str, Iterable[str] | str | None] | Iterable[Any]


def normalize_call_graph(call_graph: CallGraphInput | None) -> dict[str, set[str]]:
    """Normalize supported call graph shapes to {node: {successors}}."""
    graph: dict[str, set[str]] = {}
    if call_graph is None:
        return graph

    if isinstance(call_graph, Mapping):
        for caller, callees in call_graph.items():
            caller_name = _node_name(caller)
            if not caller_name:
                continue
            graph.setdefault(caller_name, set())
            for callee in _iter_callees(callees):
                callee_name = _node_name(callee)
                if not callee_name:
                    continue
                graph[caller_name].add(callee_name)
                graph.setdefault(callee_name, set())
        return graph

    for edge in call_graph:
        caller, callee = _edge_endpoints(edge)
        if not caller or not callee:
            continue
        graph.setdefault(caller, set()).add(callee)
        graph.setdefault(callee, set())
    return graph


def analyze_cycles(call_graph: CallGraphInput | None, *, max_cycles: int = 1000) -> CycleDetectionResult:
    """Detect cycles and report whether the configured limit truncated output."""
    graph = normalize_call_graph(call_graph)
    limit = _coerce_max_cycles(max_cycles)
    search_limit = limit + 1 if limit >= 0 else 1
    found = _detect_cycles_normalized(graph, max_cycles=search_limit)
    truncated = len(found) > limit
    cycles = tuple(found[:limit])
    return CycleDetectionResult(
        cycles=cycles,
        max_cycles=limit,
        truncated=truncated,
    )


def detect_cycles(call_graph: CallGraphInput | None, *, max_cycles: int = 1000) -> list[FunctionCycle]:
    """Detect simple directed cycles in a call graph.

    Equivalent rotations are deduplicated. For example, A->B->A and B->A->B
    produce the same canonical cycle.
    """
    return list(analyze_cycles(call_graph, max_cycles=max_cycles).cycles)


def _detect_cycles_normalized(
    graph: dict[str, set[str]],
    *,
    max_cycles: int,
) -> list[FunctionCycle]:
    found: dict[tuple[str, ...], FunctionCycle] = {}

    for start in sorted(graph):
        _walk_cycles(
            graph=graph,
            start=start,
            current=start,
            path=[start],
            seen={start},
            found=found,
            max_cycles=max_cycles,
        )
        if len(found) >= max_cycles:
            break

    return sorted(found.values(), key=lambda cycle: (cycle.nodes, cycle.length, cycle.cycle_id))


def cycles_to_findings(
    cycles: Iterable[FunctionCycle],
    *,
    source: str = "cycle_detector",
    severity: str = "info",
    confidence: float = 0.55,
) -> list[Finding]:
    """Convert cycles to optional low-severity report Findings."""
    findings: list[Finding] = []
    for cycle in cycles:
        path = _cycle_path(cycle.nodes)
        findings.append(Finding(
            source=source,
            rule_id="CALL_GRAPH_CYCLE",
            title="Call graph cycle detected",
            description=f"Function call cycle detected: {path}",
            severity=severity,
            confidence=confidence,
            evidence=path,
            fingerprint=cycle.fingerprint,
            dedup_key=cycle.cycle_id,
            metadata={
                "cycle_id": cycle.cycle_id,
                "nodes": list(cycle.nodes),
                "length": cycle.length,
                "entry_node": cycle.entry_node,
            },
        ))
    return findings


def detect_cycle_findings(
    call_graph: CallGraphInput | None,
    *,
    max_cycles: int = 1000,
    severity: str = "info",
    confidence: float = 0.55,
) -> list[Finding]:
    result = analyze_cycles(call_graph, max_cycles=max_cycles)
    return cycles_to_findings(result.cycles, severity=severity, confidence=confidence)


def detect_cycle_findings_with_metadata(
    call_graph: CallGraphInput | None,
    *,
    max_cycles: int = 1000,
    severity: str = "info",
    confidence: float = 0.55,
) -> tuple[list[Finding], dict[str, Any]]:
    """Return cycle findings plus report-ready metadata."""
    result = analyze_cycles(call_graph, max_cycles=max_cycles)
    findings = cycles_to_findings(
        result.cycles,
        severity=severity,
        confidence=confidence,
    )
    return findings, result.to_metadata(enabled=True)


def _walk_cycles(
    *,
    graph: dict[str, set[str]],
    start: str,
    current: str,
    path: list[str],
    seen: set[str],
    found: dict[tuple[str, ...], FunctionCycle],
    max_cycles: int,
) -> None:
    if len(found) >= max_cycles:
        return

    for neighbor in sorted(graph.get(current, ())):
        if neighbor == start:
            canonical = _canonical_cycle(path)
            found.setdefault(canonical, _make_cycle(canonical))
            if len(found) >= max_cycles:
                return
            continue

        if neighbor in seen:
            continue

        seen.add(neighbor)
        path.append(neighbor)
        _walk_cycles(
            graph=graph,
            start=start,
            current=neighbor,
            path=path,
            seen=seen,
            found=found,
            max_cycles=max_cycles,
        )
        path.pop()
        seen.remove(neighbor)


def _canonical_cycle(nodes: list[str]) -> tuple[str, ...]:
    if len(nodes) <= 1:
        return tuple(nodes)
    rotations = [
        tuple(nodes[index:] + nodes[:index])
        for index in range(len(nodes))
    ]
    return min(rotations)


def _make_cycle(nodes: tuple[str, ...]) -> FunctionCycle:
    payload = json.dumps(list(nodes), separators=(",", ":"), ensure_ascii=True)
    fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return FunctionCycle(
        cycle_id=f"cycle-{fingerprint}",
        nodes=nodes,
        length=len(nodes),
        entry_node=nodes[0] if nodes else None,
        fingerprint=fingerprint,
    )


def _iter_callees(value: Iterable[str] | str | None) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return value


def _node_name(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _edge_endpoints(edge: Any) -> tuple[str, str]:
    if isinstance(edge, Mapping):
        caller = edge.get("caller") or edge.get("src") or edge.get("source")
        callee = edge.get("callee") or edge.get("dst") or edge.get("target")
        return _node_name(caller), _node_name(callee)

    if isinstance(edge, (tuple, list)) and len(edge) >= 2:
        return _node_name(edge[0]), _node_name(edge[1])

    caller = (
        getattr(edge, "caller", None)
        or getattr(edge, "src", None)
        or getattr(edge, "source", None)
    )
    callee = (
        getattr(edge, "callee", None)
        or getattr(edge, "dst", None)
        or getattr(edge, "target", None)
    )
    return _node_name(caller), _node_name(callee)


def _cycle_path(nodes: tuple[str, ...]) -> str:
    if not nodes:
        return ""
    return " -> ".join((*nodes, nodes[0]))


def _coerce_max_cycles(max_cycles: int) -> int:
    try:
        return max(0, int(max_cycles))
    except (TypeError, ValueError):
        return 1000


__all__ = [
    "CycleDetectionResult",
    "FunctionCycle",
    "normalize_call_graph",
    "analyze_cycles",
    "detect_cycles",
    "cycles_to_findings",
    "detect_cycle_findings",
    "detect_cycle_findings_with_metadata",
]
