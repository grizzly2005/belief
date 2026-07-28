"""Read-first MCP tools backed by BELIEF's existing application services."""

from __future__ import annotations

import copy
import re
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from belief.static_analysis_pipeline import (
    STATIC_ANALYSIS_CATEGORIES,
    StaticAnalysisOptions,
    analyze_static_target,
)
from belief.validation.benchmark import run_local_validation_benchmark
from belief.validation.plan_models import canonical_digest
from belief.validation.plans import build_validation_plan

from .contracts import (
    MCP_COMPARISON_SCHEMA_VERSION,
    MCP_EXPLANATION_SCHEMA_VERSION,
    MCP_RUN_SCHEMA_VERSION,
    MCP_SCAN_RESPONSE_SCHEMA_VERSION,
    PUBLIC_SCHEMAS,
    resource_template_definitions,
    static_resource_definitions,
    status_payload,
    tool_definitions,
)

_RUN_URI = re.compile(
    r"^belief://runs/(?P<run_id>run_[0-9a-f]{64})"
    r"(?:/(?P<kind>audit-cases|validation-plans|validation-results))?$"
)
_RUN_ID = re.compile(r"^run_[0-9a-f]{64}$")
_SENSITIVE_DIRECTORY_NAMES = frozenset({"benchmark_susvibes"})
_MAX_WORKSPACE_ARGUMENT_LENGTH = 4096
_MAX_IDENTIFIER_LENGTH = 512
_MAX_STORED_RUNS = 32


class BeliefMCPError(ValueError):
    """A safe, user-correctable MCP tool or resource error."""


@dataclass
class _StoredRun:
    run_id: str
    target: str
    cases: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    plans: dict[str, dict[str, Any]] = field(default_factory=dict)


class _RunStore:
    """Small process-local store; no scan or plan artifact is written to disk."""

    def __init__(self, *, max_runs: int = _MAX_STORED_RUNS) -> None:
        self._max_runs = max_runs
        self._runs: OrderedDict[str, _StoredRun] = OrderedDict()

    def put(self, analysis: Mapping[str, Any]) -> _StoredRun:
        snapshot = dict(analysis)
        run_id = f"run_{canonical_digest(snapshot)}"
        existing = self._runs.get(run_id)
        if existing is not None:
            self._runs.move_to_end(run_id)
            return existing

        raw_cases = snapshot.get("audit_cases")
        cases: dict[str, dict[str, Any]] = {}
        if isinstance(raw_cases, list):
            for raw_case in raw_cases:
                if not isinstance(raw_case, dict):
                    continue
                case_id = str(raw_case.get("case_id") or "")
                if not case_id:
                    continue
                if case_id in cases:
                    raise BeliefMCPError(
                        f"scan produced duplicate audit case ID: {case_id}"
                    )
                cases[case_id] = copy.deepcopy(raw_case)

        summary = _run_summary(run_id, snapshot, len(cases))
        stored = _StoredRun(
            run_id=run_id,
            target=str(snapshot.get("target") or ""),
            cases=dict(sorted(cases.items())),
            summary=summary,
        )
        self._runs[run_id] = stored
        while len(self._runs) > self._max_runs:
            self._runs.popitem(last=False)
        return stored

    def get(self, run_id: object) -> _StoredRun:
        normalized = _identifier(run_id, field_name="run_id")
        if not _RUN_ID.fullmatch(normalized):
            raise BeliefMCPError("run_id must be a BELIEF MCP run identifier")
        try:
            stored = self._runs[normalized]
        except KeyError as exc:
            raise BeliefMCPError(
                f"unknown or evicted BELIEF MCP run: {normalized}"
            ) from exc
        self._runs.move_to_end(normalized)
        return stored

    def values(self) -> list[_StoredRun]:
        return list(self._runs.values())


class BeliefMCPTools:
    """Closed MCP v0.1 facade over stable BELIEF services."""

    def __init__(
        self,
        *,
        workspace_root: str | Path | None = None,
    ) -> None:
        root = Path.cwd() if workspace_root is None else Path(workspace_root)
        try:
            self.workspace_root = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise BeliefMCPError(
                f"MCP workspace root does not exist: {root}"
            ) from exc
        if not self.workspace_root.is_dir():
            raise BeliefMCPError("MCP workspace root must be a directory")
        if any(
            part.casefold() in _SENSITIVE_DIRECTORY_NAMES
            for part in self.workspace_root.parts
        ):
            raise BeliefMCPError(
                "MCP workspace root cannot be inside a reserved holdout location"
            )

        self._benchmark_corpus = self._resolve_benchmark_corpus()
        self._runs = _RunStore()
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "belief_status": self._status,
            "belief_scan": self._scan,
            "belief_get_case": self._get_case,
            "belief_explain_case": self._explain_case,
            "belief_build_validation_plan": self._build_validation_plan,
            "belief_compare_runs": self._compare_runs,
            "belief_run_local_benchmark": self._run_local_benchmark,
        }

    def call_tool(self, name: object, arguments: object) -> dict[str, Any]:
        if not isinstance(name, str) or not name:
            raise BeliefMCPError("tool name must be a non-empty string")
        if not isinstance(arguments, dict):
            raise BeliefMCPError("tool arguments must be a JSON object")
        handler = self._handlers.get(name)
        if handler is None:
            raise BeliefMCPError(f"unknown BELIEF MCP tool: {name}")
        return handler(arguments)

    def list_tools(self) -> list[dict[str, Any]]:
        return copy.deepcopy(tool_definitions())

    def list_resources(self) -> list[dict[str, Any]]:
        resources = static_resource_definitions()
        for stored in self._runs.values():
            resources.extend(_run_resource_definitions(stored.run_id))
        return resources

    def list_resource_templates(self) -> list[dict[str, Any]]:
        return copy.deepcopy(resource_template_definitions())

    def read_resource(self, uri: object) -> tuple[dict[str, Any], str]:
        normalized = _identifier(uri, field_name="resource URI")
        if normalized == "belief://status":
            return self.status(), "application/json"
        if normalized == "belief://capabilities":
            return self.capabilities(), "application/json"
        if normalized in PUBLIC_SCHEMAS:
            return copy.deepcopy(PUBLIC_SCHEMAS[normalized]), "application/schema+json"

        match = _RUN_URI.fullmatch(normalized)
        if match is None:
            raise BeliefMCPError(f"unknown BELIEF MCP resource: {normalized}")
        stored = self._runs.get(match.group("run_id"))
        kind = match.group("kind")
        if kind is None:
            return copy.deepcopy(stored.summary), "application/json"
        if kind == "audit-cases":
            payload = {
                "schema_version": "belief.mcp_audit_case_collection.v1",
                "run_id": stored.run_id,
                "count": len(stored.cases),
                "audit_cases": copy.deepcopy(list(stored.cases.values())),
            }
            return payload, "application/json"
        if kind == "validation-plans":
            payload = {
                "schema_version": "belief.mcp_validation_plan_collection.v1",
                "run_id": stored.run_id,
                "count": len(stored.plans),
                "validation_plans": copy.deepcopy(
                    [stored.plans[key] for key in sorted(stored.plans)]
                ),
                "execution_enabled": False,
            }
            return payload, "application/json"
        payload = {
            "schema_version": "belief.mcp_validation_result_collection.v1",
            "run_id": stored.run_id,
            "count": 0,
            "validation_results": [],
            "execution_enabled": False,
            "reason": "Dynamic validation execution is not exposed in MCP v0.1.",
        }
        return payload, "application/json"

    def status(self) -> dict[str, Any]:
        return status_payload(
            workspace_root=self.workspace_root.as_posix(),
            benchmark_available=self._benchmark_corpus is not None,
        )

    def capabilities(self) -> dict[str, Any]:
        tools = self.list_tools()
        return {
            "schema_version": "belief.mcp_capabilities.v1",
            "mode": "local_stdio_read_first",
            "tools": [item["name"] for item in tools],
            "resources": [
                item["uri"] for item in static_resource_definitions()
            ],
            "resource_templates": [
                item["uriTemplate"] for item in resource_template_definitions()
            ],
            "storage": {
                "kind": "process_memory",
                "max_runs": _MAX_STORED_RUNS,
                "writes_artifacts_to_disk": False,
                "retains_full_analysis": False,
                "retains_source_text": False,
                "retained_objects": [
                    "run_summary",
                    "audit_cases",
                    "generated_validation_plans",
                ],
            },
            "boundaries": {
                "workspace_confined": True,
                "network": False,
                "subprocess": False,
                "shell": False,
                "docker": False,
                "dynamic_import": False,
                "dynamic_execution": False,
                "target_writes": False,
                "custom_adapters": False,
                "susvibes_holdout": False,
                "confirmed_vulnerability_verdict": False,
            },
            "limitations": [
                "Python static analysis only.",
                "Audit cases are candidates, not confirmed vulnerabilities.",
                "Validation plans are generated but never executed by MCP v0.1.",
                "Only the transparent local_validation_v2 benchmark is callable.",
                "Runs are evicted after the in-memory capacity is reached.",
            ],
        }

    def _status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _arguments(arguments, allowed=())
        return self.status()

    def _scan(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _arguments(
            arguments,
            allowed=("workspace", "audit_mode", "reportability", "max_files"),
            required=("workspace",),
        )
        if arguments.get("audit_mode", True) is not True:
            raise BeliefMCPError("belief_scan requires audit_mode=true")
        reportability = arguments.get("reportability", True)
        if not isinstance(reportability, bool):
            raise BeliefMCPError("reportability must be a boolean")
        max_files = arguments.get("max_files", 200)
        if (
            not isinstance(max_files, int)
            or isinstance(max_files, bool)
            or not 1 <= max_files <= 200
        ):
            raise BeliefMCPError("max_files must be an integer between 1 and 200")

        target = self._resolve_workspace(arguments["workspace"])
        result = analyze_static_target(
            target,
            StaticAnalysisOptions(
                max_files=max_files,
                selected_categories=frozenset(STATIC_ANALYSIS_CATEGORIES),
                audit_mode=True,
                include_routes=True,
                reportability=reportability,
                dedup_audit_cases=True,
            ),
        )
        analysis = result.to_dict()
        stored = self._runs.put(analysis)
        return {
            "schema_version": MCP_SCAN_RESPONSE_SCHEMA_VERSION,
            "run_id": stored.run_id,
            "summary": copy.deepcopy(stored.summary),
            "diagnostics": copy.deepcopy(
                analysis.get("diagnostics", [])
            ),
            "resources": [
                item["uri"] for item in _run_resource_definitions(stored.run_id)
            ],
            "boundaries": {
                "local_only": True,
                "target_executed": False,
                "network_used": False,
                "subprocess_used": False,
                "shell_used": False,
                "files_written": False,
                "susvibes_artifacts_opened": False,
                "confirmed_vulnerability_claimed": False,
            },
        }

    def _get_case(self, arguments: dict[str, Any]) -> dict[str, Any]:
        stored, case = self._case_arguments(arguments)
        del stored
        return copy.deepcopy(case)

    def _explain_case(self, arguments: dict[str, Any]) -> dict[str, Any]:
        stored, case = self._case_arguments(arguments)
        structured = case.get("structured_dataflow")
        if not isinstance(structured, dict):
            structured = {}
        ordered_nodes = structured.get("ordered_nodes")
        path: list[Any]
        if isinstance(ordered_nodes, list) and ordered_nodes:
            path = [
                _node_projection(item)
                for item in ordered_nodes
                if _node_projection(item) not in (None, "", {})
            ]
        else:
            raw_path = case.get("dataflow_path")
            path = list(raw_path) if isinstance(raw_path, list) else []

        missing_evidence = _unique_strings(case.get("human_next_steps"))
        for field_name in ("rejection_reason", "truncation_reason"):
            value = structured.get(field_name)
            if value:
                missing_evidence.extend(_unique_strings([value]))

        return {
            "schema_version": MCP_EXPLANATION_SCHEMA_VERSION,
            "run_id": stored.run_id,
            "case_id": str(case.get("case_id") or ""),
            "case_type": str(case.get("case_type") or "unknown"),
            "status": str(case.get("status") or "unknown"),
            "confidence": case.get("confidence"),
            "source": copy.deepcopy(
                structured.get("source") or case.get("source") or ""
            ),
            "sink": copy.deepcopy(
                structured.get("sink") or case.get("sink") or ""
            ),
            "path": path,
            "sanitizers": _unique_strings(case.get("sanitizers")),
            "observed_guarantees": _unique_strings(case.get("guarantees")),
            "blockers": _unique_strings(case.get("missing_guarantees")),
            "contradictions": _unique_strings(case.get("unsat_core")),
            "missing_evidence": _unique_strings(missing_evidence),
            "z3_status": str(case.get("z3_status") or "not_applicable"),
            "reason": str(case.get("reason") or ""),
            "reportability": copy.deepcopy(
                (case.get("metadata") or {}).get("reportability", {})
                if isinstance(case.get("metadata"), dict)
                else {}
            ),
            "interpretation_boundary": (
                "This deterministic projection explains candidate evidence; "
                "it does not confirm exploitability or a vulnerability."
            ),
        }

    def _build_validation_plan(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        stored, case = self._case_arguments(arguments)
        plan = build_validation_plan(case).to_dict()
        stored.plans[str(plan["plan_id"])] = copy.deepcopy(plan)
        return plan

    def _compare_runs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _arguments(
            arguments,
            allowed=("before_run_id", "after_run_id"),
            required=("before_run_id", "after_run_id"),
        )
        before = self._runs.get(arguments["before_run_id"])
        after = self._runs.get(arguments["after_run_id"])
        if before.target != after.target:
            raise BeliefMCPError(
                "belief_compare_runs requires two runs of the same resolved target"
            )
        return _compare_stored_runs(before, after)

    def _run_local_benchmark(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        _arguments(arguments, allowed=("benchmark",), required=("benchmark",))
        if arguments["benchmark"] != "local_validation_v2":
            raise BeliefMCPError(
                "only the transparent local_validation_v2 benchmark is available"
            )
        if self._benchmark_corpus is None:
            raise BeliefMCPError(
                "transparent local_validation_v2 corpus is unavailable in this checkout"
            )
        return run_local_validation_benchmark(self._benchmark_corpus)

    def _case_arguments(
        self, arguments: dict[str, Any]
    ) -> tuple[_StoredRun, dict[str, Any]]:
        _arguments(
            arguments,
            allowed=("run_id", "case_id"),
            required=("run_id", "case_id"),
        )
        stored = self._runs.get(arguments["run_id"])
        case_id = _identifier(arguments["case_id"], field_name="case_id")
        try:
            case = stored.cases[case_id]
        except KeyError as exc:
            raise BeliefMCPError(
                f"run {stored.run_id} has no audit case {case_id}"
            ) from exc
        return stored, case

    def _resolve_workspace(self, value: object) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise BeliefMCPError("workspace must be a non-empty path string")
        if len(value) > _MAX_WORKSPACE_ARGUMENT_LENGTH or "\x00" in value:
            raise BeliefMCPError("workspace path is invalid")
        supplied = Path(value)
        candidate = supplied if supplied.is_absolute() else self.workspace_root / supplied
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise BeliefMCPError(f"workspace path does not exist: {value}") from exc
        try:
            relative = resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise BeliefMCPError(
                "workspace path must remain inside the configured workspace root"
            ) from exc
        if any(
            part.casefold() in _SENSITIVE_DIRECTORY_NAMES
            for part in resolved.parts
        ) or any(":" in part for part in relative.parts):
            raise BeliefMCPError(
                "workspace path targets a reserved or unsupported location"
            )
        if resolved.is_file() and resolved.suffix.casefold() != ".py":
            raise BeliefMCPError(
                "belief_scan accepts directories or individual Python files"
            )
        if not resolved.is_file() and not resolved.is_dir():
            raise BeliefMCPError(
                "workspace path must be a directory or Python file"
            )
        return resolved

    @staticmethod
    def _resolve_benchmark_corpus() -> Path | None:
        candidate = (
            Path(__file__).resolve().parents[2]
            / "benchmark_validation"
            / "cases.json"
        )
        try:
            if candidate.is_symlink():
                return None
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not resolved.is_file() or resolved.name != "cases.json":
            return None
        if "benchmark_validation" not in {
            part.casefold() for part in resolved.parts
        }:
            return None
        if any(
            part.casefold() in _SENSITIVE_DIRECTORY_NAMES
            for part in resolved.parts
        ):
            return None
        return resolved


def _run_summary(
    run_id: str,
    analysis: Mapping[str, Any],
    audit_case_count: int,
) -> dict[str, Any]:
    findings = analysis.get("findings")
    files = analysis.get("files")
    diagnostics = analysis.get("diagnostics")
    return {
        "schema_version": MCP_RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "analysis_schema_version": analysis.get("schema_version"),
        "target": analysis.get("target"),
        "files_scanned": len(files) if isinstance(files, list) else 0,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "audit_case_count": audit_case_count,
        "diagnostic_count": (
            len(diagnostics) if isinstance(diagnostics, list) else 0
        ),
        "totals": copy.deepcopy(analysis.get("totals", {})),
        "resources": {
            "run": f"belief://runs/{run_id}",
            "audit_cases": f"belief://runs/{run_id}/audit-cases",
            "validation_plans": f"belief://runs/{run_id}/validation-plans",
            "validation_results": f"belief://runs/{run_id}/validation-results",
        },
    }


def _run_resource_definitions(run_id: str) -> list[dict[str, Any]]:
    base = f"belief://runs/{run_id}"
    return [
        {
            "uri": base,
            "name": f"{run_id}-summary",
            "title": f"BELIEF run {run_id[-12:]}",
            "description": "Deterministic summary of this in-memory scan run.",
            "mimeType": "application/json",
        },
        {
            "uri": f"{base}/audit-cases",
            "name": f"{run_id}-audit-cases",
            "title": "Audit cases",
            "description": "Structured candidate audit cases from this run.",
            "mimeType": "application/json",
        },
        {
            "uri": f"{base}/validation-plans",
            "name": f"{run_id}-validation-plans",
            "title": "Validation plans",
            "description": "Non-executing plans explicitly built for this run.",
            "mimeType": "application/json",
        },
        {
            "uri": f"{base}/validation-results",
            "name": f"{run_id}-validation-results",
            "title": "Validation results",
            "description": "Empty while MCP dynamic execution remains disabled.",
            "mimeType": "application/json",
        },
    ]


def _compare_stored_runs(
    before: _StoredRun,
    after: _StoredRun,
) -> dict[str, Any]:
    direct_ids = sorted(set(before.cases) & set(after.cases))
    before_only = set(before.cases) - set(direct_ids)
    after_only = set(after.cases) - set(direct_ids)
    fingerprint_matches = _match_by_fingerprint(
        before.cases,
        after.cases,
        before_only,
        after_only,
    )
    for old_id, new_id in fingerprint_matches:
        before_only.discard(old_id)
        after_only.discard(new_id)

    matches = [(case_id, case_id, "case_id") for case_id in direct_ids]
    matches.extend(
        (old_id, new_id, "fingerprint")
        for old_id, new_id in fingerprint_matches
    )

    changed: list[dict[str, Any]] = []
    verdicts_modified: list[dict[str, Any]] = []
    blockers_added: list[dict[str, Any]] = []
    blockers_removed: list[dict[str, Any]] = []
    for old_id, new_id, matched_by in sorted(matches):
        old_case = before.cases[old_id]
        new_case = after.cases[new_id]
        changes = _case_changes(old_case, new_case)
        if changes:
            changed.append(
                {
                    "before_case_id": old_id,
                    "after_case_id": new_id,
                    "matched_by": matched_by,
                    "changes": changes,
                }
            )
        if old_case.get("status") != new_case.get("status"):
            verdicts_modified.append(
                {
                    "before_case_id": old_id,
                    "after_case_id": new_id,
                    "before_status": old_case.get("status"),
                    "after_status": new_case.get("status"),
                    "matched_by": matched_by,
                }
            )
        old_blockers = set(_unique_strings(old_case.get("missing_guarantees")))
        new_blockers = set(_unique_strings(new_case.get("missing_guarantees")))
        if added := sorted(new_blockers - old_blockers):
            blockers_added.append(
                {
                    "before_case_id": old_id,
                    "after_case_id": new_id,
                    "blockers": added,
                }
            )
        if removed := sorted(old_blockers - new_blockers):
            blockers_removed.append(
                {
                    "before_case_id": old_id,
                    "after_case_id": new_id,
                    "blockers": removed,
                }
            )

    new_cases = [_case_reference(after.cases[item]) for item in sorted(after_only)]
    resolved_cases = [
        _case_reference(before.cases[item]) for item in sorted(before_only)
    ]
    return {
        "schema_version": MCP_COMPARISON_SCHEMA_VERSION,
        "before_run_id": before.run_id,
        "after_run_id": after.run_id,
        "target": before.target,
        "counts": {
            "before": len(before.cases),
            "after": len(after.cases),
            "unchanged_or_changed_matches": len(matches),
            "new": len(new_cases),
            "resolved": len(resolved_cases),
            "changed": len(changed),
            "verdicts_modified": len(verdicts_modified),
        },
        "new_cases": new_cases,
        "resolved_cases": resolved_cases,
        "changed_cases": changed,
        "verdicts_modified": verdicts_modified,
        "blockers_added": blockers_added,
        "blockers_removed": blockers_removed,
        "validation_regressions": [],
        "validation_execution_available": False,
        "verdict_interpretation": (
            "verdicts_modified contains static AuditCase status changes, not "
            "confirmed vulnerability or runtime-validation verdicts."
        ),
        "fingerprint_stability": {
            "direct_case_id_matches": len(direct_ids),
            "matched_by_fingerprint": [
                {"before_case_id": old_id, "after_case_id": new_id}
                for old_id, new_id in fingerprint_matches
            ],
            "matched_by_fingerprint_count": len(fingerprint_matches),
        },
        "interpretation_boundary": (
            "Resolved means absent from the later static AuditCase set; it does "
            "not prove that a vulnerability was fixed."
        ),
    }


def _match_by_fingerprint(
    before_cases: Mapping[str, dict[str, Any]],
    after_cases: Mapping[str, dict[str, Any]],
    before_ids: set[str],
    after_ids: set[str],
) -> list[tuple[str, str]]:
    before_by_fingerprint: dict[str, list[str]] = {}
    after_by_fingerprint: dict[str, list[str]] = {}
    for case_id in before_ids:
        fingerprint = str(
            before_cases[case_id].get("related_finding_fingerprint") or ""
        )
        if fingerprint:
            before_by_fingerprint.setdefault(fingerprint, []).append(case_id)
    for case_id in after_ids:
        fingerprint = str(
            after_cases[case_id].get("related_finding_fingerprint") or ""
        )
        if fingerprint:
            after_by_fingerprint.setdefault(fingerprint, []).append(case_id)
    matches = []
    for fingerprint in sorted(
        set(before_by_fingerprint) & set(after_by_fingerprint)
    ):
        old_ids = sorted(before_by_fingerprint[fingerprint])
        new_ids = sorted(after_by_fingerprint[fingerprint])
        if len(old_ids) == len(new_ids) == 1:
            matches.append((old_ids[0], new_ids[0]))
    return matches


def _case_changes(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    changes: dict[str, dict[str, Any]] = {}
    for field_name in (
        "status",
        "review_priority",
        "confidence",
        "severity",
        "z3_status",
        "reason",
        "guarantees",
        "missing_guarantees",
    ):
        old_value = before.get(field_name)
        new_value = after.get(field_name)
        if old_value != new_value:
            changes[field_name] = {
                "before": copy.deepcopy(old_value),
                "after": copy.deepcopy(new_value),
            }
    return changes


def _case_reference(case: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "case_id": case.get("case_id"),
        "case_type": case.get("case_type"),
        "status": case.get("status"),
        "review_priority": case.get("review_priority"),
        "file": case.get("file"),
        "line": case.get("line"),
        "related_finding_fingerprint": case.get(
            "related_finding_fingerprint"
        ),
    }


def _arguments(
    arguments: Mapping[str, Any],
    *,
    allowed: tuple[str, ...],
    required: tuple[str, ...] = (),
) -> None:
    unknown = sorted(set(arguments) - set(allowed))
    if unknown:
        raise BeliefMCPError(
            f"unsupported argument(s): {', '.join(unknown)}"
        )
    missing = [name for name in required if name not in arguments]
    if missing:
        raise BeliefMCPError(
            f"missing required argument(s): {', '.join(missing)}"
        )


def _identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BeliefMCPError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH or "\x00" in value:
        raise BeliefMCPError(f"{field_name} is invalid")
    return value


def _node_projection(value: object) -> Any:
    if not isinstance(value, dict):
        return value
    for key in ("symbol", "expression", "name"):
        if value.get(key):
            return value[key]
    return copy.deepcopy(value)


def _unique_strings(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set)):
        return []
    return list(dict.fromkeys(str(item) for item in value if str(item)))


__all__ = ["BeliefMCPError", "BeliefMCPTools"]
