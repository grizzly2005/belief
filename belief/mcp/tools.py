"""Fixture-bound MCP tools backed by BELIEF's existing application services."""

from __future__ import annotations

import copy
import json
import re
import sys
import threading
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
from belief.source_snapshot import canonical_json_digest
from belief.validation.benchmark import run_local_validation_benchmark
from belief.validation.execution_models import ValidationContractError
from belief.validation.plan_models import ValidationPlan, canonical_digest
from belief.validation.plans import build_validation_plan
from belief.validation.worker import run_isolated_web_validation_plan

from .authorized_project import (
    AUTHORIZED_PROJECT_EXECUTION_SCOPE,
    AUTHORIZED_PROJECT_PREPARATION_SCHEMA_VERSION,
    AuthorizedProjectError,
    AuthorizedProjectGrant,
    build_authorized_project_binding,
    make_authorized_project_grant,
    prepare_authorized_project,
    project_authorized_project_abstention,
    validate_authorized_project_request,
)
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
from .execution import MCPRequestCancelled, MCPRequestExecution
from .publication import MCPPublicationError, MCPPublicationPolicy
from .validation import (
    FixtureBindingError,
    MCP_FIXTURE_PREPARATION_SCHEMA_VERSION,
    MCP_MAX_BYTES_PER_RUN,
    MCP_MAX_CASES_PER_RUN,
    MCP_MAX_CONCURRENT_VALIDATIONS,
    MCP_MAX_RESOURCE_PAGE_SIZE,
    MCP_MAX_RESPONSE_BYTES,
    MCP_MAX_RESULTS_PER_RUN,
    MCP_MAX_SERIALIZED_BYTES_PER_CASE,
    MCP_MAX_STORED_RUNS,
    MCP_MAX_TOTAL_MEMORY_BYTES,
    MCP_MAX_TOTAL_STORE_BYTES,
    MCP_MAX_TOTAL_RESULTS,
    MCP_MAX_VALIDATION_TIMEOUT_MS,
    MCP_MIN_VALIDATION_TIMEOUT_MS,
    REGISTERED_FIXTURE_EXECUTION_SCOPE,
    build_registered_fixture_binding,
    prepare_registered_fixture,
    project_validation_result,
    validate_registered_fixture_binding,
)

_RUN_URI = re.compile(
    r"^belief://runs/(?P<run_id>run_[0-9a-f]{64})"
    r"(?:/(?P<kind>audit-cases|validation-plans|validation-results))?"
    r"(?P<query>\?[^#]*)?$"
)
_RUN_ID = re.compile(r"^run_[0-9a-f]{64}$")
_SENSITIVE_DIRECTORY_NAMES = frozenset({"benchmark_susvibes"})
_MAX_WORKSPACE_ARGUMENT_LENGTH = 4096
_MAX_IDENTIFIER_LENGTH = 512
_SOURCE_DERIVED_TOOLS = frozenset({
    "belief_build_validation_plan",
    "belief_compare_runs",
    "belief_explain_case",
    "belief_get_case",
    "belief_prepare_authorized_project_pilot",
    "belief_prepare_validation_fixture",
    "belief_scan",
    "belief_validate_plan",
})


class BeliefMCPError(ValueError):
    """A safe, user-correctable MCP tool or resource error."""


@dataclass
class _StoredRun:
    run_id: str
    target: str
    cases: dict[str, dict[str, Any]]
    validation_contract_seeds: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    plans: dict[str, dict[str, Any]] = field(default_factory=dict)
    bindings: dict[str, dict[str, Any]] = field(default_factory=dict)
    results: OrderedDict[str, dict[str, Any]] = field(
        default_factory=OrderedDict
    )
    origin: str = "static_scan"
    registered_fixture_id: str = ""
    authorized_project_adapter_id: str = ""
    project_bindings: dict[str, dict[str, Any]] = field(default_factory=dict)
    serialized_bytes: int = 0
    memory_bytes: int = 0
    source_snapshot_id: str = ""
    source_manifest_digest: str = ""
    analysis_options_digest: str = ""
    engine_revision: str = ""
    analysis_id: str = ""
    coverage: dict[str, Any] = field(default_factory=dict)


class _RunStore:
    """Small process-local store; no scan or plan artifact is written to disk."""

    def __init__(
        self,
        *,
        max_runs: int = MCP_MAX_STORED_RUNS,
        max_results_per_run: int = MCP_MAX_RESULTS_PER_RUN,
        max_total_results: int = MCP_MAX_TOTAL_RESULTS,
        max_cases_per_run: int = MCP_MAX_CASES_PER_RUN,
        max_case_bytes: int = MCP_MAX_SERIALIZED_BYTES_PER_CASE,
        max_bytes_per_run: int = MCP_MAX_BYTES_PER_RUN,
        max_total_store_bytes: int = MCP_MAX_TOTAL_STORE_BYTES,
        max_total_memory_bytes: int = MCP_MAX_TOTAL_MEMORY_BYTES,
    ) -> None:
        if not 1 <= max_runs <= MCP_MAX_STORED_RUNS:
            raise ValueError("max_runs is outside the reviewed bound")
        if not 1 <= max_results_per_run <= MCP_MAX_RESULTS_PER_RUN:
            raise ValueError(
                "max_results_per_run is outside the reviewed bound"
            )
        if not 1 <= max_total_results <= MCP_MAX_TOTAL_RESULTS:
            raise ValueError(
                "max_total_results is outside the reviewed bound"
            )
        if not 1 <= max_cases_per_run <= MCP_MAX_CASES_PER_RUN:
            raise ValueError("max_cases_per_run is outside the reviewed bound")
        if not 1 <= max_case_bytes <= MCP_MAX_SERIALIZED_BYTES_PER_CASE:
            raise ValueError("max_case_bytes is outside the reviewed bound")
        if not 1 <= max_bytes_per_run <= MCP_MAX_BYTES_PER_RUN:
            raise ValueError("max_bytes_per_run is outside the reviewed bound")
        if not 1 <= max_total_store_bytes <= MCP_MAX_TOTAL_STORE_BYTES:
            raise ValueError(
                "max_total_store_bytes is outside the reviewed bound"
            )
        if not 1 <= max_total_memory_bytes <= MCP_MAX_TOTAL_MEMORY_BYTES:
            raise ValueError(
                "max_total_memory_bytes is outside the reviewed bound"
            )
        if max_bytes_per_run > max_total_store_bytes:
            raise ValueError(
                "max_bytes_per_run cannot exceed max_total_store_bytes"
            )
        self._max_runs = max_runs
        self._max_results_per_run = max_results_per_run
        self._max_total_results = max_total_results
        self._max_cases_per_run = max_cases_per_run
        self._max_case_bytes = max_case_bytes
        self._max_bytes_per_run = max_bytes_per_run
        self._max_total_store_bytes = max_total_store_bytes
        self._max_total_memory_bytes = max_total_memory_bytes
        self._runs: OrderedDict[str, _StoredRun] = OrderedDict()
        self._result_order: OrderedDict[tuple[str, str], None] = (
            OrderedDict()
        )
        self._total_bytes = 0
        self._lock = threading.RLock()
        self._total_memory_bytes = _deep_memory_size({
            "runs": self._runs,
            "result_order": self._result_order,
        })
        if self._total_memory_bytes > self._max_total_memory_bytes:
            raise ValueError(
                "max_total_memory_bytes cannot hold the empty store"
            )

    def put(self, analysis: Mapping[str, Any]) -> _StoredRun:
        snapshot = copy.deepcopy(dict(analysis))
        identity = _validated_analysis_identity(snapshot)
        run_id = "run_" + identity["analysis_id"].removeprefix(
            "analysis_"
        )
        with self._lock:
            existing = self._runs.get(run_id)
            if existing is not None:
                self._runs.move_to_end(run_id)
                return copy.deepcopy(existing)

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
                    if len(cases) >= self._max_cases_per_run:
                        raise BeliefMCPError(
                            "scan produced more audit cases than the configured "
                            "per-run capacity"
                        )
                    if _serialized_size(raw_case) > self._max_case_bytes:
                        raise BeliefMCPError(
                            f"audit case exceeds serialized byte bound: {case_id}"
                        )
                    cases[case_id] = copy.deepcopy(raw_case)

            raw_seeds = snapshot.get("validation_contract_seeds")
            validation_contract_seeds: dict[
                str,
                dict[str, Any],
            ] = {}
            if isinstance(raw_seeds, list):
                for raw_seed in raw_seeds:
                    if not isinstance(raw_seed, dict):
                        continue
                    seed_id = str(raw_seed.get("seed_id") or "")
                    if not seed_id:
                        continue
                    if seed_id in validation_contract_seeds:
                        raise BeliefMCPError(
                            "preparation produced duplicate validation "
                            f"contract seed ID: {seed_id}"
                        )
                    if _serialized_size(raw_seed) > self._max_case_bytes:
                        raise BeliefMCPError(
                            "validation contract seed exceeds serialized byte "
                            f"bound: {seed_id}"
                        )
                    validation_contract_seeds[seed_id] = copy.deepcopy(
                        raw_seed
                    )

            summary = _run_summary(run_id, snapshot, len(cases))
            stored = _StoredRun(
                run_id=run_id,
                target=str(snapshot.get("target") or ""),
                cases=dict(sorted(cases.items())),
                validation_contract_seeds=dict(
                    sorted(validation_contract_seeds.items())
                ),
                summary=summary,
                origin=str(snapshot.get("mcp_origin") or "static_scan"),
                registered_fixture_id=str(
                    snapshot.get("registered_fixture_id") or ""
                ),
                authorized_project_adapter_id=str(
                    snapshot.get("authorized_project_adapter_id") or ""
                ),
                source_snapshot_id=identity["source_snapshot_id"],
                source_manifest_digest=identity[
                    "source_manifest_digest"
                ],
                analysis_options_digest=identity[
                    "analysis_options_digest"
                ],
                engine_revision=identity["engine_revision"],
                analysis_id=identity["analysis_id"],
                coverage=copy.deepcopy(snapshot.get("coverage") or {}),
            )
            stored.serialized_bytes = _stored_run_size(stored)
            if stored.serialized_bytes > self._max_bytes_per_run:
                raise BeliefMCPError(
                    "run exceeds the configured serialized byte capacity"
                )
            stored.memory_bytes = _stored_run_memory_size(stored)
            if (
                _single_run_store_memory_size(stored)
                > self._max_total_memory_bytes
            ):
                raise BeliefMCPError(
                    "run exceeds the configured in-memory byte capacity"
            )
            self._runs[run_id] = stored
            self._total_bytes += stored.serialized_bytes
            self._recalculate_memory_usage()
            self._evict_over_capacity()
            return copy.deepcopy(stored)

    def get(self, run_id: object) -> _StoredRun:
        normalized = _identifier(run_id, field_name="run_id")
        if not _RUN_ID.fullmatch(normalized):
            raise BeliefMCPError("run_id must be a BELIEF MCP run identifier")
        with self._lock:
            try:
                stored = self._runs[normalized]
            except KeyError as exc:
                raise BeliefMCPError(
                    f"unknown or evicted BELIEF MCP run: {normalized}"
                ) from exc
            self._runs.move_to_end(normalized)
            return copy.deepcopy(stored)

    def store_plan(
        self,
        run_id: object,
        plan: Mapping[str, Any],
        *,
        binding: Mapping[str, Any] | None = None,
        project_binding: Mapping[str, Any] | None = None,
    ) -> None:
        if binding is not None and project_binding is not None:
            raise BeliefMCPError(
                "a plan cannot have both fixture and authorized-project bindings"
            )
        normalized = _identifier(run_id, field_name="run_id")
        plan_snapshot = copy.deepcopy(dict(plan))
        plan_id = _identifier(
            plan_snapshot.get("plan_id"),
            field_name="plan_id",
        )
        binding_snapshot = (
            copy.deepcopy(dict(binding))
            if binding is not None
            else None
        )
        project_binding_snapshot = (
            copy.deepcopy(dict(project_binding))
            if project_binding is not None
            else None
        )
        with self._lock:
            candidate = copy.deepcopy(self._stored(normalized))
            candidate.plans[plan_id] = plan_snapshot
            if binding_snapshot is None:
                candidate.bindings.pop(plan_id, None)
            else:
                candidate.bindings[plan_id] = binding_snapshot
            if project_binding_snapshot is None:
                candidate.project_bindings.pop(plan_id, None)
            else:
                candidate.project_bindings[plan_id] = project_binding_snapshot
            self._replace_run(candidate)
            self._runs.move_to_end(normalized)
            self._evict_over_capacity()

    def store_result(
        self,
        run_id: object,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        normalized = _identifier(run_id, field_name="run_id")
        snapshot = copy.deepcopy(dict(result))
        result_id = _identifier(
            snapshot.get("result_id"),
            field_name="result_id",
        )
        key = (normalized, result_id)
        with self._lock:
            candidate = copy.deepcopy(self._stored(normalized))
            is_new = result_id not in candidate.results
            candidate.results[result_id] = snapshot
            evicted_ids = []
            while len(candidate.results) > self._max_results_per_run:
                evicted_id, _ = candidate.results.popitem(last=False)
                evicted_ids.append(evicted_id)
            self._replace_run(candidate)
            for evicted_id in evicted_ids:
                self._result_order.pop((normalized, evicted_id), None)
            if is_new:
                self._result_order[key] = None
            while len(self._result_order) > self._max_total_results:
                (evicted_run_id, evicted_result_id), _ = (
                    self._result_order.popitem(last=False)
                )
                evicted_run = self._runs.get(evicted_run_id)
                if evicted_run is not None:
                    evicted_run.results.pop(evicted_result_id, None)
                    self._resize_run(evicted_run)
            self._runs.move_to_end(normalized)
            self._recalculate_memory_usage()
            self._evict_over_capacity()
            return copy.deepcopy(snapshot)

    def values(self) -> list[_StoredRun]:
        with self._lock:
            return copy.deepcopy(list(self._runs.values()))

    def capacities(self) -> dict[str, int]:
        with self._lock:
            return {
                "max_runs": self._max_runs,
                "max_results_per_run": self._max_results_per_run,
                "max_total_results": self._max_total_results,
                "max_cases_per_run": self._max_cases_per_run,
                "max_serialized_bytes_per_case": self._max_case_bytes,
                "max_serialized_bytes_per_run": self._max_bytes_per_run,
                "max_total_store_bytes": self._max_total_store_bytes,
                "current_total_store_bytes": self._total_bytes,
                "max_total_memory_bytes": self._max_total_memory_bytes,
                "current_total_memory_bytes": self._total_memory_bytes,
            }

    def clear(self) -> None:
        """Drop all process-local published state."""

        with self._lock:
            self._runs.clear()
            self._result_order.clear()
            self._total_bytes = 0
            self._recalculate_memory_usage()

    def atomic(self, callback: Callable[[], Any]) -> Any:
        """Apply a multi-step publication or restore the exact prior store."""

        with self._lock:
            runs_before = copy.deepcopy(self._runs)
            result_order_before = copy.deepcopy(self._result_order)
            total_bytes_before = self._total_bytes
            total_memory_before = self._total_memory_bytes
            try:
                return callback()
            except BaseException:
                self._runs = runs_before
                self._result_order = result_order_before
                self._total_bytes = total_bytes_before
                self._total_memory_bytes = total_memory_before
                raise

    def _stored(self, run_id: str) -> _StoredRun:
        try:
            return self._runs[run_id]
        except KeyError as exc:
            raise BeliefMCPError(
                f"unknown or evicted BELIEF MCP run: {run_id}"
            ) from exc

    def _discard_result_keys(
        self,
        run_id: str,
        stored: _StoredRun,
    ) -> None:
        for result_id in stored.results:
            self._result_order.pop((run_id, result_id), None)

    def _replace_run(self, candidate: _StoredRun) -> None:
        candidate.serialized_bytes = _stored_run_size(candidate)
        if candidate.serialized_bytes > self._max_bytes_per_run:
            raise BeliefMCPError(
                "run exceeds the configured serialized byte capacity"
            )
        candidate.memory_bytes = _stored_run_memory_size(candidate)
        if (
            _single_run_store_memory_size(candidate)
            > self._max_total_memory_bytes
        ):
            raise BeliefMCPError(
                "run exceeds the configured in-memory byte capacity"
            )
        previous = self._stored(candidate.run_id)
        self._runs[candidate.run_id] = candidate
        self._total_bytes += (
            candidate.serialized_bytes - previous.serialized_bytes
        )
        self._recalculate_memory_usage()

    def _resize_run(self, stored: _StoredRun) -> None:
        previous_size = stored.serialized_bytes
        stored.serialized_bytes = _stored_run_size(stored)
        stored.memory_bytes = _stored_run_memory_size(stored)
        self._total_bytes += stored.serialized_bytes - previous_size
        self._recalculate_memory_usage()

    def _recalculate_memory_usage(self) -> None:
        self._total_memory_bytes = _deep_memory_size({
            "runs": self._runs,
            "result_order": self._result_order,
        })

    def _evict_over_capacity(self) -> None:
        while (
            len(self._runs) > self._max_runs
            or self._total_bytes > self._max_total_store_bytes
            or self._total_memory_bytes > self._max_total_memory_bytes
        ):
            run_id, stored = self._runs.popitem(last=False)
            self._discard_result_keys(run_id, stored)
            self._total_bytes -= stored.serialized_bytes
            self._recalculate_memory_usage()


class BeliefMCPTools:
    """Closed MCP v0.2 facade over stable BELIEF services."""

    def __init__(
        self,
        *,
        workspace_root: str | Path | None = None,
        max_stored_runs: int = MCP_MAX_STORED_RUNS,
        max_results_per_run: int = MCP_MAX_RESULTS_PER_RUN,
        max_total_results: int = MCP_MAX_TOTAL_RESULTS,
        max_cases_per_run: int = MCP_MAX_CASES_PER_RUN,
        max_case_bytes: int = MCP_MAX_SERIALIZED_BYTES_PER_CASE,
        max_bytes_per_run: int = MCP_MAX_BYTES_PER_RUN,
        max_total_store_bytes: int = MCP_MAX_TOTAL_STORE_BYTES,
        max_total_memory_bytes: int = MCP_MAX_TOTAL_MEMORY_BYTES,
        authorized_project_grant: AuthorizedProjectGrant | None = None,
        publication_mode: str = "minimal",
        allow_full_local_output: bool = False,
        holdout_source_sha256_denylist: frozenset[str] = frozenset(),
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
        try:
            self._publication = MCPPublicationPolicy(
                workspace_root=self.workspace_root,
                mode=publication_mode,
                allow_full_local_output=allow_full_local_output,
            )
        except MCPPublicationError as exc:
            raise BeliefMCPError(str(exc)) from exc
        self._holdout_source_sha256_denylist = _sha256_set(
            holdout_source_sha256_denylist,
            field_name="holdout_source_sha256_denylist",
        )
        if authorized_project_grant is not None:
            try:
                expected_grant = make_authorized_project_grant(
                    authorized_project_grant.authorization_id
                )
            except AuthorizedProjectError as exc:
                raise BeliefMCPError(
                    "authorized project grant is invalid"
                ) from exc
            if authorized_project_grant.to_dict() != expected_grant.to_dict():
                raise BeliefMCPError(
                    "authorized project grant is not bound to the built-in pilot"
                )
        self._authorized_project_grant = authorized_project_grant

        self._benchmark_corpus = self._resolve_benchmark_corpus()
        self._runs = _RunStore(
            max_runs=max_stored_runs,
            max_results_per_run=max_results_per_run,
            max_total_results=max_total_results,
            max_cases_per_run=max_cases_per_run,
            max_case_bytes=max_case_bytes,
            max_bytes_per_run=max_bytes_per_run,
            max_total_store_bytes=max_total_store_bytes,
            max_total_memory_bytes=max_total_memory_bytes,
        )
        self._validation_capacity = threading.BoundedSemaphore(
            MCP_MAX_CONCURRENT_VALIDATIONS
        )
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "belief_status": self._status,
            "belief_get_case": self._get_case,
            "belief_explain_case": self._explain_case,
            "belief_compare_runs": self._compare_runs,
            "belief_run_local_benchmark": self._run_local_benchmark,
        }

    def call_tool(
        self,
        name: object,
        arguments: object,
        *,
        execution: MCPRequestExecution | None = None,
    ) -> dict[str, Any]:
        if not isinstance(name, str) or not name:
            raise BeliefMCPError("tool name must be a non-empty string")
        if not isinstance(arguments, dict):
            raise BeliefMCPError("tool arguments must be a JSON object")
        if name == "belief_validate_plan":
            payload = self._validate_plan(arguments, execution=execution)
        elif name == "belief_scan":
            payload = self._scan(arguments, execution=execution)
        elif name == "belief_build_validation_plan":
            payload = self._build_validation_plan(
                arguments,
                execution=execution,
            )
        elif name == "belief_prepare_validation_fixture":
            payload = self._prepare_validation_fixture(
                arguments,
                execution=execution,
            )
        elif name == "belief_prepare_authorized_project_pilot":
            payload = self._prepare_authorized_project_pilot(
                arguments,
                execution=execution,
            )
        else:
            handler = self._handlers.get(name)
            if handler is None:
                raise BeliefMCPError(f"unknown BELIEF MCP tool: {name}")
            payload = handler(arguments)
        return self._publication.publish(payload)

    def publication_metadata(
        self,
        *,
        contains_untrusted_source_content: bool,
    ) -> dict[str, Any]:
        return self._publication.metadata(
            contains_untrusted_source_content=(
                contains_untrusted_source_content
            )
        )

    def tool_contains_untrusted_source_content(self, name: object) -> bool:
        return isinstance(name, str) and name in _SOURCE_DERIVED_TOOLS

    def close(self) -> None:
        """Clear retained process-local results during MCP shutdown."""

        self._runs.clear()

    @staticmethod
    def _commit(
        execution: MCPRequestExecution | None,
        callback: Callable[[], Any],
    ) -> Any:
        try:
            if execution is None:
                return callback()
            return execution.commit_if_active(callback)
        except MCPRequestCancelled as exc:
            raise BeliefMCPError("MCP request was cancelled before commit") from exc

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
            return self._publication.publish(self.status()), "application/json"
        if normalized == "belief://capabilities":
            return (
                self._publication.publish(self.capabilities()),
                "application/json",
            )
        if normalized in PUBLIC_SCHEMAS:
            return copy.deepcopy(PUBLIC_SCHEMAS[normalized]), "application/schema+json"

        match = _RUN_URI.fullmatch(normalized)
        if match is None:
            raise BeliefMCPError(f"unknown BELIEF MCP resource: {normalized}")
        stored = self._runs.get(match.group("run_id"))
        kind = match.group("kind")
        if kind is None:
            if match.group("query"):
                raise BeliefMCPError(
                    "pagination is available only for collection resources"
                )
            return (
                self._publication.publish(copy.deepcopy(stored.summary)),
                "application/json",
            )
        cursor, limit = _resource_page(match.group("query"))
        base_uri = f"belief://runs/{stored.run_id}/{kind}"
        if kind == "audit-cases":
            payload = _paginated_collection(
                list(stored.cases.values()),
                schema_version="belief.mcp_audit_case_collection.v2",
                run_id=stored.run_id,
                field_name="audit_cases",
                base_uri=base_uri,
                cursor=cursor,
                limit=limit,
            )
            return self._publication.publish(payload), "application/json"
        if kind == "validation-plans":
            plans = []
            for plan_id in sorted(stored.plans):
                plan = copy.deepcopy(stored.plans[plan_id])
                binding = stored.bindings.get(plan_id)
                if binding is not None:
                    plan["registered_fixture_binding"] = copy.deepcopy(
                        binding
                    )
                project_binding = stored.project_bindings.get(plan_id)
                if project_binding is not None:
                    plan["authorized_project_binding"] = copy.deepcopy(
                        project_binding
                    )
                plans.append(plan)
            payload = _paginated_collection(
                plans,
                schema_version="belief.mcp_validation_plan_collection.v2",
                run_id=stored.run_id,
                field_name="validation_plans",
                base_uri=base_uri,
                cursor=cursor,
                limit=limit,
            )
            payload.update({
                "execution_enabled": bool(stored.bindings),
                "execution_scope": (
                    REGISTERED_FIXTURE_EXECUTION_SCOPE
                    if stored.bindings
                    else None
                ),
                "authorized_project_scope": (
                    AUTHORIZED_PROJECT_EXECUTION_SCOPE
                    if stored.project_bindings
                    else None
                ),
                "authorized_project_dynamic_execution_enabled": False,
            })
            return self._publication.publish(payload), "application/json"
        payload = _paginated_collection(
            list(stored.results.values()),
            schema_version="belief.mcp_validation_result_collection.v2",
            run_id=stored.run_id,
            field_name="validation_results",
            base_uri=base_uri,
            cursor=cursor,
            limit=limit,
        )
        payload.update({
            "execution_enabled": bool(stored.bindings),
            "execution_scope": (
                REGISTERED_FIXTURE_EXECUTION_SCOPE
                if stored.bindings
                else None
            ),
        })
        return self._publication.publish(payload), "application/json"

    def status(self) -> dict[str, Any]:
        storage_limits = self._runs.capacities()
        payload = status_payload(
            workspace_root=self.workspace_root.as_posix(),
            benchmark_available=self._benchmark_corpus is not None,
            authorized_project_pilot_available=(
                self._authorized_project_grant is not None
            ),
            storage_limits=storage_limits,
        )
        payload["publication"] = self.publication_metadata(
            contains_untrusted_source_content=False
        )
        payload["state_commit_cancellation_safe"] = True
        payload["holdout_source_digest_denylist_count"] = len(
            self._holdout_source_sha256_denylist
        )
        payload["active_cancellation_scope"] = (
            "all_request_state_commits_and_dynamic_worker_termination"
        )
        return payload

    def capabilities(self) -> dict[str, Any]:
        tools = self.list_tools()
        storage_limits = self._runs.capacities()
        return {
            "schema_version": "belief.mcp_capabilities.v2",
            "mode": "local_stdio_fixture_bound_validation",
            "tools": [item["name"] for item in tools],
            "resources": [
                item["uri"] for item in static_resource_definitions()
            ],
            "resource_templates": [
                item["uriTemplate"] for item in resource_template_definitions()
            ],
            "storage": {
                "kind": "process_memory",
                **storage_limits,
                "max_resource_page_size": MCP_MAX_RESOURCE_PAGE_SIZE,
                "max_mcp_response_bytes": MCP_MAX_RESPONSE_BYTES,
                "writes_artifacts_to_disk": False,
                "retains_full_analysis": False,
                "retains_source_text": False,
                "retained_objects": [
                    "run_summary",
                    "audit_cases",
                    "generated_validation_plans",
                    "registered_fixture_bindings",
                    "authorized_project_static_bindings",
                    "projected_validation_results",
                ],
            },
            "boundaries": {
                "workspace_confined": True,
                "live_network_target_allowed": False,
                "worker_process_spawn": True,
                "target_process_spawn": False,
                "shell": False,
                "docker": False,
                "allowlisted_framework_imports": True,
                "caller_controlled_imports": False,
                "outbound_network_publication": False,
                "temporary_fixture_writes": True,
                "target_workspace_writes": False,
                "dynamic_execution": True,
                "dynamic_execution_scope": (
                    REGISTERED_FIXTURE_EXECUTION_SCOPE
                ),
                "max_concurrent_validations": (
                    MCP_MAX_CONCURRENT_VALIDATIONS
                ),
                "custom_adapters": False,
                "active_cancellation_scope": (
                    "all_request_state_commits_and_dynamic_worker_termination"
                ),
                "cancelled_non_worker_response_suppressed": True,
                "state_commit_cancellation_safe": True,
                "authorized_project_pilot": True,
                "authorized_project_pilot_configured": (
                    self._authorized_project_grant is not None
                ),
                "authorized_project_dynamic_execution": False,
                "susvibes_holdout": False,
                "holdout_name_guard": True,
                "holdout_source_digest_denylist_count": len(
                    self._holdout_source_sha256_denylist
                ),
                "holdout_strong_os_isolation": False,
                "confirmed_vulnerability_verdict": False,
            },
            "limitations": [
                "Python static analysis only.",
                "Audit cases are candidates, not confirmed vulnerabilities.",
                "Arbitrary project scan plans are never executable.",
                (
                    "Dynamic execution is limited to plans prepared from exact "
                    "registered transparent fixture sources."
                ),
                "Fixture evidence never confirms an arbitrary scanned target.",
                (
                    "The explicit flask-jwt-extended pilot requires local "
                    "operator opt-in, exact revision and source digest "
                    "matching, analyzes a temporary byte snapshot, and always "
                    "abstains from dynamic execution. The opt-in is not "
                    "cryptographic authorization."
                ),
                "Only the transparent local_validation_v2 benchmark is callable.",
                "Runs are evicted after the in-memory capacity is reached.",
                (
                    "Digest denial prevents parsing and analysis after the "
                    "bounded digest read; preventing even byte access requires "
                    "external OS permissions, encryption, or account isolation."
                ),
                (
                    "Cancellation suppresses every cancelled request response "
                    "and prevents later state publication; only isolated dynamic "
                    "validation has a worker process to terminate."
                ),
            ],
            "publication": self.publication_metadata(
                contains_untrusted_source_content=False
            ),
        }

    def _status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        _arguments(arguments, allowed=())
        return self.status()

    def _scan(
        self,
        arguments: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
    ) -> dict[str, Any]:
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
                denied_source_sha256=(
                    self._holdout_source_sha256_denylist
                ),
            ),
        )
        analysis = result.to_dict()
        stored = self._commit(
            execution,
            lambda: self._runs.put(analysis),
        )
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
        self,
        arguments: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
    ) -> dict[str, Any]:
        stored, case = self._case_arguments(arguments)
        plan = build_validation_plan(case).to_dict()
        self._commit(
            execution,
            lambda: self._runs.store_plan(stored.run_id, plan),
        )
        return plan

    def _prepare_validation_fixture(
        self,
        arguments: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
    ) -> dict[str, Any]:
        _arguments(
            arguments,
            allowed=("fixture_id",),
            required=("fixture_id",),
        )
        fixture_id = _identifier(
            arguments["fixture_id"],
            field_name="fixture_id",
        )
        try:
            prepared = prepare_registered_fixture(fixture_id)

            def publish_fixture() -> tuple[_StoredRun, Any]:
                def transaction() -> tuple[_StoredRun, Any]:
                    stored_run = self._runs.put(prepared.analysis_snapshot)
                    fixture_binding = build_registered_fixture_binding(
                        prepared,
                        run_id=stored_run.run_id,
                    )
                    self._runs.store_plan(
                        stored_run.run_id,
                        prepared.plan.to_dict(),
                        binding=fixture_binding.to_dict(),
                    )
                    return stored_run, fixture_binding

                return self._runs.atomic(transaction)

            stored, binding = self._commit(execution, publish_fixture)
        except FixtureBindingError as exc:
            raise BeliefMCPError(str(exc)) from exc
        except (OSError, UnicodeError, ValueError) as exc:
            raise BeliefMCPError(
                "registered fixture preparation could not be completed safely"
            ) from exc
        return {
            "schema_version": MCP_FIXTURE_PREPARATION_SCHEMA_VERSION,
            "run_id": stored.run_id,
            "validation_contract_seed_id": prepared.plan.subject_id,
            "subject_kind": prepared.plan.subject_kind,
            "plan_id": prepared.plan.plan_id,
            "fixture_id": prepared.fixture_id,
            "binding": binding.to_dict(),
            "binding_digest": binding.digest,
            "static_scan": copy.deepcopy(prepared.static_scan),
            "limitations": list(prepared.limitations),
            "resources": {
                "run": f"belief://runs/{stored.run_id}",
                "audit_cases": (
                    f"belief://runs/{stored.run_id}/audit-cases"
                ),
                "validation_plans": (
                    f"belief://runs/{stored.run_id}/validation-plans"
                ),
                "validation_results": (
                    f"belief://runs/{stored.run_id}/validation-results"
                ),
            },
            "boundaries": {
                "execution_scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
                "arbitrary_source_accepted": False,
                "arbitrary_path_accepted": False,
                "arbitrary_module_accepted": False,
                "arbitrary_callable_accepted": False,
                "network_used": False,
                "subprocess_used": False,
                "target_files_written": False,
                "susvibes_artifacts_opened": False,
                "target_vulnerability_confirmed": False,
                "human_confirmation_required": True,
            },
        }

    def _validate_plan(
        self,
        arguments: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
    ) -> dict[str, Any]:
        _arguments(
            arguments,
            allowed=(
                "run_id",
                "plan_id",
                "fixture_id",
                "timeout_ms",
                "acknowledge_local_execution",
            ),
            required=(
                "run_id",
                "plan_id",
                "fixture_id",
                "timeout_ms",
                "acknowledge_local_execution",
            ),
        )
        if arguments["acknowledge_local_execution"] is not True:
            raise BeliefMCPError(
                "acknowledge_local_execution must be the JSON boolean true"
            )
        timeout_ms = arguments["timeout_ms"]
        if (
            not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or not MCP_MIN_VALIDATION_TIMEOUT_MS
            <= timeout_ms
            <= MCP_MAX_VALIDATION_TIMEOUT_MS
        ):
            raise BeliefMCPError(
                "timeout_ms must be an integer between "
                f"{MCP_MIN_VALIDATION_TIMEOUT_MS} and "
                f"{MCP_MAX_VALIDATION_TIMEOUT_MS}"
            )
        run_id = _identifier(arguments["run_id"], field_name="run_id")
        plan_id = _identifier(arguments["plan_id"], field_name="plan_id")
        fixture_id = _identifier(
            arguments["fixture_id"],
            field_name="fixture_id",
        )
        stored = self._runs.get(run_id)
        if (
            stored.origin != "registered_fixture_preparation"
            or not stored.registered_fixture_id
        ):
            raise BeliefMCPError(
                "validation plan is unbound; prepare a registered fixture first"
            )
        if stored.registered_fixture_id != fixture_id:
            raise BeliefMCPError(
                "fixture_id does not match the prepared validation run"
            )
        try:
            raw_plan = stored.plans[plan_id]
        except KeyError as exc:
            raise BeliefMCPError(
                "plan_id does not exist in the requested run"
            ) from exc
        binding_payload = stored.bindings.get(plan_id)
        if binding_payload is None:
            raise BeliefMCPError(
                "validation plan has no trusted registered-fixture binding"
            )
        try:
            plan = ValidationPlan.from_dict(raw_plan)
            if plan.to_dict() != raw_plan:
                raise FixtureBindingError(
                    "stored validation plan is not canonical"
                )
            contract_seed = stored.validation_contract_seeds[
                plan.subject_id
            ]
            binding = validate_registered_fixture_binding(
                binding_payload,
                run_id=stored.run_id,
                plan=plan,
                contract_seed=contract_seed,
                fixture_id=fixture_id,
            )
        except KeyError as exc:
            raise BeliefMCPError(
                "validation plan contract seed is missing from its run"
            ) from exc
        except (FixtureBindingError, ValueError) as exc:
            raise BeliefMCPError(str(exc)) from exc

        if execution is not None and execution.cancelled:
            raise BeliefMCPError("validation request was cancelled")
        if not self._validation_capacity.acquire(blocking=False):
            raise BeliefMCPError(
                "validation capacity is busy; retry after the active local "
                "fixture validation completes"
            )

        worker_holder: list[Any] = []

        def register_worker(worker: Any) -> None:
            worker_holder.append(worker)
            if execution is not None:
                execution.register_worker(worker)

        try:
            if execution is not None and execution.cancelled:
                raise BeliefMCPError("validation request was cancelled")
            result = run_isolated_web_validation_plan(
                plan,
                fixture_id=fixture_id,
                source_revision=binding.source_revision,
                timeout_ms=timeout_ms,
                correlation_id=(
                    "mcp_"
                    + canonical_digest(
                        {
                            "run_id": run_id,
                            "plan_id": plan_id,
                            "fixture_id": fixture_id,
                            "timeout_ms": timeout_ms,
                        }
                    )[:16]
                ),
                on_handle=register_worker,
            )
            if execution is not None and execution.cancelled:
                raise BeliefMCPError("validation request was cancelled")
            result_payload = result.to_dict()
            worker_state = _worker_state(result_payload)
            if (
                worker_state != "completed"
                and not _storable_worker_abstention(
                    result_payload,
                    worker_state,
                )
            ):
                raise BeliefMCPError(
                    _worker_tool_error(result_payload, worker_state)
                )
            try:
                projected = project_validation_result(
                    result_payload,
                    run_id=stored.run_id,
                    plan=plan,
                    binding=binding,
                )
            except FixtureBindingError as exc:
                raise BeliefMCPError(str(exc)) from exc
            return self._commit(
                execution,
                lambda: self._runs.store_result(stored.run_id, projected),
            )
        except ValidationContractError as exc:
            raise BeliefMCPError(
                "the hardened validation worker rejected the bound plan"
            ) from exc
        finally:
            if execution is not None and worker_holder:
                execution.release_worker(worker_holder[-1])
            self._validation_capacity.release()

    def _prepare_authorized_project_pilot(
        self,
        arguments: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
    ) -> dict[str, Any]:
        _arguments(
            arguments,
            allowed=(
                "adapter_id",
                "authorization_id",
                "source_revision",
                "source_digest",
                "acknowledge_authorized_project_access",
            ),
            required=(
                "adapter_id",
                "authorization_id",
                "source_revision",
                "source_digest",
                "acknowledge_authorized_project_access",
            ),
        )
        if arguments["acknowledge_authorized_project_access"] is not True:
            raise BeliefMCPError(
                "acknowledge_authorized_project_access must be the JSON boolean true"
            )
        try:
            grant = validate_authorized_project_request(
                self._authorized_project_grant,
                adapter_id=arguments["adapter_id"],
                authorization_id=arguments["authorization_id"],
                source_revision=arguments["source_revision"],
                source_digest=arguments["source_digest"],
            )
            prepared = prepare_authorized_project(
                self.workspace_root,
                grant,
            )

            def publish_authorized_project() -> tuple[
                _StoredRun,
                list[dict[str, Any]],
                list[dict[str, Any]],
            ]:
                def transaction() -> tuple[
                    _StoredRun,
                    list[dict[str, Any]],
                    list[dict[str, Any]],
                ]:
                    stored_run = self._runs.put(prepared.analysis_snapshot)
                    published_bindings: list[dict[str, Any]] = []
                    published_abstentions: list[dict[str, Any]] = []
                    for plan in prepared.plans:
                        project_binding = build_authorized_project_binding(
                            prepared,
                            run_id=stored_run.run_id,
                            plan=plan,
                            grant=grant,
                        )
                        self._runs.store_plan(
                            stored_run.run_id,
                            plan.to_dict(),
                            project_binding=project_binding.to_dict(),
                        )
                        published_bindings.append(
                            {
                                "plan_id": plan.plan_id,
                                "binding": project_binding.to_dict(),
                                "binding_digest": project_binding.digest,
                            }
                        )
                        published_abstentions.append(
                            project_authorized_project_abstention(
                                run_id=stored_run.run_id,
                                plan=plan,
                                binding=project_binding,
                            )
                        )
                    return (
                        stored_run,
                        published_bindings,
                        published_abstentions,
                    )

                return self._runs.atomic(transaction)

            stored, bindings, abstentions = self._commit(
                execution,
                publish_authorized_project,
            )
        except AuthorizedProjectError as exc:
            raise BeliefMCPError(str(exc)) from exc
        except (OSError, UnicodeError, ValueError) as exc:
            raise BeliefMCPError(
                "authorized project preparation could not be completed safely"
            ) from exc

        return {
            "schema_version": AUTHORIZED_PROJECT_PREPARATION_SCHEMA_VERSION,
            "run_id": stored.run_id,
            "adapter_id": prepared.attestation.adapter_id,
            "project_id": prepared.attestation.project_id,
            "authorization_id": grant.authorization_id,
            "authorization_grant_digest": grant.digest,
            "source_attestation": prepared.attestation.to_dict(),
            "static_summary": copy.deepcopy(stored.summary),
            "plan_count": len(prepared.plans),
            "bindings": bindings,
            "abstentions": abstentions,
            "outcome": "inconclusive",
            "execution_status": "abstained",
            "limitations": list(prepared.limitations),
            "resources": {
                "run": f"belief://runs/{stored.run_id}",
                "audit_cases": (
                    f"belief://runs/{stored.run_id}/audit-cases"
                ),
                "validation_plans": (
                    f"belief://runs/{stored.run_id}/validation-plans"
                ),
                "validation_results": (
                    f"belief://runs/{stored.run_id}/validation-results"
                ),
            },
            "boundaries": {
                "execution_scope": AUTHORIZED_PROJECT_EXECUTION_SCOPE,
                "local_operator_opt_in_required": True,
                "local_operator_opt_in_verified": True,
                "cryptographic_authorization_proof": False,
                "exact_revision_verified": True,
                "exact_source_digest_verified": True,
                "immutable_source_snapshot_analyzed": True,
                "live_workspace_analyzed_in_place": False,
                "live_workspace_reattested_after_analysis": True,
                "target_executed": False,
                "target_imported": False,
                "target_files_written": False,
                "network_used": False,
                "subprocess_used": False,
                "shell_used": False,
                "arbitrary_source_accepted": False,
                "arbitrary_path_accepted": False,
                "arbitrary_module_accepted": False,
                "arbitrary_callable_accepted": False,
                "dynamic_execution_authorized": False,
                "target_vulnerability_confirmed": False,
                "human_confirmation_required": True,
            },
        }

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
        "source_snapshot_id": analysis.get(
            "analysis_identity", {}
        ).get("source_snapshot_id"),
        "source_manifest_digest": analysis.get(
            "analysis_identity", {}
        ).get("source_manifest_digest"),
        "analysis_options_digest": analysis.get(
            "analysis_identity", {}
        ).get("analysis_options_digest"),
        "engine_revision": analysis.get(
            "analysis_identity", {}
        ).get("engine_revision"),
        "analysis_id": analysis.get(
            "analysis_identity", {}
        ).get("analysis_id"),
        "analysis_schema_version": analysis.get("schema_version"),
        "target": analysis.get("target"),
        "files_scanned": len(files) if isinstance(files, list) else 0,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "audit_case_count": audit_case_count,
        "diagnostic_count": (
            len(diagnostics) if isinstance(diagnostics, list) else 0
        ),
        "totals": copy.deepcopy(analysis.get("totals", {})),
        "coverage": copy.deepcopy(analysis.get("coverage", {})),
        "resources": {
            "run": f"belief://runs/{run_id}",
            "audit_cases": f"belief://runs/{run_id}/audit-cases",
            "validation_plans": f"belief://runs/{run_id}/validation-plans",
            "validation_results": f"belief://runs/{run_id}/validation-results",
        },
    }


def _validated_analysis_identity(
    analysis: Mapping[str, Any],
) -> dict[str, str]:
    """Reject runs that are not bound to exact source, options, and engine."""

    raw_identity = analysis.get("analysis_identity")
    raw_manifest = analysis.get("source_snapshot")
    raw_options = analysis.get("analysis_options")
    if (
        not isinstance(raw_identity, Mapping)
        or not isinstance(raw_manifest, Mapping)
        or not isinstance(raw_options, Mapping)
    ):
        raise BeliefMCPError(
            "analysis is missing its exact source identity contract"
        )
    fields = {
        name: str(raw_identity.get(name) or "")
        for name in (
            "source_snapshot_id",
            "source_manifest_digest",
            "analysis_options_digest",
            "engine_revision",
            "analysis_id",
        )
    }
    digest_fields = (
        "source_manifest_digest",
        "analysis_options_digest",
        "engine_revision",
    )
    if any(
        re.fullmatch(r"[0-9a-f]{64}", fields[name]) is None
        for name in digest_fields
    ):
        raise BeliefMCPError("analysis identity contains an invalid digest")
    if fields["source_snapshot_id"] != (
        "src_" + fields["source_manifest_digest"]
    ):
        raise BeliefMCPError(
            "analysis source snapshot identifier does not match its manifest"
        )
    expected_options_digest = canonical_json_digest(dict(raw_options))
    if fields["analysis_options_digest"] != expected_options_digest:
        raise BeliefMCPError(
            "analysis options digest does not match the effective options"
        )
    for name, value in (
        ("source_snapshot_id", fields["source_snapshot_id"]),
        ("source_manifest_digest", fields["source_manifest_digest"]),
        ("analysis_options_digest", fields["analysis_options_digest"]),
        ("engine_revision", fields["engine_revision"]),
        ("analysis_id", fields["analysis_id"]),
    ):
        if str(raw_manifest.get(name) or "") != value:
            raise BeliefMCPError(
                f"analysis identity disagrees with source manifest field: {name}"
            )
    expected_analysis_id = "analysis_" + canonical_json_digest({
        "source_manifest_digest": fields["source_manifest_digest"],
        "analysis_options_digest": fields["analysis_options_digest"],
        "engine_revision": fields["engine_revision"],
    })
    if fields["analysis_id"] != expected_analysis_id:
        raise BeliefMCPError(
            "analysis identifier does not bind source, options, and engine"
        )
    unsigned_manifest = dict(raw_manifest)
    observed_manifest_digest = str(
        unsigned_manifest.pop("manifest_digest", "")
    )
    if (
        re.fullmatch(r"[0-9a-f]{64}", observed_manifest_digest) is None
        or canonical_json_digest(unsigned_manifest)
        != observed_manifest_digest
    ):
        raise BeliefMCPError("source snapshot manifest digest is invalid")
    return fields


def _stored_run_size(stored: _StoredRun) -> int:
    return _serialized_size(_stored_run_payload(stored))


def _stored_run_memory_size(stored: _StoredRun) -> int:
    return _deep_memory_size(_stored_run_payload(stored))


def _single_run_store_memory_size(stored: _StoredRun) -> int:
    return _deep_memory_size({
        "runs": OrderedDict(((stored.run_id, stored),)),
        "result_order": OrderedDict(
            ((stored.run_id, result_id), None)
            for result_id in stored.results
        ),
    })


def _stored_run_payload(stored: _StoredRun) -> dict[str, Any]:
    return {
        "run_id": stored.run_id,
        "target": stored.target,
        "cases": stored.cases,
        "validation_contract_seeds": stored.validation_contract_seeds,
        "summary": stored.summary,
        "plans": stored.plans,
        "bindings": stored.bindings,
        "results": stored.results,
        "origin": stored.origin,
        "registered_fixture_id": stored.registered_fixture_id,
        "authorized_project_adapter_id": stored.authorized_project_adapter_id,
        "project_bindings": stored.project_bindings,
        "source_snapshot_id": stored.source_snapshot_id,
        "source_manifest_digest": stored.source_manifest_digest,
        "analysis_options_digest": stored.analysis_options_digest,
        "engine_revision": stored.engine_revision,
        "analysis_id": stored.analysis_id,
        "coverage": stored.coverage,
    }


def _serialized_size(value: object) -> int:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return len(rendered.encode("utf-8"))
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise BeliefMCPError(
            "MCP store object is not bounded canonical JSON"
        ) from exc


def _deep_memory_size(value: object) -> int:
    seen: set[int] = set()
    stack = [value]
    total = 0
    while stack:
        current = stack.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        total += sys.getsizeof(current)
        if isinstance(current, Mapping):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (list, tuple, set, frozenset)):
            stack.extend(current)
        elif isinstance(current, _StoredRun):
            stack.append(vars(current))
    return total


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
            "description": (
                "Plans for this run; only exact registered-fixture bindings "
                "make a plan executable."
            ),
            "mimeType": "application/json",
        },
        {
            "uri": f"{base}/validation-results",
            "name": f"{run_id}-validation-results",
            "title": "Validation results",
            "description": (
                "Bounded fixture-only results that never confirm a scanned target."
            ),
            "mimeType": "application/json",
        },
    ]


def _resource_page(query: str | None) -> tuple[int, int]:
    if not query:
        return 0, MCP_MAX_RESOURCE_PAGE_SIZE
    fields: dict[str, str] = {}
    for part in query.removeprefix("?").split("&"):
        if not part or "=" not in part:
            raise BeliefMCPError("resource pagination query is invalid")
        name, value = part.split("=", 1)
        if name not in {"cursor", "limit"} or name in fields:
            raise BeliefMCPError("resource pagination query is invalid")
        if re.fullmatch(r"[0-9]+", value) is None:
            raise BeliefMCPError("resource pagination values must be integers")
        fields[name] = value
    cursor = int(fields.get("cursor", "0"))
    limit = int(fields.get("limit", str(MCP_MAX_RESOURCE_PAGE_SIZE)))
    if cursor > MCP_MAX_CASES_PER_RUN:
        raise BeliefMCPError("resource cursor exceeds the reviewed bound")
    if not 1 <= limit <= MCP_MAX_RESOURCE_PAGE_SIZE:
        raise BeliefMCPError(
            "resource page limit is outside the reviewed bound"
        )
    return cursor, limit


def _paginated_collection(
    items: list[dict[str, Any]],
    *,
    schema_version: str,
    run_id: str,
    field_name: str,
    base_uri: str,
    cursor: int,
    limit: int,
) -> dict[str, Any]:
    total = len(items)
    end = min(total, cursor + limit)
    next_cursor = end if end < total else None
    return {
        "schema_version": schema_version,
        "run_id": run_id,
        "count": total,
        "returned": max(0, end - cursor) if cursor <= total else 0,
        "cursor": cursor,
        "limit": limit,
        "next_cursor": next_cursor,
        "next_uri": (
            f"{base_uri}?cursor={next_cursor}&limit={limit}"
            if next_cursor is not None
            else None
        ),
        field_name: copy.deepcopy(items[cursor:end]),
    }


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
        "before_source_snapshot_id": before.source_snapshot_id,
        "after_source_snapshot_id": after.source_snapshot_id,
        "source_changed": (
            before.source_manifest_digest
            != after.source_manifest_digest
        ),
        "engine_changed": before.engine_revision != after.engine_revision,
        "analysis_options_changed": (
            before.analysis_options_digest
            != after.analysis_options_digest
        ),
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


def _sha256_set(
    values: frozenset[str],
    *,
    field_name: str,
) -> frozenset[str]:
    if not isinstance(values, frozenset):
        raise BeliefMCPError(f"{field_name} must be a frozenset")
    for value in values:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(
                character not in "0123456789abcdef"
                for character in value
            )
        ):
            raise BeliefMCPError(
                f"{field_name} entries must be lowercase SHA-256 values"
            )
    return values


def _identifier(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BeliefMCPError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH or "\x00" in value:
        raise BeliefMCPError(f"{field_name} is invalid")
    return value


def _worker_state(result: Mapping[str, Any]) -> str:
    metadata = result.get("metadata")
    if not isinstance(metadata, Mapping):
        return "unavailable"
    worker = metadata.get("isolated_worker")
    if not isinstance(worker, Mapping):
        return "unavailable"
    return str(worker.get("worker_status") or "unavailable")


def _worker_tool_error(
    result: Mapping[str, Any],
    worker_state: str,
) -> str:
    codes = _worker_error_codes(result)
    if "cancelled" in codes or worker_state == "cancelled":
        return "validation request was cancelled"
    if "timeout" in codes or worker_state == "timed_out":
        return "registered fixture validation exceeded its hard timeout"
    if "policy_violation" in codes or worker_state == "policy_violation":
        return "registered fixture validation was stopped by worker policy"
    if "dependency_unavailable" in codes or worker_state == "unsupported":
        return "registered fixture dependency is unavailable"
    if "binding_mismatch" in codes:
        return "worker evidence did not match the trusted fixture binding"
    return "registered fixture validation ended without valid worker evidence"


def _worker_error_codes(result: Mapping[str, Any]) -> set[str]:
    metadata = result.get("metadata")
    limitations: list[str] = []
    if isinstance(metadata, Mapping):
        execution = metadata.get("execution")
        if isinstance(execution, Mapping):
            limitations = _unique_strings(execution.get("limitations"))
    return {
        item.removeprefix("worker_error:")
        for item in limitations
        if item.startswith("worker_error:")
    }


def _storable_worker_abstention(
    result: Mapping[str, Any],
    worker_state: str,
) -> bool:
    codes = _worker_error_codes(result)
    if codes & {
        "binding_mismatch",
        "cancelled",
        "invalid_request",
        "unknown_fixture",
        "unsupported_protocol",
    }:
        return False
    return bool(
        codes
        & {
            "child_crash",
            "dependency_unavailable",
            "internal_error",
            "malformed_response",
            "policy_violation",
            "response_too_large",
            "timeout",
        }
        or worker_state
        in {
            "crashed",
            "inconclusive",
            "policy_violation",
            "timed_out",
            "unsupported",
        }
    )


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
