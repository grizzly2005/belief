"""Causal guard classification and applicability checks.

Guard-like text is evidence, not proof.  This module deliberately keeps the
checks small and deterministic so reportability and hypothesis reasoning share
the same conservative vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal


GuardCategory = Literal[
    "authentication_guard",
    "role_authorization_guard",
    "ownership_guard",
    "tenant_guard",
    "resource_binding_guard",
    "input_validation_guard",
    "path_containment_guard",
    "sanitizer_guard",
]

GuardBlocker = Literal[
    "authentication_only",
    "guard_not_resource_bound",
    "guard_after_sink",
    "guard_on_different_value",
    "guard_in_unrelated_context",
    "sanitizer_result_unused",
    "flow_not_demonstrated",
]

GUARD_CATEGORIES: tuple[GuardCategory, ...] = (
    "authentication_guard",
    "role_authorization_guard",
    "ownership_guard",
    "tenant_guard",
    "resource_binding_guard",
    "input_validation_guard",
    "path_containment_guard",
    "sanitizer_guard",
)

GUARD_BLOCKERS: tuple[GuardBlocker, ...] = (
    "authentication_only",
    "guard_not_resource_bound",
    "guard_after_sink",
    "guard_on_different_value",
    "guard_in_unrelated_context",
    "sanitizer_result_unused",
    "flow_not_demonstrated",
)


@dataclass(frozen=True)
class GuardApplicability:
    """One guard candidate and whether it can protect the concrete sink."""

    category: GuardCategory
    expression: str
    applicable: bool
    reason: str
    blockers: tuple[GuardBlocker, ...] = ()
    guard_file: str = ""
    guard_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "expression": self.expression,
            "applicable": bool(self.applicable),
            "reason": self.reason,
            "blockers": list(self.blockers),
            "guard_file": self.guard_file,
            "guard_line": self.guard_line,
        }


@dataclass(frozen=True)
class _GuardCandidate:
    expression: str
    category: GuardCategory
    file: str = ""
    line: int | None = None
    function: str = ""
    route: str = ""
    value: str = ""
    direct_context: bool = False
    propagated: bool = False
    call_path: bool = False
    result_used: bool | None = None
    bypass_possible: bool = False


def classify_guard(expression: str, explicit_category: str = "") -> GuardCategory | None:
    """Classify guard evidence without treating the classification as proof."""
    normalized_category = str(explicit_category or "").strip().lower()
    if normalized_category in GUARD_CATEGORIES:
        return normalized_category  # type: ignore[return-value]

    text = str(expression or "").strip().lower()
    if not text:
        return None
    if any(token in text for token in (
        "requires_login",
        "login_required",
        "authenticated",
        "authentication",
        "is_authenticated",
    )):
        return "authentication_guard"
    if any(token in text for token in (
        "requires_admin",
        "admin_required",
        "permission_required",
        "has_permission",
        "has_role",
        "role_required",
        "role_authorization",
    )):
        return "role_authorization_guard"
    if any(token in text for token in (
        "scoped_to_",
        "filter_by",
        "resource_binding",
        "object_binding",
        "bound_to_resource",
        "source_id",
    )):
        return "resource_binding_guard"
    if any(token in text for token in (
        "current_user.tenant",
        "tenant_id",
        "tenant_scope",
        "tenant scoped",
        "tenant-bound",
    )):
        return "tenant_guard"
    if any(token in text for token in (
        "current_user.id",
        "current_source",
        "current_user",
        "owner_id",
        "owner_scope",
        "ownership",
        "owner_tenant_scope",
    )):
        return "ownership_guard"
    if any(token in text for token in (
        "is_within_store",
        "enforces_store_boundary",
        "commonpath",
        "path_containment",
        "within_root",
        "within_base",
    )):
        return "path_containment_guard"
    if any(token in text for token in (
        "matches_allowed_pattern",
        "allow_list",
        "allowlist",
        "allowed_extension",
        "input_validation",
        "validate_input",
        "server_generated",
        "user_controlled == false",
        "value_is_header_name",
        "value_is_runtime_supplied",
        "input_trusted",
    )):
        return "input_validation_guard"
    if any(token in text for token in (
        "sanitiz",
        "escaped",
        "escape(",
        "basename_only",
        "is_normalized",
        "safe_loader",
    )):
        return "sanitizer_guard"
    return None


def assess_guard_applicability(
    expression: str,
    *,
    category: str = "",
    guard_file: str = "",
    guard_line: int | None = None,
    guard_function: str = "",
    guard_route: str = "",
    guard_value: str = "",
    sink_file: str = "",
    source_line: int | None = None,
    sink_line: int | None = None,
    sink_function: str = "",
    sink_route: str = "",
    sink_value: str = "",
    case_type: str = "",
    direct_context: bool = False,
    propagated: bool = False,
    call_path: bool = False,
    result_used: bool | None = None,
    bypass_possible: bool = False,
) -> GuardApplicability:
    """Require a causal relationship before accepting a guard for a sink."""
    guard_category = classify_guard(expression, category)
    if guard_category is None:
        # Callers only pass classified candidates in normal operation.  Keeping
        # this fallback typed avoids turning unknown text into a proof.
        guard_category = "input_validation_guard"
        return _rejected(
            guard_category,
            expression,
            "guard type is not compatible with the reported flow",
            "flow_not_demonstrated",
            guard_file,
            guard_line,
        )

    normalized_guard_file = _norm_path(guard_file)
    normalized_sink_file = _norm_path(sink_file)
    cross_file_link = propagated or call_path
    if (
        normalized_guard_file
        and normalized_sink_file
        and normalized_guard_file != normalized_sink_file
        and not cross_file_link
    ):
        return _rejected(
            guard_category,
            expression,
            "guard and sink are in unrelated files or call contexts",
            "guard_in_unrelated_context",
            normalized_guard_file,
            guard_line,
        )

    if (
        guard_function
        and sink_function
        and not _same_function_context(guard_function, sink_function)
        and not cross_file_link
    ):
        return _rejected(
            guard_category,
            expression,
            "guard and sink are in unrelated functions or call contexts",
            "guard_in_unrelated_context",
            normalized_guard_file,
            guard_line,
        )

    if guard_route and sink_route and _norm_route(guard_route) != _norm_route(sink_route):
        return _rejected(
            guard_category,
            expression,
            "guard belongs to a different route",
            "guard_in_unrelated_context",
            normalized_guard_file,
            guard_line,
        )

    if (
        guard_line is not None
        and sink_line is not None
        and (not normalized_guard_file or normalized_guard_file == normalized_sink_file)
        and guard_line > sink_line
    ):
        return _rejected(
            guard_category,
            expression,
            "guard executes after the reported sink",
            "guard_after_sink",
            normalized_guard_file,
            guard_line,
        )

    if (
        guard_category in _VALUE_BOUND_CATEGORIES
        and guard_line is not None
        and source_line is not None
        and (not normalized_guard_file or normalized_guard_file == normalized_sink_file)
        and guard_line < source_line
    ):
        return _rejected(
            guard_category,
            expression,
            "guard executes before the current source value is produced",
            "guard_on_different_value",
            normalized_guard_file,
            guard_line,
        )

    if guard_value and not sink_value and _guard_requires_sink_value(
        guard_category,
        expression,
        case_type,
    ):
        blocker: GuardBlocker = (
            "guard_not_resource_bound"
            if guard_category in _AUTHORIZATION_CATEGORIES
            else "flow_not_demonstrated"
        )
        return _rejected(
            guard_category,
            expression,
            "no demonstrated sink value can be linked to this guard",
            blocker,
            normalized_guard_file,
            guard_line,
        )

    if guard_value and sink_value and not _values_related(guard_value, sink_value):
        return _rejected(
            guard_category,
            expression,
            "guard validates or authorizes a different value",
            "guard_on_different_value",
            normalized_guard_file,
            guard_line,
        )

    if result_used is False:
        if guard_category in {"sanitizer_guard", "input_validation_guard"}:
            reason = "sanitizer return value is ignored"
            blocker: GuardBlocker = "sanitizer_result_unused"
        elif guard_category in _AUTHORIZATION_CATEGORIES:
            reason = "authorization query result does not participate in the reported sink"
            blocker = "guard_not_resource_bound"
        else:
            reason = "guard result does not participate in the reported sink"
            blocker = "flow_not_demonstrated"
        return _rejected(
            guard_category,
            expression,
            reason,
            blocker,
            normalized_guard_file,
            guard_line,
        )

    if bypass_possible:
        blocker: GuardBlocker = (
            "guard_not_resource_bound"
            if guard_category in _AUTHORIZATION_CATEGORIES
            else "flow_not_demonstrated"
        )
        return _rejected(
            guard_category,
            expression,
            "a bypass path can reach the sink without this guard",
            blocker,
            normalized_guard_file,
            guard_line,
        )

    if not _compatible_category(guard_category, case_type, expression):
        return _rejected(
            guard_category,
            expression,
            "guard type is not compatible with the reported flow",
            "flow_not_demonstrated",
            normalized_guard_file,
            guard_line,
        )

    if guard_category == "authentication_guard":
        return _rejected(
            guard_category,
            expression,
            "authentication does not bind access to the requested resource",
            "authentication_only",
            normalized_guard_file,
            guard_line,
        )

    if guard_category in _AUTHORIZATION_CATEGORIES and not _resource_bound(
        expression,
        guard_category,
        guard_value,
        sink_value,
        case_type,
    ):
        return _rejected(
            guard_category,
            expression,
            "authorization guard is not bound to the requested resource",
            "guard_not_resource_bound",
            normalized_guard_file,
            guard_line,
        )

    same_function = bool(
        guard_function
        and sink_function
        and _same_function_context(guard_function, sink_function)
    )
    same_route = bool(
        guard_route
        and sink_route
        and _norm_route(guard_route) == _norm_route(sink_route)
    )
    has_context = bool(direct_context or cross_file_link or same_function or same_route)
    if not has_context:
        return _rejected(
            guard_category,
            expression,
            "no execution path links the guard to the reported sink",
            "flow_not_demonstrated",
            normalized_guard_file,
            guard_line,
        )

    return GuardApplicability(
        category=guard_category,
        expression=str(expression or ""),
        applicable=True,
        reason="guard is causally linked to the sink and compatible with the flow",
        guard_file=normalized_guard_file,
        guard_line=guard_line,
    )


def evaluate_case_guards(case: Any, metadata: dict[str, Any] | None = None) -> list[GuardApplicability]:
    """Evaluate all guard evidence attached to an AuditCase-like object."""
    meta = metadata if isinstance(metadata, dict) else {}
    route_context = getattr(case, "route_context", {}) or {}
    if not isinstance(route_context, dict):
        route_context = {}
    structured = getattr(case, "structured_dataflow", {}) or {}
    if not isinstance(structured, dict):
        structured = {}
    structured_sink = structured.get("sink")
    if not isinstance(structured_sink, dict):
        structured_sink = {}
    structured_source = structured.get("source")
    if not isinstance(structured_source, dict):
        structured_source = {}
    sink_file = str(
        meta.get("sink_file")
        or structured_sink.get("file")
        or getattr(case, "file", "")
        or ""
    )
    sink_line = _int_or_none(meta.get("sink_line"))
    if sink_line is None:
        sink_line = (
            _int_or_none(structured_sink.get("line"))
            or _int_or_none(getattr(case, "line", None))
        )
    source_line = (
        _int_or_none(meta.get("source_line"))
        or _int_or_none(structured_source.get("line"))
    )
    sink_function = str(
        meta.get("sink_function")
        or meta.get("function_context")
        or structured.get("function_context")
        or route_context.get("function")
        or route_context.get("function_qualname")
        or ""
    )
    sink_route = str(
        meta.get("route")
        or meta.get("path")
        or route_context.get("route")
        or route_context.get("path")
        or ""
    )
    sink_value = str(
        meta.get("sink_value")
        or meta.get("object_id_source")
        or meta.get("resource")
        or structured_sink.get("symbol")
        or getattr(case, "source", "")
        or ""
    )
    case_type = " ".join(str(value or "") for value in (
        getattr(case, "case_type", ""),
        meta.get("category"),
        meta.get("action"),
        getattr(case, "sink", ""),
    ))

    candidates: list[_GuardCandidate] = []
    results: list[GuardApplicability] = []
    precomputed_expressions: set[str] = set()
    for raw in _as_list(meta.get("guard_applicability")):
        precomputed = _rejected_applicability_from_raw(raw)
        if precomputed is not None:
            results.append(precomputed)
            precomputed_expressions.add(precomputed.expression)
            continue
        candidate = _candidate_from_raw(raw, direct_context=False)
        if candidate is not None:
            candidates.append(candidate)
            precomputed_expressions.add(candidate.expression)

    signal_type = str(meta.get("tool_signal_type") or "")
    direct_observation = signal_type == "access_observation"
    for raw in _as_list(meta.get("detected_guards")):
        candidate = _candidate_from_raw(
            raw,
            default_file=sink_file,
            default_route=sink_route,
            direct_context=direct_observation,
        )
        if candidate is not None and candidate.expression not in precomputed_expressions:
            candidates.append(candidate)

    for raw in getattr(case, "guarantees", ()) or ():
        candidate = _case_guard_candidate(
            raw,
            structured=structured,
            sink_file=sink_file,
            sink_route=sink_route,
        )
        if candidate is not None and candidate.expression not in precomputed_expressions:
            candidates.append(candidate)

    for raw in getattr(case, "sanitizers", ()) or ():
        candidate = _case_guard_candidate(
            raw,
            structured=structured,
            sink_file=sink_file,
            sink_route=sink_route,
            explicit_category="sanitizer_guard",
        )
        if candidate is not None and candidate.expression not in precomputed_expressions:
            candidates.append(candidate)

    for raw in _as_list(route_context.get("auth_guarantees")):
        candidate = _candidate_from_raw(
            raw,
            default_file=sink_file,
            default_route=sink_route,
            direct_context=True,
        )
        if candidate is not None and candidate.expression not in precomputed_expressions:
            candidates.append(candidate)

    if bool(meta.get("strong_guard")) and not candidates and not results:
        category = classify_guard(
            str(meta.get("guard_expression") or ""),
            str(meta.get("guard_category") or ""),
        ) or "input_validation_guard"
        results.append(GuardApplicability(
            category=category,
            expression=str(meta.get("guard_expression") or "strong_guard == true"),
            applicable=False,
            reason="unstructured strong-guard flag has no causal execution proof",
            blockers=("flow_not_demonstrated",),
            guard_file=_norm_path(sink_file),
        ))

    seen: set[tuple[str, str, int | None, str]] = {
        (result.expression, result.guard_file, result.guard_line, result.category)
        for result in results
    }
    for candidate in candidates:
        key = (candidate.expression, candidate.file, candidate.line, candidate.category)
        if key in seen:
            continue
        seen.add(key)
        results.append(assess_guard_applicability(
            candidate.expression,
            category=candidate.category,
            guard_file=candidate.file,
            guard_line=candidate.line,
            guard_function=candidate.function,
            guard_route=candidate.route,
            guard_value=candidate.value,
            sink_file=sink_file,
            source_line=source_line,
            sink_line=sink_line,
            sink_function=sink_function,
            sink_route=sink_route,
            sink_value=sink_value,
            case_type=case_type,
            direct_context=candidate.direct_context,
            propagated=candidate.propagated,
            call_path=candidate.call_path,
            result_used=candidate.result_used,
            bypass_possible=candidate.bypass_possible,
        ))
    return sorted(
        results,
        key=lambda item: (
            item.expression,
            item.category,
            item.guard_file,
            item.guard_line or 0,
            item.reason,
        ),
    )


def _case_guard_candidate(
    raw: Any,
    *,
    structured: dict[str, Any],
    sink_file: str,
    sink_route: str,
    explicit_category: str = "",
) -> _GuardCandidate | None:
    expression = str(raw or "").strip()
    category = classify_guard(expression, explicit_category)
    if not expression or category is None:
        return None

    applicability = structured.get("guard_applicability")
    structured_proven = bool(
        isinstance(applicability, dict)
        and applicability.get("guard_applicable") is True
    )
    evidence_node: dict[str, Any] = {}
    nodes = structured.get("ordered_nodes")
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if str(node.get("expression") or "") != expression:
                continue
            if str(node.get("kind") or "") not in {"guarantee", "sanitizer"}:
                continue
            evidence_node = node
            break

    supported = bool(structured_proven and evidence_node)
    node_metadata = evidence_node.get("metadata")
    if not isinstance(node_metadata, dict):
        node_metadata = {}
    return _GuardCandidate(
        expression=expression,
        category=category,
        file=str(evidence_node.get("file") or (sink_file if supported else "")),
        line=_int_or_none(evidence_node.get("line")),
        function=str(evidence_node.get("function_name") or node_metadata.get("function") or ""),
        route=sink_route if supported else "",
        direct_context=supported,
        result_used=True if supported and category == "sanitizer_guard" else None,
    )


def _rejected_applicability_from_raw(raw: Any) -> GuardApplicability | None:
    if not isinstance(raw, dict) or raw.get("applicable") is not False:
        return None
    expression = str(
        raw.get("expression")
        or raw.get("guard")
        or raw.get("name")
        or raw.get("value")
        or ""
    )
    category = classify_guard(expression, str(raw.get("category") or ""))
    blockers = tuple(
        blocker for blocker in GUARD_BLOCKERS
        if blocker in {str(value) for value in _as_list(raw.get("blockers"))}
    )
    if not expression or category is None or not blockers:
        return None
    return GuardApplicability(
        category=category,
        expression=expression,
        applicable=False,
        reason=str(raw.get("reason") or "guard applicability was rejected upstream"),
        blockers=blockers,
        guard_file=_norm_path(str(raw.get("guard_file") or raw.get("file") or "")),
        guard_line=_int_or_none(
            raw.get("guard_line") if "guard_line" in raw else raw.get("line")
        ),
    )


def blockers_for(results: Iterable[GuardApplicability]) -> tuple[GuardBlocker, ...]:
    """Return unique blockers in the stable public order."""
    present = {blocker for result in results for blocker in result.blockers}
    return tuple(blocker for blocker in GUARD_BLOCKERS if blocker in present)


def _candidate_from_raw(
    raw: Any,
    *,
    default_file: str = "",
    default_route: str = "",
    direct_context: bool = False,
    explicit_category: str = "",
) -> _GuardCandidate | None:
    if isinstance(raw, GuardApplicability):
        return _GuardCandidate(
            expression=raw.expression,
            category=raw.category,
            file=raw.guard_file,
            line=raw.guard_line,
            direct_context=direct_context,
        )
    if isinstance(raw, dict):
        expression = str(
            raw.get("expression")
            or raw.get("guard")
            or raw.get("name")
            or raw.get("value")
            or ""
        )
        category = classify_guard(expression, str(raw.get("category") or explicit_category))
        if category is None:
            return None
        raw_blockers = {str(value) for value in _as_list(raw.get("blockers"))}
        return _GuardCandidate(
            expression=expression,
            category=category,
            file=str(raw.get("guard_file") or raw.get("file") or default_file or ""),
            line=_int_or_none(raw.get("guard_line") if "guard_line" in raw else raw.get("line")),
            function=str(
                raw.get("guard_function")
                or raw.get("function_qualname")
                or raw.get("function")
                or ""
            ),
            route=str(raw.get("guard_route") or raw.get("route") or default_route or ""),
            value=str(
                raw.get("guard_value")
                or raw.get("variable")
                or raw.get("resource")
                or raw.get("object_id_source")
                or ""
            ),
            direct_context=bool(raw.get("direct_context", direct_context)),
            propagated=bool(raw.get("propagated")),
            call_path=bool(raw.get("call_path") or raw.get("call_path_linked")),
            result_used=_bool_or_none(
                raw.get("result_used")
                if "result_used" in raw
                else raw.get("return_value_used")
            ),
            bypass_possible=bool(
                raw.get("bypass_possible")
                or raw.get("bypass")
                or "flow_not_demonstrated" in raw_blockers
                or "guard_not_resource_bound" in raw_blockers
            ),
        )

    expression = str(raw or "").strip()
    category = classify_guard(expression, explicit_category)
    if not expression or category is None:
        return None
    return _GuardCandidate(
        expression=expression,
        category=category,
        file=default_file,
        route=default_route,
        direct_context=direct_context,
    )


def _rejected(
    category: GuardCategory,
    expression: str,
    reason: str,
    blocker: GuardBlocker,
    guard_file: str,
    guard_line: int | None,
) -> GuardApplicability:
    return GuardApplicability(
        category=category,
        expression=str(expression or ""),
        applicable=False,
        reason=reason,
        blockers=(blocker,),
        guard_file=guard_file,
        guard_line=guard_line,
    )


_AUTHORIZATION_CATEGORIES = {
    "role_authorization_guard",
    "ownership_guard",
    "tenant_guard",
    "resource_binding_guard",
}

_VALUE_BOUND_CATEGORIES = {
    "ownership_guard",
    "tenant_guard",
    "resource_binding_guard",
    "input_validation_guard",
    "path_containment_guard",
    "sanitizer_guard",
}


def _resource_bound(
    expression: str,
    category: GuardCategory,
    guard_value: str,
    sink_value: str,
    case_type: str,
) -> bool:
    if category == "resource_binding_guard":
        text = str(expression or "").lower()
        principal_bound = any(token in text for token in (
            "current_user",
            "current_source",
            "current_tenant",
            "owner_id",
            "tenant_id",
            "source_id",
        ))
        explicitly_scoped = any(token in text for token in (
            "scoped_to_",
            "bound_to_resource",
            "owner",
            "tenant",
        ))
        values_match = bool(
            guard_value
            and sink_value
            and _norm_value(guard_value) == _norm_value(sink_value)
        )
        return principal_bound and (explicitly_scoped or values_match)
    if category == "role_authorization_guard":
        text = f"{expression} {case_type}".lower()
        action_text = str(case_type or "").lower()
        is_privileged_action = any(token in action_text for token in (
            "admin",
            "promote",
            "role",
            "permission",
            "deactivate",
        ))
        return is_privileged_action and any(
            token in text for token in ("admin", "role", "permission")
        )
    if guard_value and sink_value:
        return _norm_value(guard_value) == _norm_value(sink_value)
    text = str(expression or "").lower()
    return any(token in text for token in (
        "owner_id",
        "tenant_id",
        "current_user.id",
        "current_user.tenant",
        "current_source",
        "scoped",
        "scope",
        "filter_by",
        "bound_to_resource",
    ))


def _compatible_category(category: GuardCategory, case_type: str, expression: str) -> bool:
    case_text = str(case_type or "").lower()
    expression_text = str(expression or "").lower()
    if category in {"path_containment_guard", "input_validation_guard"}:
        if "path" in expression_text or "filename" in expression_text:
            return not case_text or any(token in case_text for token in ("path", "file"))
    if category in _AUTHORIZATION_CATEGORIES or category == "authentication_guard":
        return any(token in case_text for token in (
            "idor",
            "bola",
            "authorization",
            "access",
            "permission",
        ))
    if category == "sanitizer_guard":
        if "escape" in expression_text:
            return any(token in case_text for token in ("xss", "html", "template"))
        if "normaliz" in expression_text:
            return False
        if any(token in expression_text for token in ("path", "basename")):
            return any(token in case_text for token in ("path", "file"))
    return True


def _guard_requires_sink_value(
    category: GuardCategory,
    expression: str,
    case_type: str,
) -> bool:
    if category in _AUTHORIZATION_CATEGORIES:
        return True
    if category in {"path_containment_guard", "sanitizer_guard"}:
        return True
    if category != "input_validation_guard":
        return False
    text = f"{expression} {case_type}".lower()
    if "credential." in text or "runtime.surface" in text:
        return False
    return any(token in text for token in ("filename", "path", "xss", "html", "template"))


def _norm_path(value: str) -> str:
    return str(value or "").replace("\\", "/").strip().lower()


def _norm_name(value: str) -> str:
    return "".join(char for char in str(value or "").lower() if char.isalnum() or char == ".")


def _same_function_context(left: str, right: str) -> bool:
    normalized_left = _norm_name(left)
    normalized_right = _norm_name(right)
    if not normalized_left or not normalized_right:
        return False
    if "." in normalized_left and "." in normalized_right:
        return normalized_left == normalized_right
    return normalized_left.rsplit(".", 1)[-1] == normalized_right.rsplit(".", 1)[-1]


def _norm_route(value: str) -> str:
    return "/" + "/".join(part for part in str(value or "").lower().split("/") if part)


def _norm_value(value: str) -> str:
    return "".join(char for char in str(value or "").lower() if char.isalnum() or char == "_")


def _values_related(left: str, right: str) -> bool:
    if _norm_value(left) == _norm_value(right):
        return True
    ignored = {
        "base",
        "base_dir",
        "commonpath",
        "filter_by",
        "first_or_404",
        "get",
        "open",
        "os",
        "path",
        "query",
        "root",
        "root_dir",
        "str",
        "upload_dir",
    }
    left_tokens = set(_value_tokens(left)) - ignored
    right_tokens = set(_value_tokens(right)) - ignored
    return bool(left_tokens and right_tokens and left_tokens & right_tokens)


def _value_tokens(value: str) -> list[str]:
    text = str(value or "").lower()
    tokens: list[str] = []
    current = ""
    for char in text:
        if char.isalnum() or char == "_":
            current += char
        elif current:
            tokens.append(current)
            current = ""
    if current:
        tokens.append(current)
    return tokens


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple)):
        return list(value)
    return [] if value in (None, "") else [value]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return bool(value)


__all__ = [
    "GUARD_BLOCKERS",
    "GUARD_CATEGORIES",
    "GuardApplicability",
    "GuardBlocker",
    "GuardCategory",
    "assess_guard_applicability",
    "blockers_for",
    "classify_guard",
    "evaluate_case_guards",
]
