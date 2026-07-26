"""Resource-identity and authorization semantic contracts."""

from __future__ import annotations

import ast

from .common import (
    ClassContractContext,
    ContractObservations,
    FunctionContractContext,
    aborts,
    call_name,
    expression,
    is_top_level_statement,
    make_concern,
    make_guard_transition,
    referenced_names,
    resource_for,
    string_constants,
    walk_function,
)


def analyze_authorization_contracts(
    context: FunctionContractContext | ClassContractContext,
) -> ContractObservations:
    """Evaluate authorization contracts for one syntax scope."""

    if isinstance(context, ClassContractContext):
        return _analyze_class(context)
    return _analyze_function(context)


def _analyze_function(
    context: FunctionContractContext,
) -> ContractObservations:
    concerns = []
    guards = []
    transitions = []
    resource_parameters = [
        name
        for name in context.parameters
        if (name.lower() == "id" or name.lower().endswith("_id"))
        and name.lower() not in {"self", "cls"}
    ]
    authority_parameters = [
        name
        for name in context.parameters
        if name.lower() in {"context", "request", "user", "current_user"}
    ]
    for item in walk_function(context.node):
        if not isinstance(item, ast.If):
            continue
        text = expression(item.test)
        lowered = text.lower()
        if (
            resource_parameters
            and authority_parameters
            and any(name in referenced_names(item.test) for name in resource_parameters)
            and any(name in referenced_names(item.test) for name in authority_parameters)
            and any(token in lowered for token in ("is_admin", "is_superuser", "permission"))
            and aborts(item.body)
            and is_top_level_statement(context, item)
        ):
            selected = next(
                name for name in resource_parameters if name in referenced_names(item.test)
            )
            guard, transition = make_guard_transition(
                context=context,
                resource=resource_for(
                    ast.Name(id=selected),
                    context.parameters,
                ),
                property_name="resource_authorization",
                safe_value="same_principal_or_privileged",
                effect="abortive_resource_identity_guard",
                line=item.lineno,
                condition=text,
                abortive=True,
                branch="false",
                dominates_sink=True,
                column=item.col_offset,
            )
            guards.append(guard)
            transitions.append(transition)

    permission_decorator = _has_permission_decorator(context)
    if resource_parameters and authority_parameters and not permission_decorator:
        for item in walk_function(context.node):
            if not isinstance(item, ast.Call):
                continue
            name = call_name(item.func)
            tail = name.lower().split(".")[-1]
            if not tail.startswith(
                (
                    "add",
                    "create",
                    "delete",
                    "ensure",
                    "remove",
                    "set",
                    "update",
                )
            ):
                continue
            referenced = referenced_names(item)
            selected_resources = [
                parameter for parameter in resource_parameters if parameter in referenced
            ]
            if not selected_resources:
                continue
            selected = selected_resources[0]
            if _has_resource_guard(
                context,
                selected,
                item.lineno,
            ):
                continue
            concerns.append(
                make_concern(
                    context,
                    contract_id="BELIEF-SEM-RESOURCE-AUTHORIZATION",
                    category="missing_authorization_guard",
                    cwe="CWE-862",
                    title="Cross-resource operation lacks an identity guard",
                    description=(
                        "A resource identifier reaches a state-changing "
                        "operation without proving same-principal ownership "
                        "or an explicit privileged context."
                    ),
                    line=item.lineno,
                    function=context.qualified_name,
                    class_name=context.class_name,
                    resource=resource_for(
                        ast.Name(id=selected),
                        context.parameters,
                    ),
                    source="resource_identifier_parameter",
                    sink=name,
                    missing_states=("same_principal_or_privileged",),
                    evidence=expression(item),
                    confidence=0.88,
                    security_property="resource_authorization",
                )
            )
            break

    if not _has_authentication_decorator(context):
        concerns.extend(_sensitive_static_resource_concerns(context))
    decorator_guard = _decorator_guard(context)
    if decorator_guard:
        guard, transition = decorator_guard
        guards.append(guard)
        transitions.append(transition)
    return ContractObservations(
        concerns=tuple(
            sorted(
                concerns,
                key=lambda item: item.sort_key,
            )
        ),
        guards=tuple(
            sorted(
                guards,
                key=lambda item: (
                    item.guard_id,
                    item.resource.canonical,
                ),
            )
        ),
        transitions=tuple(
            sorted(
                transitions,
                key=lambda item: (
                    item.transition_id,
                    item.resource.canonical,
                ),
            )
        ),
    )


def _analyze_class(
    context: ClassContractContext,
) -> ContractObservations:
    bases = {call_name(base).lower() for base in context.node.bases}
    attributes = {
        target.id.lower()
        for item in context.node.body
        if isinstance(item, (ast.Assign, ast.AnnAssign))
        for target in (item.targets if isinstance(item, ast.Assign) else [item.target])
        if isinstance(target, ast.Name)
    }
    bulk_action = any(base.split(".")[-1].endswith("bulkaction") for base in bases)
    permission_boundary = (
        any("permission" in base for base in bases)
        or "permission_policy" in attributes
        or any("permission_required" in name for name in attributes)
    )
    if not bulk_action or permission_boundary:
        return ContractObservations()
    resource = resource_for(
        ast.Name(id=context.qualified_name),
        (),
    )
    concern = make_concern(
        context,
        contract_id="BELIEF-SEM-PERMISSION-MIXIN",
        category="missing_authorization_guard",
        cwe="CWE-862",
        title="Bulk state-changing action has no permission boundary",
        description=(
            "A bulk action class declares mutable model scope without a "
            "permission-checking mixin or policy."
        ),
        line=context.node.lineno,
        function=f"{context.qualified_name}.<class>",
        class_name=context.qualified_name,
        resource=resource,
        source="bulk_action_request",
        sink="bulk_model_action",
        missing_states=("permission_policy",),
        evidence=expression(context.node.bases[0]),
        confidence=0.9,
        security_property="resource_authorization",
    )
    return ContractObservations(concerns=(concern,))


def _has_resource_guard(
    context: FunctionContractContext,
    resource: str,
    sink_line: int,
) -> bool:
    for item in walk_function(context.node):
        if (
            not isinstance(item, ast.If)
            or not is_top_level_statement(context, item)
            or item.lineno >= sink_line
            or not aborts(item.body)
        ):
            continue
        text = expression(item.test).lower()
        if resource in referenced_names(item.test) and any(
            token in text for token in ("is_admin", "is_superuser", "permission")
        ):
            return True
    return False


def _sensitive_static_resource_concerns(
    context: FunctionContractContext,
) -> list:
    concerns = []
    for item in walk_function(context.node):
        if not isinstance(item, ast.Call):
            continue
        name = call_name(item.func).lower()
        if not name.endswith("register_static_path"):
            continue
        text = expression(item).lower()
        strings = {value.lower() for value in string_constants(item)}
        if not (
            any(token in text for token in ("error", "log"))
            or any(token in value for value in strings for token in ("error", "log"))
        ):
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-SENSITIVE-STATIC-RESOURCE",
                category="missing_authorization_guard",
                cwe="CWE-200",
                title="Sensitive diagnostic resource is exposed as static content",
                description=(
                    "A log or error resource is registered as a static path "
                    "without an authenticated view boundary."
                ),
                line=item.lineno,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    item.args[1] if len(item.args) > 1 else item,
                    context.parameters,
                ),
                source="diagnostic_resource",
                sink=call_name(item.func),
                missing_states=("authenticated_view",),
                evidence=expression(item),
                confidence=0.9,
                security_property="resource_authorization",
            )
        )
    return concerns


def _decorator_guard(
    context: FunctionContractContext,
):
    for decorator in context.node.decorator_list:
        name = call_name(decorator.func if isinstance(decorator, ast.Call) else decorator)
        lowered = name.lower()
        if not any(
            token in lowered
            for token in (
                "auth",
                "login_required",
                "permission",
                "is_admin",
            )
        ):
            continue
        resource = resource_for(
            ast.Name(id=context.qualified_name),
            context.parameters,
        )
        return make_guard_transition(
            context=context,
            resource=resource,
            property_name="resource_authorization",
            safe_value="decorator_authorized",
            effect="authorization_decorator",
            line=getattr(decorator, "lineno", context.node.lineno),
            condition=name,
            abortive=True,
            branch="true",
            column=getattr(decorator, "col_offset", None),
        )
    return None


def _has_permission_decorator(
    context: FunctionContractContext,
) -> bool:
    return any(
        any(
            token
            in call_name(decorator.func if isinstance(decorator, ast.Call) else decorator).lower()
            for token in ("admin", "permission")
        )
        for decorator in context.node.decorator_list
    )


def _has_authentication_decorator(
    context: FunctionContractContext,
) -> bool:
    return any(
        any(
            token
            in call_name(decorator.func if isinstance(decorator, ast.Call) else decorator).lower()
            for token in (
                "auth",
                "is_admin",
                "login_required",
                "permission",
            )
        )
        for decorator in context.node.decorator_list
    )


__all__ = ["analyze_authorization_contracts"]
