"""Protocol parsing, header, redirect, and secret-egress contracts."""

from __future__ import annotations

import ast

from .common import (
    ClassContractContext,
    ContractObservations,
    FunctionContractContext,
    aborts,
    call_name,
    expression,
    has_effective_abortive_summary,
    has_effective_sanitizer_reassignment,
    has_ancestor,
    is_top_level_statement,
    lineage_names,
    make_concern,
    make_guard_transition,
    referenced_names,
    resource_for,
    string_constants,
    walk_function,
)


def analyze_protocol_contracts(
    context: FunctionContractContext | ClassContractContext,
) -> ContractObservations:
    """Evaluate protocol-boundary contracts for one syntax scope."""

    if isinstance(context, ClassContractContext):
        return _analyze_class(context)
    return _analyze_function(context)


def _analyze_function(
    context: FunctionContractContext,
) -> ContractObservations:
    concerns = []
    guards = []
    transitions = []
    items = list(walk_function(context.node))
    all_strings = {value.lower() for item in items for value in string_constants(item)}
    calls = [item for item in items if isinstance(item, ast.Call)]
    parents = _parent_map(context.node)

    json_calls = [item for item in calls if call_name(item.func).lower().endswith(".json")]
    body_calls = [item for item in calls if call_name(item.func).lower().endswith(".body")]
    for item in json_calls:
        receiver = (
            item.func.value if isinstance(item.func, ast.Attribute) else ast.Name(id="request")
        )
        if not body_calls or _has_content_type_gate(
            context,
            receiver,
            item,
        ):
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-CONTENT-TYPE-GATE",
                category="protocol_validation_gap",
                cwe="CWE-20",
                title="Request body is decoded without a media-type gate",
                description=(
                    "Raw request bytes are parsed as JSON without first "
                    "proving a JSON-compatible Content-Type."
                ),
                line=item.lineno,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    receiver,
                    context.parameters,
                ),
                source="request_body",
                sink=call_name(item.func),
                missing_states=("json_compatible_media_type",),
                evidence=expression(item),
                confidence=0.92,
                security_property="media_type",
            )
        )

    if "http_headers" in all_strings and _forwards_protocol_metadata(calls):
        line = _first_string_line(items, "http_headers")
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-HEADER-MAP-SCOPE",
                category="sensitive_header_scope",
                cwe="CWE-200",
                title="Arbitrary header map crosses a request boundary",
                description=(
                    "A serialized metadata field can forward an unrestricted "
                    "header mapping to another request context."
                ),
                line=line,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    ast.Name(id="http_headers"),
                    context.parameters,
                ),
                source="serialized_header_map",
                sink="outbound_request_headers",
                missing_states=("header_allowlist",),
                evidence="http_headers metadata reaches request construction",
                confidence=0.9,
                security_property="header_scope",
            )
        )

    forwarded = _forwarded_request_header_variables(context)
    for variable, source_line, sink_line in forwarded:
        if _header_removed_before(
            context,
            variable,
            source_line,
            sink_line,
            "authorization",
        ):
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-CREDENTIAL-HEADER-SCOPE",
                category="sensitive_header_scope",
                cwe="CWE-200",
                title="Credential-bearing request headers cross trust contexts",
                description=(
                    "Inbound request headers are serialized for another "
                    "request without removing Authorization."
                ),
                line=sink_line,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    ast.Name(id=variable),
                    context.parameters,
                ),
                source="inbound_request_headers",
                sink="outbound_request_headers",
                missing_states=("authorization_header_removed",),
                evidence=f"{variable} forwards request headers",
                confidence=0.91,
                security_property="credential_header_scope",
            )
        )

    for item in items:
        if isinstance(item, ast.If):
            extracted = _protocol_guard(context, item)
            if extracted:
                guard, transition = extracted
                guards.append(guard)
                transitions.append(transition)

    for item in items:
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        target, value = _single_assignment(item)
        if target is None or value is None:
            continue
        key = _subscript_string(target)
        if key != "proxy-authorization":
            continue
        protected = has_ancestor(
            item,
            parents,
            _non_tunnel_branch,
        ) or _has_https_abort_before(context, item.lineno)
        if protected:
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-PROXY-AUTH-CONTEXT",
                category="sensitive_header_scope",
                cwe="CWE-200",
                title="Proxy credentials may be attached to a TLS tunnel",
                description=(
                    "Proxy-Authorization is emitted without excluding the HTTPS tunneling context."
                ),
                line=item.lineno,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    target.value if isinstance(target, ast.Subscript) else target,
                    context.parameters,
                ),
                source="proxy_credentials",
                sink="Proxy-Authorization",
                missing_states=("non_tunneled_proxy_request",),
                evidence=expression(item),
                confidence=0.94,
                security_property="credential_header_scope",
            )
        )

    concerns.extend(_argv_egress_concerns(context))
    concerns.extend(_header_storage_concerns(context))
    concerns.extend(_redirect_concerns(context))
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
    concerns = []
    for item in context.node.body:
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        target_names = {target.id.lower() for target in targets if isinstance(target, ast.Name)}
        if not any("remove_headers_on_redirect" in name for name in target_names):
            continue
        values = {value.lower() for value in string_constants(item.value)}
        if "authorization" not in values or "cookie" in values:
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-REDIRECT-HEADER-STRIP",
                category="sensitive_header_scope",
                cwe="CWE-200",
                title="Redirect policy retains ambient cookies",
                description=(
                    "A redirect header-removal policy strips Authorization "
                    "but leaves Cookie available across origins."
                ),
                line=item.lineno,
                function=f"{context.qualified_name}.<class>",
                class_name=context.qualified_name,
                resource=resource_for(
                    ast.Name(id=next(iter(target_names))),
                    (),
                ),
                source="ambient_credentials",
                sink="redirected_request_headers",
                missing_states=("cookie_header_removed",),
                evidence=expression(item.value),
                confidence=0.93,
                security_property="credential_header_scope",
            )
        )
    return ContractObservations(
        concerns=tuple(
            sorted(
                concerns,
                key=lambda item: item.sort_key,
            )
        )
    )


def _argv_egress_concerns(
    context: FunctionContractContext,
) -> list:
    items = list(walk_function(context.node))
    source_variables = set()
    sanitized_variables = set()
    direct_egress = []
    for item in items:
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        target, value = _single_assignment(item)
        if target is None or value is None:
            continue
        if _contains_raw_sys_argv(value):
            if isinstance(target, ast.Name):
                source_variables.add(target.id)
                if _contains_redaction(value):
                    sanitized_variables.add(target.id)
            if isinstance(target, ast.Subscript):
                direct_egress.append(item)
        if isinstance(value, ast.Dict) and _contains_raw_sys_argv(value):
            direct_egress.append(item)
    if _contains_raw_sys_argv(context.node) and not source_variables:
        for item in items:
            if isinstance(item, ast.Dict) and _contains_raw_sys_argv(item):
                direct_egress.append(item)
    redacted = {
        target.value.id
        for item in items
        if isinstance(item, (ast.Assign, ast.AnnAssign))
        for target in _assignment_targets(item)
        if isinstance(target, ast.Subscript)
        and isinstance(target.value, ast.Name)
        and target.value.id in source_variables
        and _contains_redaction(item.value)
    }
    concerns = []
    for item in direct_egress:
        concerns.append(_argv_concern(context, item.lineno))
    for variable in sorted(source_variables - redacted - sanitized_variables):
        if _variable_reaches_mapping_or_call(context, variable):
            line = next(
                item.lineno
                for item in items
                if isinstance(item, (ast.Assign, ast.AnnAssign))
                and any(
                    isinstance(target, ast.Name) and target.id == variable
                    for target in _assignment_targets(item)
                )
            )
            concerns.append(_argv_concern(context, line))
    return concerns


def _argv_concern(
    context: FunctionContractContext,
    line: int,
):
    return make_concern(
        context,
        contract_id="BELIEF-SEM-ARGV-REDACTION",
        category="sensitive_data_egress",
        cwe="CWE-312",
        title="Command-line secrets reach telemetry without redaction",
        description=(
            "The complete process argument vector is stored or emitted "
            "without a value-redaction transition."
        ),
        line=line,
        function=context.qualified_name,
        class_name=context.class_name,
        resource=resource_for(
            ast.Attribute(
                value=ast.Name(id="sys"),
                attr="argv",
            ),
            context.parameters,
        ),
        source="process_arguments",
        sink="telemetry_or_metrics",
        missing_states=("sensitive_values_redacted",),
        evidence="sys.argv reaches a mapping or call",
        confidence=0.9,
        security_property="secret_redaction",
    )


def _header_storage_concerns(
    context: FunctionContractContext,
) -> list:
    if "header" not in context.class_name.lower():
        return []
    try:
        value_index = next(
            index
            for index, name in enumerate(context.parameters)
            if name.lower() in {"value", "val", "header_value"}
        )
    except StopIteration:
        return []
    value_name = context.parameters[value_index]
    for item in walk_function(context.node):
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            target, value = _single_assignment(item)
            if (
                target is not None
                and value is not None
                and value_name in referenced_names(value)
                and isinstance(target, ast.Subscript)
            ):
                if (
                    _has_header_guard_before(
                        context,
                        value_name,
                        item.lineno,
                    )
                    or has_effective_abortive_summary(
                        context,
                        value_name,
                        before_line=item.lineno,
                    )
                    or has_effective_sanitizer_reassignment(
                        context,
                        value_name,
                        before_line=item.lineno,
                    )
                ):
                    return []
                return [
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-HEADER-CONTROL-CHARS",
                        category="protocol_validation_gap",
                        cwe="CWE-93",
                        title="Header value is stored without control-character validation",
                        description=(
                            "A header container accepts a raw value without "
                            "a validator that rejects CR, LF, or NUL."
                        ),
                        line=item.lineno,
                        function=context.qualified_name,
                        class_name=context.class_name,
                        resource=resource_for(
                            ast.Name(id=value_name),
                            context.parameters,
                        ),
                        source="header_value_parameter",
                        sink="header_container",
                        missing_states=("control_characters_rejected",),
                        evidence=expression(item),
                        confidence=0.93,
                        security_property="header_value_safety",
                    )
                ]
    return []


def _has_header_guard_before(
    context: FunctionContractContext,
    value_name: str,
    sink_line: int,
) -> bool:
    return any(
        isinstance(item, ast.If)
        and item in context.node.body
        and item.lineno < sink_line
        and aborts(item.body)
        and value_name in referenced_names(item.test)
        and bool({"\n", "\r", "\x00"} & string_constants(item.test))
        for item in context.node.body
    )


def _redirect_concerns(
    context: FunctionContractContext,
) -> list:
    concerns = []
    items = list(walk_function(context.node))
    for item in items:
        if not isinstance(item, ast.Call) or not item.args:
            continue
        tail = call_name(item.func).lower().split(".")[-1]
        if tail not in {"httpredirect", "redirect"}:
            continue
        argument = item.args[0]
        names = referenced_names(argument)
        if not names or not (
            names & set(context.parameters)
            or {"next", "url", "target"} & {value.lower() for value in names}
        ):
            continue
        if _has_origin_guard_for(context, argument, item):
            continue
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-REDIRECT-ORIGIN",
                category="protocol_validation_gap",
                cwe="CWE-601",
                title="Redirect target has no same-origin proof",
                description=(
                    "A dynamic redirect reaches the response boundary "
                    "without a host or origin allowlist."
                ),
                line=item.lineno,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    argument,
                    context.parameters,
                ),
                source="dynamic_redirect_target",
                sink=call_name(item.func),
                missing_states=("same_origin",),
                evidence=expression(item),
                confidence=0.9,
                security_property="redirect_origin",
            )
        )
    return concerns


def _has_origin_guard_for(
    context: FunctionContractContext,
    argument: ast.AST,
    sink: ast.Call,
) -> bool:
    sink_line = sink.lineno
    sink_names = lineage_names(
        context,
        argument,
        before_line=sink_line,
    )
    parents = _parent_map(context.node)
    for item in walk_function(context.node):
        if not isinstance(item, ast.If) or item.lineno > sink_line:
            continue
        text = expression(item.test).lower()
        if not any(
            token in text
            for token in (
                "allowed_host",
                "hostname",
                "is_safe",
                "netloc",
                "same_origin",
            )
        ):
            continue
        guard_names = lineage_names(
            context,
            item.test,
            before_line=sink_line,
        )
        if not sink_names.intersection(guard_names):
            continue
        sink_in_branch = has_ancestor(
            sink,
            parents,
            lambda parent: parent is item,
        )
        positive_safe_branch = (
            sink_in_branch and "not " not in text and "!=" not in text and " not in " not in text
        )
        abortive_fallthrough = (
            item in context.node.body
            and item.lineno < sink_line
            and aborts(item.body)
            and ("not " in text or "!=" in text or " not in " in text or "netloc" in text)
        )
        if positive_safe_branch or abortive_fallthrough:
            return True
    return False


def _has_content_type_gate(
    context: FunctionContractContext,
    receiver: ast.AST,
    sink: ast.Call,
) -> bool:
    sink_line = sink.lineno
    sink_names = lineage_names(
        context,
        receiver,
        before_line=sink_line,
    )
    receiver_type_evidence = _has_receiver_content_type_evidence(
        context,
        sink_names,
        sink_line,
    )
    parents = _parent_map(context.node)
    for item in walk_function(context.node):
        if not isinstance(item, ast.If) or item.lineno > sink_line:
            continue
        text = expression(item.test).lower()
        strings = {value.lower() for value in string_constants(item.test)}
        if not (
            {"content-type", "content_type"} & strings
            or "content_type" in text
            or "get_content_" in text
            or ("json" in strings and receiver_type_evidence)
        ):
            continue
        guard_names = lineage_names(
            context,
            item.test,
            before_line=sink_line,
        )
        if sink_names and not sink_names.intersection(guard_names) and not receiver_type_evidence:
            continue
        sink_in_branch = has_ancestor(
            sink,
            parents,
            lambda parent: parent is item,
        )
        positive_json_branch = (
            sink_in_branch
            and ("json" in strings or "json" in text)
            and "not " not in text
            and "!=" not in text
        )
        abortive_non_json = (
            item in context.node.body
            and item.lineno < sink_line
            and aborts(item.body)
            and ("not " in text or "!=" in text or " not in " in text)
        )
        if positive_json_branch or abortive_non_json:
            return True
    return False


def _has_receiver_content_type_evidence(
    context: FunctionContractContext,
    receiver_names: frozenset[str],
    sink_line: int,
) -> bool:
    return any(
        isinstance(item, ast.Call)
        and item.lineno < sink_line
        and "content-type" in {value.lower() for value in string_constants(item)}
        and bool(receiver_names.intersection(referenced_names(item)))
        for item in walk_function(context.node)
    )


def _protocol_guard(
    context: FunctionContractContext,
    node: ast.If,
):
    text = expression(node.test)
    lowered = text.lower()
    property_name = ""
    safe_value = ""
    effect = ""
    names = referenced_names(node.test)
    if {"\n", "\r", "\x00"} & string_constants(node.test) and names and aborts(node.body):
        property_name = "header_value_safety"
        safe_value = "control_characters_rejected"
        effect = "abortive_header_validation"
    elif ("netloc" in lowered or "allowed_host" in lowered) and names:
        property_name = "redirect_origin"
        safe_value = "same_origin"
        effect = "origin_validation"
    elif "is_hidden" in lowered and names and aborts(node.body):
        property_name = "path_visibility"
        safe_value = "visible_or_allowed"
        effect = "abortive_hidden_path_guard"
    else:
        return None
    selected = sorted(names & set(context.parameters) or names)[0]
    return make_guard_transition(
        context=context,
        resource=resource_for(
            ast.Name(id=selected),
            context.parameters,
        ),
        property_name=property_name,
        safe_value=safe_value,
        effect=effect,
        line=node.lineno,
        condition=text,
        abortive=aborts(node.body),
        branch="false" if aborts(node.body) else "true",
        dominates_sink=is_top_level_statement(context, node),
    )


def _forwarded_request_header_variables(
    context: FunctionContractContext,
) -> list[tuple[str, int, int]]:
    sources = {}
    for item in walk_function(context.node):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        target, value = _single_assignment(item)
        if (
            isinstance(target, ast.Name)
            and value is not None
            and "request.headers" in expression(value).lower()
            and not _header_mapping_is_allowlisted(value)
        ):
            sources[target.id] = item.lineno
    result = []
    for variable, source_line in sources.items():
        sinks = [
            item.lineno
            for item in walk_function(context.node)
            if isinstance(item, ast.Call)
            and item.lineno > source_line
            and variable in referenced_names(item)
            and (
                "headers" in {value.lower() for value in string_constants(item)}
                or "request" in call_name(item.func).lower()
                or "send" in call_name(item.func).lower()
            )
        ]
        if sinks:
            result.append((variable, source_line, min(sinks)))
    return sorted(result)


def _header_mapping_is_allowlisted(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        return bool(node.keys) and all(
            isinstance(key, ast.Constant) and isinstance(key.value, str)
            for key in node.keys
            if key is not None
        )
    names = {call_name(item.func).lower() for item in ast.walk(node) if isinstance(item, ast.Call)}
    if any(
        any(
            token in name
            for token in (
                "allowlist",
                "filter_headers",
                "select_headers",
            )
        )
        for name in names
    ):
        return True
    return isinstance(
        node,
        (ast.DictComp, ast.ListComp, ast.SetComp),
    ) and bool(node.generators and any(generator.ifs for generator in node.generators))


def _header_removed_before(
    context: FunctionContractContext,
    variable: str,
    source_line: int,
    sink_line: int,
    header: str,
) -> bool:
    for item in walk_function(context.node):
        if not isinstance(item, ast.Call):
            continue
        name = call_name(item.func).lower()
        if (
            name == f"{variable.lower()}.pop"
            and header in {value.lower() for value in string_constants(item)}
            and source_line <= item.lineno < sink_line
            and _nearest_statement(context.node, item) in context.node.body
        ):
            return True
    return False


def _forwards_protocol_metadata(calls: list[ast.Call]) -> bool:
    return any(
        any(
            token in call_name(item.func).lower()
            for token in (
                "request",
                "smuggle",
                "url_result",
                "webpage",
            )
        )
        for item in calls
    )


def _first_string_line(items: list[ast.AST], value: str) -> int:
    for item in items:
        if value in {selected.lower() for selected in string_constants(item)}:
            return getattr(item, "lineno", 1)
    return 1


def _single_assignment(
    item: ast.Assign | ast.AnnAssign,
) -> tuple[ast.AST | None, ast.AST | None]:
    if isinstance(item, ast.Assign):
        return (
            item.targets[0] if len(item.targets) == 1 else None,
            item.value,
        )
    return item.target, item.value


def _assignment_targets(
    item: ast.Assign | ast.AnnAssign,
) -> list[ast.AST]:
    return item.targets if isinstance(item, ast.Assign) else [item.target]


def _subscript_string(node: ast.AST) -> str:
    if not isinstance(node, ast.Subscript):
        return ""
    selected = node.slice
    if isinstance(selected, ast.Constant) and isinstance(
        selected.value,
        str,
    ):
        return selected.value.lower()
    return ""


def _non_tunnel_branch(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    strings = {value.lower() for value in string_constants(node.test)}
    text = expression(node.test).lower()
    return "http" in strings or ("https" in strings and ("not " in text or "!=" in text))


def _has_https_abort_before(
    context: FunctionContractContext,
    sink_line: int,
) -> bool:
    return any(
        isinstance(item, ast.If)
        and item in context.node.body
        and item.lineno < sink_line
        and aborts(item.body)
        and "https" in {value.lower() for value in string_constants(item.test)}
        and "!=" not in expression(item.test)
        and "not " not in expression(item.test).lower()
        for item in context.node.body
    )


def _contains_raw_sys_argv(node: ast.AST) -> bool:
    parents = _parent_map(node)
    for item in ast.walk(node):
        if not (
            isinstance(item, ast.Attribute)
            and item.attr == "argv"
            and isinstance(item.value, ast.Name)
            and item.value.id == "sys"
        ):
            continue
        parent = parents.get(item)
        if isinstance(parent, ast.Call) and call_name(parent.func).lower() == "len":
            continue
        return True
    return False


def _contains_redaction(node: ast.AST) -> bool:
    text = expression(node).lower()
    return any(
        token in text
        for token in (
            "<redacted>",
            "mask_secret",
            "redact",
            "sanitize",
        )
    )


def _variable_reaches_mapping_or_call(
    context: FunctionContractContext,
    variable: str,
) -> bool:
    return any(
        (isinstance(item, (ast.Dict, ast.Call)) and variable in referenced_names(item))
        for item in walk_function(context.node)
    )


def _parent_map(root: ast.AST) -> dict[ast.AST, ast.AST]:
    result = {}
    for parent in ast.walk(root):
        for child in ast.iter_child_nodes(parent):
            result[child] = parent
    return result


def _nearest_statement(
    root: ast.AST,
    node: ast.AST,
) -> ast.stmt | None:
    parents = _parent_map(root)
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.stmt):
            return current
    return None


__all__ = ["analyze_protocol_contracts"]
