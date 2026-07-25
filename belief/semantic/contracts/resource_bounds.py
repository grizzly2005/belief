"""Resource-bound, termination, and regex semantic contracts."""

from __future__ import annotations

import ast
import re

from .common import (
    ClassContractContext,
    ContractObservations,
    FunctionContractContext,
    aborts,
    call_name,
    enclosing_nodes,
    expression,
    has_ancestor,
    has_effective_abortive_summary,
    is_top_level_statement,
    lineage_names,
    make_concern,
    make_guard_transition,
    referenced_names,
    resource_for,
    statement_before,
    walk_function,
)


_BOUNDED_FIELD_NAMES = (
    "email",
    "fullname",
    "label",
    "name",
    "title",
    "username",
)
_TEXT_FIELD_TYPES = {
    "EmailField",
    "PasswordField",
    "StringField",
    "TextField",
    "URLField",
}


def analyze_resource_contracts(
    context: FunctionContractContext | ClassContractContext,
) -> ContractObservations:
    """Evaluate one function or class against reusable resource contracts."""

    if isinstance(context, ClassContractContext):
        return _analyze_class(context)
    return _analyze_function(context)


def _analyze_function(
    context: FunctionContractContext,
) -> ContractObservations:
    concerns = []
    guards = []
    transitions = []
    for item in walk_function(context.node):
        if not isinstance(item, ast.If) or not aborts(item.body):
            continue
        bound = _length_bound(item.test, context.parameters)
        if bound is None:
            continue
        resource, condition = bound
        guard, transition = make_guard_transition(
            context=context,
            resource=resource,
            property_name="resource_bound",
            safe_value="bounded",
            effect="abortive_upper_bound",
            line=item.lineno,
            condition=condition,
            abortive=True,
            branch="false",
            dominates_sink=is_top_level_statement(context, item),
        )
        guards.append(guard)
        transitions.append(transition)

    parents = enclosing_nodes(context.node)
    constants = _local_string_constants(context.node)
    for item in walk_function(context.node):
        if not isinstance(item, ast.Call):
            continue
        name = call_name(item.func)
        tail = name.lower().split(".")[-1]
        if tail in {"decompress", "decompressobj"} and item.args:
            resource_node = item.args[0]
            if not _statically_bounded(resource_node) and not _has_length_bound_before(
                context,
                resource_node,
                item.lineno,
            ):
                resource = resource_for(
                    resource_node,
                    context.parameters,
                )
                concerns.append(
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-RESOURCE-BOUND",
                        category="unbounded_resource_consumption",
                        cwe="CWE-770",
                        title="Compressed input is expanded without a prior bound",
                        description=(
                            "A decompression boundary consumes data whose "
                            "size is not rejected before expansion."
                        ),
                        line=item.lineno,
                        function=context.qualified_name,
                        class_name=context.class_name,
                        resource=resource,
                        source="function_input",
                        sink=name,
                        missing_states=("bounded_before_expansion",),
                        evidence=expression(item),
                        confidence=0.94,
                        security_property="resource_bound",
                    )
                )
        if _is_recursive_call(item, context):
            protected = has_ancestor(
                item,
                parents,
                _handles_recursion_failure,
            ) or _has_recursion_bound_before(
                context,
                item.lineno,
            )
            if not protected:
                resource_node = (
                    item.func.value
                    if isinstance(item.func, ast.Attribute)
                    else (item.args[0] if item.args else ast.Name(id="recursive_input"))
                )
                concerns.append(
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-RECURSION-BOUND",
                        category="unbounded_resource_consumption",
                        cwe="CWE-674",
                        title="Recursive expansion has no bounded failure state",
                        description=(
                            "A recursive call can exhaust interpreter depth "
                            "without translating the limit into a controlled "
                            "failure."
                        ),
                        line=item.lineno,
                        function=context.qualified_name,
                        class_name=context.class_name,
                        resource=resource_for(
                            resource_node,
                            context.parameters,
                        ),
                        source="recursive_structure",
                        sink=name,
                        missing_states=("bounded_recursion_failure",),
                        evidence=expression(item),
                        confidence=0.9,
                        security_property="recursion_bound",
                    )
                )

        pattern = _pattern_argument(item, constants)
        if pattern is not None:
            risk = _regex_risk(pattern)
            input_node = _regex_input_node(item, context)
            if risk and not _has_length_bound_before(
                context,
                input_node,
                item.lineno,
            ):
                resource = _regex_resource(item, context)
                concerns.append(
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-REGEX-COMPLEXITY",
                        category="unbounded_resource_consumption",
                        cwe="CWE-1333",
                        title="Validation regex has an ambiguous unbounded path",
                        description=(
                            "A repeated or wildcard regex branch can consume "
                            "super-linear work without an input bound."
                        ),
                        line=item.lineno,
                        function=context.qualified_name,
                        class_name=context.class_name,
                        resource=resource,
                        source="validation_input",
                        sink=name,
                        missing_states=("bounded_input_or_unambiguous_regex",),
                        evidence=risk,
                        confidence=0.88,
                        security_property="regex_complexity_bound",
                    )
                )

    concerns.extend(_loop_progress_concerns(context))
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
    class_has_maximum = any(
        isinstance(item, (ast.Assign, ast.AnnAssign))
        and any(_target_name(target) == "max_length" for target in _assignment_targets(item))
        for item in context.node.body
    )
    for item in context.node.body:
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        value = item.value
        if not isinstance(value, ast.Call):
            continue
        target_names = [
            name for target in _assignment_targets(item) if (name := _target_name(target))
        ]
        tail = call_name(value.func).split(".")[-1]
        if tail in _TEXT_FIELD_TYPES:
            for field_name in target_names:
                if any(
                    token in field_name.lower() for token in _BOUNDED_FIELD_NAMES
                ) and not _field_has_length_bound(value):
                    resource = resource_for(
                        ast.Name(id=field_name),
                        (),
                    )
                    concerns.append(
                        make_concern(
                            context,
                            contract_id="BELIEF-SEM-DECLARATIVE-BOUND",
                            category="unbounded_resource_consumption",
                            cwe="CWE-770",
                            title="Text input has no declarative upper bound",
                            description=(
                                "A user-controlled text field is accepted "
                                "without a maximum length validator."
                            ),
                            line=item.lineno,
                            function=f"{context.qualified_name}.<class>",
                            class_name=context.qualified_name,
                            resource=resource,
                            source="declarative_input_field",
                            sink=tail,
                            missing_states=("maximum_length",),
                            evidence=expression(value),
                            confidence=0.82,
                            security_property="resource_bound",
                        )
                    )

        for pattern in _patterns_from_assignment(item):
            risk = _regex_risk(pattern)
            if risk and not class_has_maximum:
                resource = resource_for(
                    ast.Name(id=target_names[0] if target_names else "regex"),
                    (),
                )
                concerns.append(
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-REGEX-COMPLEXITY",
                        category="unbounded_resource_consumption",
                        cwe="CWE-1333",
                        title="Validation regex has an ambiguous unbounded path",
                        description=(
                            "A class-level validation regex is potentially "
                            "super-linear and has no explicit input bound."
                        ),
                        line=item.lineno,
                        function=f"{context.qualified_name}.<class>",
                        class_name=context.qualified_name,
                        resource=resource,
                        source="validation_input",
                        sink="regex_validation",
                        missing_states=("bounded_input_or_unambiguous_regex",),
                        evidence=risk,
                        confidence=0.88,
                        security_property="regex_complexity_bound",
                    )
                )
            if _soft_end_anchor(pattern) and _validation_context(context.qualified_name):
                resource = resource_for(
                    ast.Name(id=target_names[0] if target_names else "regex"),
                    (),
                )
                concerns.append(
                    make_concern(
                        context,
                        contract_id="BELIEF-SEM-ABSOLUTE-REGEX-END",
                        category="protocol_validation_gap",
                        cwe="CWE-20",
                        title="Validation regex accepts data after a soft line end",
                        description=(
                            "A security-sensitive validator uses '$' instead "
                            "of an absolute end or full-match operation."
                        ),
                        line=item.lineno,
                        function=f"{context.qualified_name}.<class>",
                        class_name=context.qualified_name,
                        resource=resource,
                        source="validation_input",
                        sink="regex_validation",
                        missing_states=("absolute_end_match",),
                        evidence="validation pattern terminates with $",
                        confidence=0.86,
                        security_property="absolute_end_match",
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


def _length_bound(
    node: ast.AST,
    parameters: tuple[str, ...],
):
    for item in ast.walk(node):
        if not isinstance(item, ast.Compare) or len(item.ops) != 1 or len(item.comparators) != 1:
            continue
        left = item.left
        right = item.comparators[0]
        operator = item.ops[0]
        length_call = None
        if _is_length_call(left) and isinstance(operator, (ast.Gt, ast.GtE)):
            length_call = left
        elif _is_length_call(right) and isinstance(operator, (ast.Lt, ast.LtE)):
            length_call = right
        if length_call is None:
            continue
        target = length_call.args[0]
        return (
            resource_for(target, parameters),
            expression(node),
        )
    return None


def _has_length_bound_before(
    context: FunctionContractContext,
    resource_node: ast.AST,
    line: int,
) -> bool:
    target_names = lineage_names(
        context,
        resource_node,
        before_line=line,
    )
    if isinstance(resource_node, ast.Name):
        if has_effective_abortive_summary(
            context,
            resource_node.id,
            before_line=line,
        ):
            return True
    for item in walk_function(context.node):
        if (
            isinstance(item, ast.If)
            and is_top_level_statement(context, item)
            and statement_before(item, line)
            and aborts(item.body)
        ):
            bound = _length_bound(item.test, context.parameters)
            if bound is None:
                continue
            if bound[0].symbol in target_names:
                return True
    return False


def _is_length_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and call_name(node.func) == "len" and bool(node.args)


def _statically_bounded(node: ast.AST) -> bool:
    return isinstance(
        node,
        (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict),
    )


def _handles_recursion_failure(node: ast.AST) -> bool:
    if not isinstance(node, ast.Try):
        return False
    return any(
        any(name in {"RecursionError", "RuntimeError"} for name in _exception_names(handler.type))
        for handler in node.handlers
    )


def _has_recursion_bound_before(
    context: FunctionContractContext,
    sink_line: int,
) -> bool:
    depth_parameters = {
        name
        for name in context.parameters
        if any(token in name.lower() for token in ("depth", "level", "recursion"))
    }
    if not depth_parameters:
        return False
    return any(
        isinstance(item, ast.If)
        and item in context.node.body
        and item.lineno < sink_line
        and aborts(item.body)
        and depth_parameters.intersection(referenced_names(item.test))
        and any(
            isinstance(operator, (ast.Gt, ast.GtE))
            for comparison in ast.walk(item.test)
            if isinstance(comparison, ast.Compare)
            for operator in comparison.ops
        )
        for item in context.node.body
    )


def _exception_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Tuple):
        return {name for item in node.elts for name in _exception_names(item)}
    return set()


def _loop_progress_concerns(
    context: FunctionContractContext,
) -> list:
    concerns = []
    for item in walk_function(context.node):
        if not isinstance(item, ast.While):
            continue
        condition_names = referenced_names(item.test)
        updated = {name for statement in item.body for name in _assigned_names(statement)}
        candidates = sorted(
            name
            for name in condition_names & updated
            if (
                name in context.parameters
                or lineage_names(
                    context,
                    ast.Name(id=name),
                    before_line=item.lineno,
                )
                & set(context.parameters)
            )
            and _has_uncertain_progress_update(item, name)
        )
        if not candidates:
            continue
        if _has_monotonic_progress_guard(item, candidates):
            continue
        resource_name = candidates[0]
        concerns.append(
            make_concern(
                context,
                contract_id="BELIEF-SEM-LOOP-PROGRESS",
                category="unbounded_resource_consumption",
                cwe="CWE-400",
                title="Input-driven loop has no monotonic progress guard",
                description=(
                    "A loop repeatedly transforms attacker-influenced data "
                    "without rejecting non-shrinking progress."
                ),
                line=item.lineno,
                function=context.qualified_name,
                class_name=context.class_name,
                resource=resource_for(
                    ast.Name(id=resource_name),
                    context.parameters,
                ),
                source="function_input",
                sink="input_driven_loop",
                missing_states=("monotonic_progress",),
                evidence=expression(item.test),
                confidence=0.87,
                security_property="termination_progress",
            )
        )
    return concerns


def _is_recursive_call(
    node: ast.Call,
    context: FunctionContractContext,
) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id == context.node.name
    return (
        bool(context.class_name)
        and context.qualified_name == f"{context.class_name}.{context.node.name}"
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == context.node.name
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in {"self", "cls"}
    )


def _has_uncertain_progress_update(
    node: ast.While,
    resource_name: str,
) -> bool:
    for item in ast.walk(node):
        if isinstance(item, ast.AugAssign):
            if isinstance(item.target, ast.Name) and (item.target.id == resource_name):
                continue
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        targets = _assignment_targets(item)
        if not any(
            isinstance(target, ast.Name) and target.id == resource_name for target in targets
        ):
            continue
        value = item.value
        if isinstance(value, ast.BinOp) and isinstance(
            value.op,
            (ast.Add, ast.Sub),
        ):
            continue
        if (
            isinstance(value, ast.Subscript)
            and isinstance(value.value, ast.Name)
            and value.value.id == resource_name
            and isinstance(value.slice, ast.Slice)
        ):
            continue
        return True
    return False


def _has_monotonic_progress_guard(
    node: ast.While,
    candidates: list[str],
) -> bool:
    progress_sources = {
        candidate: {
            name
            for item in ast.walk(node)
            if isinstance(item, (ast.Assign, ast.AnnAssign))
            for target in _assignment_targets(item)
            if isinstance(target, ast.Name) and target.id == candidate
            for name in referenced_names(item.value)
            if name != candidate
        }
        for candidate in candidates
    }
    for item in ast.walk(node):
        if not isinstance(item, ast.If) or not aborts(item.body):
            continue
        text = expression(item.test)
        if "len(" in text and any(name in text for name in candidates) and any(
            isinstance(operator, (ast.Gt, ast.GtE))
            for compare in ast.walk(item.test)
            if isinstance(compare, ast.Compare)
            for operator in compare.ops
        ):
            return True
        for compare in ast.walk(item.test):
            if not isinstance(compare, ast.Compare):
                continue
            names = referenced_names(compare)
            if not any(
                candidate in names
                and progress_sources[candidate].intersection(names)
                for candidate in candidates
            ):
                continue
            if any(
                isinstance(operator, (ast.Eq, ast.Is))
                for operator in compare.ops
            ):
                return True
    return False


def _assigned_names(node: ast.AST) -> set[str]:
    values = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(
            item.ctx,
            ast.Store,
        ):
            values.add(item.id)
    return values


def _local_string_constants(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, str]:
    values = {}
    for item in walk_function(node):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)):
            continue
        value = item.value
        if not isinstance(value, ast.Constant) or not isinstance(
            value.value,
            str,
        ):
            continue
        for target in _assignment_targets(item):
            name = _target_name(target)
            if name:
                values[name] = value.value
    return values


def _pattern_argument(
    node: ast.Call,
    constants: dict[str, str],
) -> str | None:
    name = call_name(node.func).lower()
    tail = name.split(".")[-1]
    if (
        tail
        not in {
            "compile",
            "findall",
            "fullmatch",
            "match",
            "search",
            "sub",
        }
        or not node.args
    ):
        return None
    value = node.args[0]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Name):
        return constants.get(value.id)
    return None


def _patterns_from_assignment(
    node: ast.Assign | ast.AnnAssign,
) -> list[str]:
    value = node.value
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return [value.value]
    if isinstance(value, ast.Call) and call_name(value.func).lower().endswith(
        (".compile", "_compile")
    ):
        return [
            argument.value
            for argument in value.args[:1]
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
        ]
    return []


def _regex_risk(pattern: str) -> str:
    if re.search(
        r"\((?:\?:)?(?:\\.|[^()])*(?<!\\)[*+]"
        r"(?:\\.|[^()])*\)(?<!\\)[*+{]",
        pattern,
    ):
        return "nested repeated group"
    if len(re.findall(r"(?<!\\)\.\*\??", pattern)) >= 2:
        return "multiple unbounded wildcard branches"
    for match in re.finditer(
        r"\((?:\?:)?([^()|]+)\|([^()|]+)\)(?<!\\)[*+{]",
        pattern,
    ):
        left, right = match.groups()
        if left.startswith(right) or right.startswith(left):
            return "overlapping repeated alternatives"
    if (
        re.search(r"\[[^\]]*['\"][^\]]*\]", pattern)
        and ("|'[" in pattern or '|"[' in pattern)
        and re.search(r"\)\*$", pattern)
    ):
        return "overlapping quoted and single-character alternatives"
    return ""


def _soft_end_anchor(pattern: str) -> bool:
    stripped = pattern.rstrip()
    return stripped.endswith("$") and not stripped.endswith(r"\$") and r"\Z" not in stripped


def _validation_context(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("endpoint", "route", "url", "validator"))


def _regex_resource(
    node: ast.Call,
    context: FunctionContractContext,
):
    for argument in node.args[1:]:
        names = referenced_names(argument) & set(context.parameters)
        if names:
            return resource_for(
                ast.Name(id=sorted(names)[0]),
                context.parameters,
            )
    return resource_for(
        ast.Name(id=context.parameters[0] if context.parameters else "input"),
        context.parameters,
    )


def _regex_input_node(
    node: ast.Call,
    context: FunctionContractContext,
) -> ast.AST:
    for argument in node.args[1:]:
        if referenced_names(argument) & set(context.parameters):
            return argument
    return ast.Name(id=context.parameters[0] if context.parameters else "input")


def _field_has_length_bound(node: ast.Call) -> bool:
    if any(keyword.arg == "max_length" for keyword in node.keywords):
        return True
    for keyword in node.keywords:
        if keyword.arg != "validators":
            continue
        for item in ast.walk(keyword.value):
            if not isinstance(item, ast.Call):
                continue
            tail = call_name(item.func).lower().split(".")[-1]
            if tail in {"length", "max_length"} and any(
                child.arg in {"max", "max_length"} for child in item.keywords
            ):
                return True
    return False


def _assignment_targets(
    node: ast.Assign | ast.AnnAssign,
) -> list[ast.AST]:
    return node.targets if isinstance(node, ast.Assign) else [node.target]


def _target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


__all__ = ["analyze_resource_contracts"]
