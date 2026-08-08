"""Strict logical AST and semantics-preserving predicate negation."""

from __future__ import annotations

import ast
import math
from dataclasses import dataclass
from typing import TypeAlias


class PredicateLogicError(ValueError):
    """A semi-formal predicate is outside the reviewed logical subset."""


@dataclass(frozen=True)
class Atom:
    expression: str


@dataclass(frozen=True)
class Compare:
    left: str
    operator: str
    right: str


@dataclass(frozen=True)
class Membership:
    member: str
    operator: str
    container: str


@dataclass(frozen=True)
class Not:
    operand: "LogicNode"


@dataclass(frozen=True)
class And:
    operands: tuple["LogicNode", ...]


@dataclass(frozen=True)
class Or:
    operands: tuple["LogicNode", ...]


LogicNode: TypeAlias = Atom | Compare | Membership | Not | And | Or

_COMPARISON_OPERATORS: dict[type[ast.cmpop], str] = {
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Is: "is",
    ast.IsNot: "is not",
}
_NEGATED_COMPARISON = {
    "==": "!=",
    "!=": "==",
    "<": ">=",
    "<=": ">",
    ">": "<=",
    ">=": "<",
    "is": "is not",
    "is not": "is",
}
_ALLOWED_OPERAND_CALLS = {
    "count",
    "isinstance",
    "len",
    "size",
    "sizeof",
    "type",
}
_ALLOWED_BINARY_OPERATORS = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.BitAnd,
    ast.BitOr,
    ast.BitXor,
    ast.LShift,
    ast.RShift,
)
_ALLOWED_UNARY_OPERATORS = (ast.UAdd, ast.USub, ast.Invert)


def parse_logical_expression(expression: str) -> LogicNode:
    """Parse a Python-like predicate into the closed logical subset."""

    if not isinstance(expression, str) or not expression.strip():
        raise PredicateLogicError("predicate expression is empty")
    try:
        parsed = ast.parse(expression.strip(), mode="eval")
    except (SyntaxError, ValueError) as exc:
        raise PredicateLogicError("predicate expression is not valid syntax") from exc
    return _parse_boolean(parsed.body)


def negate_expression(expression: str) -> str:
    """Return a structured logical negation or explicitly abstain."""

    return render_logical_expression(
        negate_logical_node(parse_logical_expression(expression))
    )


def negate_logical_node(node: LogicNode) -> LogicNode:
    """Negate a logical node with operator duals and De Morgan."""

    if isinstance(node, Not):
        return node.operand
    if isinstance(node, And):
        return _or(tuple(negate_logical_node(item) for item in node.operands))
    if isinstance(node, Or):
        return _and(tuple(negate_logical_node(item) for item in node.operands))
    if isinstance(node, Compare):
        return Compare(
            left=node.left,
            operator=_NEGATED_COMPARISON[node.operator],
            right=node.right,
        )
    if isinstance(node, Membership):
        return Membership(
            member=node.member,
            operator="in" if node.operator == "not in" else "not in",
            container=node.container,
        )
    if isinstance(node, Atom):
        return Not(node)
    raise PredicateLogicError("predicate node is unsupported")


def render_logical_expression(node: LogicNode) -> str:
    """Render the logical AST with explicit precedence."""

    return _render(node, parent_precedence=0)


def _parse_boolean(node: ast.expr) -> LogicNode:
    if isinstance(node, ast.BoolOp):
        operands = tuple(_parse_boolean(item) for item in node.values)
        if isinstance(node.op, ast.And):
            return _and(operands)
        if isinstance(node.op, ast.Or):
            return _or(operands)
        raise PredicateLogicError("boolean operator is unsupported")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return Not(_parse_boolean(node.operand))
    if isinstance(node, ast.Compare):
        return _parse_comparison(node)
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return Atom(_operand_text(node))
    raise PredicateLogicError(
        "predicate is outside the supported boolean logical subset"
    )


def _parse_comparison(node: ast.Compare) -> LogicNode:
    if not node.ops or len(node.ops) != len(node.comparators):
        raise PredicateLogicError("comparison structure is invalid")
    operands: list[LogicNode] = []
    left = node.left
    for operator, right in zip(node.ops, node.comparators, strict=True):
        left_text = _operand_text(left)
        right_text = _operand_text(right)
        if isinstance(operator, ast.In):
            operands.append(Membership(left_text, "in", right_text))
        elif isinstance(operator, ast.NotIn):
            operands.append(Membership(left_text, "not in", right_text))
        else:
            rendered_operator = _COMPARISON_OPERATORS.get(type(operator))
            if rendered_operator is None:
                raise PredicateLogicError("comparison operator is unsupported")
            operands.append(
                Compare(left_text, rendered_operator, right_text)
            )
        left = right
    return operands[0] if len(operands) == 1 else _and(tuple(operands))


def _operand_text(node: ast.expr) -> str:
    _validate_operand(node)
    return ast.unparse(node)


def _validate_operand(node: ast.AST) -> None:
    if isinstance(node, ast.Name):
        return
    if isinstance(node, ast.Attribute):
        _validate_operand(node.value)
        return
    if isinstance(node, ast.Subscript):
        _validate_operand(node.value)
        _validate_operand(node.slice)
        return
    if isinstance(node, ast.Slice):
        for value in (node.lower, node.upper, node.step):
            if value is not None:
                _validate_operand(value)
        return
    if isinstance(node, ast.Constant):
        if isinstance(node.value, float) and not math.isfinite(node.value):
            raise PredicateLogicError("non-finite predicate literal is invalid")
        if node.value is Ellipsis:
            raise PredicateLogicError("ellipsis is not a logical operand")
        if not isinstance(
            node.value,
            (str, bytes, int, float, complex, bool, type(None)),
        ):
            raise PredicateLogicError("predicate literal is unsupported")
        return
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for item in node.elts:
            _validate_operand(item)
        return
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                raise PredicateLogicError(
                    "dictionary unpacking is not a logical operand"
                )
            _validate_operand(key)
            _validate_operand(value)
        return
    if isinstance(node, ast.Call):
        if (
            not isinstance(node.func, ast.Name)
            or node.func.id not in _ALLOWED_OPERAND_CALLS
            or node.keywords
        ):
            raise PredicateLogicError("predicate call operand is unsupported")
        for argument in node.args:
            if isinstance(argument, ast.Starred):
                raise PredicateLogicError(
                    "starred predicate operand is unsupported"
                )
            _validate_operand(argument)
        return
    if isinstance(node, ast.BinOp) and isinstance(
        node.op,
        _ALLOWED_BINARY_OPERATORS,
    ):
        _validate_operand(node.left)
        _validate_operand(node.right)
        return
    if isinstance(node, ast.UnaryOp) and isinstance(
        node.op,
        _ALLOWED_UNARY_OPERATORS,
    ):
        _validate_operand(node.operand)
        return
    raise PredicateLogicError("predicate operand is unsupported")


def _and(operands: tuple[LogicNode, ...]) -> LogicNode:
    flattened: list[LogicNode] = []
    for item in operands:
        if isinstance(item, And):
            flattened.extend(item.operands)
        else:
            flattened.append(item)
    if not flattened:
        raise PredicateLogicError("empty conjunction is invalid")
    return flattened[0] if len(flattened) == 1 else And(tuple(flattened))


def _or(operands: tuple[LogicNode, ...]) -> LogicNode:
    flattened: list[LogicNode] = []
    for item in operands:
        if isinstance(item, Or):
            flattened.extend(item.operands)
        else:
            flattened.append(item)
    if not flattened:
        raise PredicateLogicError("empty disjunction is invalid")
    return flattened[0] if len(flattened) == 1 else Or(tuple(flattened))


def _render(node: LogicNode, *, parent_precedence: int) -> str:
    if isinstance(node, Atom):
        text = node.expression
        precedence = 4
    elif isinstance(node, Compare):
        text = f"{node.left} {node.operator} {node.right}"
        precedence = 4
    elif isinstance(node, Membership):
        text = f"{node.member} {node.operator} {node.container}"
        precedence = 4
    elif isinstance(node, Not):
        inner = _render(node.operand, parent_precedence=0)
        text = (
            f"not {inner}"
            if isinstance(node.operand, Atom)
            else f"not ({inner})"
        )
        precedence = 3
    elif isinstance(node, And):
        text = " and ".join(
            _render(item, parent_precedence=2)
            for item in node.operands
        )
        precedence = 2
    elif isinstance(node, Or):
        text = " or ".join(
            _render(item, parent_precedence=1)
            for item in node.operands
        )
        precedence = 1
    else:
        raise PredicateLogicError("predicate node is unsupported")
    return f"({text})" if precedence < parent_precedence else text


__all__ = [
    "And",
    "Atom",
    "Compare",
    "LogicNode",
    "Membership",
    "Not",
    "Or",
    "PredicateLogicError",
    "negate_expression",
    "negate_logical_node",
    "parse_logical_expression",
    "render_logical_expression",
]
