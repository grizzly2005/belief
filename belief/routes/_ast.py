"""Small AST helpers for route extraction."""

from __future__ import annotations

import ast
import re


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
AUTH_DECORATOR_TOKENS = (
    "login_required",
    "admin_required",
    "permission_required",
    "has_perm",
    "requires_auth",
    "authenticated",
    "Security",
    "Depends",
)


def call_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Call):
        return call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def literal_string(node: ast.AST | None) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def literal_string_list(node: ast.AST | None) -> tuple[str, ...]:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = [literal_string(item).upper() for item in node.elts]
        return tuple(value for value in values if value)
    value = literal_string(node)
    return (value.upper(),) if value else ()


def keyword(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    return tuple(call_name(decorator) for decorator in func.decorator_list if call_name(decorator))


def auth_guarantees_from_names(names: tuple[str, ...]) -> tuple[str, ...]:
    guarantees = []
    lowered = " ".join(names).lower()
    if "login_required" in lowered or "authenticated" in lowered or "requires_auth" in lowered:
        guarantees.append("route.requires_login == true")
    if "admin_required" in lowered:
        guarantees.append("route.requires_admin == true")
    if "permission_required" in lowered or "has_perm" in lowered or "security" in lowered:
        guarantees.append("route.requires_permission == true")
    if "depends" in lowered:
        guarantees.append("route.has_dependency_guard == true")
    return tuple(dict.fromkeys(guarantees))


def params_from_route(route: str) -> tuple[str, ...]:
    flask_style = re.findall(r"<(?:[^:<>]+:)?([^<>]+)>", route or "")
    fastapi_style = re.findall(r"{([^{}]+)}", route or "")
    return tuple(dict.fromkeys([*flask_style, *fastapi_style]))


def source_segment(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node) if source else None
    if segment:
        return re.sub(r"\s+", " ", segment).strip()
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


__all__ = [
    "HTTP_METHODS",
    "call_name",
    "literal_string",
    "literal_string_list",
    "keyword",
    "decorator_names",
    "auth_guarantees_from_names",
    "params_from_route",
    "source_segment",
]
