"""Static Flask route extraction."""

from __future__ import annotations

import ast

from ._ast import (
    auth_guarantees_from_names,
    call_name,
    decorator_names,
    keyword,
    literal_string,
    literal_string_list,
    params_from_route,
    source_segment,
)
from .models import RouteRecord, route_sort_key


def extract_flask_routes(tree: ast.AST, file_path: str = "", source: str = "") -> list[RouteRecord]:
    routes: list[RouteRecord] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            routes.extend(_decorated_routes(node, file_path, source))
        elif isinstance(node, ast.Call):
            route = _add_url_rule_route(node, file_path, source)
            if route:
                routes.append(route)
    return sorted(_dedupe(routes), key=route_sort_key)


def _decorated_routes(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    source: str,
) -> list[RouteRecord]:
    records = []
    looks_flask = _looks_like_flask_source(source)
    decorators = decorator_names(func)
    auth = auth_guarantees_from_names(decorators)
    for decorator in func.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        name = call_name(decorator)
        short = name.rsplit(".", 1)[-1].lower()
        if short not in {"route", "get", "post", "put", "patch", "delete"}:
            continue
        if short != "route" and not looks_flask:
            continue
        if call is None:
            continue
        route = literal_string(call.args[0]) if call.args else ""
        if not route:
            continue
        methods = literal_string_list(keyword(call, "methods"))
        if not methods and short in {"get", "post", "put", "patch", "delete"}:
            methods = (short.upper(),)
        records.append(RouteRecord(
            framework="flask",
            file=file_path,
            line=getattr(func, "lineno", None),
            route=route,
            methods=methods or ("GET",),
            handler=func.name,
            decorators=decorators,
            auth_guarantees=auth,
            params=params_from_route(route),
            raw=source_segment(source, decorator),
        ))
    return records


def _looks_like_flask_source(source: str) -> bool:
    if not source:
        return True
    lowered = source.lower()
    return "from flask" in lowered or "import flask" in lowered or "flask(" in lowered


def _add_url_rule_route(call: ast.Call, file_path: str, source: str) -> RouteRecord | None:
    name = call_name(call)
    if not name.endswith("add_url_rule"):
        return None
    route = literal_string(call.args[0]) if call.args else ""
    if not route:
        return None
    methods = literal_string_list(keyword(call, "methods"))
    handler = ""
    view_func = keyword(call, "view_func")
    if view_func is not None:
        handler = call_name(view_func) or literal_string(view_func)
    elif len(call.args) >= 3:
        handler = call_name(call.args[2]) or literal_string(call.args[2])
    return RouteRecord(
        framework="flask",
        file=file_path,
        line=getattr(call, "lineno", None),
        route=route,
        methods=methods or ("GET",),
        handler=handler,
        params=params_from_route(route),
        raw=source_segment(source, call),
    )


def _dedupe(routes: list[RouteRecord]) -> list[RouteRecord]:
    seen = set()
    result = []
    for route in routes:
        key = (route.framework, route.file, route.line, route.route, route.handler, route.methods)
        if key in seen:
            continue
        seen.add(key)
        result.append(route)
    return result


__all__ = ["extract_flask_routes"]
