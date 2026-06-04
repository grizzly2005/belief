"""Static Django URL pattern extraction."""

from __future__ import annotations

import ast

from ._ast import call_name, literal_string, params_from_route, source_segment
from .models import RouteRecord, route_sort_key


def extract_django_routes(tree: ast.AST, file_path: str = "", source: str = "") -> list[RouteRecord]:
    routes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = call_name(node)
            short = name.rsplit(".", 1)[-1]
            if short not in {"path", "re_path", "include"}:
                continue
            route = literal_string(node.args[0]) if node.args else ""
            if not route:
                continue
            handler = ""
            if len(node.args) >= 2:
                handler = call_name(node.args[1]) or literal_string(node.args[1])
            routes.append(RouteRecord(
                framework="django",
                file=file_path,
                line=getattr(node, "lineno", None),
                route=route,
                methods=(),
                handler=handler,
                decorators=(),
                auth_guarantees=(),
                params=params_from_route(route),
                raw=source_segment(source, node),
            ))
    return sorted(_dedupe(routes), key=route_sort_key)


def _dedupe(routes: list[RouteRecord]) -> list[RouteRecord]:
    seen = set()
    result = []
    for route in routes:
        key = (route.framework, route.file, route.line, route.route, route.handler)
        if key in seen:
            continue
        seen.add(key)
        result.append(route)
    return result


__all__ = ["extract_django_routes"]
