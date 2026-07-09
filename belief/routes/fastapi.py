"""Static FastAPI route extraction."""

from __future__ import annotations

import ast

from ._ast import (
    auth_guarantees_from_names,
    call_name,
    decorator_names,
    literal_string,
    params_from_route,
    source_segment,
)
from .models import RouteRecord, route_sort_key


FASTAPI_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def extract_fastapi_routes(tree: ast.AST, file_path: str = "", source: str = "") -> list[RouteRecord]:
    if source and not _looks_like_fastapi_source(source):
        return []
    routes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            routes.extend(_decorated_routes(node, file_path, source))
    return sorted(routes, key=route_sort_key)


def _looks_like_fastapi_source(source: str) -> bool:
    lowered = source.lower()
    return "from fastapi" in lowered or "import fastapi" in lowered or "apirouter" in source or "fastapi(" in lowered


def _decorated_routes(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    source: str,
) -> list[RouteRecord]:
    records = []
    decorators = decorator_names(func)
    dependency_names = _dependency_names(func)
    auth = auth_guarantees_from_names((*decorators, *dependency_names))
    for decorator in func.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        name = call_name(decorator)
        method = name.rsplit(".", 1)[-1].lower()
        if method not in FASTAPI_METHODS:
            continue
        route = literal_string(decorator.args[0]) if decorator.args else ""
        if not route:
            continue
        records.append(RouteRecord(
            framework="fastapi",
            file=file_path,
            line=getattr(func, "lineno", None),
            route=route,
            methods=(method.upper(),),
            handler=func.name,
            decorators=decorators,
            auth_guarantees=auth,
            params=params_from_route(route),
            raw=source_segment(source, decorator),
        ))
    return records


def _dependency_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    names = []
    for arg in list(func.args.args) + list(func.args.kwonlyargs):
        default = None
        if func.args.defaults:
            offset = len(func.args.args) - len(func.args.defaults)
            if arg in func.args.args:
                idx = func.args.args.index(arg)
                if idx >= offset:
                    default = func.args.defaults[idx - offset]
        if arg in func.args.kwonlyargs:
            idx = func.args.kwonlyargs.index(arg)
            default = func.args.kw_defaults[idx]
        if default is not None:
            name = call_name(default)
            if name.endswith("Depends") or name.endswith("Security"):
                names.append(name)
    return tuple(names)


__all__ = ["extract_fastapi_routes"]
