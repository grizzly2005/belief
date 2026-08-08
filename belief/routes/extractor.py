"""Framework-neutral static route extraction."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterable, Mapping

from .django import extract_django_routes
from .fastapi import extract_fastapi_routes
from .flask import extract_flask_routes
from .models import RouteRecord, route_sort_key


def extract_routes_from_file(path: str | Path) -> list[RouteRecord]:
    file_path = Path(path)
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []
    return _extract_from_ast(tree, str(file_path), source)


def extract_routes_from_files(
    files: Iterable[str | Path],
    *,
    target_root: str | Path | None = None,
) -> list[RouteRecord]:
    root = Path(target_root).resolve() if target_root else None
    routes = []
    for file_path in files:
        path = Path(file_path)
        rel = _display_path(path, root)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        routes.extend(_extract_from_ast(tree, rel, source))
    return sorted(_dedupe(routes), key=route_sort_key)


def extract_routes_from_sources(
    sources: Mapping[str, str],
    *,
    ast_map: Mapping[str, ast.Module] | None = None,
) -> list[RouteRecord]:
    """Extract routes from one immutable source snapshot without disk reads."""

    trees = ast_map or {}
    routes: list[RouteRecord] = []
    for logical_path, source in sorted(sources.items()):
        try:
            tree = trees.get(logical_path) or ast.parse(
                source,
                filename=logical_path,
            )
        except SyntaxError:
            continue
        routes.extend(_extract_from_ast(tree, logical_path, source))
    return sorted(_dedupe(routes), key=route_sort_key)


def extract_routes_from_tree(root: str | Path, max_files: int | None = None) -> list[RouteRecord]:
    root_path = Path(root)
    if root_path.is_file():
        return extract_routes_from_file(root_path)
    files = sorted(root_path.rglob("*.py"))
    if max_files is not None:
        files = files[:max_files]
    return extract_routes_from_files(files, target_root=root_path)


def routes_to_audit_context(routes: Iterable[RouteRecord]) -> dict[str, list[dict]]:
    by_handler: dict[str, list[dict]] = {}
    for route in sorted(routes, key=route_sort_key):
        if route.handler:
            by_handler.setdefault(route.handler, []).append(route.to_dict())
        by_handler.setdefault(route.file, []).append(route.to_dict())
    return by_handler


def _extract_from_ast(tree: ast.AST, file_path: str, source: str) -> list[RouteRecord]:
    routes = []
    routes.extend(extract_flask_routes(tree, file_path, source))
    routes.extend(extract_fastapi_routes(tree, file_path, source))
    routes.extend(extract_django_routes(tree, file_path, source))
    return sorted(_dedupe(routes), key=route_sort_key)


def _dedupe(routes: Iterable[RouteRecord]) -> list[RouteRecord]:
    seen = set()
    result = []
    for route in routes:
        key = (
            route.framework,
            route.file,
            route.line,
            route.route,
            route.handler,
            route.methods,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(route)
    return result


def _display_path(path: Path, root: Path | None) -> str:
    if root:
        try:
            return str(path.resolve().relative_to(root)).replace("\\", "/")
        except ValueError:
            pass
    return str(path).replace("\\", "/")


__all__ = [
    "extract_routes_from_file",
    "extract_routes_from_tree",
    "extract_routes_from_files",
    "extract_routes_from_sources",
    "routes_to_audit_context",
]
