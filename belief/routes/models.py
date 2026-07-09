"""Route inventory data model."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RouteRecord:
    framework: str
    file: str
    line: int | None
    route: str
    methods: tuple[str, ...] = ()
    handler: str = ""
    decorators: tuple[str, ...] = ()
    auth_guarantees: tuple[str, ...] = ()
    params: tuple[str, ...] = ()
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "file": self.file,
            "line": self.line,
            "route": self.route,
            "methods": list(self.methods),
            "handler": self.handler,
            "decorators": list(self.decorators),
            "auth_guarantees": list(self.auth_guarantees),
            "params": list(self.params),
            "raw": self.raw,
        }


def route_sort_key(route: RouteRecord) -> tuple:
    return (
        route.framework,
        route.file,
        route.line or 0,
        route.route,
        route.handler,
        route.methods,
    )


__all__ = ["RouteRecord", "route_sort_key"]
