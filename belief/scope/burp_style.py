"""Helpers for future Burp-style scope conversion.

This pass keeps scope JSON native to BELIEF. The helper is intentionally tiny so
future Burp export adapters can map include/exclude entries without importing
Burp, browser, or HYDRA runtime code.
"""

from __future__ import annotations

from .models import ScopePolicy


def scope_to_burp_style_summary(scope: ScopePolicy) -> dict[str, list[str]]:
    return {
        "include": list(scope.include),
        "exclude": list(scope.exclude),
    }


__all__ = ["scope_to_burp_style_summary"]
