"""Parallel execution placeholder.

Executor v1 is intentionally sequential to keep safety behavior simple and
deterministic. This module documents the future extension point.
"""

from __future__ import annotations


def max_parallelism() -> int:
    return 1


__all__ = ["max_parallelism"]
