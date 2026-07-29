"""Bounded, non-executing recovery for targeted partial Python snippets."""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from typing import Any


DEFAULT_MAX_WINDOW_LINES = 25
DEFAULT_MAX_SYNTHETIC_PARAMETERS = 64
DEFAULT_MAX_SOURCE_CHARS = 100_000
DEFAULT_MAX_TARGET_CHARS = 8_192


@dataclass(frozen=True)
class PythonFragmentRecovery:
    """One parseable projection with a map back to original source lines."""

    source: str
    method: str
    line_map: tuple[int | None, ...]
    target_original_lines: tuple[int, ...]
    target_transformed_lines: tuple[int, ...]
    synthetic_parameters: tuple[str, ...] = ()
    window_start_line: int = 1
    window_end_line: int = 1

    @property
    def synthetic_wrapper(self) -> bool:
        return (
            self.method.startswith("target_window_")
            or self.method.endswith("_wrapper")
        )

    def map_lines(
        self,
        transformed_lines: tuple[int, ...] | list[int],
    ) -> tuple[int, ...]:
        """Map one-based transformed lines onto one-based original lines."""

        mapped = set()
        for value in transformed_lines:
            if isinstance(value, bool):
                continue
            try:
                line = int(value)
            except (TypeError, ValueError):
                continue
            if not 1 <= line <= len(self.line_map):
                continue
            original = self.line_map[line - 1]
            if original is not None:
                mapped.add(original)
        return tuple(sorted(mapped))


def recover_targeted_python_fragment(
    source: str,
    target_text: str,
    *,
    max_window_lines: int = DEFAULT_MAX_WINDOW_LINES,
    max_synthetic_parameters: int = (
        DEFAULT_MAX_SYNTHETIC_PARAMETERS
    ),
) -> PythonFragmentRecovery | None:
    """Return the first parseable projection, preferring full source."""

    projections = recover_targeted_python_projections(
        source,
        target_text,
        max_window_lines=max_window_lines,
        max_synthetic_parameters=max_synthetic_parameters,
    )
    return projections[0] if projections else None


def recover_targeted_python_projections(
    source: str,
    target_text: str,
    *,
    max_window_lines: int = DEFAULT_MAX_WINDOW_LINES,
    max_synthetic_parameters: int = (
        DEFAULT_MAX_SYNTHETIC_PARAMETERS
    ),
) -> tuple[PythonFragmentRecovery, ...]:
    """Recover parseable projections without importing or executing source.

    Recovery is syntax-driven and does not accept a label, CWE, case ID,
    module, callable, or execution target. It preserves a parseable full-source
    view when possible and adds a full wrapper that exposes otherwise unbound
    names as boundary parameters. If the full source is not parseable, it
    searches the smallest bounded target-containing window.
    """

    _validate_inputs(
        source,
        target_text,
        max_window_lines=max_window_lines,
        max_synthetic_parameters=max_synthetic_parameters,
    )
    original_lines = source.splitlines()
    target_lines = _target_lines(original_lines, target_text)
    if not target_lines:
        return ()
    identity_map = tuple(range(1, len(original_lines) + 1))
    full_source = ""
    full_method = ""
    if _parses(source):
        full_source = source
        full_method = "raw"
    else:
        dedented = textwrap.dedent(source)
        if _parses(dedented):
            full_source = dedented
            full_method = "full_dedent"

    if full_source:
        projections = [PythonFragmentRecovery(
            source=full_source,
            method=full_method,
            line_map=identity_map,
            target_original_lines=target_lines,
            target_transformed_lines=target_lines,
            window_start_line=1,
            window_end_line=max(1, len(original_lines)),
        )]
        wrapped = _parameterized_wrapper(
            full_source,
            asynchronous=False,
            max_parameters=max_synthetic_parameters,
        )
        if wrapped is not None:
            wrapped_source, parameters = wrapped
            wrapped_map = (None, *identity_map)
            projections.append(PythonFragmentRecovery(
                source=wrapped_source,
                method=f"{full_method}_wrapper",
                line_map=tuple(wrapped_map),
                target_original_lines=target_lines,
                target_transformed_lines=tuple(
                    line + 1 for line in target_lines
                ),
                synthetic_parameters=parameters,
                window_start_line=1,
                window_end_line=max(1, len(original_lines)),
            ))
        return tuple(projections)

    for start, end in _candidate_windows(
        len(original_lines),
        target_lines,
        max_window_lines=max_window_lines,
    ):
        body = textwrap.dedent("\n".join(original_lines[start:end]))
        for asynchronous in (False, True):
            wrapped = _parameterized_wrapper(
                body,
                asynchronous=asynchronous,
                max_parameters=max_synthetic_parameters,
            )
            if wrapped is None:
                continue
            wrapped_source, parameters = wrapped
            line_map = (
                None,
                *range(start + 1, end + 1),
            )
            transformed_targets = tuple(
                index
                for index, original in enumerate(line_map, start=1)
                if original in target_lines
            )
            if not transformed_targets:
                continue
            method = (
                "target_window_async"
                if asynchronous
                else "target_window_sync"
            )
            return (PythonFragmentRecovery(
                source=wrapped_source,
                method=method,
                line_map=tuple(line_map),
                target_original_lines=target_lines,
                target_transformed_lines=transformed_targets,
                synthetic_parameters=parameters,
                window_start_line=start + 1,
                window_end_line=end,
            ),)
    return ()


def _candidate_windows(
    line_count: int,
    target_lines: tuple[int, ...],
    *,
    max_window_lines: int,
) -> tuple[tuple[int, int], ...]:
    candidates = set()
    for one_based_target in target_lines:
        target = one_based_target - 1
        lower = max(0, target - max_window_lines + 1)
        upper = min(line_count, target + max_window_lines)
        for start in range(lower, target + 1):
            for end in range(target + 1, upper + 1):
                length = end - start
                if length <= max_window_lines:
                    balance = abs(
                        (target - start) - (end - target - 1)
                    )
                    candidates.add((length, balance, start, end))
    return tuple(
        (start, end)
        for _length, _balance, start, end in sorted(candidates)
    )


def _parameterized_wrapper(
    body: str,
    *,
    asynchronous: bool,
    max_parameters: int,
) -> tuple[str, tuple[str, ...]] | None:
    prefix = "async def" if asynchronous else "def"
    unparameterized = (
        f"{prefix} __belief_partial__():\n"
        f"{textwrap.indent(body, '    ')}\n"
    )
    if not _parses(unparameterized):
        return None
    tree = ast.parse(unparameterized)

    excluded = {
        name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Global, ast.Nonlocal))
        for name in node.names
    }
    loaded = sorted({
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id not in excluded
    })
    parameters = tuple(loaded[:max_parameters])
    rendered = (
        f"{prefix} __belief_partial__({', '.join(parameters)}):\n"
        f"{textwrap.indent(body, '    ')}\n"
    )
    if not _parses(rendered):
        return unparameterized, ()
    return rendered, parameters


def _target_lines(
    source_lines: list[str],
    target_text: str,
) -> tuple[int, ...]:
    target = target_text.strip()
    if not target:
        return ()
    return tuple(
        index
        for index, line in enumerate(source_lines, start=1)
        if line.strip() == target
    )


def _parses(source: str) -> bool:
    try:
        tree = ast.parse(source)
        compile(
            tree,
            "<belief-partial>",
            "exec",
            dont_inherit=True,
            optimize=0,
        )
    except (SyntaxError, TypeError, ValueError):
        return False
    return True


def _validate_inputs(
    source: Any,
    target_text: Any,
    *,
    max_window_lines: int,
    max_synthetic_parameters: int,
) -> None:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("partial Python source must be non-empty text")
    if len(source) > DEFAULT_MAX_SOURCE_CHARS:
        raise ValueError("partial Python source exceeds size limit")
    if not isinstance(target_text, str) or not target_text.strip():
        raise ValueError("partial Python target must be non-empty text")
    if len(target_text) > DEFAULT_MAX_TARGET_CHARS:
        raise ValueError("partial Python target exceeds size limit")
    if "\n" in target_text:
        raise ValueError("partial Python target must be one line")
    if target_text.count("\r") > 1 or (
        "\r" in target_text and not target_text.endswith("\r")
    ):
        raise ValueError(
            "partial Python target has an internal carriage return"
        )
    if not 1 <= max_window_lines <= 100:
        raise ValueError("max_window_lines must be between 1 and 100")
    if not 0 <= max_synthetic_parameters <= 256:
        raise ValueError(
            "max_synthetic_parameters must be between 0 and 256"
        )


__all__ = [
    "DEFAULT_MAX_SOURCE_CHARS",
    "DEFAULT_MAX_SYNTHETIC_PARAMETERS",
    "DEFAULT_MAX_TARGET_CHARS",
    "DEFAULT_MAX_WINDOW_LINES",
    "PythonFragmentRecovery",
    "recover_targeted_python_fragment",
    "recover_targeted_python_projections",
]
