"""Closed registry of transparent web-validation fixtures."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .contracts import WorkerObservation, WorkerProtocolError


class OptionalWebDependencyUnavailable(RuntimeError):
    """A registered fixture cannot run because its framework is absent."""

    def __init__(self, framework: str) -> None:
        super().__init__(f"optional dependency unavailable: {framework}")
        self.framework = framework


FixtureRunner = Callable[
    ["FixtureSpec", Path, Mapping[str, Any]],
    "RegisteredFixtureResult",
]


@dataclass(frozen=True)
class RegisteredFixtureResult:
    """Evidence emitted by one internal fixture runner."""

    observations: tuple[WorkerObservation, ...]
    limitations: tuple[str, ...] = ()
    capability_used: str = "framework_test_client"

    def __post_init__(self) -> None:
        if any(
            not isinstance(item, WorkerObservation)
            for item in self.observations
        ):
            raise WorkerProtocolError(
                "invalid_fixture_result",
                "registered fixture returned invalid observations",
            )
        if not isinstance(self.capability_used, str):
            raise WorkerProtocolError(
                "invalid_fixture_result",
                "registered fixture capability is invalid",
            )


@dataclass(frozen=True)
class FixtureSpec:
    """Immutable metadata and trusted entrypoint for one fixture."""

    fixture_id: str
    framework: str
    case_type: str
    vulnerable: bool
    runner: FixtureRunner

    def public_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "framework": self.framework,
            "case_type": self.case_type,
            "expected_security_posture": (
                "vulnerable" if self.vulnerable else "protected"
            ),
        }


def _run_flask(
    spec: FixtureSpec,
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> RegisteredFixtureResult:
    from ..web.flask_adapter import run_flask_fixture

    return run_flask_fixture(spec, temporary_root, parameters)


def _run_fastapi(
    spec: FixtureSpec,
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> RegisteredFixtureResult:
    from ..web.fastapi_adapter import run_fastapi_fixture

    return run_fastapi_fixture(spec, temporary_root, parameters)


_FIXTURES: Mapping[str, FixtureSpec] = MappingProxyType({
    "flask_path_traversal_vulnerable_v1": FixtureSpec(
        fixture_id="flask_path_traversal_vulnerable_v1",
        framework="flask",
        case_type="path_traversal_possible",
        vulnerable=True,
        runner=_run_flask,
    ),
    "flask_path_traversal_protected_v1": FixtureSpec(
        fixture_id="flask_path_traversal_protected_v1",
        framework="flask",
        case_type="path_traversal_possible",
        vulnerable=False,
        runner=_run_flask,
    ),
    "flask_idor_vulnerable_v1": FixtureSpec(
        fixture_id="flask_idor_vulnerable_v1",
        framework="flask",
        case_type="idor_bola_possible",
        vulnerable=True,
        runner=_run_flask,
    ),
    "flask_idor_protected_v1": FixtureSpec(
        fixture_id="flask_idor_protected_v1",
        framework="flask",
        case_type="idor_bola_possible",
        vulnerable=False,
        runner=_run_flask,
    ),
    "fastapi_path_traversal_vulnerable_v1": FixtureSpec(
        fixture_id="fastapi_path_traversal_vulnerable_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        vulnerable=True,
        runner=_run_fastapi,
    ),
    "fastapi_path_traversal_protected_v1": FixtureSpec(
        fixture_id="fastapi_path_traversal_protected_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        vulnerable=False,
        runner=_run_fastapi,
    ),
    "fastapi_idor_vulnerable_v1": FixtureSpec(
        fixture_id="fastapi_idor_vulnerable_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        vulnerable=True,
        runner=_run_fastapi,
    ),
    "fastapi_idor_protected_v1": FixtureSpec(
        fixture_id="fastapi_idor_protected_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        vulnerable=False,
        runner=_run_fastapi,
    ),
})


def get_fixture_spec(fixture_id: str) -> FixtureSpec | None:
    """Return an immutable fixture definition by exact stable ID."""

    return _FIXTURES.get(fixture_id)


def registered_fixture_metadata() -> tuple[dict[str, Any], ...]:
    """Return a defensive, serializable snapshot without callables."""

    return tuple(
        _FIXTURES[fixture_id].public_dict()
        for fixture_id in sorted(_FIXTURES)
    )


def registered_fixture_ids() -> tuple[str, ...]:
    return tuple(sorted(_FIXTURES))


__all__ = [
    "FixtureSpec",
    "OptionalWebDependencyUnavailable",
    "RegisteredFixtureResult",
    "get_fixture_spec",
    "registered_fixture_ids",
    "registered_fixture_metadata",
]
