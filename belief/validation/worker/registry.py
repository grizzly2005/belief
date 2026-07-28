"""Closed, immutable registry of transparent web-validation fixtures."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .contracts import WorkerObservation, WorkerProtocolError


FIXTURE_REGISTRY_SCHEMA_VERSION = "belief.validation_fixture_registry.v2"
FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION = "belief.validation_fixture_source.v1"


class OptionalWebDependencyUnavailable(RuntimeError):
    """A registered fixture cannot run because its framework is absent."""

    def __init__(self, framework: str) -> None:
        super().__init__(f"optional dependency unavailable: {framework}")
        self.framework = framework


PreparedFixture = Callable[[], "RegisteredFixtureResult"]
FixturePreparer = Callable[
    ["FixtureSpec", Path, Mapping[str, Any]],
    PreparedFixture,
]


@dataclass(frozen=True)
class RegisteredFixtureResult:
    """Evidence emitted by one internal fixture runner."""

    observations: tuple[WorkerObservation, ...]
    limitations: tuple[str, ...] = ()
    capability_used: str = "framework_test_client"

    def __post_init__(self) -> None:
        if any(not isinstance(item, WorkerObservation) for item in self.observations):
            raise WorkerProtocolError(
                "internal_error",
                "registered fixture returned invalid observations",
            )
        if not isinstance(self.capability_used, str):
            raise WorkerProtocolError(
                "internal_error",
                "registered fixture capability is invalid",
            )


@dataclass(frozen=True)
class FixtureSpec:
    """Immutable metadata for one hardcoded first-party fixture."""

    fixture_id: str
    framework: str
    case_type: str
    security_enforced: bool
    expected_security_posture: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "framework": self.framework,
            "case_type": self.case_type,
            "expected_security_posture": self.expected_security_posture,
            "fixture_source_digest": fixture_source_digest(self),
        }

    def registry_dict(self) -> dict[str, Any]:
        return {
            **self.public_dict(),
            "security_behavior": (
                "owner_tenant_or_path_boundary_enforced"
                if self.security_enforced
                else "authentication_or_fixture_boundary_only"
            ),
        }


_FIXTURES: Mapping[str, FixtureSpec] = MappingProxyType({
    "flask_path_traversal_vulnerable_v1": FixtureSpec(
        fixture_id="flask_path_traversal_vulnerable_v1",
        framework="flask",
        case_type="path_traversal_possible",
        security_enforced=False,
        expected_security_posture="vulnerable",
    ),
    "flask_path_traversal_protected_v1": FixtureSpec(
        fixture_id="flask_path_traversal_protected_v1",
        framework="flask",
        case_type="path_traversal_possible",
        security_enforced=True,
        expected_security_posture="protected",
    ),
    "flask_idor_vulnerable_v1": FixtureSpec(
        fixture_id="flask_idor_vulnerable_v1",
        framework="flask",
        case_type="idor_bola_possible",
        security_enforced=False,
        expected_security_posture="vulnerable",
    ),
    "flask_idor_protected_v1": FixtureSpec(
        fixture_id="flask_idor_protected_v1",
        framework="flask",
        case_type="idor_bola_possible",
        security_enforced=True,
        expected_security_posture="protected",
    ),
    "fastapi_path_traversal_vulnerable_v1": FixtureSpec(
        fixture_id="fastapi_path_traversal_vulnerable_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        security_enforced=False,
        expected_security_posture="vulnerable",
    ),
    "fastapi_path_traversal_protected_v1": FixtureSpec(
        fixture_id="fastapi_path_traversal_protected_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        security_enforced=True,
        expected_security_posture="protected",
    ),
    "fastapi_idor_vulnerable_v1": FixtureSpec(
        fixture_id="fastapi_idor_vulnerable_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        security_enforced=False,
        expected_security_posture="vulnerable",
    ),
    "fastapi_idor_protected_v1": FixtureSpec(
        fixture_id="fastapi_idor_protected_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        security_enforced=True,
        expected_security_posture="protected",
    ),
})


def get_fixture_spec(fixture_id: str) -> FixtureSpec | None:
    """Return an immutable fixture definition by exact stable ID."""

    return _FIXTURES.get(fixture_id)


def load_fixture_runner(spec: FixtureSpec) -> FixturePreparer:
    """Import one hardcoded adapter after the child policies are installed."""

    from ..web import optional_framework_available

    if not optional_framework_available(spec.framework):
        raise OptionalWebDependencyUnavailable(spec.framework)
    if spec.framework == "flask":
        from ..web.flask_adapter import prepare_flask_fixture

        return prepare_flask_fixture
    if spec.framework == "fastapi":
        from ..web.fastapi_adapter import prepare_fastapi_fixture

        return prepare_fastapi_fixture
    raise OptionalWebDependencyUnavailable(spec.framework)


def registered_fixture_metadata() -> tuple[dict[str, Any], ...]:
    """Return a defensive, serializable registry snapshot without callables."""

    return tuple(
        dict(_FIXTURES[fixture_id].public_dict())
        for fixture_id in sorted(_FIXTURES)
    )


def registered_fixture_ids() -> tuple[str, ...]:
    return tuple(sorted(_FIXTURES))


@lru_cache(maxsize=1)
def fixture_registry_digest() -> str:
    payload = {
        "schema_version": FIXTURE_REGISTRY_SCHEMA_VERSION,
        "fixtures": [
            _FIXTURES[fixture_id].registry_dict()
            for fixture_id in sorted(_FIXTURES)
        ],
    }
    return _canonical_digest(payload)


@lru_cache(maxsize=16)
def _fixture_source_digest_by_id(fixture_id: str) -> str:
    spec = _FIXTURES[fixture_id]
    return _canonical_digest(_fixture_source_manifest(spec, include_source=True))


def fixture_source_digest(spec_or_id: FixtureSpec | str) -> str:
    spec = _coerce_spec(spec_or_id)
    if _FIXTURES.get(spec.fixture_id) == spec:
        return _fixture_source_digest_by_id(spec.fixture_id)
    return _canonical_digest(_fixture_source_manifest(spec, include_source=True))


def fixture_source_manifest(spec_or_id: FixtureSpec | str) -> dict[str, Any]:
    """Return inspectable logical source names and digests, never host paths."""

    return _fixture_source_manifest(_coerce_spec(spec_or_id), include_source=False)


def fixture_source_documents(spec_or_id: FixtureSpec | str) -> dict[str, str]:
    """Return normalized first-party source documents for trusted preparation."""

    spec = _coerce_spec(spec_or_id)
    return dict(_source_documents(spec.framework))


def _fixture_source_manifest(
    spec: FixtureSpec,
    *,
    include_source: bool,
) -> dict[str, Any]:
    documents = _source_documents(spec.framework)
    rows = []
    for logical_name, source in documents:
        row = {
            "logical_name": logical_name,
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        }
        if include_source:
            row["source"] = source
        rows.append(row)
    return {
        "schema_version": FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION,
        "fixture": {
            "fixture_id": spec.fixture_id,
            "framework": spec.framework,
            "case_type": spec.case_type,
            "security_enforced": spec.security_enforced,
        },
        "documents": rows,
    }


@lru_cache(maxsize=2)
def _source_documents(framework: str) -> tuple[tuple[str, str], ...]:
    worker_dir = Path(__file__).resolve().parent
    web_dir = worker_dir.parent / "web"
    selected = (
        ("worker/registry.py", worker_dir / "registry.py"),
        ("web/__init__.py", web_dir / "__init__.py"),
        ("web/_shared.py", web_dir / "_shared.py"),
        (f"web/{framework}_adapter.py", web_dir / f"{framework}_adapter.py"),
    )
    documents: list[tuple[str, str]] = []
    for logical_name, path in selected:
        source = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        documents.append((logical_name, source))
    return tuple(documents)


def _coerce_spec(value: FixtureSpec | str) -> FixtureSpec:
    if isinstance(value, FixtureSpec):
        return value
    if isinstance(value, str) and value in _FIXTURES:
        return _FIXTURES[value]
    raise KeyError("unknown registered fixture")


def _canonical_digest(payload: Any) -> str:
    rendered = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


__all__ = [
    "FIXTURE_REGISTRY_SCHEMA_VERSION",
    "FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION",
    "FixturePreparer",
    "FixtureSpec",
    "OptionalWebDependencyUnavailable",
    "PreparedFixture",
    "RegisteredFixtureResult",
    "fixture_registry_digest",
    "fixture_source_digest",
    "fixture_source_documents",
    "fixture_source_manifest",
    "get_fixture_spec",
    "load_fixture_runner",
    "registered_fixture_ids",
    "registered_fixture_metadata",
]
