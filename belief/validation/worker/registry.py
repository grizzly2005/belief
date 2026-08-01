"""Closed fixture registry and immutable first-party execution bundles.

Application source, fixture descriptors, and evaluator ground truth have
separate identities.  The public registry never publishes evaluator content
or its digest.  A parent captures every first-party module once, verifies its
code object, and passes only that immutable built-in transport to a spawned
child.  The child executes those bytes through a closed in-memory importer.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.abc
import importlib.util
import io
import json
import re
import sys
import tokenize
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import CodeType, MappingProxyType, ModuleType
from typing import Any

from .contracts import WorkerObservation, WorkerProtocolError


FIXTURE_REGISTRY_SCHEMA_VERSION = "belief.validation_fixture_registry.v4"
FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION = "belief.validation_fixture_source.v3"
FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION = (
    "belief.validation_fixture_execution_bundle.v1"
)
_APPLICATION_SOURCE_SCHEMA_VERSION = (
    "belief.validation_fixture_application_source.v1"
)
_GROUND_TRUTH_SCHEMA_VERSION = "belief.validation_fixture_ground_truth.v1"
_CODE_OBJECT_SCHEMA_VERSION = "belief.validation_fixture_code_objects.v1"
_DESCRIPTOR_SCHEMA_VERSION = "belief.validation_fixture_descriptor.v1"
_MAX_BUNDLE_MODULES = 24
_MAX_BUNDLE_FILE_BYTES = 512 * 1024
_MAX_BUNDLE_TOTAL_BYTES = 2 * 1024 * 1024
_MODULE_RE = re.compile(
    r"^belief\.validation\.web(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)


class OptionalWebDependencyUnavailable(RuntimeError):
    """A registered fixture cannot run because its framework is absent."""

    def __init__(self, framework: str) -> None:
        super().__init__(f"optional dependency unavailable: {framework}")
        self.framework = framework


PreparedFixture = Callable[[], "RegisteredFixtureResult"]
FixturePreparer = Callable[
    [Path, Mapping[str, Any]],
    PreparedFixture,
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
    """Immutable descriptor for one hardcoded first-party fixture."""

    fixture_id: str
    framework: str
    case_type: str
    implementation_id: str

    def descriptor_dict(self) -> dict[str, str]:
        return {
            "fixture_id": self.fixture_id,
            "framework": self.framework,
            "case_type": self.case_type,
            "implementation_id": self.implementation_id,
        }

    def public_dict(
        self,
        bundle: "PreparedExecutionBundle | None" = None,
    ) -> dict[str, Any]:
        captured = bundle or prepare_execution_bundle(self)
        return {
            "fixture_id": self.fixture_id,
            "framework": self.framework,
            "case_type": self.case_type,
            "fixture_source_digest": captured.source_digest,
            "fixture_descriptor_digest": captured.descriptor_digest,
            "fixture_execution_bundle_digest": captured.execution_bundle_digest,
            "fixture_code_object_digest": captured.code_object_digest,
        }

    def registry_dict(self) -> dict[str, str]:
        return self.descriptor_dict()


_FIXTURES: Mapping[str, FixtureSpec] = MappingProxyType({
    "fx_01d7c2_v1": FixtureSpec(
        fixture_id="fx_01d7c2_v1",
        framework="flask",
        case_type="path_traversal_possible",
        implementation_id="f01",
    ),
    "fx_18a4e9_v1": FixtureSpec(
        fixture_id="fx_18a4e9_v1",
        framework="flask",
        case_type="path_traversal_possible",
        implementation_id="f02",
    ),
    "fx_2f6b10_v1": FixtureSpec(
        fixture_id="fx_2f6b10_v1",
        framework="flask",
        case_type="idor_bola_possible",
        implementation_id="f03",
    ),
    "fx_3c8d57_v1": FixtureSpec(
        fixture_id="fx_3c8d57_v1",
        framework="flask",
        case_type="idor_bola_possible",
        implementation_id="f04",
    ),
    "fx_47e1a3_v1": FixtureSpec(
        fixture_id="fx_47e1a3_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        implementation_id="f05",
    ),
    "fx_5b9c20_v1": FixtureSpec(
        fixture_id="fx_5b9c20_v1",
        framework="fastapi",
        case_type="path_traversal_possible",
        implementation_id="f06",
    ),
    "fx_6d04f8_v1": FixtureSpec(
        fixture_id="fx_6d04f8_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        implementation_id="f07",
    ),
    "fx_7a2e61_v1": FixtureSpec(
        fixture_id="fx_7a2e61_v1",
        framework="fastapi",
        case_type="idor_bola_possible",
        implementation_id="f08",
    ),
})


@dataclass(frozen=True)
class _BundledModule:
    module_name: str
    logical_name: str
    source_bytes: bytes = field(repr=False)
    group: str
    is_package: bool
    source_sha256: str
    code_object_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.module_name, str) or not _MODULE_RE.fullmatch(
            self.module_name
        ):
            raise ValueError("execution bundle module name is invalid")
        logical = Path(self.logical_name)
        if (
            not isinstance(self.logical_name, str)
            or not self.logical_name
            or logical.is_absolute()
            or ".." in logical.parts
            or "\\" in self.logical_name
        ):
            raise ValueError("execution bundle logical source name is invalid")
        if self.group not in {"application", "ground_truth"}:
            raise ValueError("execution bundle source group is invalid")
        if not isinstance(self.is_package, bool):
            raise ValueError("execution bundle package marker is invalid")
        if not isinstance(self.source_bytes, bytes):
            raise ValueError("execution bundle source must be exact bytes")
        if len(self.source_bytes) > _MAX_BUNDLE_FILE_BYTES:
            raise ValueError("execution bundle source exceeds its file bound")
        expected_source = hashlib.sha256(self.source_bytes).hexdigest()
        if self.source_sha256 != expected_source:
            raise ValueError("execution bundle source digest mismatch")
        expected_code = _compiled_source_digest(
            self.source_bytes,
            self.logical_name,
        )
        if self.code_object_sha256 != expected_code:
            raise ValueError("execution bundle code-object digest mismatch")

    def digest_row(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "logical_name": self.logical_name,
            "size": len(self.source_bytes),
            "sha256": self.source_sha256,
        }

    def code_row(self) -> dict[str, str]:
        return {
            "module_name": self.module_name,
            "code_object_sha256": self.code_object_sha256,
        }

    def transport(self) -> tuple[Any, ...]:
        return (
            self.module_name,
            self.logical_name,
            self.source_bytes,
            self.group,
            self.is_package,
            self.source_sha256,
            self.code_object_sha256,
        )

    @classmethod
    def from_transport(cls, value: Any) -> "_BundledModule":
        if not isinstance(value, tuple) or len(value) != 7:
            raise ValueError("execution bundle module transport is invalid")
        (
            module_name,
            logical_name,
            source_bytes,
            group,
            is_package,
            source_sha256,
            code_object_sha256,
        ) = value
        return cls(
            module_name=module_name,
            logical_name=logical_name,
            source_bytes=source_bytes,
            group=group,
            is_package=is_package,
            source_sha256=source_sha256,
            code_object_sha256=code_object_sha256,
        )


@dataclass(frozen=True)
class PreparedExecutionBundle:
    """Parent-captured first-party code executed exactly once by one child."""

    fixture_id: str
    framework: str
    case_type: str
    implementation_id: str
    source_digest: str
    descriptor_digest: str
    execution_bundle_digest: str
    code_object_digest: str
    modules: tuple[_BundledModule, ...] = field(repr=False)
    _ground_truth_digest: str = field(repr=False)
    schema_version: str = FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION:
            raise ValueError("execution bundle schema is unsupported")
        modules = tuple(self.modules)
        if not 1 <= len(modules) <= _MAX_BUNDLE_MODULES:
            raise ValueError("execution bundle module count is invalid")
        if any(not isinstance(item, _BundledModule) for item in modules):
            raise ValueError("execution bundle modules are invalid")
        if sum(len(item.source_bytes) for item in modules) > _MAX_BUNDLE_TOTAL_BYTES:
            raise ValueError("execution bundle exceeds its total byte bound")
        module_names = [item.module_name for item in modules]
        logical_names = [item.logical_name for item in modules]
        if (
            len(module_names) != len(set(module_names))
            or len(logical_names) != len(set(logical_names))
        ):
            raise ValueError("execution bundle contains duplicate modules")
        object.__setattr__(self, "modules", modules)

        descriptor = _descriptor_digest_from_values(
            fixture_id=self.fixture_id,
            framework=self.framework,
            case_type=self.case_type,
            implementation_id=self.implementation_id,
        )
        application_rows = [
            item.digest_row()
            for item in modules
            if item.group == "application"
        ]
        ground_truth_rows = [
            item.digest_row()
            for item in modules
            if item.group == "ground_truth"
        ]
        if not application_rows or not ground_truth_rows:
            raise ValueError("execution bundle source groups are incomplete")
        source_digest = _canonical_digest({
            "schema_version": _APPLICATION_SOURCE_SCHEMA_VERSION,
            "documents": application_rows,
        })
        ground_truth_digest = _canonical_digest({
            "schema_version": _GROUND_TRUTH_SCHEMA_VERSION,
            "documents": ground_truth_rows,
        })
        code_object_digest = _canonical_digest({
            "schema_version": _CODE_OBJECT_SCHEMA_VERSION,
            "modules": [item.code_row() for item in modules],
        })
        execution_digest = _canonical_digest({
            "schema_version": FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION,
            "source_digest": source_digest,
            "fixture_descriptor_digest": descriptor,
            "ground_truth_digest": ground_truth_digest,
            "code_object_digest": code_object_digest,
        })
        supplied = {
            "source digest": (self.source_digest, source_digest),
            "descriptor digest": (self.descriptor_digest, descriptor),
            "ground-truth digest": (
                self._ground_truth_digest,
                ground_truth_digest,
            ),
            "code-object digest": (
                self.code_object_digest,
                code_object_digest,
            ),
            "execution bundle digest": (
                self.execution_bundle_digest,
                execution_digest,
            ),
        }
        if any(actual != expected for actual, expected in supplied.values()):
            mismatched = next(
                name
                for name, (actual, expected) in supplied.items()
                if actual != expected
            )
            raise ValueError(f"execution bundle {mismatched} mismatch")

    def transport(self) -> tuple[Any, ...]:
        """Return a built-in-only value safe for multiprocessing spawn."""

        return (
            self.schema_version,
            self.fixture_id,
            self.framework,
            self.case_type,
            self.implementation_id,
            self.source_digest,
            self.descriptor_digest,
            self._ground_truth_digest,
            self.execution_bundle_digest,
            self.code_object_digest,
            tuple(item.transport() for item in self.modules),
        )

    def application_source_documents(self) -> dict[str, bytes]:
        """Return exact SUT bytes without evaluator documents or identities."""

        return {
            item.logical_name: bytes(item.source_bytes)
            for item in self.modules
            if item.group == "application"
        }

    @classmethod
    def from_transport(cls, value: Any) -> "PreparedExecutionBundle":
        if not isinstance(value, tuple) or len(value) != 11:
            raise ValueError("execution bundle transport is invalid")
        (
            schema_version,
            fixture_id,
            framework,
            case_type,
            implementation_id,
            source_digest,
            descriptor_digest,
            ground_truth_digest,
            execution_bundle_digest,
            code_object_digest,
            module_values,
        ) = value
        if not isinstance(module_values, tuple):
            raise ValueError("execution bundle module transport is invalid")
        return cls(
            schema_version=schema_version,
            fixture_id=fixture_id,
            framework=framework,
            case_type=case_type,
            implementation_id=implementation_id,
            source_digest=source_digest,
            descriptor_digest=descriptor_digest,
            _ground_truth_digest=ground_truth_digest,
            execution_bundle_digest=execution_bundle_digest,
            code_object_digest=code_object_digest,
            modules=tuple(
                _BundledModule.from_transport(item)
                for item in module_values
            ),
        )


def get_fixture_spec(fixture_id: str) -> FixtureSpec | None:
    """Return an immutable fixture definition by exact stable ID."""

    return _FIXTURES.get(fixture_id)


def fixture_registry_digest() -> str:
    """Digest only closed registry descriptors, never source or labels."""

    return _canonical_digest({
        "schema_version": FIXTURE_REGISTRY_SCHEMA_VERSION,
        "fixtures": [
            _FIXTURES[fixture_id].registry_dict()
            for fixture_id in sorted(_FIXTURES)
        ],
    })


def fixture_descriptor_digest(spec_or_id: FixtureSpec | str) -> str:
    spec = _coerce_spec(spec_or_id)
    return _descriptor_digest_from_values(**spec.descriptor_dict())


def fixture_source_digest(spec_or_id: FixtureSpec | str) -> str:
    """Digest exact application bytes and logical names, nothing else."""

    return prepare_execution_bundle(spec_or_id).source_digest


def fixture_execution_bundle_digest(
    spec_or_id: FixtureSpec | str,
) -> str:
    return prepare_execution_bundle(spec_or_id).execution_bundle_digest


def fixture_code_object_digest(spec_or_id: FixtureSpec | str) -> str:
    return prepare_execution_bundle(spec_or_id).code_object_digest


def execution_bundle_identity(
    bundle: PreparedExecutionBundle,
) -> dict[str, str]:
    """Return public binding fields without evaluator identity or content."""

    if not isinstance(bundle, PreparedExecutionBundle):
        raise ValueError("fixture execution bundle is invalid")
    return {
        "fixture_registry_digest": fixture_registry_digest(),
        "fixture_source_digest": bundle.source_digest,
        "fixture_descriptor_digest": bundle.descriptor_digest,
        "fixture_execution_bundle_digest": bundle.execution_bundle_digest,
        "fixture_code_object_digest": bundle.code_object_digest,
    }


def fixture_source_manifest(spec_or_id: FixtureSpec | str) -> dict[str, Any]:
    """Return application-only names/digests; never evaluator identity."""

    bundle = prepare_execution_bundle(spec_or_id)
    return {
        "schema_version": FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION,
        "source_digest": bundle.source_digest,
        "documents": [
            item.digest_row()
            for item in bundle.modules
            if item.group == "application"
        ],
    }


def fixture_source_documents(spec_or_id: FixtureSpec | str) -> dict[str, bytes]:
    """Return defensive copies of exact application source bytes."""

    bundle = prepare_execution_bundle(spec_or_id)
    return bundle.application_source_documents()


def prepare_execution_bundle(
    spec_or_id: FixtureSpec | str,
) -> PreparedExecutionBundle:
    """Capture and compile every allowlisted first-party module exactly once."""

    spec = _coerce_spec(spec_or_id)
    modules = tuple(
        _capture_module(
            module_name=module_name,
            logical_name=logical_name,
            path=path,
            group=group,
            is_package=is_package,
        )
        for (
            module_name,
            logical_name,
            path,
            group,
            is_package,
        ) in _module_paths(spec)
    )
    descriptor_digest = fixture_descriptor_digest(spec)
    source_digest = _canonical_digest({
        "schema_version": _APPLICATION_SOURCE_SCHEMA_VERSION,
        "documents": [
            item.digest_row()
            for item in modules
            if item.group == "application"
        ],
    })
    ground_truth_digest = _canonical_digest({
        "schema_version": _GROUND_TRUTH_SCHEMA_VERSION,
        "documents": [
            item.digest_row()
            for item in modules
            if item.group == "ground_truth"
        ],
    })
    code_object_digest = _canonical_digest({
        "schema_version": _CODE_OBJECT_SCHEMA_VERSION,
        "modules": [item.code_row() for item in modules],
    })
    execution_bundle_digest = _canonical_digest({
        "schema_version": FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION,
        "source_digest": source_digest,
        "fixture_descriptor_digest": descriptor_digest,
        "ground_truth_digest": ground_truth_digest,
        "code_object_digest": code_object_digest,
    })
    return PreparedExecutionBundle(
        fixture_id=spec.fixture_id,
        framework=spec.framework,
        case_type=spec.case_type,
        implementation_id=spec.implementation_id,
        source_digest=source_digest,
        descriptor_digest=descriptor_digest,
        _ground_truth_digest=ground_truth_digest,
        execution_bundle_digest=execution_bundle_digest,
        code_object_digest=code_object_digest,
        modules=modules,
    )


def load_fixture_runner(
    spec: FixtureSpec,
    bundle: PreparedExecutionBundle | None = None,
) -> FixturePreparer:
    """Return the sole closed runner over parent-captured in-memory modules."""

    from ..web import optional_framework_available

    captured = bundle or prepare_execution_bundle(spec)
    _require_bundle_matches_spec(captured, spec)
    if not optional_framework_available(spec.framework):
        raise OptionalWebDependencyUnavailable(spec.framework)
    if spec.framework == "flask":
        import flask.testing
        from importlib.metadata import version

        if not flask.testing._werkzeug_version:
            flask.testing._werkzeug_version = version("werkzeug")
    elif spec.framework == "fastapi":
        # Import the fixed optional framework before the child filesystem
        # sandbox is installed.  Pydantic performs distribution discovery at
        # first import; application requests themselves require no checkout
        # or site-packages reads after this closed preload.
        import fastapi
        import fastapi.responses

        del fastapi

    def prepare(
        temporary_root: Path,
        parameters: Mapping[str, Any],
    ) -> PreparedFixture:
        with _execution_bundle_imports(captured):
            runner = importlib.import_module(
                "belief.validation.web.fixtures.runner"
            )
            prepare_fixture = getattr(runner, "prepare_fixture", None)
            if not callable(prepare_fixture):
                raise RuntimeError("closed fixture runner is unavailable")
            prepared = prepare_fixture(
                spec.fixture_id,
                temporary_root,
                parameters,
            )
        if not callable(prepared):
            raise RuntimeError("closed fixture did not return an executor")
        return prepared

    return prepare


def registered_fixture_metadata() -> tuple[dict[str, Any], ...]:
    """Return public registry metadata without evaluator identities."""

    rows = []
    for fixture_id in sorted(_FIXTURES):
        spec = _FIXTURES[fixture_id]
        bundle = prepare_execution_bundle(spec)
        rows.append(spec.public_dict(bundle))
    return tuple(rows)


def registered_fixture_ids() -> tuple[str, ...]:
    return tuple(sorted(_FIXTURES))


def _descriptor_digest_from_values(
    *,
    fixture_id: str,
    framework: str,
    case_type: str,
    implementation_id: str,
) -> str:
    return _canonical_digest({
        "schema_version": _DESCRIPTOR_SCHEMA_VERSION,
        "fixture": {
            "fixture_id": fixture_id,
            "framework": framework,
            "case_type": case_type,
            "implementation_id": implementation_id,
        },
    })


def _module_paths(
    spec: FixtureSpec,
) -> tuple[tuple[str, str, Path, str, bool], ...]:
    worker_dir = Path(__file__).resolve().parent
    web_dir = worker_dir.parent / "web"
    case_module = (
        "path"
        if spec.case_type == "path_traversal_possible"
        else "idor"
    )
    rows = (
        (
            "belief.validation.web.fixtures",
            "web/fixtures/__init__.py",
            web_dir / "fixtures" / "__init__.py",
            "ground_truth",
            True,
        ),
        (
            "belief.validation.web.fixtures.apps",
            "web/fixtures/apps/__init__.py",
            web_dir / "fixtures" / "apps" / "__init__.py",
            "application",
            True,
        ),
        (
            "belief.validation.web.fixtures.apps.contracts",
            "web/fixtures/apps/contracts.py",
            web_dir / "fixtures" / "apps" / "contracts.py",
            "application",
            False,
        ),
        (
            "belief.validation.web.fixtures.apps.support",
            "web/fixtures/apps/support.py",
            web_dir / "fixtures" / "apps" / "support.py",
            "application",
            False,
        ),
        (
            f"belief.validation.web.{spec.framework}_adapter",
            f"web/{spec.framework}_adapter.py",
            web_dir / f"{spec.framework}_adapter.py",
            "application",
            False,
        ),
        (
            f"belief.validation.web.fixtures.apps.{spec.implementation_id}",
            f"web/fixtures/apps/{spec.implementation_id}.py",
            web_dir / "fixtures" / "apps" / f"{spec.implementation_id}.py",
            "application",
            False,
        ),
        (
            "belief.validation.web.fixtures.ground_truth",
            "web/fixtures/ground_truth/__init__.py",
            web_dir / "fixtures" / "ground_truth" / "__init__.py",
            "ground_truth",
            True,
        ),
        (
            f"belief.validation.web.fixtures.ground_truth.{case_module}",
            f"web/fixtures/ground_truth/{case_module}.py",
            web_dir / "fixtures" / "ground_truth" / f"{case_module}.py",
            "ground_truth",
            False,
        ),
        (
            "belief.validation.web.fixtures.oracles",
            "web/fixtures/oracles/__init__.py",
            web_dir / "fixtures" / "oracles" / "__init__.py",
            "ground_truth",
            True,
        ),
        (
            f"belief.validation.web.fixtures.oracles.{case_module}",
            f"web/fixtures/oracles/{case_module}.py",
            web_dir / "fixtures" / "oracles" / f"{case_module}.py",
            "ground_truth",
            False,
        ),
        (
            "belief.validation.web.fixtures.runner",
            "web/fixtures/runner.py",
            web_dir / "fixtures" / "runner.py",
            "ground_truth",
            False,
        ),
    )
    return tuple(sorted(rows, key=lambda item: item[0]))


def _capture_module(
    *,
    module_name: str,
    logical_name: str,
    path: Path,
    group: str,
    is_package: bool,
) -> _BundledModule:
    resolved = path.resolve(strict=True)
    web_root = (Path(__file__).resolve().parent.parent / "web").resolve()
    if (
        path.is_symlink()
        or not resolved.is_relative_to(web_root)
        or not resolved.is_file()
    ):
        raise ValueError("fixture source path escaped its allowlisted root")
    before = resolved.stat()
    with resolved.open("rb") as handle:
        source_bytes = handle.read(_MAX_BUNDLE_FILE_BYTES + 1)
    after = resolved.stat()
    if len(source_bytes) > _MAX_BUNDLE_FILE_BYTES:
        raise ValueError("fixture source exceeds its byte bound")
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_size != len(source_bytes)
    ):
        raise ValueError("fixture source changed while being captured")
    return _BundledModule(
        module_name=module_name,
        logical_name=logical_name,
        source_bytes=source_bytes,
        group=group,
        is_package=is_package,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        code_object_sha256=_compiled_source_digest(
            source_bytes,
            logical_name,
        ),
    )


def _compiled_source(
    source_bytes: bytes,
    logical_name: str,
):
    try:
        encoding, _ = tokenize.detect_encoding(
            io.BytesIO(source_bytes).readline
        )
        source = source_bytes.decode(encoding, errors="strict")
    except (LookupError, SyntaxError, UnicodeDecodeError) as exc:
        raise ValueError("fixture source encoding is invalid") from exc
    try:
        return compile(
            source,
            logical_name,
            "exec",
            dont_inherit=True,
            optimize=0,
        )
    except (SyntaxError, ValueError) as exc:
        raise ValueError("fixture source cannot be compiled exactly") from exc


def _compiled_source_digest(
    source_bytes: bytes,
    logical_name: str,
) -> str:
    return _canonical_digest(
        _code_identity(_compiled_source(source_bytes, logical_name))
    )


def _code_identity(code: CodeType) -> dict[str, Any]:
    """Return a deterministic code-object identity without marshal interning."""

    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize,
        "flags": code.co_flags,
        "bytecode": code.co_code.hex(),
        "constants": [_constant_identity(item) for item in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
        "name": code.co_name,
        "qualname": code.co_qualname,
        "firstlineno": code.co_firstlineno,
        "linetable": code.co_linetable.hex(),
        "exceptiontable": code.co_exceptiontable.hex(),
    }


def _constant_identity(value: Any) -> Any:
    if isinstance(value, CodeType):
        return {"type": "code", "value": _code_identity(value)}
    if value is None:
        return {"type": "none"}
    if value is Ellipsis:
        return {"type": "ellipsis"}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, float):
        return {"type": "float", "value": value.hex()}
    if isinstance(value, complex):
        return {
            "type": "complex",
            "real": value.real.hex(),
            "imag": value.imag.hex(),
        }
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if isinstance(value, bytes):
        return {"type": "bytes", "value": value.hex()}
    if isinstance(value, tuple):
        return {
            "type": "tuple",
            "value": [_constant_identity(item) for item in value],
        }
    if isinstance(value, frozenset):
        members = [_constant_identity(item) for item in value]
        members.sort(
            key=lambda item: json.dumps(
                item,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return {"type": "frozenset", "value": members}
    raise ValueError("fixture code object contains an unsupported constant")


class _InMemoryBundleLoader(importlib.abc.Loader):
    def __init__(self, document: _BundledModule) -> None:
        self._document = document

    def create_module(self, spec: Any) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        code = _compiled_source(
            self._document.source_bytes,
            self._document.logical_name,
        )
        if _canonical_digest(_code_identity(code)) != (
            self._document.code_object_sha256
        ):
            raise ImportError("bundled module code-object digest mismatch")
        exec(code, module.__dict__)


class _InMemoryBundleFinder(importlib.abc.MetaPathFinder):
    def __init__(self, bundle: PreparedExecutionBundle) -> None:
        self._documents = {
            item.module_name: item
            for item in bundle.modules
        }

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: Any = None,
    ):
        del path, target
        document = self._documents.get(fullname)
        if document is None:
            return None
        loader = _InMemoryBundleLoader(document)
        return importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=document.logical_name,
            is_package=document.is_package,
        )


@contextmanager
def _execution_bundle_imports(
    bundle: PreparedExecutionBundle,
) -> Iterator[None]:
    finder = _InMemoryBundleFinder(bundle)
    bundled_names = {item.module_name for item in bundle.modules}
    purge_names = {
        name
        for name in tuple(sys.modules)
        if (
            name in bundled_names
            or name.startswith("belief.validation.web.fixtures.")
            or name == "belief.validation.web.fixtures"
            or name
            in {
                "belief.validation.web.flask_adapter",
                "belief.validation.web.fastapi_adapter",
            }
        )
    }
    previous = {
        name: sys.modules[name]
        for name in purge_names
    }
    for name in sorted(purge_names, key=lambda item: item.count("."), reverse=True):
        sys.modules.pop(name, None)
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
        for name in tuple(sys.modules):
            if (
                name in bundled_names
                or name.startswith("belief.validation.web.fixtures.")
                or name == "belief.validation.web.fixtures"
                or name
                in {
                    "belief.validation.web.flask_adapter",
                    "belief.validation.web.fastapi_adapter",
                }
            ):
                sys.modules.pop(name, None)
        sys.modules.update(previous)


def _require_bundle_matches_spec(
    bundle: PreparedExecutionBundle,
    spec: FixtureSpec,
) -> None:
    if not isinstance(bundle, PreparedExecutionBundle):
        raise ValueError("fixture execution bundle is invalid")
    expected = (
        spec.fixture_id,
        spec.framework,
        spec.case_type,
        spec.implementation_id,
        fixture_descriptor_digest(spec),
    )
    actual = (
        bundle.fixture_id,
        bundle.framework,
        bundle.case_type,
        bundle.implementation_id,
        bundle.descriptor_digest,
    )
    if actual != expected:
        raise ValueError("fixture execution bundle descriptor mismatch")


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
    "FIXTURE_EXECUTION_BUNDLE_SCHEMA_VERSION",
    "FIXTURE_REGISTRY_SCHEMA_VERSION",
    "FIXTURE_SOURCE_MANIFEST_SCHEMA_VERSION",
    "FixturePreparer",
    "FixtureSpec",
    "OptionalWebDependencyUnavailable",
    "PreparedExecutionBundle",
    "PreparedFixture",
    "RegisteredFixtureResult",
    "fixture_code_object_digest",
    "fixture_descriptor_digest",
    "fixture_execution_bundle_digest",
    "execution_bundle_identity",
    "fixture_registry_digest",
    "fixture_source_digest",
    "fixture_source_documents",
    "fixture_source_manifest",
    "get_fixture_spec",
    "load_fixture_runner",
    "prepare_execution_bundle",
    "registered_fixture_ids",
    "registered_fixture_metadata",
]
