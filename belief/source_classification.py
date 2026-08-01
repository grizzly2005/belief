"""Fail-closed classification and syntax checking for bundled Python sources."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SOURCE_CLASSIFICATION_SCHEMA_VERSION = "belief.python_source_classification.v1"
DEFAULT_MANIFEST = Path(__file__).with_name("python_source_classification.json")
_TOP_LEVEL_FIELDS = frozenset({"schema_version", "python3_roots", "classifications"})
_CLASSIFICATION_FIELDS = frozenset(
    {
        "classification_id",
        "path_prefix",
        "language",
        "role",
        "python3_compile",
        "execution",
        "expected_python_file_count",
        "inventory_sha256",
    }
)


class SourceClassificationError(ValueError):
    """Raised when the source classification cannot be trusted."""


@dataclass(frozen=True)
class LegacySourceClassification:
    classification_id: str
    path_prefix: str
    language: str
    role: str
    python3_compile: str
    execution: str
    expected_python_file_count: int
    inventory_sha256: str


@dataclass(frozen=True)
class SourceCheckReport:
    schema_version: str
    compiled_python3_files: int
    excluded_legacy_files: int
    classifications: tuple[str, ...]
    syntax_errors: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.syntax_errors

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["ok"] = self.ok
        return payload


def _reject_constant(value: str) -> None:
    raise SourceClassificationError(f"non-finite JSON value is forbidden: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceClassificationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _require_exact_fields(
    payload: dict[str, Any],
    expected: frozenset[str],
    *,
    context: str,
) -> None:
    actual = frozenset(payload)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    raise SourceClassificationError(
        f"{context} fields do not match schema; missing={missing}, unknown={unknown}"
    )


def _relative_posix_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceClassificationError(f"{field} must be a non-empty string")
    if "\\" in value or ":" in value:
        raise SourceClassificationError(f"{field} must use a portable relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        raise SourceClassificationError(f"{field} must be a normalized relative path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SourceClassificationError(f"{field} contains a forbidden path component")
    return value


def _sha256(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SourceClassificationError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SourceClassificationError(f"{field} must be a positive integer")
    return value


def load_source_classification(
    manifest_path: Path = DEFAULT_MANIFEST,
) -> tuple[tuple[str, ...], tuple[LegacySourceClassification, ...]]:
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        payload = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceClassificationError(f"cannot read classification manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise SourceClassificationError("classification manifest must be a JSON object")
    _require_exact_fields(payload, _TOP_LEVEL_FIELDS, context="manifest")
    if payload["schema_version"] != SOURCE_CLASSIFICATION_SCHEMA_VERSION:
        raise SourceClassificationError("unsupported source classification schema")

    roots_payload = payload["python3_roots"]
    if not isinstance(roots_payload, list) or not roots_payload:
        raise SourceClassificationError("python3_roots must be a non-empty array")
    roots = tuple(
        _relative_posix_path(value, field="python3_roots entry") for value in roots_payload
    )
    if len(set(roots)) != len(roots):
        raise SourceClassificationError("python3_roots entries must be unique")

    entries_payload = payload["classifications"]
    if not isinstance(entries_payload, list):
        raise SourceClassificationError("classifications must be an array")
    entries: list[LegacySourceClassification] = []
    identifiers: set[str] = set()
    prefixes: set[str] = set()
    for index, item in enumerate(entries_payload):
        if not isinstance(item, dict):
            raise SourceClassificationError(f"classification[{index}] must be an object")
        _require_exact_fields(
            item,
            _CLASSIFICATION_FIELDS,
            context=f"classification[{index}]",
        )
        identifier = item["classification_id"]
        if (
            not isinstance(identifier, str)
            or not identifier
            or not identifier.replace("_", "").isalnum()
        ):
            raise SourceClassificationError("classification_id is not canonical")
        if identifier in identifiers:
            raise SourceClassificationError("classification_id entries must be unique")
        identifiers.add(identifier)

        prefix = _relative_posix_path(item["path_prefix"], field="path_prefix")
        if prefix in prefixes:
            raise SourceClassificationError("path_prefix entries must be unique")
        prefixes.add(prefix)
        for existing in prefixes - {prefix}:
            if prefix.startswith(f"{existing}/") or existing.startswith(f"{prefix}/"):
                raise SourceClassificationError("classified path prefixes must not overlap")

        if item["language"] != "python2":
            raise SourceClassificationError("only explicit Python 2 classifications are supported")
        if item["role"] != "vendored_reference_examples":
            raise SourceClassificationError("unsupported legacy source role")
        if item["python3_compile"] != "excluded":
            raise SourceClassificationError("legacy source must be excluded from Python 3 compile")
        if item["execution"] != "forbidden":
            raise SourceClassificationError("legacy source execution must be forbidden")

        entries.append(
            LegacySourceClassification(
                classification_id=identifier,
                path_prefix=prefix,
                language="python2",
                role="vendored_reference_examples",
                python3_compile="excluded",
                execution="forbidden",
                expected_python_file_count=_positive_int(
                    item["expected_python_file_count"],
                    field="expected_python_file_count",
                ),
                inventory_sha256=_sha256(
                    item["inventory_sha256"],
                    field="inventory_sha256",
                ),
            )
        )
    return roots, tuple(entries)


def _resolved_inside(root: Path, candidate: Path, *, context: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise SourceClassificationError(f"{context} escapes or is unavailable") from exc
    return resolved_candidate


def _canonical_source_bytes(data: bytes) -> bytes:
    """Return the Git-platform-neutral representation used by the inventory."""

    return data.replace(b"\r\n", b"\n")


def build_python_inventory(repo_root: Path, path_prefix: str) -> tuple[int, str]:
    prefix = _resolved_inside(
        repo_root,
        repo_root / PurePosixPath(path_prefix),
        context="classified path",
    )
    if not prefix.is_dir():
        raise SourceClassificationError("classified path must be a directory")

    records: list[dict[str, Any]] = []
    for path in sorted(prefix.rglob("*.py"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise SourceClassificationError("classified Python source cannot be a symlink")
        resolved = _resolved_inside(prefix, path, context="classified Python source")
        data = _canonical_source_bytes(resolved.read_bytes())
        records.append(
            {
                "path": resolved.relative_to(repo_root.resolve(strict=True)).as_posix(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    canonical = json.dumps(
        records,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return len(records), hashlib.sha256(canonical).hexdigest()


def check_python3_sources(
    repo_root: Path,
    *,
    manifest_path: Path | None = None,
) -> SourceCheckReport:
    repo_root = repo_root.resolve(strict=True)
    if not repo_root.is_dir():
        raise SourceClassificationError("repository root must be a directory")
    selected_manifest = manifest_path or repo_root / "belief" / DEFAULT_MANIFEST.name
    roots, classifications = load_source_classification(selected_manifest)

    excluded_prefixes: list[str] = []
    excluded_count = 0
    for classification in classifications:
        count, digest = build_python_inventory(repo_root, classification.path_prefix)
        if count != classification.expected_python_file_count:
            raise SourceClassificationError(
                f"{classification.classification_id} file count mismatch: "
                f"expected {classification.expected_python_file_count}, observed {count}"
            )
        if digest != classification.inventory_sha256:
            raise SourceClassificationError(
                f"{classification.classification_id} inventory digest mismatch: "
                f"expected {classification.inventory_sha256}, observed {digest}"
            )
        excluded_prefixes.append(f"{classification.path_prefix}/")
        excluded_count += count

    compiled_count = 0
    syntax_errors: list[str] = []
    seen_sources: set[str] = set()
    for root_value in roots:
        source_root = _resolved_inside(
            repo_root,
            repo_root / PurePosixPath(root_value),
            context="Python 3 source root",
        )
        if not source_root.is_dir():
            raise SourceClassificationError("Python 3 source root must be a directory")
        for path in sorted(source_root.rglob("*.py"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise SourceClassificationError("Python source cannot be a symlink")
            resolved = _resolved_inside(repo_root, path, context="Python source")
            relative = resolved.relative_to(repo_root).as_posix()
            if relative in seen_sources:
                raise SourceClassificationError("Python source roots must not overlap")
            seen_sources.add(relative)
            if any(relative.startswith(prefix) for prefix in excluded_prefixes):
                continue
            try:
                compile(resolved.read_bytes(), relative, "exec", dont_inherit=True)
            except (OSError, SyntaxError, UnicodeError, ValueError) as exc:
                message = getattr(exc, "msg", str(exc))
                line = getattr(exc, "lineno", None)
                suffix = f":{line}" if line is not None else ""
                syntax_errors.append(f"{relative}{suffix}: {message}")
            compiled_count += 1

    return SourceCheckReport(
        schema_version=SOURCE_CLASSIFICATION_SCHEMA_VERSION,
        compiled_python3_files=compiled_count,
        excluded_legacy_files=excluded_count,
        classifications=tuple(item.classification_id for item in classifications),
        syntax_errors=tuple(syntax_errors),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compile-check Python 3 sources using the fail-closed legacy manifest."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="classification manifest (default: belief/python_source_classification.json)",
    )
    args = parser.parse_args(argv)
    try:
        report = check_python3_sources(args.root, manifest_path=args.manifest)
    except SourceClassificationError as exc:
        print(json.dumps({"ok": False, "classification_error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
