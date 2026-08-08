"""Immutable, content-addressed Python source snapshots.

The static-analysis pipeline must never assemble one result from several
versions of the same file.  This module therefore owns source discovery,
bounded one-shot reads, strict PEP 263 decoding, and the manifest that binds an
analysis to the exact bytes it consumed.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import tokenize
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .parser import DEFAULT_EXCLUDE_DIRS, GENERATED_FILE_NAMES


SOURCE_SNAPSHOT_MANIFEST_SCHEMA_VERSION = "belief.source_snapshot_manifest.v1"
SOURCE_COVERAGE_SCHEMA_VERSION = "belief.source_coverage.v1"
SOURCE_DOCUMENT_SCHEMA_VERSION = "belief.source_document.v1"

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_AST_NODES = 250_000

_ENCODING_COOKIE = re.compile(br"^[ \t\f]*#.*?coding[:=][ \t]*([-_.a-zA-Z0-9]+)")
_SENSITIVE_UNENUMERATED_DIRS = frozenset({"benchmark_susvibes"})
_ENGINE_RELATIVE_PATHS = (
    "__init__.py",
    "audit_case.py",
    "cycle_detector.py",
    "dataflow.py",
    "guarantee_index.py",
    "hypothesis_engine.py",
    "invariant_miner.py",
    "models.py",
    "parser.py",
    "security_patterns.py",
    "source_snapshot.py",
    "static_analysis_pipeline.py",
    "structural.py",
    "temporal/__init__.py",
    "taint/__init__.py",
    "routes/extractor.py",
)


@dataclass(frozen=True)
class SourceDocument:
    """One exact source document retained entirely in memory."""

    logical_path: str
    disk_path: Path
    content_bytes: bytes
    decoded_source: str | None
    sha256: str
    size: int
    encoding: str
    decode_status: str
    parse_status: str
    ast_node_count: int | None = None
    diagnostic: str = ""
    parsed_ast: ast.Module | None = field(default=None, repr=False, compare=False)
    schema_version: str = SOURCE_DOCUMENT_SCHEMA_VERSION

    @property
    def analyzable(self) -> bool:
        return (
            self.decoded_source is not None
            and self.decode_status
            in {"decoded_exactly", "decoded_from_encoding_cookie"}
            and self.parse_status == "parsed"
            and self.parsed_ast is not None
        )

    def manifest_row(self) -> dict[str, Any]:
        """Describe bytes and decode state without publishing source content."""

        return {
            "schema_version": self.schema_version,
            "logical_path": self.logical_path,
            "sha256": self.sha256,
            "size": self.size,
            "encoding": self.encoding,
            "decode_status": self.decode_status,
            "parse_status": self.parse_status,
            "ast_node_count": self.ast_node_count,
        }


@dataclass(frozen=True)
class SourceCoverage:
    """Exact known scan coverage plus explicit inventory blind spots."""

    discovered_files: int
    eligible_files: int
    scanned_files: int
    excluded_files_by_reason: dict[str, int]
    excluded_files: tuple[dict[str, Any], ...]
    excluded_subtrees: tuple[dict[str, str], ...]
    truncated_files: tuple[str, ...]
    failed_files: tuple[str, ...]
    scan_complete: bool
    inventory_complete: bool
    project_conclusion_allowed: bool
    max_files: int
    max_file_bytes: int
    max_total_source_bytes: int
    max_ast_nodes: int
    parse_time_limit: str = "not_preemptively_enforced"
    schema_version: str = SOURCE_COVERAGE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        denominator = self.eligible_files or 1
        return {
            "schema_version": self.schema_version,
            "discovered_files": self.discovered_files,
            "eligible_files": self.eligible_files,
            "scanned_files": self.scanned_files,
            "excluded_files_by_reason": dict(
                sorted(self.excluded_files_by_reason.items())
            ),
            "excluded_files": [dict(item) for item in self.excluded_files],
            "excluded_subtrees": [dict(item) for item in self.excluded_subtrees],
            "truncated_files": list(self.truncated_files),
            "failed_files": list(self.failed_files),
            "scan_complete": self.scan_complete,
            "inventory_complete": self.inventory_complete,
            "project_conclusion_allowed": self.project_conclusion_allowed,
            "python_source_coverage": round(
                self.scanned_files / denominator,
                6,
            ),
            "limits": {
                "max_files": self.max_files,
                "max_file_bytes": self.max_file_bytes,
                "max_total_source_bytes": self.max_total_source_bytes,
                "max_ast_nodes": self.max_ast_nodes,
                "parse_time_limit": self.parse_time_limit,
            },
        }


@dataclass(frozen=True)
class SourceSnapshotManifest:
    """Versioned identity of one source snapshot and analysis configuration."""

    target_identity: str
    source_revision: str
    file_count: int
    total_bytes: int
    files: tuple[dict[str, Any], ...]
    analysis_options: dict[str, Any]
    analysis_options_digest: str
    belief_version: str
    belief_commit: str
    engine_revision: str
    source_content_digest: str
    source_manifest_digest: str
    coverage: SourceCoverage
    schema_version: str = SOURCE_SNAPSHOT_MANIFEST_SCHEMA_VERSION

    @property
    def source_snapshot_id(self) -> str:
        return f"src_{self.source_manifest_digest}"

    @property
    def analysis_id(self) -> str:
        return "analysis_" + canonical_json_digest({
            "source_manifest_digest": self.source_manifest_digest,
            "analysis_options_digest": self.analysis_options_digest,
            "engine_revision": self.engine_revision,
        })

    @property
    def manifest_digest(self) -> str:
        return canonical_json_digest(self._unsigned_dict())

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_identity": self.target_identity,
            "source_revision": self.source_revision,
            "source_snapshot_id": self.source_snapshot_id,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "files": [dict(item) for item in self.files],
            "analysis_options": _canonical_json_value(self.analysis_options),
            "analysis_options_digest": self.analysis_options_digest,
            "belief_version": self.belief_version,
            "belief_commit": self.belief_commit,
            "engine_revision": self.engine_revision,
            "source_content_digest": self.source_content_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "analysis_id": self.analysis_id,
            "coverage": self.coverage.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._unsigned_dict(),
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True)
class SourceSnapshot:
    """In-memory source snapshot consumed by every analysis component."""

    documents: tuple[SourceDocument, ...]
    manifest: SourceSnapshotManifest

    @property
    def analyzable_documents(self) -> tuple[SourceDocument, ...]:
        return tuple(item for item in self.documents if item.analyzable)

    @property
    def source_map(self) -> dict[str, str]:
        return {
            item.logical_path: item.decoded_source
            for item in self.analyzable_documents
            if item.decoded_source is not None
        }

    @property
    def ast_map(self) -> dict[str, ast.Module]:
        return {
            item.logical_path: item.parsed_ast
            for item in self.analyzable_documents
            if item.parsed_ast is not None
        }


def build_source_snapshot(
    target: str | Path,
    *,
    analysis_options: Mapping[str, Any],
    max_files: int,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_source_bytes: int = DEFAULT_MAX_TOTAL_SOURCE_BYTES,
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES,
    denied_source_sha256: frozenset[str] = frozenset(),
    target_identity: str | None = None,
) -> SourceSnapshot:
    """Read each selected Python file once and build its immutable snapshot."""

    target_path = Path(target)
    try:
        resolved_target = target_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"analysis target is unavailable: {target_path}") from exc
    if not resolved_target.is_file() and not resolved_target.is_dir():
        raise ValueError("analysis target must be a Python file or directory")
    if max_files < 0:
        raise ValueError("max_files must be non-negative")
    for name, value in (
        ("max_file_bytes", max_file_bytes),
        ("max_total_source_bytes", max_total_source_bytes),
        ("max_ast_nodes", max_ast_nodes),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    denied_digests = _validated_sha256_set(denied_source_sha256)

    (
        discovered,
        eligible,
        excluded,
        excluded_subtrees,
        inventory_complete,
    ) = _discover_python_sources(resolved_target)
    selected = eligible[:max_files]
    truncated = tuple(
        _logical_path(path, resolved_target) for path in eligible[max_files:]
    )

    documents: list[SourceDocument] = []
    failed: list[str] = []
    total_bytes = 0
    exclusion_rows = list(excluded)
    for path in selected:
        logical = _logical_path(path, resolved_target)
        try:
            stat = path.stat()
        except OSError:
            failed.append(logical)
            exclusion_rows.append(_excluded_file(logical, "unreadable", None, None))
            continue
        if stat.st_size > max_file_bytes:
            failed.append(logical)
            exclusion_rows.append(
                _excluded_file(logical, "file_too_large", stat.st_size, None)
            )
            continue
        if total_bytes + stat.st_size > max_total_source_bytes:
            failed.append(logical)
            exclusion_rows.append(
                _excluded_file(
                    logical,
                    "total_source_byte_budget_exhausted",
                    stat.st_size,
                    None,
                )
            )
            continue
        document = _read_document_once(
            path,
            logical_path=logical,
            max_file_bytes=max_file_bytes,
            max_ast_nodes=max_ast_nodes,
            denied_source_sha256=denied_digests,
        )
        documents.append(document)
        total_bytes += document.size
        if not document.analyzable:
            failed.append(logical)
            if document.decode_status == "reserved_digest_blocked":
                exclusion_rows.append(
                    _excluded_file(
                        logical,
                        "reserved_source_digest",
                        document.size,
                        document.sha256,
                    )
                )

    documents.sort(key=lambda item: item.logical_path)
    exclusion_rows.sort(
        key=lambda item: (str(item["logical_path"]), str(item["reason"]))
    )
    reason_counts = Counter(str(item["reason"]) for item in exclusion_rows)
    scanned_count = sum(item.analyzable for item in documents)
    scan_complete = not truncated and not failed
    project_conclusion_allowed = (
        scan_complete
        and inventory_complete
        and not exclusion_rows
        and not excluded_subtrees
    )
    coverage = SourceCoverage(
        discovered_files=len(discovered),
        eligible_files=len(eligible),
        scanned_files=scanned_count,
        excluded_files_by_reason=dict(reason_counts),
        excluded_files=tuple(exclusion_rows),
        excluded_subtrees=tuple(excluded_subtrees),
        truncated_files=truncated,
        failed_files=tuple(sorted(set(failed))),
        scan_complete=scan_complete,
        inventory_complete=inventory_complete,
        project_conclusion_allowed=project_conclusion_allowed,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_source_bytes=max_total_source_bytes,
        max_ast_nodes=max_ast_nodes,
    )
    file_rows = tuple(item.manifest_row() for item in documents)
    source_content_digest = canonical_json_digest({
        "schema_version": SOURCE_DOCUMENT_SCHEMA_VERSION,
        "target_kind": "file" if resolved_target.is_file() else "directory",
        "files": file_rows,
        "coverage_identity": {
            "eligible_files": len(eligible),
            "truncated_files": list(truncated),
            "failed_files": list(sorted(set(failed))),
            "excluded_files": exclusion_rows,
            "excluded_subtrees": list(excluded_subtrees),
            "inventory_complete": inventory_complete,
        },
    })
    canonical_options = _canonical_json_value(dict(analysis_options))
    options_digest = canonical_json_digest(canonical_options)
    logical_target_identity = (
        target_identity
        if target_identity is not None
        else _normalized_absolute_path(resolved_target)
    )
    source_manifest_digest = _source_manifest_digest(
        target_identity=logical_target_identity,
        source_content_digest=source_content_digest,
        files=file_rows,
        coverage=coverage,
    )
    manifest = SourceSnapshotManifest(
        target_identity=logical_target_identity,
        source_revision=f"snapshot:{source_content_digest}",
        file_count=len(documents),
        total_bytes=sum(item.size for item in documents),
        files=file_rows,
        analysis_options=canonical_options,
        analysis_options_digest=options_digest,
        belief_version=__version__,
        belief_commit=belief_commit(),
        engine_revision=belief_engine_revision(),
        source_content_digest=source_content_digest,
        source_manifest_digest=source_manifest_digest,
        coverage=coverage,
    )
    return SourceSnapshot(documents=tuple(documents), manifest=manifest)


def rebind_snapshot_target(
    snapshot: SourceSnapshot,
    target_identity: str,
) -> SourceSnapshot:
    """Give an already captured byte snapshot a stable logical target identity."""

    if not isinstance(target_identity, str) or not target_identity.strip():
        raise ValueError("target identity must be a non-empty string")
    current = snapshot.manifest
    source_manifest_digest = _source_manifest_digest(
        target_identity=target_identity.strip(),
        source_content_digest=current.source_content_digest,
        files=current.files,
        coverage=current.coverage,
    )
    rebound = SourceSnapshotManifest(
        target_identity=target_identity.strip(),
        source_revision=current.source_revision,
        file_count=current.file_count,
        total_bytes=current.total_bytes,
        files=current.files,
        analysis_options=current.analysis_options,
        analysis_options_digest=current.analysis_options_digest,
        belief_version=current.belief_version,
        belief_commit=current.belief_commit,
        engine_revision=current.engine_revision,
        source_content_digest=current.source_content_digest,
        source_manifest_digest=source_manifest_digest,
        coverage=current.coverage,
    )
    return SourceSnapshot(documents=snapshot.documents, manifest=rebound)


def rebind_source_manifest_payload(
    payload: Mapping[str, Any],
    target_identity: str,
) -> dict[str, Any]:
    """Rebind a serialized manifest without rereading any source bytes."""

    if not isinstance(target_identity, str) or not target_identity.strip():
        raise ValueError("target identity must be a non-empty string")
    rebound = dict(payload)
    files = rebound.get("files")
    coverage = rebound.get("coverage")
    source_content_digest = str(
        rebound.get("source_content_digest") or ""
    )
    options_digest = str(rebound.get("analysis_options_digest") or "")
    engine_revision = str(rebound.get("engine_revision") or "")
    if (
        not isinstance(files, list)
        or not isinstance(coverage, Mapping)
        or not all(
            re.fullmatch(r"[0-9a-f]{64}", value)
            for value in (
                source_content_digest,
                options_digest,
                engine_revision,
            )
        )
    ):
        raise ValueError("serialized source manifest is not canonical")
    identity = target_identity.strip()
    source_manifest_digest = canonical_json_digest({
        "schema_version": SOURCE_SNAPSHOT_MANIFEST_SCHEMA_VERSION,
        "target_identity": identity,
        "source_revision": f"snapshot:{source_content_digest}",
        "source_content_digest": source_content_digest,
        "files": files,
        "coverage_identity": {
            "eligible_files": coverage.get("eligible_files"),
            "truncated_files": coverage.get("truncated_files"),
            "failed_files": coverage.get("failed_files"),
            "excluded_files": coverage.get("excluded_files"),
            "excluded_subtrees": coverage.get("excluded_subtrees"),
            "inventory_complete": coverage.get("inventory_complete"),
        },
    })
    analysis_id = "analysis_" + canonical_json_digest({
        "source_manifest_digest": source_manifest_digest,
        "analysis_options_digest": options_digest,
        "engine_revision": engine_revision,
    })
    rebound.update({
        "target_identity": identity,
        "source_revision": f"snapshot:{source_content_digest}",
        "source_snapshot_id": f"src_{source_manifest_digest}",
        "source_manifest_digest": source_manifest_digest,
        "analysis_id": analysis_id,
    })
    rebound.pop("manifest_digest", None)
    rebound["manifest_digest"] = canonical_json_digest(rebound)
    return rebound


def source_snapshot_diagnostics(
    snapshot: SourceSnapshot,
) -> tuple[dict[str, Any], ...]:
    """Return deterministic diagnostics for every incomplete source operation."""

    diagnostics: list[dict[str, Any]] = []
    for document in snapshot.documents:
        if document.decode_status == "reserved_digest_blocked":
            diagnostics.append({
                "code": "reserved_source_digest_abstained",
                "message": (
                    "The file was not parsed or analyzed because its SHA-256 "
                    "matched the explicitly configured reserved-source denylist."
                ),
                "file": document.logical_path,
                "details": {
                    "decode_status": document.decode_status,
                    "content_retained": False,
                },
            })
        elif document.decode_status not in {
            "decoded_exactly",
            "decoded_from_encoding_cookie",
        }:
            diagnostics.append({
                "code": "source_decode_abstained",
                "message": (
                    "The file was not analyzed because its bytes could not be "
                    "decoded exactly under PEP 263."
                ),
                "file": document.logical_path,
                "details": {
                    "decode_status": document.decode_status,
                    "encoding": document.encoding,
                },
            })
        elif document.parse_status != "parsed":
            diagnostics.append({
                "code": "source_parse_abstained",
                "message": (
                    "The file was not analyzed because its exact decoded source "
                    "did not satisfy the bounded Python AST contract."
                ),
                "file": document.logical_path,
                "details": {
                    "parse_status": document.parse_status,
                    "ast_node_count": document.ast_node_count,
                },
            })
    coverage = snapshot.manifest.coverage
    if coverage.truncated_files:
        diagnostics.append({
            "code": "source_scan_truncated_max_files",
            "message": "Eligible Python files were omitted by max_files.",
            "details": {
                "truncated_files": list(coverage.truncated_files),
                "scan_complete": False,
            },
        })
    if coverage.failed_files:
        diagnostics.append({
            "code": "source_scan_incomplete",
            "message": "One or more selected Python files were not analyzable.",
            "details": {
                "failed_files": list(coverage.failed_files),
                "scan_complete": False,
            },
        })
    if not coverage.inventory_complete:
        diagnostics.append({
            "code": "source_inventory_partial",
            "message": (
                "Reserved or excluded subtrees were not enumerated; no "
                "project-global conclusion is permitted."
            ),
            "details": {
                "excluded_subtrees": [
                    dict(item) for item in coverage.excluded_subtrees
                ],
                "project_conclusion_allowed": False,
            },
        })
    return tuple(diagnostics)


def canonical_json_digest(value: Any) -> str:
    encoded = json.dumps(
        _canonical_json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _source_manifest_digest(
    *,
    target_identity: str,
    source_content_digest: str,
    files: tuple[dict[str, Any], ...],
    coverage: SourceCoverage,
) -> str:
    return canonical_json_digest({
        "schema_version": SOURCE_SNAPSHOT_MANIFEST_SCHEMA_VERSION,
        "target_identity": target_identity,
        "source_revision": f"snapshot:{source_content_digest}",
        "source_content_digest": source_content_digest,
        "files": [dict(item) for item in files],
        "coverage_identity": {
            "eligible_files": coverage.eligible_files,
            "truncated_files": list(coverage.truncated_files),
            "failed_files": list(coverage.failed_files),
            "excluded_files": [
                dict(item) for item in coverage.excluded_files
            ],
            "excluded_subtrees": [
                dict(item) for item in coverage.excluded_subtrees
            ],
            "inventory_complete": coverage.inventory_complete,
        },
    })


def belief_engine_revision() -> str:
    """Digest the reviewed first-party modules that define static semantics."""

    package_root = Path(__file__).resolve().parent
    records: list[dict[str, Any]] = []
    for relative in _ENGINE_RELATIVE_PATHS:
        path = package_root.joinpath(*relative.split("/"))
        try:
            data = path.read_bytes()
        except OSError:
            records.append({"path": relative, "status": "unavailable"})
            continue
        records.append({
            "path": relative,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return canonical_json_digest({
        "schema_version": "belief.engine_revision.v1",
        "files": records,
    })


def belief_commit() -> str:
    """Read the local engine Git revision without spawning Git."""

    repository_root = Path(__file__).resolve().parent.parent
    git_root = repository_root / ".git"
    if not git_root.is_dir():
        return "unavailable"
    try:
        head = (git_root / "HEAD").read_text(
            encoding="ascii",
            errors="strict",
        ).strip()
    except (OSError, UnicodeError):
        return "unavailable"
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", head):
        return head.lower()
    if not head.startswith("ref: "):
        return "unavailable"
    reference = head.removeprefix("ref: ").strip()
    if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", reference) or ".." in reference:
        return "unavailable"
    ref_path = git_root.joinpath(*reference.split("/"))
    try:
        value = ref_path.read_text(encoding="ascii", errors="strict").strip()
    except (OSError, UnicodeError):
        value = ""
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        return value.lower()
    try:
        packed = (git_root / "packed-refs").read_text(
            encoding="ascii",
            errors="strict",
        )
    except (OSError, UnicodeError):
        return "unavailable"
    for line in packed.splitlines():
        revision, separator, candidate = line.partition(" ")
        if (
            separator
            and candidate == reference
            and re.fullmatch(r"[0-9a-fA-F]{40,64}", revision)
        ):
            return revision.lower()
    return "unavailable"


def _discover_python_sources(
    target: Path,
) -> tuple[
    list[Path],
    list[Path],
    list[dict[str, Any]],
    list[dict[str, str]],
    bool,
]:
    discovered: list[Path] = []
    eligible: list[Path] = []
    excluded: list[dict[str, Any]] = []
    excluded_subtrees: list[dict[str, str]] = []
    inventory_complete = True
    if target.is_file():
        if target.suffix.casefold() != ".py":
            return discovered, eligible, excluded, excluded_subtrees, True
        discovered.append(target)
        reason = _file_exclusion_reason(target)
        if reason:
            excluded.append(_excluded_file(target.name, reason, None, None))
        else:
            eligible.append(target)
        return discovered, eligible, excluded, excluded_subtrees, True

    for current_raw, dirnames, filenames in os.walk(target, followlinks=False):
        current = Path(current_raw)
        retained_dirs: list[str] = []
        for name in sorted(dirnames, key=str.casefold):
            candidate = current / name
            logical = _logical_path(candidate, target)
            reason = _directory_exclusion_reason(candidate)
            if reason:
                excluded_subtrees.append({
                    "logical_path": logical,
                    "reason": reason,
                    "enumerated": "false",
                })
                inventory_complete = False
            else:
                retained_dirs.append(name)
        dirnames[:] = retained_dirs
        for name in sorted(filenames, key=str.casefold):
            if not name.casefold().endswith(".py"):
                continue
            path = current / name
            logical = _logical_path(path, target)
            discovered.append(path)
            reason = _file_exclusion_reason(path)
            if reason:
                excluded.append(_excluded_file(logical, reason, None, None))
            else:
                eligible.append(path)
    discovered.sort(key=lambda path: _logical_path(path, target))
    eligible.sort(key=lambda path: _logical_path(path, target))
    excluded_subtrees.sort(key=lambda item: item["logical_path"])
    return discovered, eligible, excluded, excluded_subtrees, inventory_complete


def _read_document_once(
    path: Path,
    *,
    logical_path: str,
    max_file_bytes: int,
    max_ast_nodes: int,
    denied_source_sha256: frozenset[str],
) -> SourceDocument:
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            data = handle.read(max_file_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=b"",
            decoded_source=None,
            sha256=hashlib.sha256(b"").hexdigest(),
            size=0,
            encoding="",
            decode_status="unreadable",
            parse_status="not_parsed",
            diagnostic="source file could not be read",
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest in denied_source_sha256:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=b"",
            decoded_source=None,
            sha256=digest,
            size=len(data),
            encoding="",
            decode_status="reserved_digest_blocked",
            parse_status="not_parsed",
            diagnostic=(
                "source bytes matched the configured reserved-source digest"
            ),
        )
    if len(data) > max_file_bytes:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=data[:max_file_bytes],
            decoded_source=None,
            sha256=digest,
            size=len(data),
            encoding="",
            decode_status="file_too_large",
            parse_status="not_parsed",
            diagnostic="source file exceeded the byte bound while being read",
        )
    stable = (
        before.st_size == after.st_size == len(data)
        and getattr(before, "st_mtime_ns", None)
        == getattr(after, "st_mtime_ns", None)
        and getattr(before, "st_ino", None) == getattr(after, "st_ino", None)
    )
    if not stable:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=data,
            decoded_source=None,
            sha256=digest,
            size=len(data),
            encoding="",
            decode_status="unstable_during_read",
            parse_status="not_parsed",
            diagnostic="source file changed while its snapshot was captured",
        )
    source, encoding, decode_status, diagnostic = _decode_python_source(data)
    if source is None:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=data,
            decoded_source=None,
            sha256=digest,
            size=len(data),
            encoding=encoding,
            decode_status=decode_status,
            parse_status="not_parsed",
            diagnostic=diagnostic,
        )
    try:
        tree = ast.parse(source, filename=logical_path)
    except (SyntaxError, ValueError):
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=data,
            decoded_source=source,
            sha256=digest,
            size=len(data),
            encoding=encoding,
            decode_status=decode_status,
            parse_status="syntax_error",
            diagnostic="exact source is not valid Python syntax",
        )
    node_count = sum(1 for _ in ast.walk(tree))
    if node_count > max_ast_nodes:
        return SourceDocument(
            logical_path=logical_path,
            disk_path=path,
            content_bytes=data,
            decoded_source=source,
            sha256=digest,
            size=len(data),
            encoding=encoding,
            decode_status=decode_status,
            parse_status="ast_node_limit_exceeded",
            ast_node_count=node_count,
            diagnostic="source AST exceeded the reviewed node bound",
        )
    return SourceDocument(
        logical_path=logical_path,
        disk_path=path,
        content_bytes=data,
        decoded_source=source,
        sha256=digest,
        size=len(data),
        encoding=encoding,
        decode_status=decode_status,
        parse_status="parsed",
        ast_node_count=node_count,
        parsed_ast=tree,
    )


def _decode_python_source(
    data: bytes,
) -> tuple[str | None, str, str, str]:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    except (LookupError, SyntaxError, UnicodeError):
        return None, "", "invalid_encoding", "PEP 263 encoding declaration is invalid"
    try:
        source = data.decode(encoding, errors="strict")
    except (LookupError, UnicodeDecodeError, UnicodeError):
        return None, encoding, "invalid_encoding", "source bytes do not decode exactly"
    first_two = data.splitlines(keepends=True)[:2]
    has_cookie = any(_ENCODING_COOKIE.match(line) for line in first_two)
    status = (
        "decoded_from_encoding_cookie"
        if has_cookie or encoding.casefold().replace("_", "-") == "utf-8-sig"
        else "decoded_exactly"
    )
    return source, encoding, status, ""


def _directory_exclusion_reason(path: Path) -> str:
    if _is_link_or_junction(path):
        return "link_or_junction_subtree"
    name = path.name.casefold()
    if name in _SENSITIVE_UNENUMERATED_DIRS:
        return "reserved_holdout_subtree"
    if name in DEFAULT_EXCLUDE_DIRS:
        return "excluded_directory_name"
    if name.endswith(".egg-info") or name.endswith("_adapted"):
        return "excluded_directory_class"
    return ""


def _file_exclusion_reason(path: Path) -> str:
    if _is_link_or_junction(path):
        return "link_or_junction_file"
    name = path.name.casefold()
    if any(name.endswith(suffix) for suffix in GENERATED_FILE_NAMES):
        return "generated_filename"
    if name.endswith("_generated.py") or name.endswith(".generated.py"):
        return "generated_filename"
    return ""


def _is_link_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        predicate = getattr(path, "is_junction", None)
        return bool(predicate()) if callable(predicate) else False
    except OSError:
        return True


def _excluded_file(
    logical_path: str,
    reason: str,
    size: int | None,
    sha256: str | None,
) -> dict[str, Any]:
    return {
        "logical_path": logical_path.replace("\\", "/"),
        "reason": reason,
        "size": size,
        "sha256": sha256,
        "content_read": sha256 is not None,
    }


def _logical_path(path: Path, target: Path) -> str:
    if target.is_file():
        return target.name
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.name


def _normalized_absolute_path(path: Path) -> str:
    return os.path.normcase(str(path)).replace("\\", "/")


def _canonical_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("non-finite value is not canonical JSON")
        return value
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(
            (_canonical_json_value(item) for item in value),
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )
    raise TypeError(f"value is not canonical JSON: {type(value).__name__}")


def _validated_sha256_set(values: frozenset[str]) -> frozenset[str]:
    if not isinstance(values, frozenset):
        raise ValueError("denied_source_sha256 must be a frozenset")
    for value in values:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(
                "denied_source_sha256 entries must be lowercase SHA-256 values"
            )
    return values


__all__ = [
    "DEFAULT_MAX_AST_NODES",
    "DEFAULT_MAX_FILE_BYTES",
    "DEFAULT_MAX_TOTAL_SOURCE_BYTES",
    "SOURCE_COVERAGE_SCHEMA_VERSION",
    "SOURCE_DOCUMENT_SCHEMA_VERSION",
    "SOURCE_SNAPSHOT_MANIFEST_SCHEMA_VERSION",
    "SourceCoverage",
    "SourceDocument",
    "SourceSnapshot",
    "SourceSnapshotManifest",
    "belief_commit",
    "belief_engine_revision",
    "build_source_snapshot",
    "canonical_json_digest",
    "rebind_snapshot_target",
    "rebind_source_manifest_payload",
    "source_snapshot_diagnostics",
]
