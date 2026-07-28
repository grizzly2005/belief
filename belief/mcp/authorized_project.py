"""Closed, static-only pilot adapter for one authorized real project.

The MCP-facing tool never accepts a path, module, callable, source string, or
adapter implementation. The configured MCP workspace is verified against one
hard-coded revision and one canonical source inventory before and after static
analysis. Dynamic target execution remains unavailable and every projected
result abstains.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belief.static_analysis_pipeline import (
    STATIC_ANALYSIS_CATEGORIES,
    StaticAnalysisOptions,
    analyze_static_target,
)
from belief.validation.plan_models import ValidationPlan, canonical_digest
from belief.validation.plans import build_validation_plan

AUTHORIZED_PROJECT_BINDING_SCHEMA_VERSION = (
    "belief.authorized_project_binding.v1"
)
AUTHORIZED_PROJECT_PREPARATION_SCHEMA_VERSION = (
    "belief.authorized_project_preparation.v1"
)
AUTHORIZED_PROJECT_RESULT_SCHEMA_VERSION = (
    "belief.authorized_project_abstention.v1"
)
AUTHORIZED_PROJECT_SOURCE_INVENTORY_SCHEMA_VERSION = (
    "belief.authorized_project_source_inventory.v1"
)
AUTHORIZED_PROJECT_EXECUTION_SCOPE = "authorized_real_project_static_only"
AUTHORIZED_PROJECT_BINDING_CREATOR = (
    "belief_prepare_authorized_project_pilot"
)

FLASKJWT_PILOT_ADAPTER_ID = "flask_jwt_extended_authorized_pilot_v1"
FLASKJWT_PILOT_PROJECT_ID = "github.com/vimalloc/flask-jwt-extended"
FLASKJWT_PILOT_SOURCE_REVISION = "1910726f152016c3e48d61792983eebe11f54ac2"
FLASKJWT_PILOT_SOURCE_DIGEST = (
    "4e42c82b7d0a210350cc99fcc698e478f1b62b76785a413d40525b0555b70c52"
)
FLASKJWT_PILOT_SOURCE_FILE_COUNT = 79
FLASKJWT_PILOT_SOURCE_TOTAL_BYTES = 300_343

FLASKJWT_PILOT_AUTHORIZED_ENV = "BELIEF_MCP_FLASKJWT_PILOT_AUTHORIZED"
FLASKJWT_PILOT_AUTHORIZATION_ID_ENV = (
    "BELIEF_MCP_FLASKJWT_PILOT_AUTHORIZATION_ID"
)

_AUTHORIZATION_ID = re.compile(r"^auth_[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GIT_REF = re.compile(r"^refs/heads/[A-Za-z0-9._/-]+$")
_MAX_SOURCE_FILES = 512
_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_GIT_METADATA_BYTES = 1024 * 1024
_ABSTENTION_REASON = (
    "Dynamic execution of the authorized real project is intentionally "
    "unavailable in this static-only pilot adapter."
)


class AuthorizedProjectError(ValueError):
    """An authorization, identity, or exact-source invariant failed."""


@dataclass(frozen=True)
class AuthorizedProjectGrant:
    """Separate local-operator grant bound to the one built-in pilot."""

    authorization_id: str
    adapter_id: str = FLASKJWT_PILOT_ADAPTER_ID
    project_id: str = FLASKJWT_PILOT_PROJECT_ID
    source_revision: str = FLASKJWT_PILOT_SOURCE_REVISION
    source_digest: str = FLASKJWT_PILOT_SOURCE_DIGEST
    authorization_scope: str = AUTHORIZED_PROJECT_EXECUTION_SCOPE
    granted_by: str = "local_operator"

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "adapter_id": self.adapter_id,
            "project_id": self.project_id,
            "source_revision": self.source_revision,
            "source_digest": self.source_digest,
            "authorization_scope": self.authorization_scope,
            "granted_by": self.granted_by,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


@dataclass(frozen=True)
class AuthorizedProjectAttestation:
    """Exact immutable identity observed for the configured workspace."""

    adapter_id: str
    project_id: str
    source_revision: str
    source_digest: str
    source_file_count: int
    source_total_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "project_id": self.project_id,
            "source_revision": self.source_revision,
            "source_digest": self.source_digest,
            "source_file_count": self.source_file_count,
            "source_total_bytes": self.source_total_bytes,
        }


@dataclass(frozen=True)
class PreparedAuthorizedProject:
    """Static analysis artifacts for the exact authorized source snapshot."""

    attestation: AuthorizedProjectAttestation
    analysis_snapshot: dict[str, Any]
    plans: tuple[ValidationPlan, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class AuthorizedProjectBinding:
    """Non-executable binding between one static plan and exact real source."""

    run_id: str
    audit_case_id: str
    validation_plan_id: str
    validation_plan_digest: str
    authorization_id: str
    authorization_grant_digest: str
    adapter_id: str = FLASKJWT_PILOT_ADAPTER_ID
    project_id: str = FLASKJWT_PILOT_PROJECT_ID
    source_revision: str = FLASKJWT_PILOT_SOURCE_REVISION
    source_digest: str = FLASKJWT_PILOT_SOURCE_DIGEST
    source_file_count: int = FLASKJWT_PILOT_SOURCE_FILE_COUNT
    source_total_bytes: int = FLASKJWT_PILOT_SOURCE_TOTAL_BYTES
    binding_kind: str = AUTHORIZED_PROJECT_BINDING_SCHEMA_VERSION
    created_by: str = AUTHORIZED_PROJECT_BINDING_CREATOR
    execution_scope: str = AUTHORIZED_PROJECT_EXECUTION_SCOPE
    dynamic_execution_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_kind": self.binding_kind,
            "adapter_id": self.adapter_id,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "audit_case_id": self.audit_case_id,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "source_revision": self.source_revision,
            "source_digest": self.source_digest,
            "source_file_count": self.source_file_count,
            "source_total_bytes": self.source_total_bytes,
            "authorization_id": self.authorization_id,
            "authorization_grant_digest": self.authorization_grant_digest,
            "created_by": self.created_by,
            "execution_scope": self.execution_scope,
            "dynamic_execution_authorized": self.dynamic_execution_authorized,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


def make_authorized_project_grant(
    authorization_id: str,
) -> AuthorizedProjectGrant:
    """Create the only supported grant without accepting target dispatch data."""

    normalized = _authorization_id(authorization_id)
    return AuthorizedProjectGrant(
        authorization_id=normalized,
        adapter_id=FLASKJWT_PILOT_ADAPTER_ID,
        project_id=FLASKJWT_PILOT_PROJECT_ID,
        source_revision=FLASKJWT_PILOT_SOURCE_REVISION,
        source_digest=FLASKJWT_PILOT_SOURCE_DIGEST,
        authorization_scope=AUTHORIZED_PROJECT_EXECUTION_SCOPE,
        granted_by="local_operator",
    )


def authorized_project_grant_from_environment(
    environment: Mapping[str, str],
) -> AuthorizedProjectGrant | None:
    """Load an explicit startup grant from two project-specific variables."""

    enabled = environment.get(FLASKJWT_PILOT_AUTHORIZED_ENV)
    identifier = environment.get(FLASKJWT_PILOT_AUTHORIZATION_ID_ENV)
    if enabled is None and identifier is None:
        return None
    if enabled != "true":
        raise AuthorizedProjectError(
            f"{FLASKJWT_PILOT_AUTHORIZED_ENV} must be exactly true"
        )
    if identifier is None:
        raise AuthorizedProjectError(
            f"{FLASKJWT_PILOT_AUTHORIZATION_ID_ENV} is required"
        )
    return make_authorized_project_grant(identifier)


def validate_authorized_project_request(
    grant: AuthorizedProjectGrant | None,
    *,
    adapter_id: object,
    authorization_id: object,
    source_revision: object,
    source_digest: object,
) -> AuthorizedProjectGrant:
    """Verify explicit request fields and the independent startup grant."""

    if adapter_id != FLASKJWT_PILOT_ADAPTER_ID:
        raise AuthorizedProjectError("authorized project adapter_id is not supported")
    if source_revision != FLASKJWT_PILOT_SOURCE_REVISION:
        raise AuthorizedProjectError("authorized project source revision does not match")
    if source_digest != FLASKJWT_PILOT_SOURCE_DIGEST:
        raise AuthorizedProjectError("authorized project source digest does not match")
    normalized_authorization = _authorization_id(authorization_id)
    if grant is None:
        raise AuthorizedProjectError(
            "separate local-operator authorization is not configured"
        )
    expected = make_authorized_project_grant(normalized_authorization)
    if grant.to_dict() != expected.to_dict():
        raise AuthorizedProjectError(
            "authorization does not match this adapter, revision, and source digest"
        )
    return grant


def prepare_authorized_project(
    workspace_root: Path,
    grant: AuthorizedProjectGrant,
) -> PreparedAuthorizedProject:
    """Statically scan only the exact configured and separately granted source."""

    expected_grant = make_authorized_project_grant(grant.authorization_id)
    if grant.to_dict() != expected_grant.to_dict():
        raise AuthorizedProjectError("authorization grant is not canonical")

    before = _attest_workspace(workspace_root)
    result = analyze_static_target(
        workspace_root,
        StaticAnalysisOptions(
            max_files=200,
            selected_categories=frozenset(STATIC_ANALYSIS_CATEGORIES),
            audit_mode=True,
            include_routes=True,
            reportability=True,
            dedup_audit_cases=True,
        ),
    )
    after = _attest_workspace(workspace_root)
    if after != before:
        raise AuthorizedProjectError(
            "authorized project changed during static analysis"
        )

    snapshot = result.to_dict()
    snapshot["target"] = (
        f"authorized-project:{before.project_id}@{before.source_revision}"
    )
    snapshot["mcp_origin"] = "authorized_project_pilot"
    snapshot["authorized_project_adapter_id"] = before.adapter_id
    snapshot["authorized_project_id"] = before.project_id
    snapshot["source_revision"] = before.source_revision
    snapshot["source_digest"] = before.source_digest
    snapshot["source_file_count"] = before.source_file_count
    snapshot["source_total_bytes"] = before.source_total_bytes
    rows = snapshot.get("audit_cases")
    plans = tuple(
        sorted(
            (
                build_validation_plan(row)
                for row in rows
                if isinstance(row, Mapping)
            ),
            key=lambda plan: plan.plan_id,
        )
        if isinstance(rows, list)
        else ()
    )
    limitations = (
        "Only the exact pinned flask-jwt-extended source snapshot was read.",
        "The target was statically analyzed but never imported or executed.",
        _ABSTENTION_REASON,
        "Static candidate evidence does not confirm a vulnerability.",
        "Independent human confirmation remains required before reporting.",
    )
    return PreparedAuthorizedProject(
        attestation=before,
        analysis_snapshot=copy.deepcopy(snapshot),
        plans=plans,
        limitations=limitations,
    )


def build_authorized_project_binding(
    prepared: PreparedAuthorizedProject,
    *,
    run_id: str,
    plan: ValidationPlan,
    grant: AuthorizedProjectGrant,
) -> AuthorizedProjectBinding:
    """Bind one static plan to the exact attestation and separate grant."""

    if plan.plan_id not in {item.plan_id for item in prepared.plans}:
        raise AuthorizedProjectError("validation plan is not part of this preparation")
    attestation = prepared.attestation
    expected_attestation = _expected_attestation()
    if attestation != expected_attestation:
        raise AuthorizedProjectError("authorized project attestation is not canonical")
    canonical_grant = make_authorized_project_grant(grant.authorization_id)
    if grant.to_dict() != canonical_grant.to_dict():
        raise AuthorizedProjectError("authorization grant is not canonical")
    return AuthorizedProjectBinding(
        run_id=run_id,
        audit_case_id=plan.subject_id,
        validation_plan_id=plan.plan_id,
        validation_plan_digest=canonical_digest(plan.to_dict()),
        authorization_id=grant.authorization_id,
        authorization_grant_digest=grant.digest,
        adapter_id=attestation.adapter_id,
        project_id=attestation.project_id,
        source_revision=attestation.source_revision,
        source_digest=attestation.source_digest,
        source_file_count=attestation.source_file_count,
        source_total_bytes=attestation.source_total_bytes,
    )


def project_authorized_project_abstention(
    *,
    run_id: str,
    plan: ValidationPlan,
    binding: AuthorizedProjectBinding,
) -> dict[str, Any]:
    """Return a deterministic, non-reportable abstention for one bound plan."""

    unsigned = {
        "schema_version": AUTHORIZED_PROJECT_RESULT_SCHEMA_VERSION,
        "run_id": run_id,
        "case_id": plan.subject_id,
        "case_type": plan.case_type,
        "plan_id": plan.plan_id,
        "validation_plan_digest": canonical_digest(plan.to_dict()),
        "adapter_id": binding.adapter_id,
        "project_id": binding.project_id,
        "binding_digest": binding.digest,
        "source_revision": binding.source_revision,
        "source_digest": binding.source_digest,
        "outcome": "inconclusive",
        "maturity": "statically_supported",
        "execution_status": "abstained",
        "abstention_reason": _ABSTENTION_REASON,
        "evidence_scope": AUTHORIZED_PROJECT_EXECUTION_SCOPE,
        "target_vulnerability_confirmed": False,
        "human_confirmation_required": True,
        "human_confirmed": False,
        "report_ready": False,
        "confirmed_vulnerability": False,
        "boundaries": {
            "target_executed": False,
            "target_imported": False,
            "target_files_written": False,
            "network_used": False,
            "subprocess_used": False,
            "shell_used": False,
            "arbitrary_path_accepted": False,
            "arbitrary_module_accepted": False,
            "arbitrary_callable_accepted": False,
            "dynamic_execution_authorized": False,
        },
    }
    return {
        "result_id": "apr_" + canonical_digest(unsigned)[:24],
        **unsigned,
    }


def _attest_workspace(workspace_root: Path) -> AuthorizedProjectAttestation:
    try:
        root = workspace_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise AuthorizedProjectError(
            "authorized project workspace is unavailable"
        ) from exc
    if not root.is_dir() or root.is_symlink() or _is_junction(root):
        raise AuthorizedProjectError(
            "authorized project workspace must be a real directory"
        )
    revision = _read_git_revision(root)
    source_file_count, source_total_bytes, source_digest = _source_inventory(root)
    observed = AuthorizedProjectAttestation(
        adapter_id=FLASKJWT_PILOT_ADAPTER_ID,
        project_id=FLASKJWT_PILOT_PROJECT_ID,
        source_revision=revision,
        source_digest=source_digest,
        source_file_count=source_file_count,
        source_total_bytes=source_total_bytes,
    )
    expected = _expected_attestation()
    if observed != expected:
        raise AuthorizedProjectError(
            "workspace does not match the exact authorized revision and source inventory"
        )
    return observed


def _expected_attestation() -> AuthorizedProjectAttestation:
    return AuthorizedProjectAttestation(
        adapter_id=FLASKJWT_PILOT_ADAPTER_ID,
        project_id=FLASKJWT_PILOT_PROJECT_ID,
        source_revision=FLASKJWT_PILOT_SOURCE_REVISION,
        source_digest=FLASKJWT_PILOT_SOURCE_DIGEST,
        source_file_count=FLASKJWT_PILOT_SOURCE_FILE_COUNT,
        source_total_bytes=FLASKJWT_PILOT_SOURCE_TOTAL_BYTES,
    )


def _source_inventory(root: Path) -> tuple[int, int, str]:
    records: list[dict[str, Any]] = []
    total_bytes = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(
                directory.iterdir(),
                key=lambda item: item.name.casefold(),
                reverse=True,
            )
        except OSError as exc:
            raise AuthorizedProjectError(
                "authorized project source inventory is unreadable"
            ) from exc
        for path in entries:
            relative = path.relative_to(root)
            if relative.parts[0] == ".git":
                if len(relative.parts) != 1:
                    raise AuthorizedProjectError(
                        "nested .git content is not allowed in the source inventory"
                    )
                continue
            if path.is_symlink() or _is_junction(path):
                raise AuthorizedProjectError(
                    "authorized project source cannot contain links or junctions"
                )
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise AuthorizedProjectError(
                    "authorized project source escapes its workspace"
                ) from exc
            if resolved.is_dir():
                stack.append(resolved)
                continue
            if not resolved.is_file():
                raise AuthorizedProjectError(
                    "authorized project source contains a special filesystem entry"
                )
            try:
                size = resolved.stat().st_size
            except OSError as exc:
                raise AuthorizedProjectError(
                    "authorized project source metadata is unreadable"
                ) from exc
            if size > _MAX_SOURCE_FILE_BYTES:
                raise AuthorizedProjectError(
                    "authorized project source file exceeds the reviewed bound"
                )
            total_bytes += size
            if total_bytes > _MAX_SOURCE_TOTAL_BYTES:
                raise AuthorizedProjectError(
                    "authorized project source exceeds the reviewed byte bound"
                )
            try:
                data = resolved.read_bytes()
            except OSError as exc:
                raise AuthorizedProjectError(
                    "authorized project source file is unreadable"
                ) from exc
            if len(data) != size:
                raise AuthorizedProjectError(
                    "authorized project source changed while being read"
                )
            records.append(
                {
                    "path": relative.as_posix(),
                    "size": size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            if len(records) > _MAX_SOURCE_FILES:
                raise AuthorizedProjectError(
                    "authorized project source exceeds the reviewed file bound"
                )
    records.sort(key=lambda row: row["path"])
    digest = canonical_digest(
        {
            "schema_version": (
                AUTHORIZED_PROJECT_SOURCE_INVENTORY_SCHEMA_VERSION
            ),
            "files": records,
        }
    )
    return len(records), total_bytes, digest


def _read_git_revision(root: Path) -> str:
    git_directory = root / ".git"
    if (
        not git_directory.is_dir()
        or git_directory.is_symlink()
        or _is_junction(git_directory)
    ):
        raise AuthorizedProjectError(
            "authorized project requires an in-place .git directory"
        )
    try:
        resolved_git = git_directory.resolve(strict=True)
        resolved_git.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AuthorizedProjectError(
            "authorized project Git metadata escapes its workspace"
        ) from exc

    head = _read_small_git_text(
        resolved_git / "HEAD",
        git_root=resolved_git,
        context="Git HEAD",
    ).strip()
    if _GIT_REVISION.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        raise AuthorizedProjectError("authorized project Git HEAD is invalid")
    reference = head.removeprefix("ref: ")
    if (
        not _GIT_REF.fullmatch(reference)
        or ".." in reference
        or reference.endswith("/")
    ):
        raise AuthorizedProjectError("authorized project Git ref is invalid")
    ref_path = resolved_git.joinpath(*reference.split("/"))
    if ref_path.is_file() and not ref_path.is_symlink() and not _is_junction(ref_path):
        revision = _read_small_git_text(
            ref_path,
            git_root=resolved_git,
            context="Git ref",
        ).strip()
        return _validated_revision(revision)

    packed_refs = resolved_git / "packed-refs"
    text = _read_small_git_text(
        packed_refs,
        git_root=resolved_git,
        context="packed Git refs",
    )
    for line in text.splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        revision, separator, candidate_ref = line.partition(" ")
        if separator and candidate_ref == reference:
            return _validated_revision(revision)
    raise AuthorizedProjectError("authorized project Git ref cannot be resolved")


def _read_small_git_text(
    path: Path,
    *,
    git_root: Path,
    context: str,
) -> str:
    if not path.is_file() or path.is_symlink() or _is_junction(path):
        raise AuthorizedProjectError(f"{context} is unavailable")
    try:
        resolved_root = os.path.normcase(os.path.realpath(git_root))
        resolved_path = os.path.normcase(os.path.realpath(path))
        common_path = os.path.commonpath([resolved_root, resolved_path])
        if common_path != resolved_root:
            raise AuthorizedProjectError(f"{context} escapes the Git directory")
        safe_path = Path(resolved_path)
        if safe_path.stat().st_size > _MAX_GIT_METADATA_BYTES:
            raise AuthorizedProjectError(f"{context} exceeds the reviewed bound")
        return safe_path.read_text(encoding="ascii", errors="strict")
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise AuthorizedProjectError(f"{context} is unreadable") from exc


def _validated_revision(value: str) -> str:
    if not _GIT_REVISION.fullmatch(value):
        raise AuthorizedProjectError("authorized project Git revision is invalid")
    return value


def _authorization_id(value: object) -> str:
    if not isinstance(value, str) or not _AUTHORIZATION_ID.fullmatch(value):
        raise AuthorizedProjectError(
            "authorization_id must be auth_ followed by 64 lowercase hex characters"
        )
    return value


def _is_junction(path: Path) -> bool:
    predicate = getattr(path, "is_junction", None)
    return bool(predicate()) if predicate is not None else False


__all__ = [
    "AUTHORIZED_PROJECT_BINDING_SCHEMA_VERSION",
    "AUTHORIZED_PROJECT_EXECUTION_SCOPE",
    "AUTHORIZED_PROJECT_PREPARATION_SCHEMA_VERSION",
    "AUTHORIZED_PROJECT_RESULT_SCHEMA_VERSION",
    "AuthorizedProjectBinding",
    "AuthorizedProjectError",
    "AuthorizedProjectGrant",
    "FLASKJWT_PILOT_ADAPTER_ID",
    "FLASKJWT_PILOT_PROJECT_ID",
    "FLASKJWT_PILOT_SOURCE_DIGEST",
    "FLASKJWT_PILOT_SOURCE_REVISION",
    "authorized_project_grant_from_environment",
    "build_authorized_project_binding",
    "make_authorized_project_grant",
    "prepare_authorized_project",
    "project_authorized_project_abstention",
    "validate_authorized_project_request",
]
