"""Deterministic preregistration for the transparent web benchmark.

The development corpus is public and contains source plus labels. Reserved
families are represented only by opaque case IDs and cryptographic digests in
the committed preregistration. This module does not execute either cohort.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from textwrap import dedent
from typing import Any


WEB_VALIDATION_BENCHMARK_ID = "belief-web-validation-generalization-v1"
WEB_VALIDATION_GENERATOR_VERSION = "belief.web_validation_generator.v1"
WEB_VALIDATION_PREREGISTRATION_SCHEMA_VERSION = (
    "belief.web_validation_preregistration.v1"
)
WEB_VALIDATION_CORPUS_SCHEMA_VERSION = "belief.web_validation_corpus.v1"
WEB_VALIDATION_SPLIT_SEED = "belief-web-validation-family-split-2026-07-29"

WEB_VALIDATION_THRESHOLDS: Mapping[str, float] = {
    "maximum_abstention_rate": 0.25,
    "maximum_functional_regression_rate": 0.0,
    "maximum_protected_regression_rate": 0.0,
    "maximum_worker_timeout_or_crash_rate": 0.0,
    "minimum_baseline_evaluability_rate": 0.90,
    "minimum_evidence_gap_resolution_rate": 0.70,
    "minimum_executable_plan_coverage": 0.75,
    "minimum_oracle_evaluability_rate": 0.85,
    "minimum_semantic_digest_stability_rate": 1.0,
    "minimum_static_precision": 0.70,
    "minimum_static_recall": 0.70,
    "minimum_windows_linux_outcome_agreement_rate": 0.95,
}

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_VARIANTS = ("vulnerable", "protected", "ambiguous", "trap")
_GROUND_TRUTH = {
    "ambiguous": "ambiguous",
    "protected": "safe",
    "trap": "safe",
    "vulnerable": "vulnerable",
}
_EXPECTED_OUTCOME = {
    "ambiguous": "inconclusive",
    "protected": "enforced",
    "trap": "enforced",
    "vulnerable": "bypassed",
}


@dataclass(frozen=True)
class WebTemplateFamily:
    """One application shape; all four variants stay in the same split."""

    family_id: str
    framework: str
    case_type: str
    route_style: str
    indirection: str
    resource_backend: str
    vulnerable_pattern: str

    @property
    def stratum(self) -> tuple[str, str]:
        return self.framework, self.case_type


_FAMILIES = (
    WebTemplateFamily(
        "flask_idor_decorator_dictionary",
        "flask",
        "idor_bola_possible",
        "sync",
        "decorator",
        "dictionary",
        "wrong_resource_guard",
    ),
    WebTemplateFamily(
        "flask_idor_direct_dictionary",
        "flask",
        "idor_bola_possible",
        "sync",
        "direct",
        "dictionary",
        "authentication_only",
    ),
    WebTemplateFamily(
        "flask_idor_helper_model",
        "flask",
        "idor_bola_possible",
        "sync",
        "helper",
        "model",
        "owner_only",
    ),
    WebTemplateFamily(
        "flask_path_decorator_dictionary",
        "flask",
        "path_traversal_possible",
        "sync",
        "decorator",
        "dictionary",
        "guard_after_sink",
    ),
    WebTemplateFamily(
        "flask_path_direct_dictionary",
        "flask",
        "path_traversal_possible",
        "sync",
        "direct",
        "dictionary",
        "unchecked_join",
    ),
    WebTemplateFamily(
        "flask_path_helper_model",
        "flask",
        "path_traversal_possible",
        "sync",
        "helper",
        "model",
        "sanitizer_result_ignored",
    ),
    WebTemplateFamily(
        "fastapi_idor_dependency_model",
        "fastapi",
        "idor_bola_possible",
        "async",
        "dependency",
        "model",
        "authentication_only",
    ),
    WebTemplateFamily(
        "fastapi_idor_direct_model",
        "fastapi",
        "idor_bola_possible",
        "async",
        "direct",
        "model",
        "tenant_only",
    ),
    WebTemplateFamily(
        "fastapi_idor_helper_dictionary",
        "fastapi",
        "idor_bola_possible",
        "async",
        "helper",
        "dictionary",
        "guard_after_sink",
    ),
    WebTemplateFamily(
        "fastapi_path_dependency_model",
        "fastapi",
        "path_traversal_possible",
        "async",
        "dependency",
        "model",
        "sanitizer_result_ignored",
    ),
    WebTemplateFamily(
        "fastapi_path_direct_model",
        "fastapi",
        "path_traversal_possible",
        "async",
        "direct",
        "model",
        "guard_after_sink",
    ),
    WebTemplateFamily(
        "fastapi_path_helper_dictionary",
        "fastapi",
        "path_traversal_possible",
        "async",
        "helper",
        "dictionary",
        "unchecked_join",
    ),
)


def build_web_validation_preregistration(
    starting_commit: str,
) -> dict[str, Any]:
    """Build the complete split seal without returning reserved source."""

    _validate_commit(starting_commit)
    cases = _build_cases()
    development_families, reserved_families = _split_families()
    development = tuple(
        case
        for case in cases
        if case["metadata"]["family_id"] in development_families
    )
    reserved = tuple(
        case
        for case in cases
        if case["metadata"]["family_id"] in reserved_families
    )
    payload: dict[str, Any] = {
        "schema_version": WEB_VALIDATION_PREREGISTRATION_SCHEMA_VERSION,
        "benchmark_id": WEB_VALIDATION_BENCHMARK_ID,
        "generator_version": WEB_VALIDATION_GENERATOR_VERSION,
        "status": "development_open_reserved_sealed",
        "starting_commit": starting_commit,
        "corpus": {
            "case_count": len(cases),
            "family_count": len(_FAMILIES),
            "dataset_sha256": _case_digest(cases),
            "source_sha256": _source_digest(cases),
            "development_case_count": len(development),
            "development_family_count": len(development_families),
            "development_case_ids": [
                case["metadata"]["case_id"] for case in development
            ],
            "development_family_ids": list(development_families),
            "development_dataset_sha256": _case_digest(development),
            "development_source_sha256": _source_digest(development),
            "reserved_case_count": len(reserved),
            "reserved_family_count": len(reserved_families),
            "reserved_case_ids": [
                case["metadata"]["case_id"] for case in reserved
            ],
            "reserved_family_ids": list(reserved_families),
            "reserved_dataset_sha256": _case_digest(reserved),
            "reserved_source_sha256": _source_digest(reserved),
        },
        "split": {
            "algorithm": "sha256_stratified_template_family_v1",
            "seed": WEB_VALIDATION_SPLIT_SEED,
            "unit": "application_template_family",
            "strata": ["framework", "case_type"],
            "families_per_stratum": 3,
            "development_families_per_stratum": 2,
            "reserved_families_per_stratum": 1,
            "outcomes_used_for_allocation": False,
        },
        "thresholds": dict(WEB_VALIDATION_THRESHOLDS),
        "permitted_tuning_inputs": [
            "development_source",
            "development_ground_truth",
            "development_static_findings",
            "development_validation_plans",
            "development_validation_results",
            "development_aggregate_metrics",
            "synthetic_metamorphic_mutations",
        ],
        "forbidden_reserved_inputs": [
            "reserved_source",
            "reserved_ground_truth",
            "reserved_static_findings",
            "reserved_validation_plans",
            "reserved_validation_results",
            "reserved_per_case_metrics",
        ],
        "boundaries": {
            "artifacts_create_only": True,
            "external_project_code_used": False,
            "network_required": False,
            "subprocess_required": False,
            "docker_required": False,
            "susvibes_artifacts_used": False,
            "susvibes_holdout_opened": False,
            "reserved_source_committed": False,
            "reserved_outcomes_committed": False,
            "secpass_equivalent": False,
            "leaderboard_comparable": False,
        },
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    return payload


def build_web_validation_development_manifest(
    starting_commit: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Return the public development manifest and its source documents."""

    preregistration = build_web_validation_preregistration(starting_commit)
    development_ids = set(
        preregistration["corpus"]["development_case_ids"]
    )
    selected = tuple(
        case
        for case in _build_cases()
        if case["metadata"]["case_id"] in development_ids
    )
    records = []
    for case in selected:
        record = dict(case["metadata"])
        logical_source = str(record.pop("logical_source_name"))
        record["source_path"] = f"development/{logical_source}"
        records.append(record)
    manifest: dict[str, Any] = {
        "schema_version": WEB_VALIDATION_CORPUS_SCHEMA_VERSION,
        "benchmark_id": WEB_VALIDATION_BENCHMARK_ID,
        "cohort": "development",
        "starting_commit": starting_commit,
        "preregistration_digest": preregistration[
            "deterministic_digest"
        ],
        "case_count": len(records),
        "family_count": len(
            {record["family_id"] for record in records}
        ),
        "dataset_sha256": _metadata_digest(records),
        "source_sha256": _source_digest(selected),
        "cases": records,
    }
    manifest["deterministic_digest"] = _semantic_digest(manifest)
    sources = {
        (
            "development/"
            + str(case["metadata"]["logical_source_name"])
        ): str(case["source"])
        for case in selected
    }
    return manifest, sources


def write_web_validation_development_corpus(
    output: str | Path,
    *,
    starting_commit: str,
) -> dict[str, Any]:
    """Create the preregistration and public corpus without overwrite."""

    root = Path(output).resolve()
    if root.exists():
        raise ValueError(
            f"refusing to overwrite web validation corpus: {root}"
        )
    preregistration = build_web_validation_preregistration(
        starting_commit
    )
    manifest, sources = build_web_validation_development_manifest(
        starting_commit
    )
    files = _artifact_files(preregistration, manifest, sources)
    root.mkdir(parents=True)
    for relative, content in files.items():
        destination = _safe_destination(root, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
    return {
        "root": str(root),
        "case_count": manifest["case_count"],
        "family_count": manifest["family_count"],
        "preregistration_digest": preregistration[
            "deterministic_digest"
        ],
        "development_digest": manifest["deterministic_digest"],
    }


def verify_web_validation_development_corpus(
    root: str | Path,
) -> dict[str, Any]:
    """Regenerate the public cohort in memory and reject any drift."""

    selected = Path(root).resolve()
    preregistration_path = selected / "preregistration.json"
    preregistration = _load_json(
        preregistration_path,
        "web validation preregistration",
    )
    starting_commit = str(preregistration.get("starting_commit") or "")
    expected_preregistration = build_web_validation_preregistration(
        starting_commit
    )
    if preregistration != expected_preregistration:
        raise ValueError("web validation preregistration drift detected")
    manifest, sources = build_web_validation_development_manifest(
        starting_commit
    )
    files = _artifact_files(
        expected_preregistration,
        manifest,
        sources,
    )
    observed = {
        path.relative_to(selected).as_posix()
        for path in selected.rglob("*")
        if path.is_file()
    }
    if observed != set(files):
        missing = sorted(set(files) - observed)
        extra = sorted(observed - set(files))
        raise ValueError(
            "web validation artifact set drift: "
            f"missing={','.join(missing) or 'none'} "
            f"extra={','.join(extra) or 'none'}"
        )
    for relative, expected in files.items():
        path = _safe_destination(selected, relative)
        try:
            actual = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError(
                f"invalid web validation artifact: {relative}: {exc}"
            ) from exc
        if actual != expected:
            raise ValueError(
                f"web validation artifact drift: {relative}"
            )
    return {
        "case_count": manifest["case_count"],
        "family_count": manifest["family_count"],
        "preregistration_digest": expected_preregistration[
            "deterministic_digest"
        ],
        "development_digest": manifest["deterministic_digest"],
    }


def _build_cases() -> tuple[dict[str, Any], ...]:
    cases = []
    for family in sorted(_FAMILIES, key=lambda item: item.family_id):
        for variant in _VARIANTS:
            identity = f"{family.family_id}\0{variant}"
            case_id = "wv_" + hashlib.sha256(
                identity.encode("utf-8")
            ).hexdigest()[:20]
            source = _render_source(family, variant)
            compile(
                source,
                f"benchmark_web_validation/{case_id}.py",
                "exec",
            )
            metadata = {
                "case_id": case_id,
                "family_id": family.family_id,
                "framework": family.framework,
                "case_type": family.case_type,
                "variant": variant,
                "ground_truth": _GROUND_TRUTH[variant],
                "expected_validation_outcome": _EXPECTED_OUTCOME[
                    variant
                ],
                "route_style": family.route_style,
                "indirection": family.indirection,
                "resource_backend": family.resource_backend,
                "feature_tags": _feature_tags(family, variant),
                "logical_source_name": f"sources/{case_id}.py",
                "source_sha256": hashlib.sha256(
                    source.encode("utf-8")
                ).hexdigest(),
            }
            cases.append({"metadata": metadata, "source": source})
    ids = [case["metadata"]["case_id"] for case in cases]
    if len(cases) != 48 or len(ids) != len(set(ids)):
        raise AssertionError("web validation case matrix is invalid")
    return tuple(cases)


def _split_families() -> tuple[tuple[str, ...], tuple[str, ...]]:
    strata: dict[tuple[str, str], list[WebTemplateFamily]] = defaultdict(
        list
    )
    for family in _FAMILIES:
        strata[family.stratum].append(family)
    development: list[str] = []
    reserved: list[str] = []
    for stratum in sorted(strata):
        families = sorted(
            strata[stratum],
            key=lambda item: item.family_id,
        )
        if len(families) != 3:
            raise AssertionError(
                "web validation split requires three families per stratum"
            )
        key = "\0".join(
            (WEB_VALIDATION_SPLIT_SEED, *stratum)
        ).encode("utf-8")
        reserved_index = int(
            hashlib.sha256(key).hexdigest()[:8],
            16,
        ) % len(families)
        for index, family in enumerate(families):
            target = reserved if index == reserved_index else development
            target.append(family.family_id)
    if len(development) != 8 or len(reserved) != 4:
        raise AssertionError("web validation family split is invalid")
    return tuple(sorted(development)), tuple(sorted(reserved))


def _render_source(
    family: WebTemplateFamily,
    variant: str,
) -> str:
    if family.case_type == "path_traversal_possible":
        return _render_path_source(family, variant)
    return _render_idor_source(family, variant)


def _render_path_source(
    family: WebTemplateFamily,
    variant: str,
) -> str:
    framework_header = (
        "from flask import Flask, abort, request\n\napp = Flask(__name__)"
        if family.framework == "flask"
        else (
            "from fastapi import Depends, FastAPI, HTTPException\n\n"
            "app = FastAPI()"
        )
    )
    optional_import = (
        "\nfrom application_policy import resolve_asset as "
        "external_resolve_asset\n"
        if variant == "ambiguous"
        else ""
    )
    header = (
        "from __future__ import annotations\n\n"
        "from functools import wraps\n"
        "from pathlib import Path\n"
        f"{optional_import}\n"
        f"{framework_header}\n\n"
        "ASSET_ROOT = Path(\"/srv/belief/assets\").resolve()\n\n"
        "def _read_asset(candidate: Path) -> str:\n"
        "    return candidate.read_text(encoding=\"utf-8\")\n"
    )
    action = _path_action_lines(family, variant)
    if family.indirection == "direct":
        return _normalize_source(
            header + "\n\n" + _path_direct_route(family, action)
        )
    if family.indirection == "helper":
        return _normalize_source(
            header
            + "\n\n"
            + _path_helper(action)
            + "\n\n"
            + _path_helper_route(family)
        )
    if family.indirection == "decorator":
        return _normalize_source(
            header
            + "\n\n"
            + _path_decorator(action)
            + "\n\n"
            + _path_decorator_route()
        )
    return _normalize_source(
        header
        + "\n\n"
        + _path_dependency(action)
        + "\n\n"
        + _path_dependency_route()
    )


def _path_action_lines(
    family: WebTemplateFamily,
    variant: str,
) -> tuple[str, ...]:
    denial = (
        "abort(404)"
        if family.framework == "flask"
        else "raise HTTPException(status_code=404)"
    )
    if variant == "ambiguous":
        return (
            "candidate = external_resolve_asset(raw_path, ASSET_ROOT)",
            "content = _read_asset(candidate)",
        )
    if variant == "protected":
        return (
            "safe_name = Path(raw_path).name",
            "candidate = (ASSET_ROOT / safe_name).resolve()",
            "if not candidate.is_relative_to(ASSET_ROOT):",
            f"    {denial}",
            "content = _read_asset(candidate)",
        )
    if variant == "trap":
        return (
            "decoy_candidate = (ASSET_ROOT / raw_path).resolve()",
            "_ = str(decoy_candidate)",
            "safe_name = Path(raw_path).name",
            "candidate = (ASSET_ROOT / safe_name).resolve()",
            "if not candidate.is_relative_to(ASSET_ROOT):",
            f"    {denial}",
            "content = _read_asset(candidate)",
        )
    if family.vulnerable_pattern == "sanitizer_result_ignored":
        return (
            "Path(raw_path).name",
            "candidate = (ASSET_ROOT / raw_path).resolve()",
            "content = _read_asset(candidate)",
        )
    if family.vulnerable_pattern == "guard_after_sink":
        return (
            "candidate = (ASSET_ROOT / raw_path).resolve()",
            "content = _read_asset(candidate)",
            "if not candidate.is_relative_to(ASSET_ROOT):",
            f"    {denial}",
        )
    return (
        "candidate = (ASSET_ROOT / raw_path).resolve()",
        "content = _read_asset(candidate)",
    )


def _path_direct_route(
    family: WebTemplateFamily,
    action: tuple[str, ...],
) -> str:
    if family.framework == "flask":
        body = (
            "@app.get(\"/assets\")\n"
            "def asset_route():\n"
            "    raw_path = request.args.get(\"path\", \"\")\n"
        )
    else:
        body = (
            "@app.get(\"/assets\")\n"
            "async def asset_route(path: str):\n"
            "    raw_path = path\n"
        )
    return body + _indent(action, 4) + "\n    return {\"content\": content}\n"


def _path_helper(action: tuple[str, ...]) -> str:
    return (
        "def load_asset(raw_path: str) -> str:\n"
        + _indent(action, 4)
        + "\n    return content\n"
    )


def _path_helper_route(family: WebTemplateFamily) -> str:
    if family.framework == "flask":
        return (
            "@app.get(\"/assets\")\n"
            "def asset_route():\n"
            "    raw_path = request.args.get(\"path\", \"\")\n"
            "    return {\"content\": load_asset(raw_path)}\n"
        )
    return (
        "@app.get(\"/assets\")\n"
        "async def asset_route(path: str):\n"
        "    return {\"content\": load_asset(path)}\n"
    )


def _path_decorator(action: tuple[str, ...]) -> str:
    return (
        "def asset_boundary(handler):\n"
        "    @wraps(handler)\n"
        "    def wrapped():\n"
        "        raw_path = request.args.get(\"path\", \"\")\n"
        + _indent(action, 8)
        + "\n        return handler(content)\n"
        "    return wrapped\n"
    )


def _path_decorator_route() -> str:
    return (
        "@app.get(\"/assets\")\n"
        "@asset_boundary\n"
        "def asset_route(content: str):\n"
        "    return {\"content\": content}\n"
    )


def _path_dependency(action: tuple[str, ...]) -> str:
    return (
        "def load_asset(path: str) -> str:\n"
        "    raw_path = path\n"
        + _indent(action, 4)
        + "\n    return content\n"
    )


def _path_dependency_route() -> str:
    return (
        "@app.get(\"/assets\")\n"
        "async def asset_route(content: str = Depends(load_asset)):\n"
        "    return {\"content\": content}\n"
    )


def _render_idor_source(
    family: WebTemplateFamily,
    variant: str,
) -> str:
    framework_header = (
        "from flask import Flask, abort, request\n\napp = Flask(__name__)"
        if family.framework == "flask"
        else (
            "from fastapi import Depends, FastAPI, HTTPException, Request\n\n"
            "app = FastAPI()"
        )
    )
    optional_import = (
        "\nfrom application_policy import authorize_resource as "
        "external_authorize_resource\n"
        if variant == "ambiguous"
        else ""
    )
    header = (
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n"
        "from functools import wraps\n"
        f"{optional_import}\n"
        f"{framework_header}\n\n"
        + _resource_fixture_source(family.resource_backend)
    )
    action = _idor_action_lines(family, variant)
    if family.indirection == "direct":
        return _normalize_source(
            header + "\n\n" + _idor_direct_route(family, action)
        )
    if family.indirection == "helper":
        return _normalize_source(
            header
            + "\n\n"
            + _idor_helper(action)
            + "\n\n"
            + _idor_helper_route(family)
        )
    if family.indirection == "decorator":
        return _normalize_source(
            header
            + "\n\n"
            + _idor_decorator(action)
            + "\n\n"
            + _idor_decorator_route()
        )
    return _normalize_source(
        header
        + "\n\n"
        + _idor_dependency(action)
        + "\n\n"
        + _idor_dependency_route()
    )


def _resource_fixture_source(backend: str) -> str:
    if backend == "model":
        return dedent(
            """
            @dataclass
            class Resource:
                resource_id: str
                owner_id: str
                tenant_id: str
                value: str
                last_viewed_by: str = ""


            RESOURCES = {
                "resource_a": Resource(
                    "resource_a", "user_a", "tenant_a", "alpha"
                ),
                "resource_b": Resource(
                    "resource_b", "user_b", "tenant_a", "bravo"
                ),
                "resource_c": Resource(
                    "resource_c", "user_a", "tenant_b", "charlie"
                ),
            }


            def _field(resource: Resource, name: str) -> str:
                return str(getattr(resource, name))


            def _touch(resource: Resource, user_id: str) -> None:
                resource.last_viewed_by = user_id


            def _serialize(resource: Resource) -> dict[str, str]:
                return {
                    "resource_id": resource.resource_id,
                    "value": resource.value,
                }
            """
        ).strip()
    return dedent(
        """
        RESOURCES = {
            "resource_a": {
                "resource_id": "resource_a",
                "owner_id": "user_a",
                "tenant_id": "tenant_a",
                "value": "alpha",
                "last_viewed_by": "",
            },
            "resource_b": {
                "resource_id": "resource_b",
                "owner_id": "user_b",
                "tenant_id": "tenant_a",
                "value": "bravo",
                "last_viewed_by": "",
            },
            "resource_c": {
                "resource_id": "resource_c",
                "owner_id": "user_a",
                "tenant_id": "tenant_b",
                "value": "charlie",
                "last_viewed_by": "",
            },
        }


        def _field(resource: dict[str, str], name: str) -> str:
            return str(resource[name])


        def _touch(resource: dict[str, str], user_id: str) -> None:
            resource["last_viewed_by"] = user_id


        def _serialize(resource: dict[str, str]) -> dict[str, str]:
            return {
                "resource_id": resource["resource_id"],
                "value": resource["value"],
            }
        """
    ).strip()


def _idor_action_lines(
    family: WebTemplateFamily,
    variant: str,
) -> tuple[str, ...]:
    denial = (
        "abort(403)"
        if family.framework == "flask"
        else "raise HTTPException(status_code=403)"
    )
    missing = (
        "abort(404)"
        if family.framework == "flask"
        else "raise HTTPException(status_code=404)"
    )
    base = (
        "resource = RESOURCES.get(resource_id)",
        "if resource is None:",
        f"    {missing}",
    )
    if variant == "ambiguous":
        return (
            *base,
            (
                "if not external_authorize_resource("
                "user_id, tenant_id, resource):"
            ),
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    if variant == "protected":
        return (
            *base,
            (
                "if (_field(resource, \"owner_id\") != user_id or "
                "_field(resource, \"tenant_id\") != tenant_id):"
            ),
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    if variant == "trap":
        return (
            *base,
            "decoy_unscoped = resource",
            "_ = _serialize(decoy_unscoped)",
            "selected = next((",
            "    candidate",
            "    for candidate in RESOURCES.values()",
            (
                "    if _field(candidate, \"resource_id\") == resource_id"
            ),
            "    and _field(candidate, \"owner_id\") == user_id",
            "    and _field(candidate, \"tenant_id\") == tenant_id",
            "), None)",
            "if selected is None:",
            f"    {denial}",
            "payload = _serialize(selected)",
        )
    if family.vulnerable_pattern == "owner_only":
        return (
            *base,
            "if _field(resource, \"owner_id\") != user_id:",
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    if family.vulnerable_pattern == "tenant_only":
        return (
            *base,
            "if _field(resource, \"tenant_id\") != tenant_id:",
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    if family.vulnerable_pattern == "wrong_resource_guard":
        return (
            *base,
            "guard_resource = RESOURCES[\"resource_a\"]",
            "if _field(guard_resource, \"owner_id\") != user_id:",
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    if family.vulnerable_pattern == "guard_after_sink":
        return (
            *base,
            "_touch(resource, user_id)",
            (
                "if (_field(resource, \"owner_id\") != user_id or "
                "_field(resource, \"tenant_id\") != tenant_id):"
            ),
            f"    {denial}",
            "selected = resource",
            "payload = _serialize(selected)",
        )
    return (
        *base,
        "if not user_id:",
        f"    {denial}",
        "selected = resource",
        "payload = _serialize(selected)",
    )


def _idor_direct_route(
    family: WebTemplateFamily,
    action: tuple[str, ...],
) -> str:
    if family.framework == "flask":
        prefix = (
            "@app.get(\"/resources/<resource_id>\")\n"
            "def resource_route(resource_id: str):\n"
            "    user_id = request.headers.get(\"X-User-ID\", \"\")\n"
            "    tenant_id = request.headers.get(\"X-Tenant-ID\", \"\")\n"
        )
    else:
        prefix = (
            "@app.get(\"/resources/{resource_id}\")\n"
            "async def resource_route(resource_id: str, request: Request):\n"
            "    user_id = request.headers.get(\"X-User-ID\", \"\")\n"
            "    tenant_id = request.headers.get(\"X-Tenant-ID\", \"\")\n"
        )
    return prefix + _indent(action, 4) + "\n    return payload\n"


def _idor_helper(action: tuple[str, ...]) -> str:
    return (
        "def load_resource(\n"
        "    resource_id: str,\n"
        "    user_id: str,\n"
        "    tenant_id: str,\n"
        ") -> dict[str, str]:\n"
        + _indent(action, 4)
        + "\n    return payload\n"
    )


def _idor_helper_route(family: WebTemplateFamily) -> str:
    if family.framework == "flask":
        return (
            "@app.get(\"/resources/<resource_id>\")\n"
            "def resource_route(resource_id: str):\n"
            "    return load_resource(\n"
            "        resource_id,\n"
            "        request.headers.get(\"X-User-ID\", \"\"),\n"
            "        request.headers.get(\"X-Tenant-ID\", \"\"),\n"
            "    )\n"
        )
    return (
        "@app.get(\"/resources/{resource_id}\")\n"
        "async def resource_route(resource_id: str, request: Request):\n"
        "    return load_resource(\n"
        "        resource_id,\n"
        "        request.headers.get(\"X-User-ID\", \"\"),\n"
        "        request.headers.get(\"X-Tenant-ID\", \"\"),\n"
        "    )\n"
    )


def _idor_decorator(action: tuple[str, ...]) -> str:
    return (
        "def resource_boundary(handler):\n"
        "    @wraps(handler)\n"
        "    def wrapped(resource_id: str):\n"
        "        user_id = request.headers.get(\"X-User-ID\", \"\")\n"
        "        tenant_id = request.headers.get(\"X-Tenant-ID\", \"\")\n"
        + _indent(action, 8)
        + "\n        return handler(resource_id, payload)\n"
        "    return wrapped\n"
    )


def _idor_decorator_route() -> str:
    return (
        "@app.get(\"/resources/<resource_id>\")\n"
        "@resource_boundary\n"
        "def resource_route(\n"
        "    resource_id: str,\n"
        "    payload: dict[str, str],\n"
        "):\n"
        "    return payload\n"
    )


def _idor_dependency(action: tuple[str, ...]) -> str:
    return (
        "def authorized_resource(\n"
        "    resource_id: str,\n"
        "    request: Request,\n"
        ") -> dict[str, str]:\n"
        "    user_id = request.headers.get(\"X-User-ID\", \"\")\n"
        "    tenant_id = request.headers.get(\"X-Tenant-ID\", \"\")\n"
        + _indent(action, 4)
        + "\n    return payload\n"
    )


def _idor_dependency_route() -> str:
    return (
        "@app.get(\"/resources/{resource_id}\")\n"
        "async def resource_route(\n"
        "    payload: dict[str, str] = Depends(authorized_resource),\n"
        "):\n"
        "    return payload\n"
    )


def _feature_tags(
    family: WebTemplateFamily,
    variant: str,
) -> list[str]:
    values = {
        family.framework,
        family.case_type,
        f"{family.route_style}_route",
        f"{family.indirection}_indirection",
        f"{family.resource_backend}_backend",
        variant,
    }
    if variant == "vulnerable":
        values.add(family.vulnerable_pattern)
        if family.case_type == "path_traversal_possible":
            values.add("sanitizer_result_ignored")
    elif variant == "protected":
        values.add("guard_before_sink")
        values.add(
            "sanitizer_result_used"
            if family.case_type == "path_traversal_possible"
            else "owner_and_tenant_bound"
        )
    elif variant == "ambiguous":
        values.add("external_policy_boundary")
    else:
        values.update(
            {
                "decoy_unscoped_flow",
                "guard_before_sink",
                "wrong_flow_not_used",
            }
        )
    return sorted(values)


def _artifact_files(
    preregistration: Mapping[str, Any],
    manifest: Mapping[str, Any],
    sources: Mapping[str, str],
) -> dict[str, str]:
    files = {
        "README.md": _readme(),
        "preregistration.json": _json_document(preregistration),
        "development/cases.json": _json_document(manifest),
    }
    files.update({
        relative: _normalize_source(source)
        for relative, source in sources.items()
    })
    return dict(sorted(files.items()))


def _readme() -> str:
    return dedent(
        """
        # Transparent web-validation generalization benchmark

        This create-only corpus is independent from SusVibes. It contains 48
        synthetic cases grouped into 12 application-template families. Each
        family contains vulnerable, protected, ambiguous, and trap variants.

        The committed development cohort contains 32 cases from eight complete
        families. The remaining 16 case IDs are preregistered by family and
        cryptographic digest, but their source and outcomes are not committed.
        A family can never be split across development and reserved cohorts.

        Coverage includes Flask and FastAPI, path traversal and IDOR/BOLA,
        synchronous and asynchronous routes, direct/helper/decorator/dependency
        shapes, dictionary and model-backed resources, before/after/wrong
        guards, owner-only/tenant-only/owner+tenant checks, and used/ignored
        sanitizer results.

        This scaffold performs no target execution. It uses no network,
        subprocess, shell, Docker, external project, or SusVibes artifact. It
        is not a SecPass measurement and cannot support a leaderboard claim.

        Verify the frozen files:

        ```bash
        python scripts/build_web_validation_corpus.py \
          --verify benchmark_web_validation
        ```

        Reserved generation and evaluation remain unavailable until a later
        reviewer freeze and explicit create-only authorization are implemented.
        """
    ).lstrip()


def _metadata_digest(records: list[dict[str, Any]]) -> str:
    return _canonical_digest(records)


def _case_digest(cases: tuple[dict[str, Any], ...]) -> str:
    return _canonical_digest([
        case["metadata"]
        for case in cases
    ])


def _source_digest(cases: tuple[dict[str, Any], ...]) -> str:
    digest = hashlib.sha256()
    for case in cases:
        path = str(case["metadata"]["logical_source_name"])
        source = str(case["source"])
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key != "deterministic_digest"
    }
    return _canonical_digest(semantic)


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_document(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"


def _normalize_source(source: str) -> str:
    return source.replace("\r\n", "\n").rstrip() + "\n"


def _indent(lines: tuple[str, ...], spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(
        f"{prefix}{line}" if line else ""
        for line in lines
    )


def _safe_destination(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise ValueError("unsafe web validation artifact path")
    destination = root.joinpath(*pure.parts).resolve()
    if not destination.is_relative_to(root):
        raise ValueError("web validation artifact escaped output root")
    return destination


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    return payload


def _validate_commit(value: str) -> None:
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise ValueError("starting commit must be a lowercase 40-hex SHA")


__all__ = [
    "WEB_VALIDATION_BENCHMARK_ID",
    "WEB_VALIDATION_CORPUS_SCHEMA_VERSION",
    "WEB_VALIDATION_GENERATOR_VERSION",
    "WEB_VALIDATION_PREREGISTRATION_SCHEMA_VERSION",
    "WEB_VALIDATION_SPLIT_SEED",
    "WEB_VALIDATION_THRESHOLDS",
    "build_web_validation_development_manifest",
    "build_web_validation_preregistration",
    "verify_web_validation_development_corpus",
    "write_web_validation_development_corpus",
]
