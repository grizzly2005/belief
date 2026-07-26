"""Prepare the minimal Git object cache used by BELIEF's SusVibes adapters.

Network access is opt-in. The script fetches fixed commits and their first
parents, hydrates only Python blobs named by explicitly selected patch fields,
performs an offline verification pass, and never checks out or executes
third-party code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.susvibes import (  # noqa: E402
    LocalGitCorpus,
    load_susvibes_cases,
    parse_security_diff,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare an isolated, minimal Git cache for offline SusVibes "
            "paired-revision analysis."
        )
    )
    parser.add_argument("--dataset", required=True, help="Pinned SusVibes JSONL file")
    parser.add_argument(
        "--repository-cache",
        required=True,
        help="Dedicated output directory for minimal project object caches",
    )
    parser.add_argument(
        "--only-cwe",
        action="append",
        default=[],
        help="Limit cases to a CWE; incompatible with a frozen cohort",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help=(
            "Maximum cases after deterministic sorting; incompatible with "
            "a frozen cohort"
        ),
    )
    parser.add_argument(
        "--experiment-manifest",
        default="",
        help="Verified frozen SusVibes experiment manifest",
    )
    parser.add_argument(
        "--cohort",
        choices=["smoke", "canary", "holdout", "full"],
        default="",
        help="Frozen cohort selected from --experiment-manifest",
    )
    parser.add_argument(
        "--patch-field",
        action="append",
        choices=[
            "security_patch",
            "mask_patch",
            "task_patch",
            "golden_patch",
        ],
        default=[],
        help=(
            "Dataset patch field whose Python blobs must be hydrated "
            "(repeatable; default: security_patch)"
        ),
    )
    parser.add_argument(
        "--manifest",
        default="",
        help="Manifest path (default: <repository-cache>/belief-cache-manifest.json)",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="Required acknowledgement for public Git fetches",
    )
    return parser.parse_args()


def _git(
    repository: Path,
    *arguments: str,
    allow_network: bool,
    discard_stdout: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    if not allow_network:
        env.update(
            {
                "GIT_ALLOW_PROTOCOL": "",
                "GIT_NO_LAZY_FETCH": "1",
            }
        )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=180,
    )
    if check and completed.returncode:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"git {' '.join(arguments)} failed in {repository}: "
            f"{error or completed.returncode}"
        )
    return completed


def _cwe_values(raw_values: Iterable[str]) -> tuple[str, ...]:
    return tuple(
        item.strip()
        for value in raw_values
        for item in str(value).split(",")
        if item.strip()
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_manifest_output(
    manifest_path: Path,
    *,
    dataset: Path,
    experiment_manifest: Path | None = None,
) -> None:
    protected_inputs = {dataset.resolve()}
    if experiment_manifest is not None:
        protected_inputs.add(experiment_manifest.resolve())
    if manifest_path.resolve() in protected_inputs:
        raise ValueError(
            "cache manifest output must not overwrite a frozen input"
        )
    if manifest_path.exists():
        raise ValueError(
            f"refusing to overwrite cache manifest: {manifest_path}"
        )


def _select_cases(
    dataset: Path,
    *,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
    instance_ids: Iterable[str] = (),
) -> list[dict[str, object]]:
    requested_ids = tuple(str(value) for value in instance_ids)
    if len(requested_ids) != len(set(requested_ids)):
        raise ValueError("cache-preparation instance IDs must be unique")
    configured_cwes = tuple(only_cwes)
    if requested_ids and (configured_cwes or max_cases):
        raise ValueError(
            "explicit instance IDs cannot be combined with only_cwes or "
            "max_cases"
        )
    cases = load_susvibes_cases(
        dataset,
        only_cwes=configured_cwes,
        max_cases=0 if requested_ids else max_cases,
    )
    if not requested_ids:
        return cases
    cases_by_id = {
        str(case["instance_id"]): case
        for case in cases
    }
    missing = [
        instance_id
        for instance_id in requested_ids
        if instance_id not in cases_by_id
    ]
    if missing:
        raise ValueError(
            "cache-preparation instance IDs are absent from the dataset: "
            + ", ".join(missing)
        )
    return [
        cases_by_id[instance_id]
        for instance_id in requested_ids
    ]


def _ensure_repository(cache_root: Path, project: str) -> Path:
    repository = cache_root / project.replace("/", "__")
    if repository.exists() and not repository.is_dir():
        raise ValueError(f"cache target is not a directory: {repository}")
    repository.mkdir(parents=True, exist_ok=True)
    if not (repository / ".git").is_dir():
        if any(repository.iterdir()):
            raise ValueError(
                f"refusing to initialize non-empty cache directory: {repository}"
            )
        completed = subprocess.run(
            ["git", "init", "--quiet", str(repository)],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if completed.returncode:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(f"git init failed for {repository}: {error}")
    return repository


def _ensure_origin(repository: Path, project: str) -> str:
    expected = f"https://github.com/{project}.git"
    existing = _git(
        repository,
        "remote",
        "get-url",
        "origin",
        allow_network=False,
        check=False,
    )
    if existing.returncode:
        _git(
            repository,
            "remote",
            "add",
            "origin",
            expected,
            allow_network=False,
        )
        return expected
    observed = existing.stdout.decode("utf-8", errors="replace").strip()
    if observed.rstrip("/") != expected.rstrip("/"):
        raise ValueError(
            f"refusing unexpected origin for {project}: {observed or '<empty>'}"
        )
    return observed


def _hydrate_case(
    repository: Path,
    case: dict[str, object],
    patch_fields: Iterable[str],
) -> dict[str, object]:
    commit = str(case["base_commit"])
    _git(
        repository,
        "fetch",
        "--no-tags",
        "--filter=blob:none",
        "--depth=2",
        "origin",
        commit,
        allow_network=True,
        discard_stdout=True,
    )
    parent = _git(
        repository,
        "rev-parse",
        f"{commit}^",
        allow_network=False,
    ).stdout.decode("utf-8", errors="replace").strip()

    wanted: set[tuple[str, str]] = set()
    for field in patch_fields:
        for diff_file in parse_security_diff(str(case.get(field, ""))):
            if field == "security_patch":
                wanted.update({
                    (parent, diff_file.old_path),
                    (commit, diff_file.new_path),
                })
                continue
            paths = {
                path
                for path in (diff_file.old_path, diff_file.new_path)
                if path
            }
            wanted.update(
                (revision, path)
                for revision in (parent, commit)
                for path in paths
            )

    hydrated: set[tuple[str, str]] = set()
    for revision, path in sorted(wanted):
        if not path:
            continue
        completed = _git(
            repository,
            "show",
            f"{revision}:{path}",
            allow_network=True,
            discard_stdout=True,
            check=False,
        )
        if completed.returncode == 0:
            hydrated.add((revision, path))
    return {
        "instance_id": str(case["instance_id"]),
        "commit": commit,
        "parent": parent,
        "python_objects": [
            {"revision": revision, "path": path}
            for revision, path in sorted(hydrated)
        ],
    }


def prepare_cache(
    dataset: Path,
    cache_root: Path,
    *,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
    instance_ids: Iterable[str] = (),
    selection_provenance: dict[str, str] | None = None,
    patch_fields: Iterable[str] = ("security_patch",),
    allow_network: bool = False,
) -> dict[str, object]:
    if not allow_network:
        raise ValueError(
            "network preparation is disabled; pass --allow-network explicitly"
        )
    configured_cwes = tuple(str(value) for value in only_cwes)
    requested_ids = tuple(str(value) for value in instance_ids)
    cases = _select_cases(
        dataset,
        only_cwes=configured_cwes,
        max_cases=max_cases,
        instance_ids=requested_ids,
    )
    selected_fields = tuple(dict.fromkeys(patch_fields))
    allowed_fields = {
        "security_patch",
        "mask_patch",
        "task_patch",
        "golden_patch",
    }
    if not selected_fields:
        selected_fields = ("security_patch",)
    unknown_fields = sorted(set(selected_fields) - allowed_fields)
    if unknown_fields:
        raise ValueError(
            "unsupported patch fields: " + ", ".join(unknown_fields)
        )
    cache_root.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for case in cases:
        grouped[str(case["project"])].append(case)

    project_rows = []
    for index, (project, project_cases) in enumerate(sorted(grouped.items()), start=1):
        print(
            f"[{index}/{len(grouped)}] preparing {project} "
            f"({len(project_cases)} case(s))",
            flush=True,
        )
        repository = _ensure_repository(cache_root, project)
        origin = _ensure_origin(repository, project)
        case_rows = [
            _hydrate_case(repository, case, selected_fields)
            for case in project_cases
        ]
        project_rows.append(
            {
                "project": project,
                "origin": origin,
                "cases": case_rows,
            }
        )

    corpus = LocalGitCorpus(cache_root)
    for project_row in project_rows:
        project = str(project_row["project"])
        for case_row in project_row["cases"]:
            commit = str(case_row["commit"])
            if not corpus.has_commit(project, commit):
                raise ValueError(f"offline verification failed for {project}@{commit}")
            for source_object in case_row["python_objects"]:
                revision = str(source_object["revision"])
                path = str(source_object["path"])
                if corpus.source(project, revision, path) is None:
                    raise ValueError(
                        "offline blob verification failed for "
                        f"{project}@{revision}:{path}"
                    )

    payload: dict[str, object] = {
        "schema_version": "belief.susvibes_cache_manifest.v1",
        "dataset": dataset.name,
        "dataset_sha256": _sha256(dataset),
        "case_count": len(cases),
        "project_count": len(project_rows),
        "only_cwes": sorted(set(configured_cwes)),
        "patch_fields": list(selected_fields),
        "projects": project_rows,
        "offline_verification_passed": True,
    }
    if requested_ids:
        selection: dict[str, object] = {
            "kind": "explicit_instance_ids",
            "case_count": len(requested_ids),
            "instance_ids_sha256": hashlib.sha256(
                json.dumps(
                    requested_ids,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest(),
        }
        if selection_provenance:
            selection["provenance"] = {
                str(key): str(value)
                for key, value in sorted(selection_provenance.items())
            }
        payload["selection"] = selection
    return payload


def main() -> int:
    args = _arguments()
    dataset = Path(args.dataset).resolve()
    cache_root = Path(args.repository_cache).resolve()
    manifest_path = (
        Path(args.manifest).resolve()
        if args.manifest
        else cache_root / "belief-cache-manifest.json"
    )
    try:
        experiment_manifest = str(args.experiment_manifest or "")
        cohort = str(args.cohort or "")
        if bool(experiment_manifest) != bool(cohort):
            raise ValueError(
                "--experiment-manifest and --cohort must be used together"
            )
        experiment_manifest_path = (
            Path(experiment_manifest).resolve()
            if experiment_manifest
            else None
        )
        _validate_manifest_output(
            manifest_path,
            dataset=dataset,
            experiment_manifest=experiment_manifest_path,
        )
        instance_ids: tuple[str, ...] = ()
        selection_provenance: dict[str, str] | None = None
        if experiment_manifest_path is not None:
            from belief.benchmark.susvibes_experiment import (
                load_experiment_cohort,
            )

            loaded_ids, selection_provenance = load_experiment_cohort(
                experiment_manifest_path,
                cohort,
                dataset=dataset,
            )
            instance_ids = tuple(loaded_ids)
        payload = prepare_cache(
            dataset,
            cache_root,
            only_cwes=_cwe_values(args.only_cwe),
            max_cases=int(args.max_cases),
            instance_ids=instance_ids,
            selection_provenance=selection_provenance,
            patch_fields=tuple(args.patch_field or ("security_patch",)),
            allow_network=bool(args.allow_network),
        )
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with manifest_path.open(
                "x",
                encoding="utf-8",
                newline="\n",
            ) as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
        except FileExistsError as exc:
            raise ValueError(
                f"refusing to overwrite cache manifest: {manifest_path}"
            ) from exc
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "case_count": payload["case_count"],
                "manifest": str(manifest_path),
                "offline_verification_passed": True,
                "project_count": payload["project_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
