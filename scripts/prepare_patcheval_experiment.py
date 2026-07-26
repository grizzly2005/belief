#!/usr/bin/env python3
"""Freeze the preregistered PatchEval-Verified Python split."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.patcheval_experiment import (  # noqa: E402
    write_patcheval_experiment_manifest,
)


PREREGISTERED_PATCHEVAL_COMMIT = (
    "217401d06684e8baa0847574b9faf83b0898f379"
)
PREREGISTERED_BELIEF_STARTING_COMMIT = (
    "54b83c748d7c217f1a801420867a93b942d53daf"
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create the evaluator-side PatchEval-Verified Python split "
            "using only aggregate terminal output. This command never "
            "pulls images or runs a case."
        )
    )
    parser.add_argument(
        "--patcheval-root",
        required=True,
        help="Clean PatchEval checkout at the preregistered commit",
    )
    parser.add_argument(
        "--dataset",
        default="",
        help=(
            "PatchEval dataset (default: <patcheval-root>/patcheval/"
            "datasets/patcheval_verified.json)"
        ),
    )
    parser.add_argument(
        "--susvibes-dataset",
        required=True,
        help="Pinned SusVibes JSONL used only for project exclusion",
    )
    parser.add_argument(
        "--protocol",
        default=str(
            REPOSITORY_ROOT
            / "docs"
            / "PATCHEVAL_VERIFIED_PROTOCOL.md"
        ),
        help="Committed preregistration protocol",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New evaluator-side manifest outside the BELIEF repository",
    )
    return parser.parse_args()


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update({
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=30,
    )
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        raise ValueError(
            f"cannot verify PatchEval checkout: "
            f"{error or completed.returncode}"
        )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _verify_checkout(root: Path) -> None:
    if not root.is_dir() or not (root / ".git").exists():
        raise ValueError("PatchEval root must be a Git checkout")
    top_level = Path(
        _git(root, "rev-parse", "--show-toplevel")
    ).resolve()
    if top_level != root:
        raise ValueError("PatchEval root is not its Git top level")
    if _git(root, "rev-parse", "HEAD").lower() != (
        PREREGISTERED_PATCHEVAL_COMMIT
    ):
        raise ValueError("PatchEval checkout commit changed")
    if _git(root, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("PatchEval checkout must be clean")


def _verify_belief_checkout() -> str:
    if _git(
        REPOSITORY_ROOT,
        "status",
        "--porcelain",
        "--untracked-files=all",
    ):
        raise ValueError(
            "BELIEF checkout must be clean before split creation"
        )
    return _git(REPOSITORY_ROOT, "rev-parse", "HEAD").lower()


def _outside_repository(path: Path) -> None:
    try:
        path.resolve().relative_to(REPOSITORY_ROOT.resolve())
    except ValueError:
        return
    raise ValueError("PatchEval manifest must be outside BELIEF")


def main() -> int:
    args = _arguments()
    root = Path(args.patcheval_root).resolve()
    dataset = (
        Path(args.dataset).resolve()
        if args.dataset
        else (
            root
            / "patcheval"
            / "datasets"
            / "patcheval_verified.json"
        )
    )
    protocol = Path(args.protocol).resolve()
    output = Path(args.output).resolve()
    try:
        _verify_checkout(root)
        preparation_commit = _verify_belief_checkout()
        try:
            dataset.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "PatchEval dataset must be inside the pinned checkout"
            ) from exc
        _outside_repository(output)
        payload = write_patcheval_experiment_manifest(
            dataset,
            Path(args.susvibes_dataset).resolve(),
            protocol,
            output,
            upstream_commit=PREREGISTERED_PATCHEVAL_COMMIT,
            belief_starting_commit=(
                PREREGISTERED_BELIEF_STARTING_COMMIT
            ),
            preparation_commit=preparation_commit,
        )
    except (
        OSError,
        UnicodeError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"error": f"{type(exc).__name__}: {exc}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    cohorts = payload["cohorts"]
    print(
        json.dumps(
            {
                "dataset_record_count": payload["source"][
                    "dataset_record_count"
                ],
                "development_case_count": cohorts["development"][
                    "case_count"
                ],
                "development_repository_count": cohorts[
                    "development"
                ]["repository_count"],
                "deterministic_digest": payload[
                    "deterministic_digest"
                ],
                "eligible_case_count": payload["selection"][
                    "eligible_case_count"
                ],
                "eligible_for_architecture_tuning": payload[
                    "eligible_for_architecture_tuning"
                ],
                "eligible_repository_count": payload["selection"][
                    "eligible_repository_count"
                ],
                "excluded_overlap_case_count": payload[
                    "susvibes_exclusion"
                ]["excluded_case_count"],
                "output": str(output),
                "python_record_count": payload["source"][
                    "python_record_count"
                ],
                "python_required_field_ineligible_count": payload[
                    "source"
                ]["python_required_field_ineligible_count"],
                "reserved_case_count": cohorts["reserved"][
                    "case_count"
                ],
                "reserved_repository_count": cohorts["reserved"][
                    "repository_count"
                ],
                "schema_version": payload["schema_version"],
                "status": payload["status"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if payload["eligible_for_architecture_tuning"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
