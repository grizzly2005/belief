#!/usr/bin/env python3
"""Create deterministic smoke, canary, and full SusVibes cohorts."""

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

from belief.benchmark.susvibes_experiment import (  # noqa: E402
    write_susvibes_experiment_manifest,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a deterministic evaluator-side SusVibes experiment "
            "manifest without starting Docker or a model."
        )
    )
    parser.add_argument(
        "--susvibes-root",
        required=True,
        help="Pinned SusVibes Git checkout",
    )
    parser.add_argument(
        "--dataset",
        default="",
        help=(
            "Dataset JSONL (default: "
            "<susvibes-root>/datasets/default/susvibes_dataset.jsonl)"
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only manifest path",
    )
    parser.add_argument("--smoke-size", type=int, default=3)
    parser.add_argument("--canary-size", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=12)
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
        timeout=15,
    )
    if completed.returncode:
        raise ValueError(
            "cannot inspect pinned SusVibes checkout: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout.decode("utf-8", errors="replace").strip()


def _git_head(repository: Path) -> str:
    head = _git(repository, "rev-parse", "HEAD")
    if _git(repository, "status", "--porcelain"):
        raise ValueError(
            "refusing to freeze a dirty SusVibes checkout"
        )
    return head


def main() -> int:
    args = _arguments()
    try:
        root = Path(args.susvibes_root).resolve()
        if not (root / ".git").exists():
            raise ValueError(
                f"SusVibes root is not a Git checkout: {root}"
            )
        dataset = (
            Path(args.dataset).resolve()
            if args.dataset
            else (
                root
                / "datasets"
                / "default"
                / "susvibes_dataset.jsonl"
            )
        )
        try:
            dataset.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                "SusVibes dataset must be inside the pinned checkout"
            ) from exc
        output = Path(args.output).resolve()
        payload = write_susvibes_experiment_manifest(
            dataset,
            output,
            susvibes_commit=_git_head(root),
            smoke_size=int(args.smoke_size),
            canary_size=int(args.canary_size),
            batch_size=int(args.batch_size),
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

    print(json.dumps({
        "schema_version": payload["schema_version"],
        "output": str(output),
        "dataset_sha256": payload["dataset"]["sha256"],
        "dataset_case_count": payload["dataset"]["case_count"],
        "smoke_case_count": payload["cohorts"]["smoke"]["case_count"],
        "canary_case_count": payload["cohorts"]["canary"]["case_count"],
        "holdout_case_count": payload["cohorts"]["holdout"]["case_count"],
        "full_case_count": payload["cohorts"]["full"]["case_count"],
        "batch_count": len(payload["batches"]),
        "holdout_batch_count": len(payload["holdout_batches"]),
        "deterministic_digest": payload["deterministic_digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
