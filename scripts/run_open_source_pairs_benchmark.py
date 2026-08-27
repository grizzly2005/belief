#!/usr/bin/env python3
"""Run the offline public vulnerable/fixed source-pair benchmark."""

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

from belief.benchmark.open_source_pairs import (  # noqa: E402
    OpenSourcePairsError,
    write_open_source_pairs_result,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze exact public vulnerable/fixed Python blobs twice without "
            "checking out, importing, installing, or executing third-party code."
        )
    )
    parser.add_argument(
        "--manifest",
        default=str(REPOSITORY_ROOT / "benchmark_open_source_pairs" / "cases.json"),
        help="Committed open-source pair corpus manifest",
    )
    parser.add_argument(
        "--repos-root",
        required=True,
        help="Local object-only Git checkouts named by the corpus manifest",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only benchmark JSON artifact",
    )
    return parser.parse_args()


def _git(*arguments: str) -> str:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(REPOSITORY_ROOT), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
        timeout=30,
    )
    if completed.returncode:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OpenSourcePairsError(
            f"cannot verify BELIEF checkout: {error or completed.returncode}"
        )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _belief_revision() -> str:
    if _git("status", "--porcelain", "--untracked-files=all"):
        raise OpenSourcePairsError(
            "BELIEF checkout must be clean before creating a benchmark result"
        )
    return _git("rev-parse", "HEAD").lower()


def main() -> int:
    args = _arguments()
    try:
        result = write_open_source_pairs_result(
            Path(args.manifest).resolve(),
            Path(args.repos_root).resolve(),
            Path(args.output).resolve(),
            belief_revision=_belief_revision(),
        )
    except (
        OSError,
        UnicodeError,
        subprocess.TimeoutExpired,
        OpenSourcePairsError,
    ) as exc:
        print(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True),
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            {
                "analysis_error_count": result["metrics"]["analysis_error_count"],
                "case_count": result["case_count"],
                "deterministic_digest": result["deterministic_digest"],
                "deterministic_repetition_rate": result["metrics"][
                    "deterministic_repetition_rate"
                ],
                "fixed_warning_false_positive_rate": result["metrics"][
                    "fixed_warning_false_positive_rate"
                ],
                "output": str(Path(args.output).resolve()),
                "paired_discrimination_rate": result["metrics"][
                    "paired_discrimination_rate"
                ],
                "schema_version": result["schema_version"],
                "status": result["status"],
                "vulnerable_warning_recall": result["metrics"][
                    "vulnerable_warning_recall"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
