#!/usr/bin/env python3
"""Run the deterministic synthetic exploration-objective pilot."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.exploration import (  # noqa: E402
    ExplorationBenchmarkError,
    write_exploration_pilot_benchmark,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare three synthetic path artifacts with expected labels; "
            "no external tool or source code is executed."
        )
    )
    parser.add_argument(
        "--corpus",
        default=str(
            REPOSITORY_ROOT
            / "research"
            / "duck_path_objective_pilot"
            / "cases.json"
        ),
        help="Closed three-case synthetic corpus JSON",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only benchmark report JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    output = Path(args.output).resolve()
    try:
        payload = write_exploration_pilot_benchmark(
            output,
            corpus_path=Path(args.corpus).resolve(),
        )
    except (ExplorationBenchmarkError, OSError, UnicodeError, ValueError) as exc:
        print(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": payload["schema_version"],
                "output": str(output),
                "case_count": payload["metrics"]["case_count"],
                "correct_count": payload["metrics"]["correct_count"],
                "abstention_count": payload["metrics"]["abstention_count"],
                "deterministic_digest": payload["deterministic_digest"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
