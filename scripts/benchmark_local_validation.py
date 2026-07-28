#!/usr/bin/env python3
"""Run the transparent eight-case local validation benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.validation.benchmark import (  # noqa: E402
    write_local_validation_benchmark,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run eight deterministic path traversal and IDOR/BOLA "
            "fixtures without network, subprocesses, or Docker."
        )
    )
    parser.add_argument(
        "--corpus",
        default=str(
            REPOSITORY_ROOT / "benchmark_validation" / "cases.json"
        ),
        help="Transparent local benchmark corpus JSON",
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
        payload = write_local_validation_benchmark(
            output,
            corpus_path=Path(args.corpus).resolve(),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
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
        "case_count": payload["corpus"]["case_count"],
        "semantic_stability": payload["semantic_stability"][
            "identical_repeated_execution"
        ],
        "static_only": payload["stages"]["static_only"],
        "after_validation_plan": payload["stages"][
            "after_validation_plan"
        ],
        "after_validation_result": payload["stages"][
            "after_validation_result"
        ],
        "deterministic_digest": payload["deterministic_digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
