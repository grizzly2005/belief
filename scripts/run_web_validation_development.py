#!/usr/bin/env python3
"""Run the frozen static benchmark over the bundled development cohort."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.web_validation_runner import (  # noqa: E402
    write_web_validation_development_result,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the frozen two-pass static evaluation over BELIEF's exact "
            "bundled web-validation development corpus."
        )
    )
    parser.add_argument(
        "--output",
        required=True,
        help=(
            "New JSON result path outside benchmark_web_validation; "
            "existing files are refused."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        result = write_web_validation_development_result(
            Path(args.output)
        )
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            json.dumps(
                {"error": f"{type(exc).__name__}: {exc}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    summary = {
        "mode": "create",
        "output": str(Path(args.output).resolve()),
        "case_count": result["metrics"]["case_count"],
        "static_precision": result["metrics"]["static_precision"],
        "static_recall": result["metrics"]["static_recall"],
        "plan_generation_coverage": result["metrics"][
            "plan_generation_coverage"
        ],
        "deterministic_digest": result["deterministic_digest"],
        "reproducible": result["reproducibility"]["identical"],
        "secpass_equivalent": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
