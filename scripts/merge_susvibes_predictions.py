#!/usr/bin/env python3
"""Merge completed BELIEF SusVibes batch directories."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.susvibes_predictions import (  # noqa: E402
    write_merged_susvibes_predictions,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate completed BELIEF SusVibes run directories and merge "
            "their predictions in frozen cohort order."
        )
    )
    parser.add_argument("--experiment-manifest", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument(
        "--cohort",
        required=True,
        choices=["smoke", "canary", "holdout", "full"],
    )
    parser.add_argument(
        "--run-dir",
        action="append",
        required=True,
        help="Completed BELIEF batch results directory (repeatable)",
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Create an explicitly incomplete diagnostic merge",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--provenance-output", required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        payload = write_merged_susvibes_predictions(
            Path(args.output).resolve(),
            Path(args.provenance_output).resolve(),
            experiment_manifest=Path(
                args.experiment_manifest
            ).resolve(),
            dataset=Path(args.dataset).resolve(),
            cohort=str(args.cohort),
            run_dirs=[
                Path(value).resolve()
                for value in args.run_dir
            ],
            require_complete=not bool(args.allow_partial),
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

    print(json.dumps({
        "schema_version": payload["schema_version"],
        "predictions": payload["output"]["predictions"],
        "provenance": payload["output"]["provenance"],
        "cohort": payload["experiment"]["cohort"],
        "prediction_count": payload["output"]["prediction_count"],
        "complete": payload["coverage"]["complete"],
        "policy_violation_suspected_count": payload[
            "quality_flags"
        ]["policy_violation_suspected_count"],
        "report_digest": payload["report_digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
