#!/usr/bin/env python3
"""Validate official SusVibes summaries and create an honest scorecard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.susvibes_scorecard import (  # noqa: E402
    write_susvibes_official_scorecard,
)


DEFAULT_COMPARATORS = (
    REPOSITORY_ROOT
    / "benchmark_susvibes"
    / "security_comparators_2026-07-23.json"
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate one or more official SusVibes summary.json files, "
            "measure run stability, and compare numerical SecPass rates "
            "without making cross-protocol leaderboard claims."
        )
    )
    parser.add_argument(
        "--experiment-manifest",
        required=True,
        help="Verified deterministic experiment manifest",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Pinned SusVibes dataset JSONL",
    )
    parser.add_argument(
        "--cohort",
        required=True,
        choices=["smoke", "canary", "holdout", "full"],
    )
    parser.add_argument(
        "--summary",
        action="append",
        required=True,
        help="Official SusVibes summary.json (repeat for independent runs)",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Run label in the same order as --summary (repeatable)",
    )
    parser.add_argument(
        "--comparators",
        default=str(DEFAULT_COMPARATORS),
        help="Versioned public comparator snapshot",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only scorecard JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    output = Path(args.output).resolve()
    try:
        payload = write_susvibes_official_scorecard(
            output,
            experiment_manifest=Path(
                args.experiment_manifest
            ).resolve(),
            dataset=Path(args.dataset).resolve(),
            cohort=str(args.cohort),
            summaries=[
                Path(value).resolve()
                for value in args.summary
            ],
            labels=[str(value) for value in args.label],
            comparators=(
                Path(args.comparators).resolve()
                if args.comparators
                else None
            ),
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

    stability = payload["stability"]
    print(json.dumps({
        "schema_version": payload["schema_version"],
        "output": str(output),
        "cohort": payload["experiment"]["cohort"],
        "case_count": payload["experiment"]["case_count"],
        "run_count": stability["run_count"],
        "func_pass_mean": stability["func_pass"]["mean"],
        "sec_pass_mean": stability["sec_pass"]["mean"],
        "leaderboard_claim_allowed": payload[
            "claim_boundary"
        ]["leaderboard_claim_allowed"],
        "report_digest": payload["report_digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
