#!/usr/bin/env python3
"""Create a read-only readiness report for a SusVibes agent run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.susvibes_preflight import (  # noqa: E402
    write_susvibes_agent_preflight,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect a pinned SusVibes experiment without starting Docker "
            "or calling a model, then create a digest-bound report."
        )
    )
    parser.add_argument(
        "--susvibes-root",
        required=True,
        help="Pinned, clean SusVibes Git checkout",
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
        "--experiment-manifest",
        required=True,
        help="Evaluator-side deterministic experiment manifest",
    )
    parser.add_argument(
        "--cohort",
        required=True,
        choices=["smoke", "canary", "full"],
    )
    parser.add_argument(
        "--results-dir",
        required=True,
        help="Absent or empty isolated output directory for the future run",
    )
    parser.add_argument(
        "--model",
        required=True,
        help="Exact Anthropic model identifier for the future run",
    )
    parser.add_argument(
        "--claude-version",
        default="2.1.83",
        help="Pinned @anthropic-ai/claude-code version",
    )
    parser.add_argument(
        "--minimum-free-gib",
        type=float,
        default=None,
        help="Override the cohort-specific free-space threshold",
    )
    parser.add_argument(
        "--acknowledge-agent-network",
        action="store_true",
        help=(
            "Acknowledge future Docker image, npm, and model API network use; "
            "the preflight itself remains read-only and offline"
        ),
    )
    parser.add_argument(
        "--runner",
        default=str(
            REPOSITORY_ROOT
            / "scripts"
            / "run_susvibes_belief_claude.py"
        ),
        help="Runner that the report will bind by SHA-256",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only JSON report",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    root = Path(args.susvibes_root).resolve()
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
    output = Path(args.output).resolve()
    try:
        payload = write_susvibes_agent_preflight(
            output,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=Path(
                args.experiment_manifest
            ).resolve(),
            cohort=str(args.cohort),
            results_dir=Path(args.results_dir).resolve(),
            model=str(args.model),
            claude_version=str(args.claude_version),
            minimum_free_gib=args.minimum_free_gib,
            acknowledge_agent_network=bool(
                args.acknowledge_agent_network
            ),
            runner_path=Path(args.runner).resolve(),
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
        "output": str(output),
        "status": payload["status"],
        "ready_for_execution": payload["ready_for_execution"],
        "required_failures": payload["required_failures"],
        "report_digest": payload["report_digest"],
    }, indent=2, sort_keys=True))
    return int(payload["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
