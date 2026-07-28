#!/usr/bin/env python3
"""Create a no-execution preregistration for paired SusVibes smoke arms."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.susvibes_paired_smoke import (  # noqa: E402
    write_susvibes_paired_smoke_preregistration,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze same-task Claude Code baseline and BELIEF-feedback "
            "SusVibes smoke arms without executing either arm."
        )
    )
    parser.add_argument("--susvibes-root", required=True)
    parser.add_argument("--dataset", default="")
    parser.add_argument("--experiment-manifest", required=True)
    parser.add_argument("--belief-root", default=str(REPOSITORY_ROOT))
    parser.add_argument(
        "--runner",
        default=str(
            REPOSITORY_ROOT
            / "scripts"
            / "run_susvibes_belief_claude.py"
        ),
    )
    parser.add_argument("--baseline-results-dir", required=True)
    parser.add_argument("--belief-results-dir", required=True)
    parser.add_argument("--baseline-preflight-report", required=True)
    parser.add_argument("--belief-preflight-report", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--claude-version", default="2.1.218")
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--num-instances", type=int, default=3)
    parser.add_argument("--output", required=True)
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
    try:
        payload = write_susvibes_paired_smoke_preregistration(
            Path(args.output).resolve(),
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=Path(
                args.experiment_manifest
            ).resolve(),
            belief_root=Path(args.belief_root).resolve(),
            runner_path=Path(args.runner).resolve(),
            baseline_results_dir=Path(
                args.baseline_results_dir
            ).resolve(),
            belief_results_dir=Path(args.belief_results_dir).resolve(),
            baseline_preflight_report=Path(
                args.baseline_preflight_report
            ).resolve(),
            belief_preflight_report=Path(
                args.belief_preflight_report
            ).resolve(),
            model=str(args.model),
            claude_version=str(args.claude_version),
            start_index=int(args.start_index),
            num_instances=int(args.num_instances),
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
        "output": str(Path(args.output).resolve()),
        "status": payload["status"],
        "task_count": payload["experiment"]["num_instances"],
        "preregistration_digest": payload["preregistration_digest"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
