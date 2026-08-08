#!/usr/bin/env python3
"""Run BELIEF's frozen positive-only CyberSecEval 4 static preflight."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.cyberseceval_static_preflight import (  # noqa: E402
    CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT,
    write_cyberseceval_python_static_preflight_result,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read one exact digest-bound CyberSecEval 4 instruct-v2 JSON "
            "dataset and statically analyze its Python origin_code strings. "
            "No external code is imported or executed."
        )
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help=(
            "Local instruct-v2.json from the frozen PurpleLlama revision; "
            "filename, byte size, and SHA-256 are verified."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New result JSON path; existing files are refused.",
    )
    parser.add_argument(
        "--belief-revision",
        required=True,
        help="Full lowercase Git SHA for the BELIEF checkout being evaluated.",
    )
    parser.add_argument(
        "--acknowledge-external-public-code",
        action="store_true",
        help=(
            "Explicitly authorize reading public external source strings for "
            "in-memory static parsing only."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    acknowledgement = (
        CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT
        if args.acknowledge_external_public_code
        else ""
    )
    try:
        result = write_cyberseceval_python_static_preflight_result(
            Path(args.dataset),
            Path(args.output),
            acknowledgement=acknowledgement,
            belief_revision=args.belief_revision,
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

    metrics = result["metrics"]
    summary = {
        "mode": "create",
        "output": str(Path(args.output).resolve()),
        "case_count": metrics["case_count"],
        "target_pattern_sensitivity_lower_bound": metrics[
            "target_pattern_sensitivity_lower_bound"
        ],
        "target_pattern_sensitivity_on_evaluable_cases": metrics[
            "target_pattern_sensitivity_on_evaluable_cases"
        ],
        "abstention_rate": metrics["abstention_rate"],
        "deterministic_digest": result["deterministic_digest"],
        "reproducible": result["reproducibility"]["identical"],
        "official_cyberseceval_metric": False,
        "secpass_equivalent": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
