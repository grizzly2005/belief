#!/usr/bin/env python3
"""Run the bounded native-detector negative-control gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.native_negative_control import (  # noqa: E402
    NegativeControlLimits,
    evaluate_native_negative_control,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure native detector crashes and high-confidence findings.",
    )
    parser.add_argument("--root", required=True, help="Presumed-safe Python source tree")
    parser.add_argument("--max-files", type=int, default=2_000)
    parser.add_argument("--max-file-bytes", type=int, default=1_048_576)
    parser.add_argument("--max-total-bytes", type=int, default=67_108_864)
    parser.add_argument("--high-confidence", type=float, default=0.8)
    parser.add_argument("--max-high-confidence-file-rate", type=float, default=0.005)
    parser.add_argument("--max-samples", type=int, default=20)
    parser.add_argument("--output", help="Optional create-only JSON output")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        result = evaluate_native_negative_control(
            args.root,
            limits=NegativeControlLimits(
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                high_confidence=args.high_confidence,
                max_high_confidence_file_rate=args.max_high_confidence_file_rate,
                max_samples=args.max_samples,
            ),
        )
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            output = Path(args.output).resolve()
            with output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(encoded)
        print(encoded, end="")
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        print(
            json.dumps({"error": f"{type(exc).__name__}: {exc}"}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
