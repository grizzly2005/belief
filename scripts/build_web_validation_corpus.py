#!/usr/bin/env python3
"""Create or verify the preregistered transparent web corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.benchmark.web_generalization import (  # noqa: E402
    verify_web_validation_development_corpus,
    write_web_validation_development_corpus,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create or verify the create-only transparent web-validation "
            "development corpus."
        )
    )
    parser.add_argument(
        "--starting-commit",
        help="Frozen 40-hex Phase B commit; required when creating.",
    )
    parser.add_argument(
        "--verify",
        metavar="ROOT",
        help="Verify an existing corpus without writing.",
    )
    parser.add_argument(
        "--output",
        help="New output directory; refused if it already exists.",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    try:
        if args.verify:
            if args.output or args.starting_commit:
                raise ValueError(
                    "--verify cannot be combined with creation arguments"
                )
            summary = verify_web_validation_development_corpus(
                Path(args.verify)
            )
            summary["mode"] = "verify"
        else:
            if not args.output or not args.starting_commit:
                raise ValueError(
                    "--output and --starting-commit are required"
                )
            summary = write_web_validation_development_corpus(
                Path(args.output),
                starting_commit=args.starting_commit,
            )
            summary["mode"] = "create"
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            json.dumps(
                {"error": f"{type(exc).__name__}: {exc}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
