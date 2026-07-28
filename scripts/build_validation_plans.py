#!/usr/bin/env python3
"""Build a deterministic validation-plan sidecar from a BELIEF audit JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.validation.plans import write_validation_plan_bundle  # noqa: E402


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert BELIEF audit evidence into versioned, deterministic, "
            "non-executing validation plans."
        )
    )
    parser.add_argument(
        "--audit",
        required=True,
        help="BELIEF scan/audit JSON containing audit_cases",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Validation-plan bundle JSON output",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacement of an existing output (default: create-only)",
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    output = Path(args.output).resolve()
    try:
        payload = write_validation_plan_bundle(
            args.audit,
            output,
            overwrite=bool(args.overwrite),
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

    print(
        json.dumps(
            {
                "schema_version": payload["schema_version"],
                "output": str(output),
                "plan_count": payload["plan_count"],
                "by_strategy": payload["counts"]["by_strategy"],
                "deterministic_digest": payload["deterministic_digest"],
                "executes_target": payload["execution_boundary"][
                    "executes_target"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
