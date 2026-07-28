#!/usr/bin/env python3
"""Create a verified, create-only static-holdout attestation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.generalization.holdout_attestation import (  # noqa: E402
    runtime_fingerprint,
    write_holdout_attestation,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a prepared evaluator-side JSON draft and create a "
            "fail-closed static-holdout attestation. This command never "
            "loads or runs the reserved cohort."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Prepared attestation draft JSON",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New attestation path outside the BELIEF repository",
    )
    parser.add_argument(
        "--bind-current-runtime",
        action="store_true",
        help=(
            "Replace binding.runtime with the current Python executable, "
            "version, implementation, and installed-distribution digest"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("attestation draft must be a JSON object")
        binding = payload.get("binding")
        if not isinstance(binding, dict):
            raise ValueError("attestation draft binding must be an object")
        if args.bind_current_runtime:
            binding["runtime"] = runtime_fingerprint()
        written = write_holdout_attestation(payload, output_path)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
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
                "deterministic_digest": written[
                    "deterministic_digest"
                ],
                "freeze_commit": written["binding"]["freeze_commit"],
                "output": str(output_path),
                "ready_for_unseal": True,
                "reserved_case_count": written["binding"][
                    "reserved_case_count"
                ],
                "schema_version": written["schema_version"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
