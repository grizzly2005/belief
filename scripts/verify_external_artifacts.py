"""Verify the create-only measurement artifacts kept outside the repository.

Recorded results bind a reviewer to artifacts that deliberately live outside
this repository. Nothing in the repository could previously tell whether those
files are still present and unmodified, so a silent loss or a bit flip on the
external volume would surface only when someone tried to reproduce a result.

This reads `research/external_artifacts.json`, hashes each listed file under a
supplied root, and reports one line per artifact. It is fail-closed: a missing
or mismatched artifact exits non-zero.

It reads bytes and computes digests. It executes nothing, opens no network
connection, writes no file, and never loads a reserved holdout case.

    python scripts/verify_external_artifacts.py --root F:/belief-rd
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

_INDEX_SCHEMA_VERSION = "belief.external_artifacts.v1"
_READ_CHUNK_BYTES = 1024 * 1024

_STATUS_VERIFIED = "verified"
_STATUS_MISSING = "missing"
_STATUS_MISMATCHED = "mismatched"
_STATUS_UNREADABLE = "unreadable"


def default_index_path() -> Path:
    return Path(__file__).resolve().parent.parent / "research" / "external_artifacts.json"


def load_index(path: Path) -> dict[str, Any]:
    """Load and structurally validate the artifact index."""
    try:
        index = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"cannot read artifact index: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"artifact index is not valid JSON: {exc}") from exc

    if not isinstance(index, dict):
        raise SystemExit("artifact index must be a JSON object")
    if index.get("schema_version") != _INDEX_SCHEMA_VERSION:
        raise SystemExit(
            f"artifact index schema must be {_INDEX_SCHEMA_VERSION}"
        )

    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit("artifact index must list at least one artifact")

    seen_paths: set[str] = set()
    for entry in artifacts:
        if not isinstance(entry, dict):
            raise SystemExit("each artifact entry must be a JSON object")
        entry_path = entry.get("path")
        digest = entry.get("sha256")
        if not isinstance(entry_path, str) or not entry_path:
            raise SystemExit("each artifact entry needs a non-empty path")
        if entry_path.startswith("/") or ".." in Path(entry_path).parts:
            raise SystemExit(
                f"artifact path must stay under the root: {entry_path}"
            )
        if entry_path in seen_paths:
            raise SystemExit(f"duplicate artifact path: {entry_path}")
        seen_paths.add(entry_path)
        if not isinstance(digest, str) or len(digest) != 64:
            raise SystemExit(
                f"artifact {entry_path} needs a 64-character sha256"
            )
        if digest != digest.lower() or set(digest) - set("0123456789abcdef"):
            raise SystemExit(
                f"artifact {entry_path} sha256 must be lowercase hexadecimal"
            )
    return index


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(root: Path, entry: dict[str, Any]) -> dict[str, Any]:
    relative = str(entry["path"])
    expected = str(entry["sha256"])
    candidate = root / relative
    result: dict[str, Any] = {
        "path": relative,
        "role": entry.get("role", ""),
        "expected_sha256": expected,
    }
    if not candidate.is_file():
        result["status"] = _STATUS_MISSING
        return result
    try:
        actual = file_sha256(candidate)
    except OSError as exc:
        result["status"] = _STATUS_UNREADABLE
        result["error"] = type(exc).__name__
        return result
    result["actual_sha256"] = actual
    result["status"] = (
        _STATUS_VERIFIED if actual == expected else _STATUS_MISMATCHED
    )
    return result


def verify(root: Path, index: dict[str, Any]) -> dict[str, Any]:
    results = [verify_artifact(root, entry) for entry in index["artifacts"]]
    counts = {
        status: sum(1 for item in results if item["status"] == status)
        for status in (
            _STATUS_VERIFIED,
            _STATUS_MISSING,
            _STATUS_MISMATCHED,
            _STATUS_UNREADABLE,
        )
    }
    return {
        "schema_version": "belief.external_artifacts_verification.v1",
        "root": root.as_posix(),
        "recorded_on": index.get("recorded_on", ""),
        "counts": counts,
        "ok": counts[_STATUS_VERIFIED] == len(results),
        "artifacts": sorted(results, key=lambda item: item["path"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify create-only measurement artifacts held outside the "
            "repository against their recorded SHA-256 digests."
        )
    )
    parser.add_argument(
        "--root",
        required=True,
        help="Directory holding the external artifact tree",
    )
    parser.add_argument(
        "--index",
        default=None,
        help="Artifact index (default: research/external_artifacts.json)",
    )
    parser.add_argument(
        "--json-output",
        default=None,
        help="Write the full verification report to this path",
    )
    args = parser.parse_args(argv)

    index_path = (
        default_index_path() if args.index is None else Path(args.index)
    )
    index = load_index(index_path)

    root = Path(args.root)
    if not root.is_dir():
        raise SystemExit(f"artifact root is not a directory: {root}")

    report = verify(root.resolve(), index)

    for item in report["artifacts"]:
        print(f"{item['status']:<11} {item['path']}")
    print(json.dumps(report["counts"], sort_keys=True))

    if args.json_output is not None:
        output = Path(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
