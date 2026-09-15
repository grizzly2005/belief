#!/usr/bin/env python3
"""Offline adjudication of the frozen Setuptools fixed-revision path helper.

Loads a hash-pinned Git blob and executes only its two reviewed pure helpers.
No package import, network operation, download or filesystem sink is executed.
The supplied namespace exposes only URL parsing and pure path operations.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import ntpath
import os
from pathlib import Path
import posixpath
import subprocess
from types import SimpleNamespace
import urllib.parse


FIXED_REVISION = "250a6d17978f9f6ac3ac887091f2d32886fbbb0b"
SOURCE_PATH = "setuptools/package_index.py"
SOURCE_SHA256 = "870ffc77a62224af26252657edcdc035002dbf31f6557be807516d0fc34f842e"
HELPERS = ("egg_info_for_url", "_resolve_download_filename")


def load_pinned_helpers(repository: Path) -> tuple[ast.Module, dict[str, list[int]]]:
    result = subprocess.run(
        ["git", "-C", str(repository), "show", f"{FIXED_REVISION}:{SOURCE_PATH}"],
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
             "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"},
        capture_output=True,
        check=True,
        timeout=15,
    )
    if hashlib.sha256(result.stdout).hexdigest() != SOURCE_SHA256:
        raise ValueError("the fixed source blob does not match the frozen SHA-256")
    tree = ast.parse(result.stdout.decode("utf-8"))
    nodes = []
    lines = {}
    for name in HELPERS:
        matches = [node for node in ast.walk(tree)
                   if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one pinned helper: {name}")
        node = copy.deepcopy(matches[0])
        lines[name] = [node.lineno, node.end_lineno]
        node.decorator_list = []
        if (isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)):
            node.body.pop(0)
        nodes.append(node)
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), lines


def adjudicate(repository: Path) -> dict:
    tree, line_ranges = load_pinned_helpers(repository)
    code = compile(tree, "<pinned-setuptools-pure-helpers>", "exec")
    rows = []
    for platform, path_module, root in (
        ("posix", posixpath, "/synthetic/download"),
        ("windows", ntpath, "C:\\synthetic\\download"),
    ):
        namespace = {
            "__builtins__": {"str": str, "ValueError": ValueError},
            "os": SimpleNamespace(path=path_module),
            "urllib": SimpleNamespace(parse=SimpleNamespace(
                urlparse=urllib.parse.urlparse, unquote=urllib.parse.unquote,
            )),
        }
        exec(code, namespace)  # exact blob hash checked before compiling two pure helpers
        helper = namespace["_resolve_download_filename"]
        sibling = path_module.join(root + "-sibling", "probe.bin")
        cases = (
            ("ordinary_leaf", root, "probe.bin", True, True),
            ("absolute_inside", root, path_module.join(root, "probe.bin"), True, True),
            ("absolute_unrelated", root, path_module.join(root + "-other", "probe.bin")
             .replace("download", "outside"), False, None),
            ("known_root_prefix_sibling", root, sibling, True, False),
            ("root_with_separator", path_module.join(root, ""), sibling, False, None),
            ("wrong_root_guess", root, sibling.replace("download", "unknown"), False, None),
            ("dot_component_scrubbing", root, "../probe.bin", True, True),
            ("empty_leaf_fallback", root, "", True, True),
        )
        for label, base, supplied, expected_accept, expected_inside in cases:
            url = "https://example.invalid/" + urllib.parse.quote(supplied, safe="")
            selected = None
            error = None
            try:
                selected = helper(url, base)
            except ValueError:
                error = "ValueError"
            accepted = selected is not None
            inside = None
            if accepted:
                inside = path_module.commonpath((base, selected)) == path_module.normpath(base)
            matched = accepted == expected_accept and inside == expected_inside
            rows.append({
                "platform": platform, "case": label, "url": url, "root": base,
                "selected_path": selected, "accepted": accepted,
                "inside_by_path_components": inside, "error": error,
                "expected_behavior_observed": matched,
            })
    reproduced = all(row["expected_behavior_observed"] for row in rows)
    payload = {
        "schema_version": "belief.paired_control_adjudication.v1",
        "case_id": "setuptools-cve-2025-47273",
        "source_revision": FIXED_REVISION,
        "source_path": SOURCE_PATH,
        "source_sha256": SOURCE_SHA256,
        "helper_line_ranges": line_ranges,
        "case_count": len(rows),
        "status": "reproduced" if reproduced else "mismatch",
        "conclusion": ("fixed_revision_not_a_universal_containment_negative_control"
                       if reproduced else "adjudication_inconclusive"),
        "limits": [
            "only the pinned filename-selection helpers were executed",
            "the sibling case assumes knowledge of the synthetic root prefix",
            "Windows behavior is pure ntpath emulation, not a Windows file write",
            "no package import, download, file write, symlink or live exploit test",
            "the original paired benchmark and thresholds remain unchanged",
        ],
        "cases": rows,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["deterministic_digest"] = hashlib.sha256(encoded).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="New create-only JSON result")
    args = parser.parse_args()
    result = adjudicate(args.repo)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({key: result[key] for key in
                      ("status", "case_count", "deterministic_digest", "conclusion")}))
    return 0 if result["status"] == "reproduced" else 1


if __name__ == "__main__":
    raise SystemExit(main())
