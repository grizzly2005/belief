"""Measure the six preregistered pure-function controls without executing them."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
import tempfile
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from belief.benchmark.open_source_pairs import (  # noqa: E402
    _git_bytes,
    _project_analysis,
    _resolve_repository,
    load_open_source_pairs_manifest,
)
from belief.static_analysis_pipeline import (  # noqa: E402
    StaticAnalysisOptions,
    analyze_static_target,
)
from scripts.run_open_source_pairs_benchmark import _belief_revision  # noqa: E402


def digest(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    if output.exists():
        raise FileExistsError(output)
    revision = _belief_revision()
    folder = Path(__file__).resolve().parent
    manifest_bytes = (folder / "benign-controls.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    assert manifest["repetitions"] == 2
    assert len(manifest["controls"]) == 6
    cases = {
        case["project"]: case
        for case in load_open_source_pairs_manifest(folder / "cases.json")["cases"]
    }
    options = StaticAnalysisOptions(
        max_files=8,
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        reportability=True,
        max_file_bytes=2 * 1024 * 1024,
        max_total_source_bytes=8 * 1024 * 1024,
    )
    prepared = []
    # Complete provenance/extraction checks before invoking the detector.
    for control in manifest["controls"]:
        case = cases[control["project"]]
        assert control["revision"] == case["fixed_revision"]
        assert control["checkout_dir"] == case["checkout_dir"]
        assert control["expected_warning_count"] == 0
        repository = _resolve_repository(Path(args.repos_root).resolve(), case)
        raw = _git_bytes(repository, "cat-file", "blob", f"{control['revision']}:{control['path']}")
        assert hashlib.sha256(raw).hexdigest() == control["source_sha256"]
        text = raw.decode("utf8")
        nodes = [
            node for node in ast.walk(ast.parse(text))
            if isinstance(node, ast.FunctionDef)
            and node.name == control["function"]
            and [node.lineno, node.end_lineno] == control["line_range"]
        ]
        assert len(nodes) == 1
        node = nodes[0]
        snippet = textwrap.dedent("\n".join(text.splitlines()[node.lineno - 1:node.end_lineno])) + "\n"
        assert hashlib.sha256(snippet.encode()).hexdigest() == control["snippet_sha256"]
        ast.parse(snippet)
        prepared.append((control, snippet))

    started = time.perf_counter()
    results = []
    for control, snippet in prepared:
        projections = []
        for _ in range(2):
            with tempfile.TemporaryDirectory(prefix="belief-benign-control-") as tmp:
                snapshot = Path(tmp)
                (snapshot / "control.py").write_bytes(snippet.encode())
                try:
                    analysis = analyze_static_target(snapshot, options)
                    projection = _project_analysis(
                        analysis,
                        {"case_type": "path_traversal_possible", "targets": [{"path": "control.py", "relevant_line_range": [1, len(snippet.splitlines())]}]},
                        snapshot,
                    )
                except Exception as exc:
                    projection = {"analysis_succeeded": False, "error_type": type(exc).__name__}
                projections.append(projection)
        hashes = [digest(item) for item in projections]
        results.append({
            "id": control["id"],
            "project": control["project"],
            "snippet_sha256": control["snippet_sha256"],
            "repetition_digests": hashes,
            "deterministic": hashes[0] == hashes[1],
            "repetitions": projections,
            "passed": hashes[0] == hashes[1] and all(
                item["analysis_succeeded"] and item["warning_count"] == 0
                for item in projections
            ),
        })
    status = "passed" if all(item["passed"] for item in results) else "failed"
    result = {
        "schema_version": "belief.benign_function_control_result.v1",
        "belief_revision": revision,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "analysis_options": options.to_dict(),
        "claim_boundary": manifest["claim_boundary"],
        "third_party_code_executed": False,
        "network_used_by_runner": False,
        "control_count": len(results),
        "repetitions_per_control": 2,
        "status": status,
        "exit_code": 0 if status == "passed" else 1,
        "controls": results,
        "deterministic_digest": digest(results),
        "duration_seconds": round(time.perf_counter() - started, 6),
    }
    with output.open("x", encoding="utf8", newline="\n") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ("status", "control_count", "exit_code", "deterministic_digest", "duration_seconds")}, indent=2))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
