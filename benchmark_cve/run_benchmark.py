"""
CVE Benchmark harness for BELIEF bridges.

Takes a folder of known-vulnerable code snippets (one directory per CVE,
each containing `vulnerable.py` and a `metadata.json` describing what
should be found), runs every available bridge, and computes:
- precision: of findings flagged, how many were on the vulnerable line(s)?
- recall: of expected vulns, how many were found?
- by-source breakdown

A handful of reference snippets are shipped under `cve_samples/`
(see benchmark_cve/cve_samples/). You can add more.

Run:
    python3 benchmark_cve/run_benchmark.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
sys.path.insert(0, str(PROJECT_ROOT))


@dataclass
class CveSample:
    """One test case.

    vulnerable_lines: a SET of line numbers (1-based) that are part of the vuln.
    expected_cwe:     optional CWE identifier (e.g. "CWE-502")
    expected_sources: list of bridge names expected to find it
    is_multifile:     True if the sample spans multiple files (v4 hotfix #3)
    vulnerable_files: relative paths of files containing the actual sink
                      (multi-file samples only)
    sample_dir:       absolute path to the sample root dir
    """
    name: str
    path: str
    vulnerable_lines: List[int]
    expected_cwe: Optional[str] = None
    expected_sources: List[str] = field(default_factory=list)
    description: str = ""
    is_multifile: bool = False
    vulnerable_files: List[str] = field(default_factory=list)
    sample_dir: str = ""


@dataclass
class BenchmarkResult:
    sample: str
    per_source: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    missed: bool = False

    @property
    def precision(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.true_positives / self.total_findings

    @property
    def detected(self) -> bool:
        return self.true_positives > 0


def load_samples(samples_dir: Path) -> List[CveSample]:
    """Discover CVE samples. Supports both:
      - single-file: <sample_dir>/vulnerable.py + metadata.json (legacy)
      - multi-file:  <sample_dir>/**.py + metadata.json with
                     "vulnerable_files": [...] (v4 hotfix #3)
    """
    out: List[CveSample] = []
    for d in sorted(samples_dir.iterdir()):
        if not d.is_dir():
            continue
        meta = d / "metadata.json"
        if not meta.exists():
            continue
        try:
            m = json.loads(meta.read_text())
        except Exception as e:
            print(f"WARN: could not parse metadata for {d.name}: {e}")
            continue

        vuln_files = m.get("vulnerable_files", [])
        legacy_vuln = d / "vulnerable.py"

        if vuln_files:
            # multi-file: metadata says which files contain the sinks
            missing = [vf for vf in vuln_files if not (d / vf).exists()]
            if missing:
                print(f"WARN: {d.name} declares missing vulnerable_files: {missing}")
                continue
            # path points to the sample dir itself; loaders copy the whole tree
            out.append(CveSample(
                name=d.name,
                path=str(d),
                vulnerable_lines=m.get("vulnerable_lines", []),
                expected_cwe=m.get("cwe"),
                expected_sources=m.get("expected_sources", []),
                description=m.get("description", ""),
                is_multifile=True,
                vulnerable_files=vuln_files,
                sample_dir=str(d),
            ))
        elif legacy_vuln.exists():
            # legacy single-file sample
            out.append(CveSample(
                name=d.name,
                path=str(legacy_vuln),
                vulnerable_lines=m.get("vulnerable_lines", []),
                expected_cwe=m.get("cwe"),
                expected_sources=m.get("expected_sources", []),
                description=m.get("description", ""),
                is_multifile=False,
                vulnerable_files=["vulnerable.py"],
                sample_dir=str(d),
            ))
        else:
            print(f"WARN: {d.name} has metadata but no vulnerable.py or "
                  f"vulnerable_files — skipping")
    return out


def _copy_sample_to(sample: CveSample, dest: Path) -> None:
    """Copy sample contents into dest. For multi-file samples, copies the
    whole directory tree (preserving package layout so imports work).
    For legacy samples, copies the single vulnerable.py."""
    if sample.is_multifile:
        # copytree into dest; dest may already exist, so merge
        src = Path(sample.sample_dir)
        for item in src.iterdir():
            if item.name == "metadata.json":
                continue  # metadata isn't part of the code under test
            if item.is_dir():
                shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
            else:
                shutil.copy(item, dest / item.name)
    else:
        shutil.copy(sample.path, dest / "vulnerable.py")


def run_sample(sample: CveSample) -> BenchmarkResult:
    """Run every project-scoped bridge on this sample."""
    from belief.bridges import registry

    result = BenchmarkResult(sample=sample.name)

    # Copy sample into its own temp dir so bridges scan only this
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        _copy_sample_to(sample, tmp_path)

        project_bridges = {"bandit", "dlint", "semgrep", "pyt", "pyre", "path_traversal"}
        for bridge_name in sorted(project_bridges & set(registry.available())):
            r = registry.run(bridge_name, project_path=str(tmp_path))
            if r.errors:
                result.per_source[bridge_name] = {
                    "status": "unavailable",
                    "error": r.errors[0][:80],
                    "findings": 0, "tp": 0, "fp": 0,
                }
                continue

            tp = fp = 0
            per_finding = []
            # For multi-file samples, a finding is only TP if it reports
            # the correct file AND the correct line. For legacy single-file
            # samples, line match alone is enough (only one file anyway).
            vuln_basenames = {Path(vf).name for vf in sample.vulnerable_files}
            for f in r.findings:
                # Determine line. Different bridges use different fields.
                line = (f.get("line") or f.get("line_number")
                        or f.get("anchor_line") or 0)
                # File match (multi-file only)
                f_file = f.get("file") or f.get("filename") or ""
                file_ok = True
                if sample.is_multifile:
                    file_ok = Path(f_file).name in vuln_basenames
                # TP if line in vulnerable_lines (±1 tolerance) AND file matches
                is_tp = file_ok and any(
                    abs(line - v) <= 1 for v in sample.vulnerable_lines
                )
                if is_tp:
                    tp += 1
                else:
                    fp += 1
                per_finding.append({
                    "line": line,
                    "file": Path(f_file).name if f_file else "",
                    "is_tp": is_tp,
                    "code": f.get("check_id") or f.get("test_id") or f.get("code"),
                    "message": (f.get("message") or f.get("issue_text") or "")[:60],
                })
            result.per_source[bridge_name] = {
                "status": "ok",
                "findings": len(r.findings),
                "tp": tp,
                "fp": fp,
                "items": per_finding[:10],
                "elapsed_s": round(r.elapsed_s, 2),
            }
            result.total_findings += len(r.findings)
            result.true_positives += tp
            result.false_positives += fp

    if result.true_positives == 0:
        result.missed = True
    return result


def print_report(samples: List[CveSample], results: List[BenchmarkResult]):
    print("\n" + "=" * 72)
    print("CVE Benchmark — BELIEF bridges")
    print("=" * 72)

    # Per-sample
    for s, r in zip(samples, results):
        tag = "[DETECTED]" if r.detected else "[MISSED]  "
        mf = " [multi-file]" if s.is_multifile else ""
        print(f"\n{tag} {s.name:30s} (CWE={s.expected_cwe}, lines={s.vulnerable_lines}){mf}")
        print(f"            {s.description[:70]}")
        print(f"            total findings: {r.total_findings}  "
              f"TP: {r.true_positives}  FP: {r.false_positives}  "
              f"precision: {r.precision*100:.0f}%")
        for src, info in r.per_source.items():
            if info["status"] == "unavailable":
                print(f"              - {src:10s} unavailable")
            else:
                print(f"              - {src:10s} "
                      f"{info['findings']:3d} findings, "
                      f"{info['tp']:2d} TP, {info['fp']:2d} FP, "
                      f"{info['elapsed_s']}s")

    # Aggregate
    print("\n" + "-" * 72)
    total_samples = len(samples)
    detected = sum(1 for r in results if r.detected)
    recall = detected / total_samples if total_samples else 0
    total_tp = sum(r.true_positives for r in results)
    total_fp = sum(r.false_positives for r in results)
    total_findings = sum(r.total_findings for r in results)
    precision = total_tp / total_findings if total_findings else 0

    print(f"SUMMARY: {detected}/{total_samples} samples detected "
          f"(recall={recall*100:.0f}%)")
    print(f"         {total_tp} true positives, {total_fp} false positives "
          f"across {total_findings} findings (precision={precision*100:.0f}%)")

    # Per-source aggregate
    src_stats: Dict[str, Dict[str, int]] = {}
    for r in results:
        for src, info in r.per_source.items():
            if info["status"] != "ok":
                continue
            s = src_stats.setdefault(src, {"tp": 0, "fp": 0, "samples": 0})
            s["tp"] += info["tp"]
            s["fp"] += info["fp"]
            s["samples"] += 1
    if src_stats:
        print()
        print(f"{'source':<14}{'samples':<10}{'TP':<8}{'FP':<8}precision")
        for src, s in sorted(src_stats.items()):
            tot = s["tp"] + s["fp"]
            prec = s["tp"] / tot if tot else 0
            print(f"{src:<14}{s['samples']:<10}{s['tp']:<8}{s['fp']:<8}{prec*100:.0f}%")

    print()


def run_cognitive_sample(sample: CveSample, memory_dir: str) -> Dict[str, Any]:
    """v4 (B-13): measure the full CognitiveLoop on one CVE sample.

    Produces the metrics the audit specified:
      - decision_quality  = fraction of top-N goals that landed on a
                             true vulnerable line
      - belief_accuracy   = precision across all beliefs produced by the
                             loop (vs just the bridges)
      - hydra_efficiency  = confirmed_vulns / goals_dispatched
      - cognitive_overhead = seconds spent in loop over seconds of bridges
    """
    from belief.cognitive.cognitive_loop import CognitiveLoop

    sample_dir = tempfile.mkdtemp(prefix=f"belief_bench_cog_{sample.name}_")
    _copy_sample_to(sample, Path(sample_dir))

    import time
    t_loop_start = time.time()
    loop = CognitiveLoop(
        project_path=sample_dir,
        config=None,  # no LLM in benchmark — bridges + cognitive only
        memory_dir=memory_dir,
        max_investigation_budget_s=30.0,
        max_goals=5,
    )
    try:
        report = loop.run()
        loop.memory.save()
    except Exception as e:
        shutil.rmtree(sample_dir, ignore_errors=True)
        return {
            "sample": sample.name,
            "error": str(e),
            "decision_quality": 0.0,
            "belief_accuracy": 0.0,
            "hydra_efficiency": 0.0,
            "cognitive_overhead_s": 0.0,
        }
    t_loop = time.time() - t_loop_start

    # decision_quality: did top goals land on vulnerable lines?
    #
    # For multi-file samples, we also require the goal's target_file to
    # match one of the declared vulnerable_files (by basename). A goal
    # pointing at a non-vulnerable file of the same sample is NOT on-vuln.
    goals_on_vuln = 0
    total_goals = len(report.verdicts)
    vuln_lines = set(sample.vulnerable_lines)
    vuln_basenames = {Path(vf).name for vf in sample.vulnerable_files}
    confirmed_on_vuln = 0
    for v in report.verdicts:
        goal_data = v.get("goal", {}) if isinstance(v, dict) else {}
        target_line = int(goal_data.get("target_line") or 0)
        target_file = str(goal_data.get("target_file") or "")
        status = v.get("status", "") if isinstance(v, dict) else ""
        line_ok = target_line and any(
            abs(target_line - vl) <= 5 for vl in vuln_lines
        )
        file_ok = True
        if sample.is_multifile and vuln_basenames:
            file_ok = Path(target_file).name in vuln_basenames if target_file else False
        is_on_vuln = bool(line_ok and file_ok)
        if is_on_vuln:
            goals_on_vuln += 1
            if status == "confirmed":
                confirmed_on_vuln += 1
    decision_quality = goals_on_vuln / total_goals if total_goals else 0.0

    # belief_accuracy: fraction of beliefs whose location is on a vuln line.
    #
    # IMPORTANT: report.beliefs is a list of `Belief` dataclass OBJECTS, not
    # dicts. Historical bug: the benchmark called b.get("scope") on objects,
    # which raised AttributeError silently swallowed somewhere up the chain.
    # Fix: access attributes directly, with a dict fallback in case the
    # report shape ever changes.
    #
    # Multi-file: also require the belief's scope.file_path to match one of
    # vulnerable_files. A belief about a non-vulnerable file isn't "accurate"
    # even if its line number happens to coincide with a vuln line elsewhere.
    beliefs_on_vuln = 0
    for b in report.beliefs:
        b_lines: List[int] = []
        b_file: str = ""
        if hasattr(b, "predicate") and hasattr(b, "scope"):
            if getattr(b.predicate, "anchor_lines", None):
                b_lines.extend(int(x) for x in b.predicate.anchor_lines)
            if getattr(b.scope, "line_start", None):
                b_lines.append(int(b.scope.line_start))
            b_file = getattr(b.scope, "file_path", "") or ""
        elif isinstance(b, dict):
            pred = b.get("predicate", {}) or {}
            scope = b.get("scope", {}) or {}
            if isinstance(pred, dict):
                anchors = pred.get("anchor_lines") or ()
                b_lines.extend(int(x) for x in anchors)
            if isinstance(scope, dict):
                if scope.get("line_start"):
                    b_lines.append(int(scope["line_start"]))
                b_file = scope.get("file_path", "") or ""

        line_match = any(abs(l - vl) <= 1 for l in b_lines for vl in vuln_lines)
        file_match = True
        if sample.is_multifile and vuln_basenames:
            file_match = Path(b_file).name in vuln_basenames if b_file else False
        if line_match and file_match:
            beliefs_on_vuln += 1
    total_beliefs = len(report.beliefs)
    belief_accuracy = beliefs_on_vuln / total_beliefs if total_beliefs else 0.0

    # hydra_efficiency: of all goals investigated, how many landed a confirmed
    # true-positive verdict on an actually-vulnerable line?
    hydra_efficiency = (
        confirmed_on_vuln / total_goals if total_goals else 0.0
    )

    shutil.rmtree(sample_dir, ignore_errors=True)
    return {
        "sample": sample.name,
        "cwe": sample.expected_cwe or "",
        "total_beliefs": total_beliefs,
        "total_goals": total_goals,
        "goals_on_vuln": goals_on_vuln,
        "confirmed_vulns": report.confirmed_vulns,
        "refuted_fps": report.refuted_fps,
        "decision_quality": round(decision_quality, 3),
        "belief_accuracy": round(belief_accuracy, 3),
        "hydra_efficiency": round(hydra_efficiency, 3),
        "cognitive_overhead_s": round(t_loop, 2),
        "phases": report.phases,
    }


def print_cognitive_report(metrics: List[Dict[str, Any]]) -> None:
    """Pretty-print cognitive benchmark metrics."""
    if not metrics:
        print("No cognitive results.")
        return
    print("\n" + "=" * 70)
    print("COGNITIVE LOOP METRICS (v4 B-13)")
    print("=" * 70)
    print(f"{'sample':<24}{'dec_qual':<10}{'bel_acc':<10}"
          f"{'hyd_eff':<10}{'loop_s':<8}")
    print("-" * 62)
    for m in metrics:
        if "error" in m:
            print(f"{m['sample']:<24}ERROR: {m['error'][:40]}")
            continue
        print(f"{m['sample']:<24}"
              f"{m['decision_quality']:<10.2f}"
              f"{m['belief_accuracy']:<10.2f}"
              f"{m['hydra_efficiency']:<10.2f}"
              f"{m['cognitive_overhead_s']:<8.1f}")
    print("-" * 62)
    valid = [m for m in metrics if "error" not in m]
    if valid:
        avg_dq = sum(m["decision_quality"] for m in valid) / len(valid)
        avg_ba = sum(m["belief_accuracy"] for m in valid) / len(valid)
        avg_he = sum(m["hydra_efficiency"] for m in valid) / len(valid)
        print(f"{'AVERAGE':<24}{avg_dq:<10.2f}{avg_ba:<10.2f}{avg_he:<10.2f}")
    print()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="BELIEF CVE benchmark")
    parser.add_argument("--full", action="store_true",
                        help="Also run CognitiveLoop metrics (v4 B-13)")
    parser.add_argument("--memory-dir", default="/tmp/belief_bench_memory",
                        help="Memory directory for cognitive runs")
    parser.add_argument("--samples-dir", default="",
                        help="Override samples directory")
    args = parser.parse_args()

    samples_dir = Path(args.samples_dir) if args.samples_dir else HERE / "cve_samples"
    if not samples_dir.exists():
        print(f"No cve_samples/ dir at {samples_dir}")
        return 1

    samples = load_samples(samples_dir)
    if not samples:
        print("No CVE samples found.")
        return 1

    print(f"Running bridges benchmark on {len(samples)} CVE samples...")
    results = [run_sample(s) for s in samples]
    print_report(samples, results)

    out_path = HERE / "results.json"
    out_path.write_text(json.dumps([asdict(r) for r in results], indent=2))
    print(f"Machine-readable results: {out_path}")

    if args.full:
        print(f"\nRunning cognitive benchmark on {len(samples)} CVE samples...")
        Path(args.memory_dir).mkdir(parents=True, exist_ok=True)
        cog_metrics = [run_cognitive_sample(s, args.memory_dir) for s in samples]
        print_cognitive_report(cog_metrics)
        cog_path = HERE / "cognitive_results.json"
        cog_path.write_text(json.dumps(cog_metrics, indent=2))
        print(f"Cognitive results: {cog_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
