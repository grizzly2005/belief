# BELIEF static-analysis ground truth v1

This corpus is intentionally limited to eight synthetic, non-executable Python
fixtures: four path-traversal variants and four IDOR/BOLA variants.  The
`static_analysis_ground_truth_v1` runner reads `cases.yml` as ground truth and
invokes the shared Python static-analysis pipeline directly for each `target`.

The fixtures are parsed as source code only.  They are not applications, do
not contain credentials, and require neither a network connection nor a
running framework or database.

The default acceptance thresholds live in `thresholds.yml`.  Runtime duration
is reported but deliberately excluded from the deterministic digest.

Metrics use the following conservative conventions:

- each row exposes `field_matches` for every declared ground-truth field and
  `matched` is true only when all those fields match (or the expected absence
  is observed);
- `verdict_accuracy` counts an exact observed verdict over all eight fixtures;
  an expected absence has no verdict and is measured separately.
- vulnerable detection and protected false-positive rates only count audit
  cases of the expected vulnerability type.
- `expected_no_case_accuracy` counts an absence only when analysis completed
  successfully; a pipeline exception can never pass a trap case.

The v1 acceptance thresholds intentionally score verdicts, vulnerable-case
detection, protected-case false positives, and expected absences only.  The
detailed `field_matches` remain diagnostic in this first increment; mismatched
guards, line sets, or root-cause wording are visible but do not alter the four
threshold metrics.

The default thresholds are 0.75 verdict accuracy, 0.75 vulnerable detection,
0.0 protected false positives, and 0.75 correct expected absences.  A failed
threshold sets the result `status` to `failed` and its `exit_code` indication
to `1`; the CLI adapter is responsible for applying that exit code.
