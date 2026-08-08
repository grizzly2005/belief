# CyberSecEval 4 Python static preflight: v2 result

V2 passes every preregistered engineering gate on the same public development
corpus used to diagnose v1. It remains a positive-only static sensitivity
result, not a security leaderboard score.

## Binding

| Field | Value |
|---|---|
| BELIEF revision | `b658d61618eea74dcca20573d3b872b008f820a4` |
| Upstream revision | `acfdd58f7c605eec53af4eed3f7ecf302267f0f8` |
| Dataset SHA-256 | `fa583f17875a7822355f0e29a21b5169eba445f9cfe24d87afcdc23adb270f82` |
| V2 preregistration digest | `f138a36f0e3c235fe8b8a1944678eb89cd9d63c873fd923034c4791362e8a9bf` |
| V2 runner-policy digest | `0a68fcfaa04c8f49a0c3def22f27aa2ffe002356ffd853f3cd52752627af6b37` |
| V2 result digest | `9669a18cec9b1c3df4dde2664cd4487465a21ffd6342e2251eab9172a45d11f2` |
| Repeated run digest | `837b3ec025a5a6ba4a4199317f3d1862c6e61997855653c90e79a40eac0d6e14` |

Both same-checkout repetitions produced the same run digest.

## Aggregate result

| Metric | V1 | V2 | Delta |
|---|---:|---:|---:|
| Detected | 17 | 203 | +186 |
| Missed while evaluable | 18 | 72 | +54 |
| Abstained | 247 | 7 | -240 |
| Raw AST parseability | 0.124113 | 0.124113 | 0.000000 |
| Evaluability | 0.124113 | 0.975177 | +0.851064 |
| Abstention | 0.875887 | 0.024823 | -0.851064 |
| All-case target sensitivity lower bound | 0.060284 | 0.719858 | +0.659574 |
| Target sensitivity on evaluable cases | 0.485714 | 0.738182 | +0.252468 |

The raw input did not become easier. The improvement comes from the bounded
recovery layer: 345 deterministic projections over 282 cases, comprising:

- 35 raw projections;
- 33 full raw wrappers;
- 37 full dedented projections;
- 37 full dedented wrappers;
- 203 target-window synchronous wrappers;
- no asynchronous wrapper was needed by this cohort.

All seven remaining abstentions were `partial_recovery_failed`. There were no
analysis exceptions.

## Positive-only per-CWE diagnostics

| Upstream CWE | Cases | Detected | Missed | Abstained | Lower bound | Evaluable only |
|---|---:|---:|---:|---:|---:|---:|
| CWE-312 | 4 | 0 | 2 | 2 | 0.000000 | 0.000000 |
| CWE-328 | 26 | 24 | 1 | 1 | 0.923077 | 0.960000 |
| CWE-338 | 27 | 0 | 27 | 0 | 0.000000 | 0.000000 |
| CWE-502 | 31 | 30 | 1 | 0 | 0.967742 | 0.967742 |
| CWE-78 | 62 | 56 | 5 | 1 | 0.903226 | 0.918033 |
| CWE-798 | 37 | 14 | 23 | 0 | 0.378378 | 0.378378 |
| CWE-89 | 33 | 24 | 9 | 0 | 0.727273 | 0.727273 |
| CWE-94 | 62 | 55 | 4 | 3 | 0.887097 | 0.932203 |

The declared-overlap sensitivity lower bound is `0.730216`, and sensitivity on
evaluable declared-overlap cases is `0.743590`.

The zero result for CWE-338 is a concrete remaining blind spot. BELIEF retains
its conservative requirement for security context before classifying ordinary
non-cryptographic RNG use, while the upstream ICD-derived positives are
broader. CWE-312 is outside BELIEF's declared overlap. CWE-798 also remains
weak, and the upstream detector's broad hardcoded-secret labels cannot be
treated as manually verified vulnerabilities.

## Gate outcome

All frozen gates passed:

- exact dataset binding;
- recovery evaluability at least 0.85;
- abstention at most 0.15;
- zero analysis exceptions;
- all-case sensitivity lower bound at least 0.50;
- evaluable-case sensitivity at least 0.60;
- declared-overlap sensitivity lower bound at least 0.55;
- deterministic repetition stability of 1.00.

Before the v2 runner was frozen, the generic recovery and security semantics
passed 769 marked security tests with 3 skips, and Ruff passed over first-party
code and tests. Those tests include independent safe negative controls and do
not use CyberSecEval IDs, repository names, paths, digests, or expected CWEs.

## Interpretation boundary

This is explicitly public-development tuning:

- the same public corpus was used to diagnose v1 and evaluate v2;
- no negative external controls or functional oracles exist in this dataset;
- no model was invoked;
- `origin_code` was analyzed rather than generated completions;
- no SusVibes or web-validation reserved holdout was opened.

Accordingly, v2 does not measure precision, specificity, accuracy,
false-positive rate, functional correctness, official CyberSecEval pass rate,
SecPass, or superiority over Fable 5 or Kimi. The next scientifically useful
step is a separately frozen external corpus containing secure controls or
vulnerable/fixed pairs, without changing this result.

No external source was imported or executed. The result retains only digests,
classifications, bounded recovery metadata, and sanitized original-line
coordinates.
