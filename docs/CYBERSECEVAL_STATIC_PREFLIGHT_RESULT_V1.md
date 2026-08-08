# CyberSecEval 4 Python static preflight: v1 baseline

This is the immutable first BELIEF result produced after the protocol and
runner were frozen. It is a deliberately negative baseline.

## Binding

| Field | Value |
|---|---|
| BELIEF revision | `b6197919ad2028235052eba7b271c95f37c0bf65` |
| Upstream revision | `acfdd58f7c605eec53af4eed3f7ecf302267f0f8` |
| Dataset SHA-256 | `fa583f17875a7822355f0e29a21b5169eba445f9cfe24d87afcdc23adb270f82` |
| Preregistration digest | `4d9e730a043fef29ec8066d248e6e6bb8dbf273118ea74f09c079be41dfd1686` |
| Runner-policy digest | `c9dcb9d6dddf2d1e210443d00ef7ad643684781d57dbafdb21db668c0992ec42` |
| Result digest | `0138ceed9ba2b141c57cea2436353a8e650e152823bc04d5ec3490ef0408f544` |
| Repeated run digest | `b32f853d73624d27ca0369515cd2dcfad4c2c8f78c6654737e8a0612da5b63b9` |

Both same-checkout repetitions produced the same run digest.

## Aggregate result

| Metric | Result |
|---|---:|
| Cases | 282 |
| Detected | 17 |
| Missed while evaluable | 18 |
| Abstained | 247 |
| Python AST parseability | 0.124113 |
| Target-line location | 1.000000 |
| Evaluability | 0.124113 |
| Abstention | 0.875887 |
| All-case target sensitivity lower bound | 0.060284 |
| Target sensitivity on evaluable cases | 0.485714 |
| Declared-overlap target sensitivity lower bound | 0.061151 |
| Declared-overlap sensitivity on evaluable cases | 0.500000 |
| Analysis exceptions | 0 |

Every abstention was `python_ast_parse_failed`. The target line was located in
all 282 records, and no analyzer crashed. The dominant failure is therefore the
AST-only treatment of intentionally partial code snippets, not input binding or
target alignment.

## Positive-only per-CWE diagnostics

| Upstream CWE | Cases | Detected | Missed | Abstained | Lower bound | Evaluable only |
|---|---:|---:|---:|---:|---:|---:|
| CWE-312 | 4 | 0 | 1 | 3 | 0.000000 | 0.000000 |
| CWE-328 | 26 | 1 | 0 | 25 | 0.038462 | 1.000000 |
| CWE-338 | 27 | 0 | 4 | 23 | 0.000000 | 0.000000 |
| CWE-502 | 31 | 2 | 3 | 26 | 0.064516 | 0.400000 |
| CWE-78 | 62 | 9 | 3 | 50 | 0.145161 | 0.750000 |
| CWE-798 | 37 | 0 | 7 | 30 | 0.000000 | 0.000000 |
| CWE-89 | 33 | 3 | 0 | 30 | 0.090909 | 1.000000 |
| CWE-94 | 62 | 2 | 0 | 60 | 0.032258 | 1.000000 |

These values are not vulnerability recall. They measure alignment to public
ICD-derived positive targets under the frozen CWE mapping.

## Gate outcome

Passed:

- exact dataset binding;
- zero analysis exceptions;
- deterministic repetition stability.

Failed:

- minimum AST parseability;
- maximum abstention;
- all-case sensitivity lower bound;
- evaluable-case sensitivity;
- declared-overlap sensitivity lower bound.

## Interpretation boundary

This result is not an official CyberSecEval run. It invokes no model and
analyzes `origin_code`, not model completions. The corpus has no negative
controls or functional oracles, so the result provides no precision,
specificity, accuracy, false-positive rate, functional correctness, SecPass,
Fable comparison, Kimi comparison, or unseen-holdout claim.

No external source was imported or executed. The result retains hashes and
sanitized coordinates, but no source, prompt, target-line text, or local input
path.

The next permissible development step is a generic, bounded recovery layer for
partial Python snippets, validated with independent synthetic/metamorphic tests
before producing a versioned v2 result. This v1 artifact must remain unchanged.
