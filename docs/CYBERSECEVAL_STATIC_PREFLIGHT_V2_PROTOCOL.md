# CyberSecEval 4 Python static preflight: v2 protocol

Status: v2 runner frozen before the v2 result.

The immutable v1 result showed that 247 of 282 public Python snippets could not
be analyzed with an AST-only whole-snippet parser. V2 changes only the
evaluability layer and two general BELIEF semantics:

- bounded partial-Python recovery committed before this runner;
- exact-line anchoring for hardcoded-credential findings;
- security-context recognition for RNG results assigned to identifiers such as
  `salt`, `nonce`, `token`, or `apiKey`.

This is public-development tuning. It is not an unseen evaluation.

## Frozen recovery policy

Recovery receives only `origin_code` and `line_text`. It does not receive the
upstream CWE, pattern, repository, path, case ID, or any BELIEF outcome.

The ordered projections are:

1. unchanged full source when syntax-valid;
2. a full-source wrapper when valid;
3. fully dedented source and wrapper when indentation is the only barrier;
4. otherwise, the smallest target-containing window that compiles inside a
   synchronous or asynchronous synthetic function.

Bounds and tie-breaking are fixed:

- at most 25 original lines in a target window;
- at most 64 sorted synthetic parameters;
- smallest window first;
- most balanced window around the target second;
- original source order last.

Loaded but otherwise unbound identifiers become synthetic boundary parameters.
This allows the fixed BELIEF analyzers to reason about a partial call site
without inventing concrete values. Every transformed line is mapped back to an
original snippet line before target alignment.

Python compilation is used only to validate syntax and control-flow placement.
The resulting code object is discarded. No source is imported or executed.

## Frozen metrics and gates

V2 retains the positive-only v1 classification:

- `detected`: mapped CWE and original target-line intersection;
- `missed`: recovered/evaluable but no mapped target finding;
- `abstain`: no bounded recovery or analyzer exception.

The v2 gates were frozen at the same substantive targets as v1, with
whole-snippet AST parseability replaced by bounded recovery evaluability:

| Gate | Threshold |
|---|---:|
| Recovery evaluability | at least 0.85 |
| Abstention | at most 0.15 |
| Analysis exception rate | exactly 0 |
| All-case sensitivity lower bound | at least 0.50 |
| Evaluable-case sensitivity | at least 0.60 |
| Declared-overlap sensitivity lower bound | at least 0.55 |
| Same-platform repetition stability | exactly 1.00 |

V1 remains immutable and is referenced by result digest
`0138ceed9ba2b141c57cea2436353a8e650e152823bc04d5ec3490ef0408f544`.
V2 may report deltas only against that same public development cohort.

## Independent controls

The recovery component is tested independently of CyberSecEval IDs and labels.
Its negative controls include:

- literal shell commands;
- `shell=False`;
- parameterized SQL;
- `yaml.safe_load`;
- SHA-256;
- environment-loaded rather than hardcoded secrets;
- `secrets.choice`;
- identifiers such as `monkey` that merely contain the substring `key`.

These controls reduce obvious benchmark-matching shortcuts, but they cannot
replace a negative external corpus.

## Claim and safety boundary

V2 remains ineligible for precision, specificity, accuracy, false-positive
rate, functional correctness, official CyberSecEval pass rate, SecPass, Fable
or Kimi comparison, and unseen-holdout claims.

It still requires explicit external-code acknowledgement and refuses network,
subprocess, shell, Docker, model calls, external imports, arbitrary modules,
arbitrary callables, arbitrary execution targets, and result overwrite. No
source, recovered source, prompt, target text, or local input path is retained.

The authoritative machine-readable protocol is
`benchmark_cyberseceval/preregistration-v2.json`.
