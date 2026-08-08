# Transparent Web-Validation Development Result v2

Status: static development gates passed after public-cohort tuning; reserved
cohort remains sealed

## Frozen lineage

- BELIEF starting commit:
  `a5e9fdac71e96b39fffdd543e8c1e8135fc4f01e`
- corpus/preregistration commit: `1a356dd`
- runner freeze commit: `9ba5334`
- immutable negative baseline commit: `8600d1c`
- general web-semantics implementation commit: `207fb91`
- preregistration digest:
  `707ed8bc95e52a09077dc37b20c088510b528848dcdc189cd18e61c3974cda11`
- development manifest digest:
  `a556ad3b2b2c2374d9dbe9b9c61470ec7536a5593f6d6dda5e92d82103543fad`
- unchanged runner policy digest:
  `61d3c8ee6a6f5c41d67db87cb234cb8de6aeae2c8e9c853d1e872104a7cb730f`

The exact machine-readable result is
[`development-static-v2.json`](../benchmark_web_validation_results/development-static-v2.json).
Its deterministic digest is
`a73ba62aa8e6eb2c33e55f781aab2b16187c18f8b068c4831f95f3cefcd86a1b`.

## Result

| Measurement | v1 | v2 | Frozen gate | v2 verdict |
|---|---:|---:|---:|---|
| Static precision | 0.000000 | 1.000000 | at least 0.70 | pass |
| Static recall | 0.000000 | 1.000000 | at least 0.70 | pass |
| Static binary accuracy | 0.583333 | 1.000000 | descriptive | n/a |
| Static abstention | 0.000000 | 0.000000 | at most 0.25 | pass |
| Plan-generation coverage | 1.000000 | 1.000000 | descriptive | n/a |
| Semantic-digest stability | 1.000000 | 1.000000 | exactly 1.00 | pass |
| Executable-plan coverage | unmeasured | unmeasured | at least 0.75 | unmeasured |

The v2 binary confusion counts are:

- true positive: 8;
- false positive: 0;
- true negative: 16;
- false negative: 0;
- binary abstention: 0.

All four vulnerable path cases and all four vulnerable IDOR/BOLA cases
produced a matching candidate. All 16 protected or trap cases produced no
matching candidate. The eight ambiguous external-policy cases were classified
`safe` by the frozen no-matching-case rule and are excluded from precision and
recall. This is absence of a matching static candidate, not proof that the
external policy is safe.

Eight cases were plan-eligible and all eight received canonical,
non-executing plans. No plan was bound to a worker or registry, so executable
coverage remains unmeasured.

## Semantic change

The v2 implementation adds bounded, framework-light AST semantics for:

- route and local dependency reachability;
- transparent same-file path-sink, serializer, and mutator wrappers;
- path basename reduction and dominating store-boundary checks;
- path guards placed after a sink;
- resource lookup provenance from route parameters or request collections;
- owner and tenant binding on the same selected resource;
- wrong-resource and partial guards;
- state mutation before authorization;
- filtered resource selection, decoy values, and external-policy boundaries;
- recursive wrapper-summary convergence.

No case ID, family ID, source digest, expected label, reserved identity, or
benchmark-specific filename is an analysis rule.

Before the v2 result was written:

- 20 independent web-semantic/metamorphic tests passed;
- 140 targeted security regressions passed;
- the complete local suite passed with `1189 passed, 34 skipped`;
- Ruff passed over `belief`, `scripts`, and `tests`.

## Reproducibility and limits

The two same-checkout Windows repetitions produced the identical pre-wrapper
digest:
`087c4d39dd054d4c717379c4bd4239de78abef4083a7a5581992ae485e579c71`.

The scan covered all 32 files with no diagnostic, yielding 663 findings in
total, eight security findings, and eight matching audit cases.

This is a tuned public-development result. It is not an unseen holdout result,
does not establish real-project generalization, and does not measure runtime
behavior, functional regressions, protected regressions, oracle evaluability,
evidence-gap resolution, executable-plan coverage, worker failures, or
Windows/Linux agreement.

The reserved 16-case cohort and every SusVibes reserved artifact remain
unopened. This result is not `SecPass`, is not an Agent Security League score,
and cannot support a comparison or superiority claim against Fable 5, Kimi,
or another system.
