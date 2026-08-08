# Transparent Web-Validation Development Result

Status: negative development baseline; reserved cohort remains sealed

## Frozen inputs

- BELIEF starting commit:
  `a5e9fdac71e96b39fffdd543e8c1e8135fc4f01e`
- corpus/preregistration commit: `1a356dd`
- runner freeze commit: `9ba5334`
- preregistration digest:
  `707ed8bc95e52a09077dc37b20c088510b528848dcdc189cd18e61c3974cda11`
- development manifest digest:
  `a556ad3b2b2c2374d9dbe9b9c61470ec7536a5593f6d6dda5e92d82103543fad`
- runner policy digest:
  `61d3c8ee6a6f5c41d67db87cb234cb8de6aeae2c8e9c853d1e872104a7cb730f`

The exact machine-readable result is
[`development-static.json`](../benchmark_web_validation_results/development-static.json).
Its deterministic digest is
`93fff3fe046e854cb9ffab0130913a20c40268c431ba437c2f3b98f00a5bc57e`.

## Result

| Measurement | Result | Gate | Verdict |
|---|---:|---:|---|
| Static precision | 0.000000 | at least 0.70 | fail |
| Static recall | 0.000000 | at least 0.70 | fail |
| Static binary accuracy | 0.583333 | descriptive | n/a |
| Static abstention | 0.000000 | at most 0.25 | pass |
| Plan-generation coverage | 1.000000 | descriptive | n/a |
| Semantic-digest stability | 1.000000 | exactly 1.00 | pass |
| Executable-plan coverage | unmeasured | at least 0.75 | unmeasured |

The binary confusion counts are:

- true positive: 0;
- false positive: 2;
- true negative: 14;
- false negative: 8;
- binary abstention: 0.

All eight ambiguous cases were classified `safe`; none produced an
abstention. Two of 32 cases produced matching audit cases, and both were safe
path-traversal cases in the same Flask decorator family: one protected case
and one false-positive trap. Both received non-executing plans, hence two of
two eligible cases had a generated plan. This does not measure executable-plan
coverage.

## Scan composition

The runner scanned all 32 expected files with no diagnostic:

- 663 filtered findings;
- 587 structural findings;
- 72 temporal findings;
- 4 security findings;
- 0 taint findings;
- 2 matching audit cases.

The two frozen repetitions produced the identical pre-wrapper digest:
`af154736e1f895fb7cc7eee6107690a25e6deed4ef14fed4c493c9d2bc4b99ba`.

## Interpretation

This is a valid negative development result, not evidence of competitive
security performance. The current generic pipeline does not recognize the
synthetic Flask/FastAPI path and resource-authorization flows, while two safe
decorator cases still surface as candidates. A plan-generation rate of 100%
over only two false-positive cases has no security value by itself.

The permitted next step is development-only improvement of general static
semantics, followed by a new versioned result. Thresholds, split membership,
and this baseline must not change. The reserved 16-case cohort and every
SusVibes reserved artifact remain unopened.

This result is not `SecPass`, is not an Agent Security League score, and cannot
support a comparison or superiority claim against Fable 5, Kimi, or any other
system.
