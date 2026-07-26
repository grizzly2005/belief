# Generalization Development Result

Status date: 2026-07-26

This report closes the preregistered 49-case development phase described in
[`GENERALIZATION_PROTOCOL.md`](GENERALIZATION_PROTOCOL.md). It reports the
negative result as measured. It does not report SusVibes `SecPass`, agent
`pass@1`, or a win over Claude Fable 5, Kimi, or any other model.

## Frozen inputs

| Input | Value |
|---|---|
| Starting commit | `c0263023d65cfef4ac577da4a85a72a3aeda462b` |
| E/F measurement commit | `5e80b0eca5bd35b3334a09fa7ffdc09cfeb87189` |
| E/F BELIEF source digest | `3f148a32c6532cd3eb884152a237803390315f55b2627428d77e6280ebfbcbb6` |
| Protocol SHA-256 | `e56262e93a15ebb27ae981276a8d335a3fb752352fd8986d3f2325b0b6a42808` |
| Dataset SHA-256 | `be9a4ca573559544c3f28146b3b3811e5565f0a8b4053ff4cc8f4aab6c6742f7` |
| Nested manifest SHA-256 | `74d916df62428882ae89cc46d10b9d14c01831a6e60826b317cbb77e3ae6631b` |
| Nested manifest semantic digest | `668b247f6bbe811ece6ae5db07213bab62dadf52c6c0931ea4f5ab6b054a878b` |
| Ordered development IDs digest | `a047a3218e878f504cbaf3c583012269d2e646581d5f77bf2b1977b6f6501307` |
| Selected / evaluable / reconstruction errors | `49 / 45 / 4` |

The reviewer received candidate worktrees only. Project names, CVE identifiers,
reference fixes, tests, and benchmark labels remained evaluator-side.

## Frozen ablation outcome

All percentages use the same 45 evaluable cases. The four reconstruction
errors remain in every selected count and were not silently removed.

| Variant | Vulnerable recall | Secure false-positive rate | Paired discrimination | Precision | F1 | Total time | Gate result |
|---|---:|---:|---:|---:|---:|---:|---|
| A — starting reviewer | 11.11% | 13.33% | 0.00% | not recorded | not recorded | 137.942 s | failed |
| B — diagnostics only | 11.11% | 13.33% | 0.00% | not recorded | not recorded | 133.592 s | failed |
| C — function summaries | 11.11% | 13.33% | 0.00% | not recorded | not recorded | 145.712 s | failed |
| D — flow states | 48.89% | 20.00% | 31.11% | not recorded | not recorded | 152.199 s | passed percentage gates |
| E — evidence graph without summary effects | 51.11% | 24.44% | 28.89% | 67.65% | 58.23% | 155.633 s | failed paired gate |
| F — full architecture, run 1 | 60.00% | 33.33% | 28.89% | 64.29% | 62.07% | 155.783 s | failed FP and paired gates |
| F — identical run 2 | 60.00% | 33.33% | 28.89% | 64.29% | 62.07% | 156.730 s | failed FP and paired gates |

The preregistered thresholds were recall at least 30%, secure false positives
at most 25%, and paired discrimination at least 30%. D passed those percentage
gates, but F is the required final variant and failed two of them.

E completed 88 of 90 candidate comparisons. Its two incomplete comparisons
contained explicit parse gaps and no graph-capacity limit. F completed 72 of
90 comparisons. Across its before/after graphs, incompleteness was dominated
by 109 `function_summary_per_function_limit_reached` gaps, with four focused
function omissions, four summary parse gaps, and four flow parse gaps.
`inconclusive` remained actionable as preregistered; it was never converted
into a secure pass.

## Determinism and resource evidence

Both F runs produced the same deterministic digest:

```text
dc7bf16dad3a52122cb1e042f934c1ce4c0be7ebf7dbdcddc845d0e4a78482e4
```

All 90 per-review digests, the source digest, the ordered selection digest,
scores, counts, classifications, and evidence metrics matched. Runtime-only
fields were intentionally excluded from that digest.

| Measurement | F run 1 | F run 2 |
|---|---:|---:|
| Total time | 155.783 s | 156.730 s |
| Median review time | 0.608694 s | 0.609517 s |
| Process peak RSS | 125.180 MiB | 124.484 MiB |

F total time was 1.129x and 1.136x the A total time. The preregistered median
ratio is **not comparable** because A predates per-review timing
instrumentation. A baseline peak-memory value is likewise unavailable.

## Artifact integrity

The create-only artifacts are retained outside the repository.

| Artifact | SHA-256 | Deterministic digest |
|---|---|---|
| `belief-generalization-dev-a-baseline-20260725-01.json` | `27cfb814ae8fffd9c24823f2aeafe96c9887d26575e18ccc9796dcb197ea8c30` | `800cd741f67bce5247838e3c3ae17de140edc011a9c2b0865af27cbbdd24e494` |
| `belief-generalization-dev-b-diagnostics-20260725-01.json` | `8881386066618f420cb5c2f0b11ac43a00f3b87a09a5a213f6454291aa843809` | `87f81d34eb6c01d21054234ddcae874debc6e5485e6774afffcc27f944a18380` |
| `belief-generalization-dev-c2-summaries-20260725-01.json` | `f70cf92e3ce0e1d85435796cfd6a4efcb63a337c965927701a97bdf9537a9c0b` | `21f2dfe40c10689fbf36333503d40b39c9ab5c068ca49ce5310de7edf3b8b773` |
| `belief-generalization-dev-d3-flow-states-20260726-01.json` | `4177426efcec95f132cf439302aafb807bcff42b41badd340b2a612fad7e0954` | `250ae91d4ea02cd372084edf1f1f8cfffa33460b53f6af102e247c564a360c1b` |
| `belief-generalization-dev-e-evidence-graph-20260726-01.json` | `c530b01fd92b165e27dd0cb5c7402ef7488c728d4b8b861efc0d691bf5d17d89` | `245b788fbe90a2d3868531439b729e2a58208dfcf43f469f506f9f35cf684fb4` |
| `belief-generalization-dev-f-full-20260726-01.json` | `33c422c5b1084f1114bd473f3fcd3ca1fcb40b6eb438bb0e818bba8fd2018c00` | `dc7bf16dad3a52122cb1e042f934c1ce4c0be7ebf7dbdcddc845d0e4a78482e4` |
| `belief-generalization-dev-f-full-20260726-02.json` | `caad60021d98288f7cd96ac1b0175196791664aa7ad462223b93c3b199a72167` | `dc7bf16dad3a52122cb1e042f934c1ce4c0be7ebf7dbdcddc845d0e4a78482e4` |

## Validation at the measurement revision

- Full test suite: 910 passed, 31 skipped.
- Security-marked suite: 456 passed.
- CI filter (`not slow and not external and not llm`): 910 passed,
  31 skipped.
- Focused schema and semantic metamorphic suite: 123 passed.
- Ruff: passed for `belief`, `tests`, and `scripts`.
- First-party Python compilation: passed. Vendored Python 2 Z3 examples were
  excluded and left unchanged.
- Dependency consistency: passed in all five repository-local isolated
  environments. The unrelated global Python environment has external package
  conflicts and is not used as release evidence.
- Anti-overfit scan: no development project, instance, CVE, local result path,
  or result filename was found in first-party production code.
- Architecture delta from the starting commit: 16 production files,
  9,042 additions and 31 deletions; nine test files, 2,932 additions; 18
  summary kinds and 17 semantic contract identifiers.

## Decision

### Verified

- The semantic architecture materially improved vulnerable recall over A.
- F is deterministic across two complete development runs.
- The implementation and protected metamorphic tests are green.
- F does not satisfy the preregistered development gates.

### Failure

- F secure false positives are 33.33%, above the 25% maximum.
- F paired discrimination is 28.89%, below the 30% minimum.

### Not tested

- The reserved 49-case cohort was not opened or executed in this development
  cycle.
- Optional variant G and the official Docker/model agent experiment were not
  run.

### Not comparable

- This static paired-feedback metric is not SusVibes `SecPass` or `FuncPass`.
- No claim about beating Fable 5 or Kimi is supported by these results.
- The exact preregistered median-time ratio cannot be computed from A.

The holdout therefore remains sealed. No further reviewer tuning may use this
49-case development cohort. Further architecture work requires a newly
preregistered public development corpus; holdout attestation tooling and
official-smoke preparation may continue without consuming the reserved cases.

## Post-result sealing control

After recording the negative result, a fail-closed holdout control was added
without changing reviewer verdict logic. The CLI now refuses to load the
reserved cohort unless a create-only `belief.holdout_attestation.v1` proves
that all development gates passed twice and binds the exact clean commit,
source digest, dataset, nested manifest, prepared Git cache, Python dependency
fingerprint, validation evidence, thresholds, full semantic mode, and two
ordered external result paths.

This is a verified prevention mechanism, not a holdout result. The real F1/F2
artifacts in this report have `status=failed`, so they cannot satisfy the
attestation validator. No attestation was created, no reserved ID was loaded,
and the 49-case holdout remains unconsumed.
