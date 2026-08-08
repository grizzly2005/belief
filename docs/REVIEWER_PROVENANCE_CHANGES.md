# Reviewer provenance changes after a recorded measurement

Recorded results in this repository bind a reviewer to an exact commit and an
exact source digest over the normalized first-party Python files. Those records
stay valid as written: they describe what a specific reviewer did at a specific
revision.

This file exists so a later reader can tell, without re-deriving it, whether a
*new* run can be compared to a recorded one. It is append-only. It does not
amend, reinterpret, or re-score any recorded result.

Two effects are tracked separately, because they are not the same thing:

- **digest break** — the reviewer source digest changes, so the recorded
  provenance no longer matches the working tree. Any code change causes this,
  including a comment.
- **behavior break** — the reviewer can emit a different verdict for the same
  input. Only this one invalidates a numeric comparison.

## Recorded measurements this file applies to

| Record | Reviewer commit | Source digest |
|---|---|---|
| [`GENERALIZATION_RESULTS.md`](GENERALIZATION_RESULTS.md) | `5e80b0eca5bd35b3334a09fa7ffdc09cfeb87189` | `3f148a32c6532cd3eb884152a237803390315f55b2627428d77e6280ebfbcbb6` |
| [`../benchmark_susvibes/README.md`](../benchmark_susvibes/README.md) artifact-unseen result | `2c6208fda2fa8fdbb281ae89a196a72a6d57b350` | `16eace68f2753bb11b64e5cd0f57cd9dd1ea9eabf4afa3290286dd38da2a6d2b` |

## 2026-08-08 — Bandit informational filtering

Change: `belief/bridges/bandit_bridge.py` gained
`BANDIT_INFORMATIONAL_TEST_IDS` and `run_bandit(drop_informational=True)`.
Bandit's blacklist-import family (`B401`-`B415`) and three control-flow
hygiene checks (`B101`, `B110`, `B112`) are removed before findings reach
triage.

- digest break: **yes**
- behavior break: **yes, outside the recorded benchmark path**

Scope of the behavior change, as checked rather than assumed:

- `bandit_bridge` is reachable only through `belief.bridges.registry` ->
  `HydraAgent` -> `CognitiveLoop`, that is the opt-in `cognitive` pipeline
  phase and its CLI entry point;
- `belief/benchmark/` and `belief/generalization/` reference neither the
  cognitive loop nor the bridge registry, so `susvibes_candidate_review_v1`
  never invokes this bridge;
- therefore the two recorded results above do not depend on it, and this change
  does not retroactively alter them.

Any workflow that *does* run the cognitive loop with Bandit installed can now
see a finding disappear. Such a run is not comparable to one made before this
date. The direction of the effect is not predicted here and was not measured
against any reserved cohort.

Reproducing a Bandit-fed measurement requires `drop_informational=False`, which
restores Bandit's raw finding set. The disk cache stores raw Bandit output, so
the same cache entry serves both settings.

`B603` and `B607` were deliberately **not** classified as informational. They
are noisy, but they are call sites carrying a real CWE-78 mapping; dropping them
would remove candidate sinks rather than noise.

## 2026-08-08 — MCP per-session store isolation

Change: `belief/mcp/session.py` added; `BeliefMCPServer` resolves one
`BeliefMCPTools` per caller session; `belief://capabilities` reports
`storage.isolation`.

- digest break: **yes**
- behavior break: **no**

The MCP facade is not on the static benchmark path. `belief benchmark
reportability` does not construct an MCP dispatcher, and the new
`validation_capacity` parameter defaults to the previous behavior. No recorded
number depends on this change.

It is listed anyway: the recorded source digests cover every normalized
first-party Python file, so the working tree no longer matches them, and a
future reader must not mistake a digest mismatch for an untouched reviewer.
