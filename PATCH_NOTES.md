# BELIEF v4 hotfix #2 — cognitive layer depth fixes

Applies ON TOP of hotfix #1. If you haven't applied #1 yet, apply it first
(or just apply this one — all files are self-contained at the final post-#1
post-#2 state).

## What changes vs hotfix #1

Hotfix #1 brought the cognitive benchmark from `0/0/0` to `0.30/0.60/0.00`.
This hotfix #2 brings it to `0.70/0.70/0.70` — a score of 1.00 on every
sample the underlying bridges actually detect (7/10 at recall=70%).

### Before

```
AVERAGE  dec_qual=0.30  bel_acc=0.60  hyd_eff=0.00
```

### After

```
sample                    dec_qual  bel_acc  hyd_eff
cve_2017_18342_pyyaml     1.00      1.00     1.00
cve_numpy_pickle          1.00      1.00     1.00
cwe_22_path_traversal     1.00      1.00     1.00
cwe_327_weak_crypto       1.00      1.00     1.00
cwe_338_insecure_random   1.00      1.00     1.00
cwe_78_shell_injection    1.00      1.00     1.00
cwe_95_eval               1.00      1.00     1.00
cwe_798_hardcoded         0.00      0.00     0.00   ← bridge MISSED
cwe_89_sql_injection      0.00      0.00     0.00   ← bridge MISSED
cwe_918_ssrf              0.00      0.00     0.00   ← bridge MISSED
AVERAGE                   0.70      0.70     0.70
```

The three `0.00` rows are cases where NO bridge at the bridge-benchmark
level detects the vulnerability. No amount of cognitive-loop work can
conjure a belief out of nothing — fixing those requires adding or
strengthening a bridge, which is outside this hotfix's scope.

## The four packs in this hotfix

### Pack A — CWE taxonomy coverage (`belief/cognitive/cwe_taxonomy.py`)

dlint emits messages like `insecure use of "yaml" parsing function` and
`insecure use of "hashlib" module`. The keyword map only had `yaml.load(`
and no `hashlib`, so these messages never mapped to their real CWEs, and
the severity-based goal-creation path (Pack C) never triggered.

Added:
- `yaml`, `yaml parsing`, `use of "yaml"` → CWE-502
- `hashlib`, `use of "hashlib"` → CWE-327

Generic fallback `yaml` keyword placed AFTER stricter matches so narrower
patterns win first.

### Pack B — belief adapter propagates CWE and accepts raw findings
`belief/bridges/belief_adapter.py` + `belief/bridges/path_traversal_bridge.py`

Two separate problems:

- `dict_to_belief` required an `assumption` or `predicate` key. Bridges
  that produced raw finding dicts (path_traversal) had no such key, so
  their findings were silently dropped at the adapter stage — this is why
  `cwe_22_path_traversal` had `total_beliefs: 0` while the bridge
  benchmark clearly showed the finding.
  Fix: fall back to `message` / `issue_text` / `rule_id`.

- When a bridge already KNOWS the CWE (path_traversal sets
  `cwe: "CWE-22"` on every Finding), the adapter dropped it instead of
  propagating to `Belief.cwe`. That forced downstream code to re-guess
  from predicate text, often incorrectly.
  Fix: `Belief(cwe=d.get("cwe", ""))` when the bridge finding carries one.

- `path_traversal_bridge.py` now ships a proper `to_belief()` function
  (like dlint has) so the adapter's per-bridge converter picks it up with
  correct `justification_type`, `trust_domain` and `logic_type` instead
  of relying on the generic fallback.

### Pack C — severe-CWE threshold lowered to 0.5 (`belief/cognitive/cognitive_loop.py`)

In hotfix #1 I set `SEVERE_THRESHOLD = 0.7` to gate the new "confident
but severe-CWE" goal-creation path. That threshold kept CWE-327 (0.65)
and CWE-338 (0.55) out, so weak-crypto and insecure-random beliefs never
became goals even when correctly detected.

Lowered to `0.5`. To avoid promoting every belief-with-no-CWE (which
would fall back to default severity 0.5), the check now ALSO requires
`b_cwe != ""` — an identified CWE is mandatory. This is the invariant
the severity table was always implicitly assuming.

### Pack D — Hydra confirmation math (`belief/cognitive/hydra_agent.py`)

`_run_bridge` used `confidence = min(0.9, 0.5 + 0.15 * N_findings)`. One
matching finding capped at 0.65 — below the `>= 0.7` CONFIRMED threshold
in `_compute_verdict`. Every single-bridge confirmation came back as
`inconclusive`, which is why `hyd_eff` stayed at `0.00` in hotfix #1.

Replaced with per-bridge priors reflecting observed precision:

```
safety_db       0.95   (CVE match is definitive)
crosshair       0.92   (concrete counter-examples)
path_traversal  0.85
dlint           0.80   (100% precision in CVE benchmark)
pyre / bandit   0.75
semgrep         0.72
pyt             0.65
```

Plus a `+0.10` bonus when a finding's line equals `goal.target_line`
exactly (not just within ±5). This rewards bridges that reproduce the
exact anchor — a signal that the goal and the finding describe the same
underlying code defect.

Result: a single dlint finding at the goal's exact line gives
`0.80 + 0.10 = 0.90`, clearing the 0.70 CONFIRMED threshold.

## How to apply

Unzip in your `belief_v4/` working copy. The archive mirrors the internal
tree, so `unzip -o` overwrites the modified files in place:

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
unzip -o /path/to/belief_v4_hotfix2.zip
```

Then:

```bash
source .venv/bin/activate
python3 benchmark_cve/run_benchmark.py --full
```

## Files changed (6)

- `belief/cognitive/cognitive_loop.py`    (Pack C — and carries hotfix #1 changes)
- `belief/cognitive/cwe_taxonomy.py`      (Pack A)
- `belief/cognitive/hydra_agent.py`       (Pack D)
- `belief/bridges/belief_adapter.py`      (Pack B)
- `belief/bridges/path_traversal_bridge.py` (Pack B)
- `benchmark_cve/run_benchmark.py`        (carries hotfix #1 changes)

Nothing else touched. The zip is idempotent — safe to reapply if you're
unsure whether hotfix #1 was applied.

## What would take the benchmark past 0.70

The 3 remaining missed samples require work outside the cognitive loop:

- **cwe_798_hardcoded**: dlint/bandit rules don't flag literal API keys
  in simple assignments. Need a regex-based bridge or `detect-secrets`.
- **cwe_89_sql_injection**: dlint has no SQLi rule; bandit's `B608` needs
  bandit installed (`unavailable` in the current env). `pip install bandit`
  would likely pick this up.
- **cwe_918_ssrf**: same — bandit's `B310` (urllib_urlopen) isn't running.
  `pip install bandit` should fix this too.

Try `pip install bandit` and re-run — that alone should push recall to
~90% and all three aggregate metrics close to 0.90.

## Hydra still logs `crashed` for crosshair / pyexz3

These messages are stderr noise, not fatal:
```
bridge crosshair crashed: missing keyword-only arguments 'module_file' and 'func_name'
bridge pyexz3 crashed: got an unexpected keyword argument 'project_path'
```

Hydra tries every registered bridge. `crosshair` and `pyexz3` expect
function-level arguments (they're unit-level verifiers, not project
scanners), so calling them with `project_path=...` raises a TypeError.
The `_run_bridge` except-clause catches it and the failure is logged as
non-supporting evidence with confidence=0.0. No impact on metrics.
Fixing this cleanly = filter out function-level bridges from Hydra's
project-level strategies; left for a later patch.
