# BELIEF proof-state audit — HEAD 44fc724

Read-only audit performed 2026-08-24 to select the next bounded implementation
increment. Three candidate directions were compared: proof/PDX F3 integration,
durable external-intelligence replay, and release/schema migration risk.

> Implementation note: the commit that adds this point-in-time audit also
> implements Option D and migrates the SFT sink to the strict, recomputed
> `belief.sft.v2` contract. Findings below intentionally describe the audited
> `44fc724` baseline; the repository tests capture their resolved behavior.

## 1. Repository state

| Item | Value |
| --- | --- |
| Toplevel | `C:/Users/tatam/Desktop/projects/belief-v4` |
| Remote | `git@github.com:grizzly2005/belief.git` |
| Branch | `grizzly/proof-state-external-intelligence` |
| HEAD | `44fc7249d3819723a7b44331b3ba61ae1a224647` |
| Initial `git status --porcelain` | empty (clean) |
| Final `git status --porcelain` | one untracked file: this document |
| Latest tag | `v0.2.0` |

The three commits under audit are `7cb056b` (gate validation proof and external
intelligence), `da6e4e8` (durable proof ledger and external intelligence), and
`44fc724` (harden proof snapshots and intelligence collection).

## 2. Verification log

Every command below was executed; exit codes are observed, not inferred.

| # | Kind | Command | Exit | Result |
| --- | --- | --- | --- | --- |
| V1 | test | `python -m pytest tests/test_validation_proof.py tests/test_validation_proof_ledger.py tests/test_intelligence_collection.py tests/test_intelligence_context.py tests/test_reportability_scoring.py -q` | 0 | 106 passed in 11.86s |
| V2 | test | `python -m pytest -q -p no:cacheprovider -m "not slow and not external and not llm"` | 0 | 1641 passed, 36 skipped, 7 warnings in 166.36s |
| V3 | lint | `python -m ruff check belief tests` | 0 | All checks passed |
| V4 | static_analysis | probe: `ReportabilityAssessment.to_dict()` key set | 0 | serialized key is `blockers`; `blocking_factors` absent |
| V5 | static_analysis | probe: `subject_kind` reachability across gate and ledger | 0 | gate pins `audit_case`; sole proof-producing path pins `validation_contract_seed` |
| V6 | static_analysis | probe: `attach_reportability_to_cases` with no proof inputs | 0 | `verdict=needs_manual_validation score=79 legacy_score=100 proof_state=quarantined` |
| V7 | static_analysis | probe: `proof_subject_digest` stability across result carriers | 0 | stable for `metadata.validation_results`, unstable for both `external_raw` carriers |
| V8 | static_analysis | probe: intelligence model round-trip capability | 0 | 5/5 classes have `to_dict`, 0/5 have `from_dict` |

An earlier V2 attempt failed with exit 4 (`unrecognized arguments: --timeout=300`
— `pytest-timeout` is not installed). It was re-run without that flag; the exit 0
above is the real run.

## 3. What actually exists at HEAD

`belief/validation/proof.py` (837 lines) defines the fail-closed proof link:
`ValidationProof`, `VerifiedProofMaterial`, `VerifiedProofIndex`, and
`assess_validation_result_proof()`. A proof cannot verify itself; promotion
requires an externally supplied index.

`belief/validation/ledger.py` (2070 lines) adds the durable authority store:
create-only scope registration, pending-record transactions with roll-forward,
an integrity-bound scope inventory, a SHA-256 CAS, and `load_scope()` returning a
lock-consistent `VerifiedProofSnapshot` (`ledger.py:655-803`).

`belief/reportability/scoring.py` (641 lines) is the gate. `assess_audit_case_reportability()`
caps any case without a verified `bypassed` proof at 79
(`scoring.py:267-274`), keeping it at `needs_manual_validation`.

`belief/intelligence/` (~2400 lines across 7 modules) implements strict NVD and
GitHub advisory parsing plus bounded multi-page collection, all marked
`classification="context_only"`, `proof_eligible=False`.

The engineering quality of these three commits is high: the transaction and
roll-forward design, the result-id collision quarantine, and the credential
isolation in the transport layer are all carefully done. The findings below are
about integration seams, not about the core mechanisms.

## 4. Findings

Severity: **P0** ships a wrong security outcome; **P1** blocks the feature from
working as documented; **P2** is a correctness or migration defect with a
workaround; **P3** is hygiene.

### P1-1 (CONFIRMED) — subject digest is self-referential on the tool-import/PDX carrier

`proof_subject_digest()` strips `external_intelligence`, `reasoning`,
`reportability`, and `validation_results` from case metadata before hashing
(`belief/validation/proof.py:685-691` and again at `:704-710`). Its docstring
(`proof.py:674-679`) states the reason: validation results are derived children
of a case, and including them "would make a proof recursively depend on itself."

But the gate discovers validation results from **three** carriers
(`belief/reportability/scoring.py:516-529`):

- `metadata["validation_results"]` — excluded from the digest ✅
- `metadata["external_raw"]["validation_results"]` — **not excluded** ❌
- `metadata["external_raw"]["pdx"]["validation_results"]` — **not excluded** ❌

`metadata["external_raw"]` is populated for every imported tool result, including
PDX bundles, at `belief/tool_results/mapper.py:53` and `belief/tools/normalize.py:16`.

Probe V7 output:

```
baseline subject digest: b50276f1c112af18 | baseline results scored: 0
metadata.validation_results          digest_stable=True  results_scored=1
external_raw.validation_results      digest_stable=False results_scored=1
external_raw.pdx.validation_results  digest_stable=False results_scored=1
BOTH direct + external_raw           digest_stable=False results_scored=2
```

**Failure scenario.** An operator builds a plan for a PDX-imported case; the plan
pins `proof_subject_sha256` (consumed at `ledger.py:389-397`). Validation runs and
the terminal result is attached through the tool-import carrier. The case content
has now changed, so `proof_subject_digest(case)` no longer equals the pinned
digest. `VerifiedProofIndex.resolve()` returns
`validation_proof_subject_sha256_mismatch` (`proof.py:513-517`), and
`assess_audit_case_reportability` quarantines the case. The proof is real, the
ledger is intact, and promotion is nevertheless impossible — permanently, because
re-deriving the digest after attachment produces a *different* digest again on the
next attachment.

This is a fail-closed failure, so it is not an authority bypass. It is
nonetheless the difference between "the proof path works for PDX-sourced cases"
and "it cannot".

**Coverage gap.** No test exercises digest stability across the `external_raw`
carrier. `tests/test_validation_proof.py` calls `proof_subject_digest` five times
(`:92, :174, :379, :429, :700`), always on `_high_signal_case({})`, which uses the
direct carrier only. `tests/test_pdx_validation_result.py` is the only test file
referencing `external_raw`, and it does not touch proofs.

### P1-2 (CONFIRMED) — no reachable promotion path for any real audit case

The gate resolves proofs with `subject_kind` hardcoded to `"audit_case"`
(`belief/reportability/scoring.py:162`).

The only code path in the repository that can emit a `ValidationProof` is
`_finish_registered_fixture_attempt` → `_finish_attempt(publish_proof=True)`
(`belief/validation/ledger.py:620` — probe V5 confirms this is the *sole*
`publish_proof=True` occurrence in the module). Its public entry point,
`run_registered_fixture_validation_with_ledger`, hard-refuses anything that is not
a contract seed against a registered fixture (`ledger.py:1955-1962`):

```python
if (
    plan.subject_kind != "validation_contract_seed"
    or authority_context.target_id != expected_target
):
    raise ValidationProofLedgerError(
        "durable fixture validation cannot authorize a project target"
    )
```

The public `finish_attempt()` always passes `publish_proof=False`
(`ledger.py:494`), and its docstring is explicit that a caller-supplied result is
"durable audit material, not an oracle verdict" (`ledger.py:478-484`).

Consequence: the ledger can never produce a `VerifiedProofSnapshot` whose index
resolves an `audit_case` subject. Every "verified" outcome in the test suite is
produced from a hand-built `VerifiedProofIndex` — see
`tests/test_validation_proof.py:267-281`
(`test_verified_bypass_proof_can_cross_reportability_gate`), which constructs
`VerifiedProofMaterial` directly via the `_material` helper at `:76-95`. The one
test that drives a real ledger end-to-end into the gate asserts the opposite:
`tests/test_validation_proof_ledger.py:537-538` requires
`proof_state == "signal_only"` and `verdict != "reportable_candidate"`.

This is **intended** at HEAD — `ledger.py:1944-1948` and
`docs/VALIDATION_PROOF_V1.md:136-144` both say a real-target executor is
deliberately deferred. It is recorded here as P1 because the gap is invisible from
the outside: the documentation reads as though the durable path is usable, and no
test names the constraint. It is the strategic blocker, not the next increment.

### P2-1 (CONFIRMED) — "operator supplied no index" is reported as "quarantined"

`docs/VALIDATION_PROOF_V1.md:34-35` defines the vocabulary: missing proof is
`signal_only`; "malformed, orphaned, unresolved, or cross-engagement/cross-target"
proof is `quarantined`. Folding *unresolved* into that bucket means a missing
operator input is indistinguishable from tampering.

This is the default production path. `belief/static_analysis_pipeline.py:696-699`
calls `attach_reportability_to_cases(cases)` with no proof arguments, and
`belief/cli.py` never constructs a snapshot (probe: no `proof_snapshot` or `ledger`
reference anywhere in `cli.py`; the only exporter call is
`write_bug_bounty_markdown` at `cli.py:795-797`, without proof arguments).

Probe V6, replicating exactly what the pipeline does:

```
CLI-equivalent path (no proof snapshot):
  verdict     = needs_manual_validation
  score       = 79
  legacy_score= 100
  proof_state = quarantined
  negative    = ['validation_proof_unresolved',
                 'verified bypass proof required for reportable candidate']
```

**Failure scenario.** A triage dashboard or benchmark reads
`metadata.reportability.proof_state` to flag suspicious cases. Every honest,
proof-carrying case from a normal CLI scan is flagged `quarantined`. The signal
that should mean "someone forged a proof link" fires on ordinary operation, so it
gets ignored — and a genuinely forged proof then hides in the noise. The
distinguishing detail exists only inside the free-text `negative_factors` list.

### P2-2 (CONFIRMED) — validation plans silently drop reportability blockers

`belief/validation/plans.py:311-318` reads `reportability.get("blocking_factors")`.
The serialized key is `blockers` (`belief/reportability/models.py:52`). Probe V4:

```
serialized_reportability_keys: ['blockers', 'confidence', 'guard_applicability',
  'legacy_score', 'missing_evidence', 'negative_factors', 'positive_factors',
  'proof_state', 'score', 'validation_steps', 'verdict', 'verified_proof_ids']
has_blocking_factors: False
has_blockers: True
```

`blocking_factors` appears exactly once in the entire repository — at that read
site. The `reportability_blocker:*` evidence gaps are therefore never emitted, and
generated validation plans understate what is missing. Dead code that looks live.

### P2-3 (CONFIRMED) — duplicated results double the legacy score delta

`_validation_results()` (`scoring.py:516-529`) concatenates all three carriers
without deduplication. Probe V7 last row: one logical result present in both the
direct and `external_raw` carriers is scored twice.

Verified proofs are protected — `scoring.py:170-173` dedupes on
`seen_verified_proof_ids` — so the gated `score` is safe. `legacy_score` is not:
`_legacy_validation_delta()` (`scoring.py:532-553`) applies its ±20/±25/±35 deltas
per occurrence. `legacy_score` is documented as diagnostic-only
(`VALIDATION_PROOF_V1.md:39-40`) and probe V6 confirms no non-test consumer reads
it, so impact is confined to audit/migration diagnostics.

### P2-4 (CONFIRMED) — serialized reportability consumers remain unmigrated

`docs/VALIDATION_PROOF_V1.md:89-92` states the requirement plainly:

> Dataset, benchmark, and MCP projections that retain serialized reportability
> fields are not authority-bearing inputs. They must be migrated to accept a
> trusted assessment object before those fields are used for training, filtering,
> or automation.

None have been migrated. All of these still read `metadata["reportability"]` as a
plain dict:

| Site | Use |
| --- | --- |
| `belief/datasets/sft.py:43` | `verdict`, `score`, factors → SFT training rows |
| `belief/reasoning/router.py:40` | factors → offline reasoning input |
| `belief/benchmark/static_analysis.py:349,367` | `verdict` → benchmark scoring |
| `belief/benchmark/susvibes.py:882` | benchmark projection |
| `belief/mcp/tools.py:1015-1019` | verbatim copy into MCP `explain_case` |
| `belief/validation/plans.py:311` | evidence gaps (also P2-2) |
| `belief/cli.py:571` | scan summary counts |

Because the pipeline writes these blocks with `proof_state="quarantined"` (P2-1),
what reaches SFT export today is a `needs_manual_validation` / 79 label on cases
whose `legacy_score` was 100. That is arguably the *conservative* direction, but
it is an unreviewed labelling change flowing into training data.

### P2-5 (CONFIRMED) — ledger record schemas are undocumented

`schemas/` contains 12 files including `belief-validation-proof-v1.schema.json`,
which does match the implementation (verified by
`tests/test_validation_proof.py:314`). Four durable on-disk record formats
introduced by `da6e4e8` have no schema file and no external contract:

- `belief.validation_proof_scope.v1` (`ledger.py:51`)
- `belief.validation_scope_inventory.v1` (`ledger.py:52`)
- `belief.validation_attempt.v1` (`ledger.py:53`)
- `belief.validation_terminal.v1` (`ledger.py:54`)

These are persisted to disk and read back after restart. Any future field change
is a silent on-disk migration with no versioned contract to diff against, and
`_validate_record_integrity` (`ledger.py:184-197`) will reject old records as a
digest mismatch rather than as a recognisable version skew.

### P3-1 (CONFIRMED) — the intelligence subsystem has no consumers and cannot replay

Probe V8: `ExternalIntelligenceCollection`, `ExternalIntelligencePage`,
`ExternalIntelligenceBatch`, `ExternalIntelligenceRecord`, and `CollectionLimits`
all expose `to_dict()`; **none** expose `from_dict()`. A collection can be
serialized and never reconstructed, so durable replay is not merely absent — the
type system has no entry point for it.

A repository-wide search for `external_intelligence` outside the package itself
returns only `belief/validation/proof.py:686` and `:705` — the exclusion list in
`proof_subject_digest`, which strips a `metadata["external_intelligence"]` key
that no producer in the repository writes. The 63 symbols in
`belief.intelligence.__all__` include nothing matching store / ledger / replay /
checkpoint / persist / resume.

### P3-2 (CONFIRMED) — `snapshot_consistency` is a frozen placeholder

`belief/intelligence/collection.py:121` declares
`snapshot_consistency: str = field(default="unverified", init=False)`. It is never
assigned anywhere. It is surfaced in `to_dict()` (`:164`) and asserted equal to
`"unverified"` by `tests/test_intelligence_collection.py:223` and `:573`. Honest
as a boundary marker; it reads as a computed field and is not one.

### P3-3 (CONFIRMED) — private helper imported across module boundaries

`belief/exporters/bug_bounty_markdown.py:14-17` imports `_resolve_proof_inputs`
from `belief.reportability.scoring`. The underscore-private mixing rule
(snapshot vs. index/context, `scoring.py:363-375`) is a real invariant and
deserves to be public API rather than a private import.

### P3-4 (CONFIRMED) — the ledger has no CLI surface

`belief/cli.py` registers ~40 subparsers; none reach `ValidationProofLedger`.
There is no way to register a scope, inspect a snapshot, or pass an authority pin
from the command line. The durable proof feature is library-only.

### P3-5 (CONFIRMED) — README omits the proof gate

`README.md:564` describes the five reportability verdicts and says BELIEF "does
not treat static-only evidence as confirmation." It does not mention that
`reportable_candidate` now requires a verified bypass proof and is unreachable
through the CLI. The README never mentions the proof ledger or external
intelligence at all.

No P0 findings. The gate fails closed in every path examined; no probe produced
an unearned promotion.

## 5. Ranked options

### Option A — proof/PDX F3 integration

**What it would mean.** Let PDX observation attestations contribute to
`VerifiedProofMaterial`, so an F3-verified observation can support promotion.

**Assessment: reject as stated.** This reverses a deliberate, documented security
decision. `belief/pdx/attestation_store.py:121` hard-requires every accepted
observation reference to carry
`proof_state == "signal_only_no_belief_attempt_result_evidence"`, and
`docs/PDX_BELIEF_INTEGRATION.md:153-156` states that no PDX producer boolean can
create BELIEF outcomes, which "require a future BELIEF-owned attempt/result/evidence
path." The F3 attestation deliberately contains no attempt id, result id, or
evidence object (`PDX_BELIEF_INTEGRATION.md:37-40`) — it is structurally incapable
of satisfying `VerifiedProofMaterial`'s bindings without inventing them. Doing this
now would be the single most dangerous change available in this repository.

There *is* a safe subset — fixing P1-1 so PDX-imported cases can carry a stable
subject digest — and that is folded into the recommendation below.

### Option B — durable external-intelligence replay

**What it would mean.** Content-address and persist collected pages so a
collection can be replayed after restart, per the note at
`docs/EXTERNAL_INTELLIGENCE.md:143-150` ("Cursor checkpoints must be durable
before adding Crossref bulk collection").

**Assessment: defer.** The subsystem currently has zero consumers (P3-1). Building
durable replay for data that nothing reads inverts the dependency order, and the
boundary is `proof_eligible=False` by design, so replay adds no authority — only
cost savings and reproducibility for a feature not yet wired in. The prerequisite
is not durability; it is a first consumer and a `from_dict` round-trip. Revisit
once something in `belief/` actually reads a collection.

### Option C — release/schema migration risk

**What it would mean.** Publish schema files for the four undocumented ledger
record formats (P2-5), migrate the seven serialized-reportability consumers
(P2-4), and correct the README (P3-5).

**Assessment: real, but not yet bounded.** P2-4 in particular touches training
data, benchmark scoring, and the MCP surface. Doing it correctly requires the
trusted-assessment object to exist first — and that depends on the vocabulary fix
in P2-1. Sequenced second.

### Recommended — Option D: proof binding hygiene

Not on the original list, but it is the correct next increment: it is small,
independently testable, fixes two confirmed defects, and is a hard prerequisite
for both A and C.

Ranking: **D (recommended) > C > B > A (reject as stated)**.

## 6. Implementation contract for Option D

Scope: `belief/validation/proof.py`, `belief/reportability/scoring.py`,
`belief/reportability/models.py`, `belief/validation/plans.py`, plus tests and
docs. No changes to `belief/validation/ledger.py` or `belief/intelligence/`.

**D1 — single source of truth for derived-child carriers.**

Introduce one module-level constant in `belief/validation/proof.py`:

```python
DERIVED_SUBJECT_METADATA_FIELDS = frozenset({
    "external_intelligence", "reasoning", "reportability", "validation_results",
})
```

Replace both duplicated literal tuples (`proof.py:685-691`, `:704-710`) with it.
Then extend `proof_subject_digest()` to strip the same derived fields from
`metadata["external_raw"]` and `metadata["external_raw"]["pdx"]`, mirroring the
exact carrier set that `scoring._validation_results()` reads.

Invariant to hold: *for every carrier from which the gate reads a validation
result, attaching a result to that carrier must not change
`proof_subject_digest(case)`.*

Prune empty containers consistently — if `external_raw` becomes `{}` after
stripping, remove the key, matching the existing `metadata` handling at
`proof.py:711-714`, so the digest does not depend on whether a carrier was
present-but-empty.

**D2 — separate `unresolved` from `quarantined`.**

Add `"unresolved"` to `VALIDATION_PROOF_STATES` (`proof.py:27`) and to
`ReportabilityProofState` (`models.py:21`). Return it from
`assess_validation_result_proof()` in exactly one place — the
`proof_index is None` branch at `proof.py:627-632` — leaving every other
quarantine reason untouched. Extend `_proof_state()` (`scoring.py:556-562`) with
precedence `quarantined > unresolved > verified > signal_only`, so a genuine
quarantine is never masked by an unresolved sibling.

Scoring must not change: `unresolved` blocks promotion exactly as `quarantined`
does today, via the unchanged `verified_bypass` check at `scoring.py:267-272`.
This is a vocabulary fix, not a policy change. Note it as an additive enum change
in `docs/VALIDATION_PROOF_V1.md`.

**D3 — fix the dead blocker read.**

`belief/validation/plans.py:316`: `blocking_factors` → `blockers`.

**D4 — dedupe carriers.**

`scoring._validation_results()`: drop exact-duplicate result payloads (compare on
canonical JSON) before returning, so a result mirrored into two carriers is scored
once.

Explicitly **not** in scope: any change to who may publish a proof, the
`subject_kind="audit_case"` binding, the ledger's authority model, or the PDX
`signal_only` boundary.

## 7. Exact tests to add

In `tests/test_validation_proof.py`:

1. `test_subject_digest_is_stable_across_every_validation_result_carrier` —
   parametrised over `metadata.validation_results`,
   `metadata.external_raw.validation_results`, and
   `metadata.external_raw.pdx.validation_results`; assert
   `proof_subject_digest(case) == baseline` for all three. Fails at HEAD for the
   last two (probe V7).
2. `test_pdx_carrier_result_does_not_invalidate_a_pinned_proof` — pin a subject
   digest, attach the result via `external_raw.pdx`, resolve through a
   `VerifiedProofIndex`, assert `proof_state == "verified"`. This is the
   end-to-end regression for P1-1.
3. `test_empty_external_raw_after_stripping_does_not_change_digest` — guards the
   D1 pruning rule.
4. `test_missing_proof_index_is_unresolved_not_quarantined` — assert
   `proof_state == "unresolved"` and `"validation_proof_unresolved" in reasons`.
5. `test_unresolved_proof_still_cannot_reach_reportable_candidate` — the
   fail-closed guarantee for D2; assert `verdict != "reportable_candidate"` and
   `score <= 79`.
6. `test_quarantine_takes_precedence_over_unresolved` — one malformed proof plus
   one unresolved proof on the same case yields `quarantined`.

In `tests/test_reportability_scoring.py`:

7. `test_duplicate_result_across_carriers_is_scored_once` — assert `legacy_score`
   matches the single-occurrence value (D4).

In `tests/test_validation_plans.py`:

8. `test_evidence_gaps_include_reportability_blockers` — build a case whose
   serialized reportability carries a non-empty `blockers` list, assert a
   `reportability_blocker:<name>` gap is emitted. Fails at HEAD (P2-2).

In `tests/test_validation_proof_ledger.py`:

9. `test_registered_fixture_runner_refuses_an_audit_case_subject` — assert
   `ValidationProofLedgerError` for `subject_kind="audit_case"`. This does not fix
   P1-2; it makes the constraint explicit and load-bearing so a future executor
   cannot silently widen it.

Regression bar: V1, V2, and V3 must stay at exit 0.

## 8. Evidence classification

**Confirmed** (read in source and reproduced by an executed probe): P1-1, P1-2,
P2-1, P2-2, P2-3, P3-1, P3-2. Also the V1/V2/V3 suite and lint results.

**Confirmed by direct source reading**, without a dedicated runtime probe: P2-4
(seven call sites listed with line numbers), P2-5 (schema-version constants
enumerated and diffed against `schemas/`), P3-3, P3-4, P3-5.

**Inference** (reasoned from confirmed facts, not directly executed):

- That P1-1 causes *permanent* quarantine follows from the digest changing on each
  attachment; the repeated-attachment case was not executed.
- That P2-4's effect on SFT data is "conservative" assumes downstream training
  treats a lower score as safer. Not measured.
- The ranking of Option B as premature assumes no out-of-repo consumer of
  `belief.intelligence` exists. Only this repository was searched.

**Untested risks** (identified, not exercised):

- Concurrency: `_exclusive()` (`ledger.py:1907`) was not tested under real
  contention or across processes on Windows.
- Crash-consistency: roll-forward (`ledger.py:1422-1504`) is covered by tests that
  simulate partial state, not by actual process kills or power loss.
- The rollback caveat documented at `VALIDATION_PROOF_V1.md:148-156` — an adversary
  rewriting both records and inventory — is acknowledged in the design and was not
  probed.
- CAS behaviour at the configured byte ceilings
  (`DEFAULT_MAX_TOTAL_EVIDENCE_BYTES`, `ledger.py:59`) was not exercised at scale.

**External facts** (from repository documentation, not independently verified in
this audit): the live provider snapshot at `docs/EXTERNAL_INTELLIGENCE.md:111-125`
(NVD/CISA KEV/OSV/GitHub probes dated 2026-08-23) and all provider licence
characterisations at `:103-109`. No network calls were made during this audit.

## 9. Recommendation

Implement Option D as the next bounded increment: one commit touching four
`belief/` files plus nine tests, fixing P1-1, P2-1, P2-2, and P2-3. It is the
prerequisite for Option C and for any safe subset of Option A, and it is the only
candidate that repairs a confirmed correctness defect rather than adding surface.

Sequence after D: Option C (publish the four ledger record schemas, then migrate
the serialized-reportability consumers behind a trusted assessment object,
starting with `belief/datasets/sft.py` since it feeds training data). Option B
after a first consumer exists. Option A only behind a separately reviewed
real-target executor and authority policy, as `ledger.py:1944-1948` already
requires.
