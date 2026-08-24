# Validation proof v1

Status: implemented as a fail-closed compatibility boundary with an opt-in
durable authority ledger.

## Context

`belief.validation_result.v1` historically exposed `tested` and
`human_validated` booleans.  Reportability and offline reasoning treated those
caller-controlled values as authority.  A forged `outcome="bypassed"` plus
`tested=true` could therefore increase a candidate score without a durable
attempt, terminal result, oracle identity, or content-addressed evidence.

PDX F3 already neutralizes this path for legacy PDX verdicts, but the generic
`ValidationResult` path remained permissive.

## Decision

1. Keep the v1 booleans readable for wire compatibility, but treat them only as
   legacy claims.
2. `validation_result_from_plan()` preserves the booleans for wire and local
   executor compatibility and mirrors them as `metadata.claimed_tested` and
   `metadata.claimed_human_validated`; neither representation is authority.
3. Add strict `belief.validation_proof.v1` links containing engagement, target,
   subject, plan, attempt, terminal result, oracle identity/version, and at
   least one content-addressed evidence reference.
4. A proof payload cannot verify itself.  Reportability accepts promotion only
   when a separate `VerifiedProofIndex`, built from trusted ledger material,
   resolves the canonical proof and every binding. The reportability caller
   must also supply a `ProofAuthorityContext` obtained outside the audit-case
   payload; `case.metadata` can never establish engagement or target scope.
5. Missing proof is `signal_only`.  Malformed, orphaned, unresolved, or
   cross-engagement/cross-target proof is `quarantined`.
6. A `reportable_candidate` requires a verified `bypassed` proof.  Heuristic
   scores without that proof are capped at 79 and remain
   `needs_manual_validation`.
7. The former score remains visible as `legacy_score` for migration and audit;
   it is never used to choose the new verdict.
8. Multiple tool names no longer establish independent corroboration.  The
   bonus requires explicit independent lineage identifiers, and the proof gate
   still controls reportability.
9. Offline reasoning no longer treats legacy `tested` or `human_validated`
   booleans as proof of enforcement or false-positive status.

## Contract

The strict JSON schema is
`schemas/belief-validation-proof-v1.schema.json`.  The implementation is
`belief/validation/proof.py`.

The trusted index repeats every binding and the evidence digest map on purpose.
Callers must construct `VerifiedProofMaterial` from authority, attempt, result,
and evidence stores—not from the validation-result JSON being assessed.

Trusted material additionally binds full SHA-256 digests for the projected
subject, canonical plan, and complete result claim (excluding only the embedded
`metadata.validation_proof` link). It also repeats trusted evidence id, kind,
media type, digest, and byte size. The index rejects conflicting global
collisions for attempt, result, plan, subject, and evidence identities before it
can resolve a proof. Distinct attempts may share a deterministic `result_id`
only when the complete trusted result digest is identical.

## Consequences

- Existing serialized results still round-trip.
- Existing producers may continue supplying legacy claims, but those claims
  cannot change reportability or suppress a candidate.
- Current local execution results remain non-promotable until the durable
  attempt/result/evidence ledger supplies trusted `VerifiedProofMaterial`.
- A valid-looking proof embedded in JSON without the external index is
  quarantined, not accepted.
- Serialized `metadata.reportability` is also a claim. Offline reasoning and
  bug-bounty/patch-review exports recompute it, while BELIEF-to-PDX export emits
  only `UNCERTAIN` with zero weight and preserves any source block as
  `proof_eligible=false` context.
- PDX attestations and external vulnerability databases remain contextual
  signals; neither can create a verified proof.

Dataset, benchmark, and MCP projections that retain serialized reportability
fields are not authority-bearing inputs. They must be migrated to accept a
trusted assessment object before those fields are used for training, filtering,
or automation.

## Rejected alternatives

- Trust a serialized `proof_state="verified"`: this recreates the original
  caller-controlled boolean weakness under a new name.
- Treat two advisory feeds as independent proof: OSV, GHSA, NVD, and vendor
  feeds frequently share upstream records.
- Embed all evidence bytes in an audit case: this makes report payloads the
  authority and defeats a durable content-addressed store.

## Durable authority ledger

`belief.validation.ledger.ValidationProofLedger` implements the first durable
slice as immutable attempt/terminal records, an atomic digest inventory, and a
SHA-256 content-addressed store:

- an externally pinned engagement/target scope is registered create-only;
- request bytes and an attempt record are fsynced before the caller spawns work;
- each attempt or terminal is first written as an exact, integrity-checked
  pending record; restart loading rolls that declared transaction forward even
  when an internally generated attempt ID was never returned to the caller;
- one attempt can publish exactly one terminal record; an identical replay is
  idempotent and a conflicting or late terminal is rejected;
- `finish_attempt()` treats caller-supplied results and opaque response bytes as
  durable audit material only: it never emits a proof or enters the verified
  snapshot;
- request, worker response, canonical result, and additional evidence are read
  back from CAS and rehashed before trusted material is constructed;
- an integrity-protected scope inventory binds every expected attempt and
  terminal record digest, so deleting either a terminal or its attempt pair
  makes restart reconstruction fail closed;
- a lock-consistent restart snapshot returns the authority context, sealed
  results, and rebuilt `VerifiedProofIndex` together;
- pending attempts remain non-promotable, and any missing/tampered record or CAS
  object fails reconstruction closed.
- a plain record outside the inventory is never adopted without its preceding
  pending intent; a corrupt or conflicting intent also fails closed.
- configurable per-object, total-evidence, reference-count, record-size, and
  per-scope attempt bounds keep publication and restart reconstruction finite.

`run_registered_fixture_validation_with_ledger()` is the only execution helper
in this slice. It is intentionally restricted to
`target_id="registered-fixture:<fixture_id>"` and
`subject_kind="validation_contract_seed"`; it cannot authorize a real project
target. Its proof path reparses the persisted execution context and strict
`WorkerResponse`, recomputes the evidence decision, and verifies that the result
was derived from those bindings during both publication and restart loading.
The general report pipeline remains opt-in until a separately reviewed
real-target executor and authority policy exist.

The scope authority digest must be pinned outside the ledger. Plain SHA-256
detects in-place corruption but does not defend against an adversary who can
rewrite the entire store and its external configuration; signatures or a MAC
remain a future hardening option. Callers that require rollback detection must
also pin `VerifiedProofSnapshot.ledger_snapshot_id` externally and pass it back
as `expected_ledger_snapshot_id` on reload; rolling back both records and their
inventory is otherwise indistinguishable from an older valid ledger state.
A pinned load is strictly non-mutating when a pending transaction exists: it
fails before roll-forward. Recovery must then be explicitly performed by an
unpinned load, whose newly returned snapshot ID must be reviewed and pinned
before subsequent pinned reads.
