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
4. A proof payload cannot verify itself. Reportability accepts promotion only
   when trusted ledger material resolves the canonical proof and every binding.
   The only public authority input is one ledger-origin
   `VerifiedProofSnapshot`, which keeps its
   `VerifiedProofIndex`, `ProofAuthorityContext`, and ledger pin in one atomic
   object. Direct snapshot construction and the legacy separate
   `proof_index`/`proof_context` authority path are rejected.
   `case.metadata` can never establish engagement or target scope.
5. Missing proof is `signal_only`. A structurally valid proof with no trusted
   snapshot is `unresolved`. Malformed, orphaned, mismatched, or
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
media type, digest, and byte size. The index pre-scans deterministic `result_id`
bindings because the v1 identifier omits confidence and metadata and is shorter
than the complete trusted result digest. If one `result_id` maps to multiple full
digests, every associated proof is quarantined with
`validation_proof_result_id_collision`; the ambiguous derived
`validation-result:<result_id>` evidence binding is excluded from the usable
index. Unrelated proofs remain resolvable regardless of input order. Structural
global identities for attempt, plan, subject, and every other evidence id are
still checked across all materials, including quarantined ones, so a result-id
collision cannot hide an unrelated identity conflict. Distinct attempts may
share a deterministic `result_id` only when the complete trusted result digest
is identical.

## Consequences

- Existing serialized results still round-trip.
- Existing producers may continue supplying legacy claims, but those claims
  cannot change reportability or suppress a candidate.
- Current local execution results remain non-promotable until the durable
  attempt/result/evidence ledger supplies trusted `VerifiedProofMaterial`.
- A valid-looking proof embedded in JSON without a ledger-origin snapshot is
  unresolved, not accepted.
- Serialized `metadata.reportability` is also a claim. Offline reasoning and
  bug-bounty/patch-review exports recompute it, while BELIEF-to-PDX export emits
  only `UNCERTAIN` with zero weight and preserves any source block as
  `proof_eligible=false` context.
- PDX attestations and external vulnerability databases remain contextual
  signals; neither can create a verified proof.

The SFT projection has migrated to `belief.sft.v2`: it strictly reconstructs
each audit case, removes serialized reportability/reasoning/feedback claims,
removes free-form human next steps from the label, redacts the complete
message-visible case projection, and recomputes reportability from that exact
projection. It rejects proof snapshots, verified labels, and reportable
candidates; snapshot and authority fields remain null until a future dataset
contract includes the complete proof evidence in the model input. Its quality
validator independently recomputes every target and rejects legacy v1 labels,
hidden scoring features, or inconsistent provenance.
Benchmark and MCP projections that still retain serialized reportability fields
remain non-authority-bearing inputs and must be migrated before those fields are
used for filtering or automation.

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
  results, rebuilt `VerifiedProofIndex`, and sorted
  `unterminated_attempt_ids` together. An unterminated ID means only that no
  durable terminal exists in this ledger generation; it is a reconciliation
  handle, not proof that a worker has stopped or that re-execution is safe;
- pending attempts remain non-promotable, and any missing/tampered record or CAS
  object fails reconstruction closed.
- a plain record outside the inventory is never adopted without its preceding
  pending intent; a corrupt or conflicting intent also fails closed.
- configurable per-object, total-evidence, reference-count, record-size, and
  per-scope attempt bounds keep publication and restart reconstruction finite.

`VerifiedProofSnapshot` rejects direct public construction. The supported path
is `load_scope()`, which applies a module-internal ledger-origin marker after
validating canonical result order, snapshot identifier, authority digest, index
type, and unterminated-attempt ordering. Public reportability and Markdown APIs
accept an exact (non-subclassed) snapshot type only; their deprecated
`proof_index` and `proof_context` keywords fail closed.

This is an API integrity boundary, not a Python sandbox. Code with arbitrary
execution inside the BELIEF process is part of the trusted computing base: it
can inspect private module state or bypass Python object guards. Untrusted audit,
PDX, tool, and dataset JSON must never execute in that process.

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
