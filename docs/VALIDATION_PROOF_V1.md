# Validation proof v1

Status: implemented as a fail-closed compatibility boundary.

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

## Next durable slice

Persist an attempt before worker spawn, write exactly one terminal result for
success/refutation/timeout/cancellation/crash, store evidence in CAS, and build
the `VerifiedProofIndex` from those stores.  Restart and cross-target tests must
precede enabling this path in the default report pipeline.
