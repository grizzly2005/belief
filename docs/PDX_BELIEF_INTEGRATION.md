# PDX / BELIEF Integration

BELIEF supports a minimal JSON-only PDX adapter for passive, offline review
workflows. PDX data is treated as upstream evidence, not as a runtime that
BELIEF executes.

## Scope

Implemented in this pass:

- PDX JSON bundle models under `belief.pdx`.
- strict `pdx.observation_attestation.v1` parsing;
- immutable `belief.pdx_engagement.v1` authority registrations;
- durable, integrity-checked attestation receipts with restart-safe replay;
- Generic `ValidationResult` under `belief.validation`.
- PDX verdict adaptation under `belief.validation.pdx`.
- PDX import/export CLI commands.
- Minimal append-only feedback JSONL store.
- Minimal deterministic SFT JSONL export from BELIEF audit reports.
- Offline deterministic reasoning over audit cases.
- Minimal deterministic SFT quality validation.

Out of scope:

- binary PDX parsing;
- native PDX libraries, ctypes, or HMAC runtime;
- HYDRA SSH honeypot, virtual filesystem, personas, lures, UI, gcloud sync,
  browser automation, API engines, or real sessions;
- CPT, ReAct, RAFT, or LLM calls.
- WebChat, network calls, active validation, or scanning.

The SSH HYDRA honeypot is explicitly outside this integration.

## Verified observation boundary (F3)

PDX and BELIEF share the identical
`schemas/pdx-observation-attestation-v1.schema.json` contract. The attestation
contains only observation identities and digests. It contains no HTTP bytes,
headers, timing, PDX CAS path/reference, payload recipe, validation verdict,
`attempt_id`, `result_id`, or evidence object.

Register BELIEF's immutable authority and scope binding first:

```powershell
python -m belief pdx register-engagement engagement.json `
  --store-dir .\belief_pdx_evidence
```

The registration schema is `belief.pdx_engagement.v1`. One id/version pair is
create-only: an exact replay is idempotent and different content is rejected.
It binds owner, status, scope reference and digest, authorization reference,
policy, budget, validity interval, and an exact target allowlist.

Then import the PDX attestation:

```powershell
python -m belief pdx import-attestation pdx-attestation.json `
  --store-dir .\belief_pdx_evidence
```

BELIEF strictly validates exact fields, source contract/canonicalization,
attestation hash/id, identity consistency, ordering, loss disclosure, and all
authority bindings. Its durable result is one of:

- `ACCEPT` (exit 0): authority bindings match; observation references are
  retained as signal-only references;
- `QUARANTINE` (exit 3): the attestation is structurally valid but engagement,
  scope, authorization, validity, target, or capture identity cannot be safely
  joined; no observation claim is emitted;
- `REJECT` (exit 2): syntax, strict shape, source contract, canonical digest,
  or attestation identity is invalid; claimed identities are not trusted.

The journal stores only engagement metadata and hash-bound receipts. It does
not store the source attestation or request/response data. Re-importing the
same bytes after restart returns the original receipt without duplication.
The same capture id and observation hash is idempotent; the same capture id
with a different observation hash is quarantined.

Partial/non-joinable identity and truncated observations may be accepted only
with explicit caveats. Every accepted observation reference has proof state
`signal_only_no_belief_attempt_result_evidence`.

The cross-repository integration test keeps the two Python environments
separate. Point `PDX_REPO` at the PDX checkout and, when BELIEF's interpreter
does not also contain the PDX dependencies, point `PDX_PYTHON` at a
PDX-capable interpreter:

```powershell
$env:PDX_REPO = '<path-to-hydra-pdx>'
$env:PDX_PYTHON = '<path-to-pdx-python>'
python -m pytest -q -p no:cacheprovider tests/test_pdx_cross_repo_contract.py
```

## PDX JSON Bundle

The supported schema is `belief.pdx.v1`:

```json
{
  "schema_version": "belief.pdx.v1",
  "tool_id": "pdx",
  "meta": {},
  "deltas": [],
  "verdicts": [],
  "chains": [],
  "conflicts": [],
  "train_entries": []
}
```

The adapter accepts only JSON. It does not import the upstream binary PDX
format or HYDRA runtime code.

## Import

Import a PDX bundle into BELIEF's normalized tool-result schema:

```bash
python -m belief pdx import tests/fixtures/pdx/pdx_bundle_sample.json \
  --normalized-output out/pdx.belief-tools.json
```

The resulting file can be imported by `scan` like any other passive bridge:

```bash
python -m belief scan ./app \
  --import-tool-results out/pdx.belief-tools.json \
  --reportability \
  --json-output out/audit.json
```

PDX deltas map to `ExternalFinding`; PDX chains map to passive review
`AttackPath` records. They are not exploit recipes.

## ValidationResult

`ValidationResult` is generic BELIEF evidence. PDX verdicts are adapted into it
without changing `Finding` or `AuditCase`.

Important rule:

- all legacy PDX vulnerability/enforcement/false-positive assertions remain
  `inconclusive` because `belief.pdx.v1` has no joinable BELIEF attempt,
  result, or evidence references;
- upstream `tested` and `human_validated` booleans are retained only as
  `source_tested` and `source_human_validated` metadata;
- BELIEF emits `tested=false`, `human_validated=false`, and
  `positive_evidence=false` for these legacy assertions;
- a PDX `VULNERABLE` assertion remains a `positive_signal`, not proof;
- producer confidence is capped at 0.5 at this unproven boundary;
- informational assertions may remain informational.

No PDX producer boolean can now create BELIEF outcomes `bypassed`, `enforced`,
`validated_candidate`, or `false_positive`. Those outcomes require a future
BELIEF-owned attempt/result/evidence path (or another independently defined
BELIEF proof path).

## Export

BELIEF audit/report JSON can be exported as a passive PDX bundle:

```bash
python -m belief pdx export out/audit.json --pdx-output out/audit.pdx.json
```

Exported PDX verdicts remain conservative. Reportable candidates are exported
as `UNCERTAIN`, not as confirmed vulnerabilities.

## Feedback Store

The feedback store is append-only JSONL:

```bash
python -m belief feedback add \
  --case-id case-auth-1 \
  --verdict false_positive \
  --reason "owner guard present"
```

Default directory:

```text
./belief_feedback
```

Use `--store-dir` to override it in tests or local experiments.

Apply feedback to an audit report by exact `case_id`:

```bash
python -m belief feedback apply \
  --audit out/audit.json \
  --store-dir ./belief_feedback \
  --output out/audit.feedback.json
```

Feedback application is deterministic and metadata-only:

- feedback only matches exact `case_id`;
- no global suppression;
- no fuzzy matching;
- no ML or RAG;
- no LLM calls;
- no evidence deletion.

Matched feedback is attached under `case.metadata.feedback_events`.
The conservative adjustment is attached under
`case.metadata.feedback_adjustment`. Reasoning consumes embedded feedback
events when running over the adjusted audit report.

## SFT Export

Minimal SFT export is deterministic and offline:

```bash
python -m belief dataset export \
  --from-audit out/audit.json \
  --format sft \
  --output out/belief.sft.jsonl
```

The exporter does not emit chain-of-thought, payload recipes, secrets, real
tokens, or active exploit instructions.

Validate generated SFT JSONL:

```bash
python -m belief dataset validate --input out/belief.sft.jsonl
```

The validator returns JSON with `passed`, `score`, and `issues`.

## Offline Reasoning

Run deterministic local reasoning over BELIEF audit cases:

```bash
python -m belief reason \
  --audit out/audit.json \
  --engine offline \
  --output out/reasoned.json
```

The offline engine uses existing reportability metadata, validation results,
missing evidence, and any feedback events already embedded in an audit case.
It does not call LLM APIs, model servers, browsers, WebChat, HYDRA runtime, PDX
runtime, or network services.

User-facing recommendations are limited to conservative review language:

- `keep`
- `lower_confidence`
- `needs_manual_validation`
- `likely_false_positive`
- `protected_by_guard`
- `request_more_evidence`

Responses include `rationale_summary` only. They do not include chain-of-thought
or hidden reasoning traces.

## Documentation Schemas

Minimal JSON Schema files live under `schemas/`. The PDX observation
attestation and engagement contracts are also enforced at runtime by exact,
dependency-free trust-boundary parsers. Other historical schemas remain
documentation contracts and do not add a production-runtime `jsonschema`
dependency. The offline test toolchain includes `jsonschema` for schema and
dataset validation tests.
