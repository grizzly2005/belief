# PDX / BELIEF Integration

BELIEF supports a minimal JSON-only PDX adapter for passive, offline review
workflows. PDX data is treated as upstream evidence, not as a runtime that
BELIEF executes.

## Scope

Implemented in this pass:

- PDX JSON bundle models under `belief.pdx`.
- Generic `ValidationResult` under `belief.validation`.
- PDX verdict adaptation under `belief.validation.pdx`.
- PDX import/export CLI commands.
- Minimal append-only feedback JSONL store.
- Minimal deterministic SFT JSONL export from BELIEF audit reports.

Out of scope:

- binary PDX parsing;
- native PDX libraries, ctypes, or HMAC runtime;
- HYDRA SSH honeypot, virtual filesystem, personas, lures, UI, gcloud sync,
  browser automation, API engines, or real sessions;
- CPT, ReAct, RAFT, or LLM calls.

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

- an untested PDX `VULNERABLE` verdict becomes `inconclusive` with positive
  evidence;
- a tested `VULNERABLE` verdict becomes `bypassed`;
- a human-only validation candidate becomes `validated_candidate`;
- a tested `NOT_VULN` verdict becomes `enforced`;
- a tested `FALSE_POS` verdict becomes `false_positive`.

Reportability scoring uses these signals conservatively. It does not promote
untested PDX evidence to a confirmed vulnerability.

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

