# PatchEval-Verified Static-Corpus Preflight Result

Status date: 2026-07-25  
Decision: `FAILURE — INELIGIBLE FOR STATIC ARCHITECTURE TUNING`

This report applies the preregistered
[`PATCHEVAL_VERIFIED_PROTOCOL.md`](PATCHEVAL_VERIFIED_PROTOCOL.md) without
relaxing its eligibility rules.

## Frozen evidence

| Input | Value |
|---|---|
| PatchEval commit | `217401d06684e8baa0847574b9faf83b0898f379` |
| PatchEval dataset SHA-256 | `97ed2ede290f26df8f396bbfbb225674dbf73ba3afe954e855b7a7f1cb572c3c` |
| BELIEF starting commit | `54b83c748d7c217f1a801420867a93b942d53daf` |
| BELIEF preparation commit | `a96a1dc0d0a8e4edec55330805f5d8145eeafaaf` |
| Protocol SHA-256 | `b3017dcff4e87b17faf35e69aa7391be0ebd8666636193cdd37bb63ff3e97185` |
| Manifest semantic digest | `c93aeaca8a39510da10233c06ea6a78320f51f122c629adda41187849b281e76` |
| Manifest file SHA-256 | `2e19fde79d61ce757fa5c91c56ad86c78bac31a6179ac4133b8df47204ff14bd` |

The create-only manifest is retained outside the repository as
`belief-patcheval-verified-python-v1-20260725-01.json`.

## Aggregate result

| Measurement | Count |
|---|---:|
| PatchEval-Verified records | 230 |
| Python records | 70 |
| Python records with a non-empty `patch_url` | 0 |
| Eligible project-disjoint static cases | 0 |
| Development cases | 0 |
| Reserved cases | 0 |

All 70 Python records were excluded by the preregistered non-empty
`patch_url` rule. No other required-field failure was observed. Because the
official-patch URL was required to reconstruct canonical vulnerable/fixed
static pairs without opening Docker images, PatchEval-Verified cannot serve as
this cycle's static architecture-development corpus.

## Verified boundaries

- No eligibility criterion, split ratio, minimum, metric, or gate was relaxed.
- No case ID, repository identity, CVE, CWE, description, patch URL, function,
  image URL, source, test, or outcome was printed during preparation.
- No PatchEval image was pulled.
- No container, model, project code, or validation test was executed.
- The old 49-case SusVibes reserved cohort remained sealed.

## Decision labels

### Verified

- The pinned PatchEval release contains 230 records and 70 Python records.
- Every Python record lacks the static `patch_url` required by this protocol.
- The ineligible manifest is deterministic and create-only.

### Failure

- The corpus has zero eligible static cases, below every preregistered cohort
  minimum.
- Static BELIEF architecture tuning must not continue on this corpus.

### Not tested

- PatchEval Docker environments and dynamic repair validation.
- BELIEF feedback versus no-feedback agent arms.
- Any PatchEval security-fix rate.

### Not comparable

- This metadata preflight is not a PatchEval repair score.
- It is not SusVibes `FuncPass` or `SecPass`.
- It provides no evidence of beating Fable 5, Kimi K2, or another model.

PatchEval-Verified remains a valid candidate for a separately authorized
dynamic development smoke because its official runner uses descriptions,
repositories, and images rather than `patch_url`. That experiment cannot be
used to tune the static reviewer and still requires the dynamic preflight
defined by the protocol.

