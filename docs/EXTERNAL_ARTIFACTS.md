# External measurement artifacts

Recorded results in this repository bind a reviewer to create-only artifacts
that deliberately live **outside** the repository. That is a protocol choice,
not an oversight: the artifacts are large, they are produced once and never
edited, and keeping them out of history prevents a result file from being
quietly rewritten after the fact.

The cost of that choice is that nothing in the repository could tell whether
those files are still present and unmodified. A lost volume or a single flipped
bit would surface only when someone tried to reproduce a result, possibly
months later, and would be indistinguishable from a reviewer regression.

`research/external_artifacts.json` closes that gap. It is an append-only index
of every artifact a recorded result depends on, with the SHA-256 that result
documents.

## Verifying

```bash
python scripts/verify_external_artifacts.py --root F:/belief-rd
```

The command prints one line per artifact and exits non-zero if any artifact is
missing, unreadable, or does not match its recorded digest. Add
`--json-output` to retain a full report.

It reads bytes and computes digests. It executes nothing, opens no network
connection, writes no file inside the artifact tree, and loads no reserved
holdout case. Verification is therefore safe to run against the sealed cohort's
own volume.

Because the index is a plain data file, it is refused rather than trusted when
malformed: absolute paths, parent traversal, duplicate paths, non-lowercase or
non-hexadecimal digests, and unknown schema versions all abort before any file
is opened.

## Status on 2026-08-08

All 14 indexed artifacts verified against `F:/belief-rd`:

```text
{"mismatched": 0, "missing": 0, "unreadable": 0, "verified": 14}
```

Coverage:

| Recorded in | Artifacts |
|---|---:|
| [`GENERALIZATION_RESULTS.md`](GENERALIZATION_RESULTS.md) | 7 ablation variants |
| [`../benchmark_susvibes/README.md`](../benchmark_susvibes/README.md) | 3 candidate-review runs, 3 manifests |
| [`PATCHEVAL_VERIFIED_RESULT.md`](PATCHEVAL_VERIFIED_RESULT.md) | 1 ineligibility manifest |

One entry needed resolving rather than transcribing. `benchmark_susvibes`
records the hydrated parent-cache manifest by digest
(`97e4cd76...`) without naming its file. A digest search resolved it to
`results/belief-cache-candidate-review-holdout-full-20260725-01.json`. It is
**not** `prepare-smoke/belief-cache-manifest.json`, which is a different and
much smaller preparation covering a single repository. The index records the
resolved path so the ambiguity does not have to be rediscovered.

## Scope

The index covers artifacts that a recorded result cites. It does not cover the
working corpus that can be rebuilt from a pinned upstream source: the prepared
Git object cache under `repos/`, the SusVibes dataset checkout, or the
PatchEval-Verified checkout. Those are reconstructible from their own pinned
commits and manifests; the recorded results are not reconstructible at all.

The index is not a backup. It detects loss and corruption; it cannot repair
them. A single external volume remains a single point of failure for evidence
that cannot be regenerated, because regenerating it would require re-running a
reviewer that has since changed. See
[`REVIEWER_PROVENANCE_CHANGES.md`](REVIEWER_PROVENANCE_CHANGES.md).
