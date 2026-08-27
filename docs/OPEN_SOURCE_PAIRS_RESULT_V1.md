# Public open-source vulnerable/fixed pairs: v1 baseline

Status date: 2026-08-27
Decision: `FAILED — RETAINED FIRST-EXPOSURE BASELINE`

This result evaluates BELIEF on three advisory-localized Python source pairs
from open-source projects that do not occur in the pinned 101-project
SusVibes v1 corpus. The engine was frozen before the formal result was
created. No third-party source was added to BELIEF and no third-party code was
imported, installed, or executed.

## Frozen binding

| Field | Value |
|---|---|
| BELIEF revision | `bb630a91e3c32fddd0f1e40a5fa2846d4c7fd2d2` |
| Corpus manifest SHA-256 | `33481a554e1d228fca0d6bd907878c01620da0100d0283349592601b9a9510a5` |
| Result semantic digest | `2b9e59b71bc3017d53136e62b0bc1d8fd933974b48a0dfd15c1edb1673d13915` |
| Result file SHA-256 | `6b752064ff9e2c131bd0bfe998b720726147bfef801d18918518dc1053f2e673` |
| SusVibes dataset SHA-256 | `be9a4ca573559544c3f28146b3b3811e5565f0a8b4053ff4cc8f4aab6c6742f7` |
| SusVibes project-set binding | 101 projects; SHA-256 `abcbba77c38dad45e812e7ebfd8398308f63c5857097f164364c513824ba38cc` |
| Repetitions | two per revision, twelve scans total |
| Dynamic execution | none |
| Network use by runner | none |

The corpus binds each fixing commit to its first parent and verifies the
SHA-256 of every source blob before analysis. Git lazy fetching is disabled
during evaluation.

## Cases

| Project | Advisory | Type | Vulnerable revision | Fixed revision | License |
|---|---|---|---|---|---|
| `pypa/setuptools` | [CVE-2025-47273](https://github.com/advisories/GHSA-5rjg-fvgr-3xxf) | CWE-22 | `d8390feaa99091d1ba9626bec0e4ba7072fc507a` | `250a6d17978f9f6ac3ac887091f2d32886fbbb0b` | MIT |
| `ormar-orm/ormar` | [CVE-2026-26198](https://github.com/advisories/GHSA-xxh2-68g9-8jqr) | CWE-89 | `ef95d3214daf9ccfd5591ae51d8b2fbe4b66c633` | `a03bae14fe01358d3eaf7e319fcd5db2e4956b16` | MIT |
| `Mayuri-Chan/pyrofork` | [CVE-2025-67720](https://github.com/advisories/GHSA-6h2f-wjhf-4wjx) | CWE-22 | `e9c40679d2d1202ef284fa0dd0695316352ba742` | `2f2d515575cc9c360bd74340a61a1d2b1e1f1f95` | LGPL-3.0-only |

## Aggregate result

| Metric | Result | Gate | Outcome |
|---|---:|---:|---|
| Vulnerable warning recall | `0/3 = 0.0` | at least `0.5` | fail |
| Fixed warning false-positive rate | `0/3 = 0.0` | at most `0.2` | pass |
| Paired vulnerable-only discrimination | `0/3 = 0.0` | at least `0.4` | fail |
| Deterministic repetition rate | `6/6 = 1.0` | exactly `1.0` | pass |
| Analysis errors | `0` | at most `0` | pass |

The fixed false-positive metric is target-specific. It does not mean that the
scans were quiet: BELIEF emitted 12 unrelated warnings on the vulnerable
revisions and the same 12 warning slots on the fixed revisions.

## Per-project observation

| Project | Target warnings, vulnerable | Target warnings, fixed | Other warnings, vulnerable/fixed |
|---|---:|---:|---:|
| setuptools | `0` | `0` | `5 / 5` |
| ormar | `0` | `0` | `7 / 7` |
| Pyrofork | `0` | `0` | `0 / 0` |

The result supports three bounded engineering diagnoses:

1. Path handling in a library method is not recognized when attacker control
   arrives through an ordinary argument or object attribute rather than a
   Flask/FastAPI request source.
2. The setuptools case requires return-value and later-write reasoning across
   helper boundaries; recognizing `os.path.join()` alone is insufficient.
3. The ormar case uses a dynamic SQLAlchemy field identifier rather than a
   directly interpolated SQL string. BELIEF lacks a generic model for
   untrusted structural query identifiers and model-field allowlists.

These are causal hypotheses for development, not proof that one change will
recover all three cases.

## Operational attempt log

The first formal process ended with Windows native exit `0xC0000005` and did
not create an output file. A second run with Python fault handling enabled
completed and produced the immutable artifact above. An additional complete
in-memory evaluation reproduced the same semantic digest and metrics. The
unreproduced native crash remains an operational stability risk; it is not
counted as a successful benchmark attempt or silently discarded.

## Interpretation boundary

- This is first exposure for the frozen engine, but the advisory and changed
  file localized each scan. It is not repository-blind discovery.
- Three selected cases cannot estimate general precision or ecosystem-wide
  recall.
- Public advisories are ground truth for the paired source change, not proof
  that BELIEF's unrelated warnings are vulnerabilities.
- No exploit, project test, service, package import, Docker image, or dynamic
  validation was run.
- The result is not PatchEval, CyberSecEval, SusVibes `SecPass`, or a
  leaderboard comparison.

## Next development gate

Before touching the three target-specific paths, add generic positive and
negative regression families for:

1. argument/attribute-controlled filenames flowing through helper returns to
   file-write sinks, with basename, containment, wrong-value, reordered, and
   unused-result controls;
2. dynamic ORM aggregate identifiers, with real model-field membership as the
   protected control and wrong-model/wrong-field variants;
3. warning stability across alpha-renamed and interprocedural variants.

Production rules must not contain project names, CVEs, commit IDs, advisory
text, target paths, or source digests. The frozen thresholds remain unchanged.
After the generic tests pass, rerun this public development corpus twice and
add further project-disjoint pairs before making any broader claim.
