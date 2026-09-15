# Validation recovery checkpoint — 2026-09-14

This checkpoint resumes the unfinished detector, AuditCase proof and unsigned
attestation work from `9f5876567d81d92d91430d2cc76de4a679c90ce5`.
It preserves the three-project paired baseline and its frozen thresholds.

## Behavior

- Native AST detectors remain opt-in through audit mode or the patch-review
  profile. A crashing detector or malformed output produces a diagnostic;
  partial results from that failed detector are discarded while other
  detectors continue.
- Path analysis distinguishes method receivers, arithmetic and file handles
  from attacker-controlled path components. A relative path label returned
  by a helper does not by itself establish a filesystem operation. The same
  rendering at a real file sink remains checked.
- String prefix checks do not prove filesystem containment. A recognized
  `is_relative_to` rejection guard requires a resolved candidate tied to the
  same root. These are conservative local AST heuristics, not a complete
  model of filesystem aliases, symlinks or interprocedural flow.
- AuditCase proof publication pins the case, plan, engagement, target
  revision/digest, executor, oracle and policy. Executor evidence IDs are
  namespaced by attempt; response request digests and evidence sets are
  rechecked. Policy byte limits are enforced at publication and replay.
- The exporter emits deterministic in-toto Statement v1 with SVR v0.2.
  Nonverified claims remain in the BELIEF extension and do not populate the
  standard verified-properties array. URI and UTC timestamp validation reject
  ambiguous values; an absent policy list is represented by an empty array.

## End-to-end contract

`tests/test_audit_case_in_toto_integration.py` exercises a static signal through
AuditCase, a policy-pinned synthetic callback, durable ledger replay,
reportability and unsigned SVR serialization. Merely attaching a result leaves
proof unresolved. The trusted replay snapshot permits a verified reportable
candidate. Altering a CAS object makes a fresh replay fail.

This is a synthetic integration test. It does not execute analyzed third-party
code, validate a real vulnerability or provide process isolation. The callback
implementation and its declared identity are trusted inputs. The exporter is
a serializer: callers must obtain `verified` from the ledger. Preparing DSSE
payload bytes does not create a signature or authenticate a producer.

## Verification

The focused recovery run passed 95 tests, including all three historical
regression scenarios through the earlier targeted and final runs. Ruff over
`belief tests tests_bridges` and `git diff --check` returned exit 0.

The broader offline regression uses:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --tb=short `
  -m 'not llm and not external and not slow'
.\.venv\Scripts\python.exe -m ruff check belief tests tests_bridges
git diff --check
```

The complete selected offline regression passed: **1841 passed, 36 skipped**,
exit 0 in 206.23 seconds, under Windows/Python 3.12 with BelowNormal priority
and affinity limited to two logical processors. Six existing cognitive/vendor
AST deprecation warnings remain. LLM, external and slow tests were excluded;
no claim is made about those paths or other operating systems.

Historical benchmark numbers are not treated as fresh evidence.

Fresh native negative control: **PASS**, exit 0 on 557 CPython 3.12 standard
library files / 10,656,366 bytes. There were zero crashes and two files with
confidence >= 0.8 (2/557 = 0.3591%, below the unchanged 0.5% ceiling).
Both high-confidence signals came from the download detector; path analysis
emitted 47 lower-confidence findings and zero high-confidence findings.
This presumed-safe corpus is a regression check, not a security certification.

### Frozen paired benchmark: remaining gate failure

Two independent CLI invocations on clean commit
`a8c99519ba0e2eea6428db3a17dfd77b6adef622` returned exit 1, with identical
metrics and deterministic digest
`691b874eed3a02047eb9b7cac2efa19c44aa0473b3510f3e5bfc0193e914fa45`.
Each invocation also repeats both variants of every pair internally.
The manifest, source blobs, line ranges and thresholds were not changed.

| Metric | Observed |
|---|---|
| Vulnerable warning recall | 3/3 |
| Fixed-revision warnings | 1/3 |
| Paired discrimination | 2/3 |
| Deterministic repetition | 100% |
| Analysis errors | 0 |
| Frozen gate | FAIL |

The remaining fixed-revision warning is the path helper in Setuptools at
`setuptools/package_index.py:844`, revision
`250a6d17978f9f6ac3ac887091f2d32886fbbb0b`. That helper uses
`filename.startswith(str(tmpdir))` as its rejection guard. The revised
detector deliberately does not treat a string-prefix check as containment.
A pure local path probe confirms that `/synthetic/download-sibling/file.bin`
starts with `/synthetic/download` while lying outside that directory by path
components. This is evidence about the guard's semantics, not a demonstration
of an exploitable upstream vulnerability or knowledge of its runtime root.

Do not suppress the warning, weaken the threshold or relabel the frozen case
to obtain a passing result. The
[September 15 adjudication](SETUPTOOLS_PAIR_ADJUDICATION_2026_09_15.md) now
executes the two pinned pure helpers and reproduces the sibling selection
under explicit synthetic-root assumptions. It preserves the frozen gate
failure; any corpus correction requires a separately versioned corpus.
This checkpoint is not a release approval.

Full results:
[run 1](../benchmark_open_source_pairs_results/recovery-v2-run1.json) and
[run 2](../benchmark_open_source_pairs_results/recovery-v2-run2.json).

## Remaining work

1. Freeze a new independent corpus of 20–30 projects before detector tuning;
   retain vulnerable/fixed pairs and independent negative controls.
2. Add a real bounded executor behind the existing policy contract and verify
   that target/executor/oracle identities come from an external trust boundary.
3. Add signing and verification outside the serializer, then check two
   independent producers/consumers and SARIF interoperability.
The accepted-observation consumer was completed on September 15. The
[PDX integration documentation](PDX_BELIEF_INTEGRATION.md#read-accepted-observations)
describes `PDXEvidenceStore.iter_accepted_observations()`, the read-only
`pdx list-observations` CLI, and its informational `ValidationResult` adapter.
Accepted receipt metadata remains a signal until BELIEF
attempt/result/evidence requirements are met.

## September 15 continuation verification

The focused PDX run passed **50 tests, 2 skipped**, exit 0 in 5.79 seconds.
It exercised the real adjacent PDX checkout through fixture persistence,
attestation export, import/replay, accepted-observation listing and the
informational adapter. Two symlink-creation tests were skipped because this
Windows host does not permit creating those links.

The complete selected offline regression then passed **1868 tests, 37
skipped, 6 warnings**, exit 0 in 191.18 seconds, with `PDX_REPO` set to the
adjacent checkout. The same `not llm and not external and not slow` selection
was used. The six existing AST deprecation warnings remain. The skipped and
excluded paths, other operating systems and hostile filesystem replacement
outside the cooperative store lock are not claimed as verified.

Ruff over `belief tests tests_bridges` and the adjudication script returned
exit 0. `git diff --check` passed. The two pure-helper adjudication invocations
returned exit 0 with identical output bytes; the frozen paired benchmark was
not rerun or modified in this continuation.

Tests ran in BelowNormal priority on two logical processors. Before the full
run, Overwatch was running, free RAM was approximately 34.3 GiB and the CPU
snapshot was 12%. The PDX checkout's HEAD, status fingerprint and tracked-diff
fingerprint matched before and after the run; its 29 pre-existing status
entries were retained. Only temporary fixture stores were written by the
cross-repository test.

## Primary specifications

- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [Simple Verification Result v0.2](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md)
- [DSSE protocol 1.0.2](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
