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

## Remaining work

1. Freeze a new independent corpus of 20–30 projects before detector tuning;
   retain vulnerable/fixed pairs and independent negative controls.
2. Add a real bounded executor behind the existing policy contract and verify
   that target/executor/oracle identities come from an external trust boundary.
3. Add signing and verification outside the serializer, then check two
   independent producers/consumers and SARIF interoperability.
4. Add a read-only accepted-observation PDX consumer. Accepted receipt metadata
   remains a signal until BELIEF attempt/result/evidence requirements are met.

## Primary specifications

- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [Simple Verification Result v0.2](https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md)
- [DSSE protocol 1.0.2](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
