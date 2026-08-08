# Transparent web-validation generalization benchmark

This create-only corpus is independent from SusVibes. It contains 48
synthetic cases grouped into 12 application-template families. Each
family contains vulnerable, protected, ambiguous, and trap variants.

The committed development cohort contains 32 cases from eight complete
families. The remaining 16 case IDs are preregistered by family and
cryptographic digest, but their source and outcomes are not committed.
A family can never be split across development and reserved cohorts.

Coverage includes Flask and FastAPI, path traversal and IDOR/BOLA,
synchronous and asynchronous routes, direct/helper/decorator/dependency
shapes, dictionary and model-backed resources, before/after/wrong
guards, owner-only/tenant-only/owner+tenant checks, and used/ignored
sanitizer results.

This scaffold performs no target execution. It uses no network,
subprocess, shell, Docker, external project, or SusVibes artifact. It
is not a SecPass measurement and cannot support a leaderboard claim.

Verify the frozen files:

```bash
python scripts/build_web_validation_corpus.py           --verify benchmark_web_validation
```

Reserved generation and evaluation remain unavailable until a later
reviewer freeze and explicit create-only authorization are implemented.
