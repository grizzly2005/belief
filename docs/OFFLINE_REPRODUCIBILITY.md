# Offline Reproducibility

BELIEF's local validation environment is reproducible without a package-index
request once a matching wheel bundle is available. This document deliberately
describes only local installation and verification; it does not bootstrap tools
from the network.

## Scope

`requirements-offline-test.lock` is a hash-locked test environment for the
validated Windows CPython 3.12 x64 stack. It includes BELIEF's local runtime,
pytest, Ruff, the JSON Schema validator used by dataset/schema tests, and the
optional Z3 package used by the test suite. `jsonschema` is test tooling, not a
BELIEF production-runtime dependency. This is not a cross-platform release
lock: `ruff`, `rpds-py`, and `z3-solver` wheels are platform-specific. The
bootstrap refuses another interpreter, platform, or bitness.

The wheel bundle belongs in `.wheelhouse/`, which is intentionally ignored by
Git. It can be preserved as a reviewed build artifact or copied from a trusted
local cache. The lock file verifies every resolved wheel hash, so a mismatched
bundle fails instead of silently selecting another version.

## Bootstrap

From the repository root, with a matching local wheelhouse present:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_offline.ps1 \
  -VenvDir .venv-repro-fresh
```

`-VenvDir` must not exist. The script deliberately refuses to reuse a venv,
because an already-installed package could otherwise satisfy a requirement
without its wheel being checked against the lock.

The script:

1. verifies Windows, CPython 3.12 x64, and a strict `name==version` SHA-256 lock;
2. checks that every locked package has a matching wheel whose hash matches the lock;
3. creates a fresh venv and verifies that system site-packages are disabled;
4. installs dependency wheels only with `--isolated`, `--no-index`,
   `--find-links`, `--require-hashes`, and `--only-binary=:all:`;
5. installs BELIEF from the current checkout with `--no-deps` and
   `--no-build-isolation`, then runs `pip check`.

A missing wheel, malformed lock entry, wrong hash, existing venv, or unsupported
Python fails before any package can be installed from another source. Pip runs in
isolated mode, so user pip configuration and `PIP_*` environment settings cannot
add an index or an extra package location.

Third-party dependencies are installed only as locked wheels; their setup scripts
are not built or run. The only source build is the explicit editable BELIEF
checkout, using its declared PEP 517 backend. The bootstrap does not start BELIEF,
run tests, contact services, or invoke any project runtime script.

## Verification

The narrow lock verifies the core offline bootstrap, dataset, and schema
contracts. It intentionally excludes the optional `web-validation` stack; a
complete test run requires a normal `.[dev,z3,web-validation]` installation or
a separately reviewed extended offline lock.

```powershell
.\.venv-repro-fresh\Scripts\python -m pip check
.\.venv-repro-fresh\Scripts\python -m pytest -q `
  tests/test_offline_bootstrap.py `
  tests/test_dataset_quality.py `
  tests/test_dataset_sft_export.py `
  tests/test_schemas_exist.py
.\.venv-repro-fresh\Scripts\ruff check belief tests
```

For a new platform, produce a separately reviewed wheelhouse and lock update.
Do not replace hashes or platform wheels opportunistically during a security
review.
