# Offline Reproducibility

BELIEF's local validation environment is reproducible without a package-index
request once a matching wheel bundle is available. This document deliberately
describes only local installation and verification; it does not bootstrap tools
from the network.

## Scope

`requirements-offline-test.lock` is a hash-locked test environment for the
validated Windows CPython 3.12 x64 stack. It includes BELIEF's local runtime,
pytest, Ruff, and the optional Z3 package used by the test suite. It is not a
cross-platform release lock: `ruff` and `z3-solver` wheels are platform-specific.

The wheel bundle belongs in `.wheelhouse/`, which is intentionally ignored by
Git. It can be preserved as a reviewed build artifact or copied from a trusted
local cache. The lock file verifies every resolved wheel hash, so a mismatched
bundle fails instead of silently selecting another version.

## Bootstrap

From the repository root, with a matching local wheelhouse present:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap_offline.ps1 \
  -VenvDir .venv-repro
```

The script:

1. creates the requested virtual environment if it does not exist;
2. installs only from `.wheelhouse/` with `--no-index` and `--require-hashes`;
3. installs BELIEF from the current checkout without dependency resolution or a persistent pip cache;
4. runs `pip check`.

It does not call a package index, use global site-packages, or write outside the
selected virtual environment, the current checkout's editable metadata, and the
existing local wheelhouse.

## Verification

```powershell
.\.venv-repro\Scripts\python -m pip check
.\.venv-repro\Scripts\python -m pytest -q
.\.venv-repro\Scripts\ruff check belief tests
```

For a new platform, produce a separately reviewed wheelhouse and lock update.
Do not replace hashes or platform wheels opportunistically during a security
review.
