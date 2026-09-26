# Setuptools paired-control adjudication — 2026-09-15

The frozen recovery benchmark still fails on the Setuptools fixed variant.
A bounded local probe now shows why its string-prefix guard is insufficient
as a universal containment negative control. No detector rule, frozen label,
source revision, line range or threshold was changed to obtain this result.

## Source and method

The [reviewed advisory](https://github.com/advisories/GHSA-5rjg-fvgr-3xxf)
identifies 78.1.1 as a patched release. The frozen corpus points to
[commit 250a6d1](https://github.com/pypa/setuptools/commit/250a6d17978f9f6ac3ac887091f2d32886fbbb0b).
That historical patch label does not by itself prove containment for every
synthetic root and input combination.

- Source: `setuptools/package_index.py` at
  `250a6d17978f9f6ac3ac887091f2d32886fbbb0b`.
- Exact blob SHA-256:
  `870ffc77a62224af26252657edcdc035002dbf31f6557be807516d0fc34f842e`.
- Reviewed helpers: `egg_info_for_url`, lines 105–113, and
  `_resolve_download_filename`, lines 811–844.

`scripts/check_setuptools_pair_adjudication.py` reads that Git object with
network protocols disabled, checks its SHA-256, and extracts only those two
function definitions. It strips decorators/docstrings and evaluates the
reviewed pure functions with URL parsing and `posixpath`/`ntpath`. It does not
import or install Setuptools, download a URL, invoke a filesystem sink, or
execute other module code. This hash-pinned probe is not a general sandbox.

## Observations

Eight scenarios were checked for each path dialect, **16 cases total**:

| Input/root relationship | Helper behavior | Component containment |
|---|---|---|
| Ordinary leaf | Accepted | Inside |
| Absolute path already inside | Accepted | Inside |
| Unrelated absolute path | `ValueError` | No path selected |
| Absolute sibling sharing the known root prefix | Accepted | **Outside** |
| Same sibling, root ending in a separator | `ValueError` | No path selected |
| Wrong guessed root prefix | `ValueError` | No path selected |
| `..` component transformed by the helper | Accepted | Inside |
| Empty leaf using the helper fallback | Accepted | Inside |

For the POSIX case, the synthetic root is `/synthetic/download`. Passing the
URL-encoded filename `/synthetic/download-sibling/probe.bin` through the real
`egg_info_for_url` and filename helper selects that sibling path. It satisfies
`filename.startswith(str(tmpdir))`, while component-based `commonpath` places
it outside the root. The analogous pure `ntpath` case reproduces this behavior
with `C:\synthetic\download`.

This establishes a filename-selection behavior under the explicit assumption
that the root prefix is known and lacks a trailing separator. It does not
establish knowledge of a production temporary directory, upstream reachability,
an actual filesystem write, symlink behavior, exploitability, or a new CVE.
Windows results here use `ntpath` emulation, not native file operations.

## Reproduction and decision

Run from the BELIEF checkout with the existing local Git object clone. The
output path must be new; the script refuses to overwrite an artifact:

```powershell
.\.venv\Scripts\python.exe scripts/check_setuptools_pair_adjudication.py `
  --repo F:\belief-rd\open-source-pairs-v1\repos\pypa__setuptools `
  --output .\setuptools-adjudication-local.json
```

Two invocations returned exit 0 and byte-identical JSON. The committed result
is [setuptools-adjudication-v1.json](../benchmark_open_source_pairs_results/setuptools-adjudication-v1.json).
The canonical deterministic digest is
`cf26731a532cdb3aa6afe9a6a3faa65435a7715cd39b4f4c84647e7f76d49768`;
the output file SHA-256 is
`b824c7fe3f2c6fe8058cc3e890c8d7de1eef95eabdd4df61ccca029b032b21ba`.

The appropriate action is to retain the conservative detector warning and
record the negative-control limitation. The frozen benchmark remains **FAIL**
(3/3 vulnerable warnings, 1/3 fixed warnings, discrimination 2/3). Its two
earlier result files remain unchanged; they were not rerun or rescored here.
Any new corpus must be versioned separately, with independently adjudicated
negative controls and explicit root/reachability assumptions frozen before
further detector tuning. An independent 20–30-project evaluation remains open.
