# Public open-source vulnerable/fixed pair benchmark

This benchmark is a static, first-exposure baseline over three public Python
projects that are absent from the pinned 101-project SusVibes v1 corpus:

- `pypa/setuptools`, CVE-2025-47273 / CWE-22;
- `ormar-orm/ormar`, CVE-2026-26198 / CWE-89;
- `Mayuri-Chan/pyrofork`, CVE-2025-67720 / CWE-22.

Each case binds the public security advisory, the exact fixing commit and its
first parent, the affected Python path, and SHA-256 for both source blobs. The
fixed revision is the negative control. Licenses are recorded in
[`cases.json`](cases.json); no third-party source is copied into BELIEF.

## Safety and interpretation boundary

The runner reads only the manifest-listed blobs from local Git object
databases. It disables Git lazy fetching, materializes the listed Python files
in a temporary directory, and invokes BELIEF static analysis twice. It never
checks out a third-party worktree, imports or installs the project, starts a
service, runs its tests, or executes its code.

The advisory and changed file localize the scan. This measures targeted
vulnerable/fixed sensitivity and paired discrimination, not repository-blind
discovery, exploitability, general precision, dynamic repair success,
`SecPass`, or superiority over another analyzer.

## Prepare object-only local repositories

Network acquisition is deliberately separate from the offline runner. Create
the three directories declared by `checkout_dir`, then fetch the exact public
history. A partial no-checkout clone is sufficient:

```powershell
$root = 'F:\belief-rd\open-source-pairs-v1\repos'
git clone --filter=blob:none --no-checkout --no-tags https://github.com/pypa/setuptools.git "$root\pypa__setuptools"
git clone --filter=blob:none --no-checkout --no-tags https://github.com/ormar-orm/ormar.git "$root\ormar-orm__ormar"
git clone --filter=blob:none --no-checkout --no-tags https://github.com/Mayuri-Chan/pyrofork.git "$root\Mayuri-Chan__pyrofork"
```

The first blob read may complete the partial clone. Perform it before the
offline run, then disconnect or firewall the runner if an independent network
boundary is required.

## Run

The BELIEF checkout must be clean and the output must not already exist:

```powershell
.\.venv\Scripts\python.exe scripts\run_open_source_pairs_benchmark.py `
  --repos-root F:\belief-rd\open-source-pairs-v1\repos `
  --output benchmark_open_source_pairs_results\public-pairs-v1.json
```

Exit code `0` means every frozen threshold passed, `1` means a measured gate
failed, and `2` means the corpus, checkout, source binding, or execution
precondition was invalid. A failed benchmark result is still retained as
evidence and must not be overwritten.
