# Python Source Classification

BELIEF targets Python 3.10 and later. A small historical Z3 playground under
`belief/tools_bundled/z3_playground/` is retained as vendored reference data
in its original Python 2 syntax.

Those files are not BELIEF runtime modules, supported examples, or executable
fixtures. They must never be imported or executed by BELIEF.

## Fail-closed manifest

`belief/python_source_classification.json` is the only Python 3 compile
exclusion. It records:

- the exact relative directory;
- the fixed `python2` and `vendored_reference_examples` classification;
- the declarative `execution = forbidden` policy;
- the expected number of Python files;
- a canonical SHA-256 inventory over every relative path, byte length, and file
  digest in that directory.

Adding, deleting, renaming, or changing a classified file invalidates the
inventory. A reviewer must then examine the change and explicitly update the
manifest. Broad filename globs and arbitrary exclusion paths are not accepted.

All other `.py` files below the declared `belief/` Python 3 package root are
compiled from bytes without being imported or executed. An unclassified
Python 2 file in that declared package root therefore fails the gate instead of
silently expanding the exclusion.

This gate does not claim repository-wide coverage: root files, `scripts/`,
`tests/`, and other undeclared roots are outside this specific metric. The 29
Python 2 files are classified as non-runtime reference assets. The
`execution = forbidden` value is policy metadata; this classifier does not
install an OS, import-hook, or interpreter-level mechanism that technically
prevents a user from executing those files directly.

Run the gate from the repository root:

```bash
python -m belief.source_classification --root .
```

The command exits with status `0` only when the manifest inventory matches and
every non-classified Python source parses under the active Python 3
interpreter.
