# Bundled Assets

BELIEF v4 intentionally keeps a small set of local assets under the main
`belief/` package for reproducibility, offline tests, and bridge development.

The BELIEF core remains in `belief/`. The directories below are supporting
assets, not a claim that every file is original BELIEF code.

## `belief/tools_bundled/`

Role:

- optional local compatibility resources;
- bridge support material for tools such as PyT, Pyre/Pysa-style stubs, Safety DB,
  PyExZ3, CrossHair, Dlint, Bandit-style experiments, and related prototypes;
- offline fixtures used to keep tests and bridge behavior reproducible.
- bridge manifests under `belief/tools_bundled/manifests/`.

Publication notes:

- these assets may include code, examples, data, or APIs inspired by third-party
  ecosystems;
- JSON manifests describe external tools and risk profiles; they are not
  vendored copies of upstream tools;
- provenance and licensing must be reviewed per subdirectory before commercial
  redistribution, repackaging, or relicensing;
- the repository MIT license does not automatically replace any license that may
  apply to a bundled third-party asset.

### `belief/tools_bundled/manifests/`

The manifests directory contains small JSON descriptors for BELIEF's external
tool bridge system.

Each manifest records:

- tool id and upstream repository URL;
- conservative license/provenance notes;
- supported execution mode;
- input/output types;
- normalized BELIEF concepts it maps to;
- risk profile flags for network, replay, fuzzing, dynamic scanning, and secret
  handling.

These manifests intentionally do not vendor Semgrep, CodeQL, ZAP, RESTler,
Schemathesis, Joern, EvoMaster, Arjun, Dradis, Faraday, AuthMatrix, Autorize, or
Param Miner source trees.

## `belief/security_rules/`

Role:

- local rule packs and rule references for Semgrep, CodeQL, Joern, Nuclei, and
  related security-analysis experiments;
- reproducibility material for security taxonomy, bridges, and tests;
- offline source of rule metadata so BELIEF does not need network access during
  normal local analysis.

Publication notes:

- rule formats and rule content may originate from different security-tool
  ecosystems;
- only one README-style provenance file was found during the latest local scan:
  `belief/security_rules/joern/README.md`;
- many subdirectories do not expose an obvious top-level `LICENSE`, `COPYING`,
  or `NOTICE` file in this repo copy.

## Current Risk Classification

Risk level: medium.

Reason:

- no real secrets were detected in the public-readiness scan;
- bundled assets are useful for reproducibility and research transparency;
- license/provenance is not fully normalized per subdirectory.

Decision:

- keep `belief/tools_bundled/` and `belief/security_rules/` in the public repo;
- document their role and limitations clearly;
- do not claim all bundled assets are original BELIEF work;
- review provenance per subdirectory before any package, commercial, or
  downstream redistribution decision.
