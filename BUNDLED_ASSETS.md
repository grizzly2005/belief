# Bundled Assets

BELIEF v4 intentionally keeps `belief/tools_bundled/` and `belief/security_rules/` in the initial public repository for reproducibility and research transparency.

These directories are not the core BELIEF runtime. The core package lives in `belief/`, while bundled assets support compatibility, bridge experiments, rule references, local tests, and future analyzer integration.

## `belief/tools_bundled/`

`belief/tools_bundled/` contains optional resources, adapted tools, compatibility code, examples, databases, or local bridge-support materials.

Observed top-level subdirectories include:

- `bandit`
- `code_analyzer`
- `codegraph`
- `contextgem`
- `crosshair`
- `dlint`
- `driftgan`
- `findimports`
- `frouros`
- `git_of_theseus`
- `importlab`
- `modulegraph2`
- `pyan`
- `pydeps`
- `pyexz3`
- `pyre_full`
- `pyt`
- `safety_db`
- `supply_chain_firewall`
- `z3_playground`

These assets may include material inspired by, adapted from, or copied from third-party ecosystems. Do not assume every file is original BELIEF code. Each subdirectory should be reviewed for provenance and license obligations before commercial redistribution or repackaging.

## `belief/security_rules/`

`belief/security_rules/` contains local rule references and rule-pack style material used by BELIEF for research, compatibility, and analyzer bridge work.

Observed top-level subdirectories include:

- `codeql`
- `joern`
- `joern_core`
- `nuclei`
- `semgrep`

These rule assets may use formats, conventions, or content from different security ecosystems. They are kept to make analysis behavior reproducible and to document the rule/reference material used during development.

## License And Provenance Notes

The repository-level BELIEF license does not automatically replace licenses that may apply to third-party assets under bundled directories.

Current license/provenance scan found README-style files under:

- `belief/security_rules/codeql/python/CWE-327/README.md`
- `belief/security_rules/joern/README.md`
- `belief/security_rules/joern_core/main/resources/scripts/README.md`

No comprehensive top-level license files were found inside `belief/tools_bundled/` or `belief/security_rules/` during the release-readiness scan. This is a medium provenance risk: the directories are retained, but any public or commercial use should include a per-subdirectory license review.

## Publication Decision

Decision for the initial public repository:

- keep `belief/tools_bundled/`;
- keep `belief/security_rules/`;
- document their role and risk clearly;
- do not claim all bundled asset content is original;
- do not treat bundled assets as the BELIEF core runtime;
- review and annotate provenance by subdirectory in a future hardening pass.
