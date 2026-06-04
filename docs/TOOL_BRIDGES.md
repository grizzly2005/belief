# BELIEF Tool Bridges

BELIEF tool bridges normalize external security-tool outputs into BELIEF's
review models without vendoring full upstream projects.

The bridge layer is intentionally conservative:

- passive import first;
- local external CLI only when safe;
- recipe export for dynamic validation;
- active/network behavior blocked unless explicitly enabled.

## Architecture

```text
ToolManifest -> ToolRegistry -> Safety Gate -> ToolBridge -> NormalizedToolResult
                                                |
                                                +-> ExternalFinding
                                                +-> AccessObservation
                                                +-> AttackPath
```

Core modules:

- `belief.tools.schemas`: dataclasses for manifests, executions, findings,
  access observations, attack paths, and normalized results.
- `belief.tools.manifest`: JSON manifest loading.
- `belief.tools.registry`: built-in bridge registration.
- `belief.tools.safety`: dynamic/network/replay/fuzzing safety gates.
- `belief.tools.runner`: safe `subprocess.run([...], shell=False)` wrapper.
- `belief.tools.bridges.*`: bridge implementations and stubs.

## Manifest Schema

Manifests live in `belief/tools_bundled/manifests/`.

Required fields:

- `tool_id`
- `name`
- `repo`
- `license`
- `description`
- `execution_mode`
- `command`
- `input_types`
- `output_types`
- `capabilities`
- `maps_to`
- `risk`
- `notes`

Risk flags include:

- `network`
- `active_scanning`
- `replays_requests`
- `fuzzing`
- `executes_target_code`
- `writes_files`
- `requires_auth_tokens`
- `external_services`
- `safe_default`

## Safety Model

Dynamic tools are rejected unless the caller explicitly opts in.

If any of these risk flags are true, BELIEF requires `allow_dynamic=True`:

- `network`
- `active_scanning`
- `replays_requests`
- `fuzzing`

If `network` is true, BELIEF also requires `allow_network=True`.

If dynamic execution is enabled, BELIEF requires a `scope_file` so the operator
records the authorized scope outside the codebase.

No bridge should read cookies, bearer tokens, or API keys from repo files.
Recipe exports use placeholders only.

## Bridge Modes

### Passive Import

Use passive import when an external tool has already produced JSON or SARIF.

Examples:

```bash
python -m belief tools import semgrep --file out/semgrep.json
python -m belief tools import codeql --file out/codeql.sarif
python -m belief tools import zap --file out/zap.json
```

### External CLI

Use external CLI mode only for local tools with safe defaults.

Example:

```bash
python -m belief tools run semgrep --target ./app --output-dir out/tools
```

External commands must be invoked as lists with `shell=False`.

### Recipe Export

Use recipe export when the next step requires a human operator or dynamic
validation. Recipes should contain no secrets.

Examples:

- Autorize-style role replay plan;
- Param Miner wordlist;
- Dradis Markdown note;
- Faraday JSON-like report;
- threat-model JSON.

### Dynamic Execution

Dynamic execution is not part of the safe default MVP.

Network-capable tools such as ZAP, RESTler, Schemathesis, EvoMaster, Arjun, and
Autorize-style replay must remain blocked unless the operator supplies explicit
flags and scope.

## Adding a New Bridge

1. Add a JSON manifest under `belief/tools_bundled/manifests/`.
2. Add a small bridge class under `belief/tools/bridges/`.
3. Prefer passive import or recipe export.
4. Add `is_available()` for external CLIs using `shutil.which`.
5. Use `subprocess.run([...], shell=False, timeout=...)` for any command.
6. Add tests that do not require the external tool.
7. Document whether the bridge is functional, passive-only, or a stub.

## MVP Bridge Status

- Semgrep: external CLI if installed, passive JSON import.
- CodeQL: passive SARIF import with code-flow evidence.
- Schemathesis: OpenAPI JSON metadata import; no dynamic tests.
- RESTler: tolerant sequence JSON import; no fuzzing.
- AuthMatrix: AuthMatrix-like JSON import/export; no Burp/Jython.
- Autorize: recipe export only; no cookies or tokens.
- Arjun: passive JSON import; dynamic CLI blocked by policy.
- Param Miner: deterministic wordlist export only.
- ZAP: passive alerts JSON import; no active scan.
- Joern: availability check and tolerant JSON placeholder.
- EvoMaster: manifest/stub only; no dynamic run.
- Dradis: Markdown note export.
- Faraday: simple JSON-like export.
- Threat Dragon: simple threat-model JSON export.

## License Policy

Do not vendor full upstream projects into BELIEF for bridge support. Manifests
may reference upstream repositories and conservative license labels. If a
license is uncertain, use `UNKNOWN - verify upstream before vendoring` and keep
the integration import/CLI/recipe based.
