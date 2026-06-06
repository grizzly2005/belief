# PDX External Pack

This directory is a documentation-only placeholder for a future passive PDX mapping pack.

The current BELIEF integration supports only offline, JSON-based PDX import/export through the
core adapter modules. This external pack does not contain executable tools, scanners, runtime
bindings, HYDRA components, binary PDX loaders, credentials, sessions, or network integrations.

## Scope

- Document passive mapping ideas for BELIEF JSON reports and PDX JSON bundles.
- Keep examples deterministic and safe for local tests.
- Avoid active validation, exploitation, scanning, callback infrastructure, or runtime imports.
- Avoid secrets, real sessions, lures, personas, API clients, WebChat, cloud sync, and HYDRA code.

## Non-goals

- No PDX/HYDRA runtime execution.
- No binary PDX, ctypes bridge, or native HMAC binding.
- No automatic vulnerability confirmation.
- No LLM, API, browser, or network calls.
- No global feedback suppression or machine-learning feedback application.

## Future Use

If this pack grows later, it should remain a bridge layer that describes safe, passive mappings.
Executable integrations should live behind explicit BELIEF commands with local tests and clear
security boundaries.
