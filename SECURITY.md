# Security Policy

BELIEF v4 is experimental security research software for authorized, local code
review.

## Supported Scope

The public repository focuses on:

- local Python source-code analysis;
- offline fixtures and regression tests;
- SARIF/JSON/Markdown reporting;
- optional local bridge experiments;
- narrow Z3 contradiction checks.

The public repository is not intended to provide an active network scanner or
an exploit-generation workflow.

## Tool Bridge Safety

BELIEF tool bridges default to passive/local behavior:

- import existing JSON/SARIF outputs;
- export validation recipes;
- run safe local commands only when explicitly requested.

Bridges that can perform dynamic testing, request replay, fuzzing, active
scanning, or network access are blocked by default. They require explicit
opt-in flags such as `--allow-dynamic`, `--allow-network`, and a scope file.

Do not store cookies, bearer tokens, auth headers, API keys, or session secrets
in repository files, test fixtures, bridge manifests, or recipe exports. Recipes
must use placeholders and require operators to supply credentials outside the
repo.

## Reporting a Vulnerability

Please report issues through GitHub security advisories or a private maintainer
channel when available. Avoid posting working exploit details publicly before a
fix is available.

Include:

- affected commit or release;
- minimal local reproduction steps;
- expected behavior;
- observed behavior;
- whether the issue involves secrets, unsafe file writes, unexpected network
  access, command execution, or incorrect security classification.

## Responsible Use

Use BELIEF only on codebases and artifacts you are authorized to review. Do not
use this project to scan or test third-party live systems without permission.
