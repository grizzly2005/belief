# Isolated Web Validation Worker Security Review

## Review scope and conclusion

This review covers the parent controller, spawned child bootstrap, JSON
contracts, fixture registry, Flask/FastAPI adapters, oracle projection, and
cleanup paths used by BELIEF's registered web-validation fixtures.

The resulting boundary is an **isolated process with Python-level controls**.
It is suitable only for reviewed first-party transparent fixtures. It is not a
secure sandbox, does not contain arbitrary hostile code, and does not provide
complete operating-system isolation.

## Threat model

Trusted:

- BELIEF first-party worker code;
- the immutable production fixture registry;
- built-in transparent Flask and FastAPI fixtures;
- canonical `ValidationPlan` models;
- the local user who installed BELIEF.

Untrusted or potentially malformed:

- future MCP or CLI arguments;
- plan and fixture identifiers;
- request and response JSON bytes;
- `source_revision`, timeout, and correlation values;
- every child response field;
- framework exceptions;
- inherited environment secrets;
- unexpected fixture stdout and stderr.

Out of scope:

- hostile native code or direct system calls;
- a compromised Python interpreter or operating-system kernel;
- malicious third-party wheels;
- kernel namespaces, seccomp, AppContainer, restricted tokens, containers, or
  a separate operating-system account;
- arbitrary project or user-provided application code.

## Confirmed defects in the pre-hardening worker

The review confirmed these concrete defects:

1. JSON object keys were not checked for duplicates.
2. JSON depth, total-node count, generic collection length, and generic string
   length were not bounded.
3. A response could not prove that it was the only child message.
4. The spawned target imported BELIEF contracts and the registry before
   changing directory, sanitizing the environment, or installing policy.
5. The child cleared most environment variables only after interpreter
   startup, but did not redirect HOME, profile, app-data, or XDG locations.
6. No filesystem guard prevented a fixture from opening the checkout, a system
   file, or another absolute path.
7. Network guards omitted socket construction, UDP send, asyncio networking,
   urllib, `http.client`, Requests, and HTTPX dispatch.
8. Process guards omitted `os.spawn*`, `os.exec*`, POSIX spawn/fork, nested
   multiprocessing, process pools, and `pty.spawn`.
9. The temporary directory belonged to the child. Forced termination could
   therefore prevent the child's context manager from proving cleanup.
10. There was no reusable cancellation handle or cooperative cancellation
    signal.
11. Child stdout and stderr inherited the invoking process streams, permitting
    protocol/log injection if the worker were later called from MCP.
12. The capability statement did not bind registry source, framework/runtime,
    installed policies, cleanup, or policy violations.
13. The semantic digest included the correlation ID and had no versioned
    separation between semantic evidence and runtime diagnostics.
14. Fixture behavior was selected from the `vulnerable` posture field, so
    behavior and descriptive labeling were not independent.
15. The registry had no stable registry digest or per-fixture source digest.
16. No optional POSIX resource limits were attempted or attested.

## Corrected architecture

The parent creates a unique private temporary root and two one-way
`multiprocessing.Connection` pipes. It starts an explicit `spawn` daemon child
using the inert `belief.validation.worker.bootstrap` target. Caller-controlled
data crosses only as canonical UTF-8 JSON through `send_bytes` and
`recv_bytes`; no caller object graph is unpickled.

The bootstrap module has only top-level standard-library imports. Before
loading BELIEF adapters or a framework, it:

1. validates and enters the parent-owned private root;
2. creates private home, profile, app-data, XDG, cache, and temp directories;
3. replaces the environment with the allowlist below;
4. redirects native stdout/stderr file descriptors to the null device;
5. installs bounded Python text capture;
6. installs preliminary network and process policy;
7. decodes the bounded request and resolves the exact fixture ID through the
   hardcoded registry.

The selected adapter and framework are then imported from fixed code paths.
Required framework initialization and metadata reads complete before the
filesystem policy is installed. Only the prepared local request/oracle
execution runs under the filesystem guard.

## Protocol controls

Request and response schemas are:

```text
belief.validation_worker_request.v2
belief.validation_worker_response.v2
belief.validation_worker_attestation.v2
```

The decoder enforces:

- canonical JSON bytes;
- duplicate-key rejection at every object depth;
- strict UTF-8 and rejection of lone surrogate code points;
- rejection of NaN and infinities;
- exact required fields;
- 16 KiB request and 256 KiB response limits;
- depth, collection, node, and string bounds;
- canonical IDs and lowercase SHA-256 values;
- integer/not-boolean timeout and cost fields;
- reviewed timeout range of 100 through 30,000 milliseconds;
- exact child-envelope and attestation binding;
- no trailing value and no second framed child response.

The closed error taxonomy is:

```text
invalid_request
unsupported_protocol
unknown_fixture
binding_mismatch
dependency_unavailable
timeout
cancelled
child_crash
malformed_response
response_too_large
policy_violation
internal_error
```

Messages are fixed and bounded. Framework exception text and tracebacks never
enter the protocol.

## Environment policy

The runtime environment is rebuilt from an allowlist. BELIEF sets:

```text
HOME
USERPROFILE
APPDATA
LOCALAPPDATA
XDG_CONFIG_HOME
XDG_CACHE_HOME
TMP
TEMP
TMPDIR
BELIEF_VALIDATION_WORKER
PYTHONDONTWRITEBYTECODE
PYTHONUTF8
PYTHONIOENCODING
```

All location variables point below the private root. Only bounded values for
`SYSTEMROOT` and `WINDIR` may be retained from the parent. Everything else is
removed, including Python path/home overrides, proxies,
cloud/provider variables, Git/SSH credential helpers, Docker/Kubernetes
configuration, and names containing token, secret, password, credential, or
API-key material.

This boundary begins inside the spawned Python entrypoint. The operating
system and Python startup machinery necessarily receive the inherited parent
environment before BELIEF code clears it. The attestation therefore means
that the sanitized environment was installed before BELIEF framework and
fixture imports; it does not claim that secrets were absent during interpreter
startup.

## Filesystem policy

Fixture request/oracle execution permits ordinary file operations only when
the resolved target remains below the worker root. Relative paths are resolved
from that root. Absolute paths, `..` escapes, symlink escapes, custom openers,
and `dir_fd` opens outside the model are denied.

The guard covers `builtins.open`, `io.open`, `os.open`,
`pathlib.Path.open/read_text/read_bytes/write_text/write_bytes`, and `chdir`.
Framework imports and required initialization are intentionally completed
before this guard so trusted installed packages can be loaded. The policy is
Python-level and has the usual time-of-check/time-of-use and native-code
limitations.

The path-traversal fixture still models two application boundaries below the
worker root: `allowed/` is the application authorization root, while
`outside/sentinel.txt` remains inside the worker policy root. A vulnerable
application can therefore demonstrate escape from `allowed/` without reaching
host data.

## Network and process policy

Network policy denies IPv4/IPv6 socket creation and network operations on
existing sockets, TCP bind/listen/connect, UDP send, DNS lookup, asyncio
connections and servers, urllib, `http.client`, Requests, and non-ASGI HTTPX
dispatch. Flask `test_client()` and BELIEF's direct in-memory ASGI transport
continue without a listener or network socket.

Process policy denies common subprocess functions, shell helpers,
`os.spawn*`, `os.exec*`, POSIX spawn/fork APIs, asyncio subprocess APIs,
nested `multiprocessing` starts, `ProcessPoolExecutor`, `pty.spawn`, and
Windows `startfile` when present. The child is also created as a daemon.

Every observed denial becomes a bounded `category:action` event. A policy
violation produces an inconclusive result; it can never become `bypassed` or
`enforced`.

## Lifecycle, cancellation, and output

The parent owns the temporary root and all handles. Normal completion,
timeout, cancellation, crash, malformed output, oversized output, start
failure, and send failure converge on the same release path:

1. signal cooperative cancellation when applicable;
2. wait for a short grace period;
3. call `terminate()`;
4. join;
5. call `kill()` and join again if still alive;
6. close every pipe endpoint and process handle;
7. remove the verified temp-root path;
8. attest the cleanup result.

`WorkerRunHandle` permits cancellation before start and during execution.
Runtime child exit codes are retained only in diagnostics and are excluded
from semantic digests.

Python stdout and stderr are captured in separate bounded 4 KiB sinks. ANSI
escapes and unsafe controls are removed; token-shaped and assignment-shaped
secrets are redacted; the absolute temporary root becomes `<worker_root>`.
Native writes to descriptors 1 and 2 go to the null device. Diagnostics are
not included in validation semantics.

## Resource limits

The hard wall-clock timeout is enforced by the parent on Windows and POSIX.
On POSIX, the child also attempts limits for CPU time, open descriptors, file
size, and child process count after framework preparation. Each control is
attested independently as `true`, `false`, or `null`.

Windows reports these POSIX controls as unavailable. BELIEF does not claim an
unreliable Windows equivalent.

## Determinism and attribution

The semantic digest includes observations, normalized errors, limitations,
and the versioned attestation. It excludes correlation ID, duration, child exit
code, stdout/stderr, cancellation text, temporary paths, process IDs,
timestamps, memory addresses, and unrestricted exception strings.

The attestation binds:

- protocol, fixture, registry, and fixture-source digests;
- plan ID and plan digest;
- source revision;
- framework and framework version;
- Python version and platform;
- installed environment/filesystem/network/process policies;
- timeout and cleanup;
- per-control resource-limit state;
- observed policy violations and stable limitations.

Fixture behavior now uses an independent `security_enforced` field. The public
expected-posture label and fixture ID do not drive an oracle or verdict.
Mutation tests rename IDs and swap posture labels while retaining behavior and
prove that observations remain unchanged.

Evidence still concerns the registered transparent fixture. It must not be
attributed to an arbitrary scanned target. Any future MCP execution requires a
separate exact trusted binding for the fixture registry digest, source digest,
plan digest, case type, and source revision.

## Residual limitations

- Python-level monkeypatches are defense in depth for reviewed code, not
  hostile-code containment.
- Native extensions, direct system calls, `ctypes`, interpreter compromise,
  and kernel compromise are outside scope.
- Installed third-party framework code is trusted for this boundary.
- Framework imports and explicit preparation read installed package/source
  files before the fixture filesystem guard.
- POSIX resource-limit availability varies by kernel and invocation authority.
- Symlink testing can be unavailable on Windows without suitable privileges.
- A killed child cannot supply trustworthy child-side policy state; the parent
  reports child attestation as unavailable while still reporting its own
  timeout and cleanup result.
