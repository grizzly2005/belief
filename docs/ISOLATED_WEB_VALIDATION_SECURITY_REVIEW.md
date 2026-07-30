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

The parent creates a unique private outer container, a fixed `child` root
inside it, and two one-way `multiprocessing.Connection` pipes. It starts an
explicit `spawn` daemon child using the inert
`belief.validation.worker.bootstrap` target. Caller-controlled data crosses
only as canonical UTF-8 JSON through `send_bytes` and `recv_bytes`; no caller
object graph is unpickled.

The bootstrap module has only top-level standard-library imports. Before
loading BELIEF adapters or a framework, it:

1. validates the outer container and fixed child relationship, then enters the
   child root;
2. creates private home, profile, app-data, XDG, cache, and temp directories;
3. replaces the environment with the allowlist below;
4. redirects native stdout/stderr file descriptors to the null device;
5. installs bounded Python text capture;
6. installs preliminary network and process policy;
7. decodes the bounded request and resolves the exact fixture ID through the
   hardcoded registry.

The selected adapter and framework are then imported from fixed code paths.
Required lazy framework metadata is preloaded, resource limits are applied, and
the filesystem policy is installed around both fixture preparation and
execution. The fixture application itself is therefore created under policy.

## Protocol controls

Request and response schemas are:

```text
belief.validation_worker_request.v2
belief.validation_worker_response.v3
belief.validation_worker_attestation.v3
```

The reader verifies canonical v2 responses and migrates them in memory. Writers
emit only v3.

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

Fixture preparation and request/oracle execution permit ordinary file
operations only when the resolved target remains below the fixed child root.
Relative paths are resolved from that root. Absolute escapes, `..` escapes,
symlink escapes, custom openers, and unsupported `dir_fd` operations are
denied.

The guard covers `builtins.open`, `io.open`, `os.open`,
`pathlib.Path.open/read_text/read_bytes/write_text/write_bytes/resolve`,
`chdir`,
rename, replace, remove, unlink, directory creation/removal, symlink, hardlink,
listdir/scandir, stat/lstat, readlink, truncate, chmod, and reviewed `shutil`
copy/move/rmtree operations. Both paths of a two-path operation are checked;
renaming, replacing, or removing the child root itself is rejected.

`Path.resolve()` validates the lexical candidate, permits only its internal
ancestor probes while resolution is active, and then validates the resolved
target. A fixture still cannot directly stat/lstat the temporary parent or use
`..` to resolve outside the child root.

Framework and fixed adapter imports occur before this guard so trusted
installed packages can be loaded. Preparation of the fixture application does
not. The policy is Python-level and has the usual time-of-check/time-of-use and
native-code limitations.

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

## Evidence conclusion policy

One shared evidence policy is used by the worker, runner, benchmark, MCP
projection, and metrics. Every observation declares one role:

```text
functional_baseline
primary_security
secondary_security
optional
```

It also declares whether it is required for a conclusion. A completed process
is not sufficient: a conclusion requires a passing required baseline and at
least one evaluated primary-security oracle. An unevaluated required security
oracle forces abstention; a failed evaluated security oracle produces
`bypassed`; only passing required security evidence can produce `enforced`.
Missing optional evidence remains an explicit limitation.

Cross-field response validation rejects completed responses with protocol
errors, failed responses with observations or a baseline, and any
cancelled/timed-out/invalid/policy-violating response that attempts a conclusive
outcome.

## Lifecycle, cancellation, and output

The parent owns the outer container, child root, and all handles. Normal completion,
timeout, cancellation, crash, malformed output, oversized output, start
failure, and send failure converge on the same release path:

1. signal cooperative cancellation when applicable;
2. wait for a short grace period;
3. call `terminate()`;
4. join;
5. call `kill()` and join again if still alive;
6. close every pipe endpoint and process handle;
7. remove the verified outer-container path, independently of the child path;
8. attest cleanup only when the complete outer container is absent.

`WorkerRunHandle` permits cancellation before start and during execution.
Runtime child exit codes are retained only in diagnostics and are excluded
from evidence digests.

Python stdout and stderr are captured in separate bounded 4 KiB sinks. ANSI
escapes and unsafe controls are removed; token-shaped and assignment-shaped
secrets are redacted; the absolute temporary root becomes `<worker_root>`.
Native writes to descriptors 1 and 2 go to the null device. Diagnostics are
not included in validation semantics.

## Resource limits

The hard wall-clock timeout is enforced by the parent on Windows and POSIX.
On POSIX, the child also attempts limits for CPU time, open descriptors, file
size, and child process count before fixture preparation. Each control is
attested independently as `true`, `false`, or `null`.

Windows reports these POSIX controls as unavailable. BELIEF does not claim an
unreliable Windows equivalent.

## Determinism and attribution

The v3 protocol separates three hashes:

- `evidence_digest` covers observations, baseline, normalized errors, and
  stable limitations, but excludes runtime/platform attestation;
- `attestation_digest` covers the complete versioned runtime attestation;
- `response_digest` covers the full response envelope.

`semantic_digest` is a deprecated compatibility alias for
`evidence_digest`. Correlation ID, duration, child exit code, stdout/stderr,
cancellation text, temporary paths, and runtime versions cannot perturb the
evidence digest.

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

The platform label derives only from `sys.platform` and interpreter pointer
width. It deliberately avoids `platform.system()`/`platform.machine()` because
older Windows Python versions may implement those probes through a subprocess
after the worker process policy is active.

Each fixture behavior now lives in a separate fixed application module behind
an opaque public ID. There is no runtime `security_enforced` switch and no
expected-posture label in scanner, worker, MCP, or plan-generation input.
Ground truth exists only in evaluator-side metadata. Tests prove that changing
evaluator labels or fixture IDs cannot change execution, that paired
applications have different source digests, and that a static miss remains a
static miss.

Evidence still concerns the registered transparent fixture. It must not be
attributed to an arbitrary scanned target. The stacked MCP v0.2 implementation
therefore requires a separate exact trusted binding for the fixture registry
digest, source digest, plan digest, case type, source revision, run, and case.
See [`MCP_DYNAMIC_VALIDATION_SECURITY.md`](MCP_DYNAMIC_VALIDATION_SECURITY.md).

## Residual limitations

- Python-level monkeypatches are defense in depth for reviewed code, not
  hostile-code containment.
- Native extensions, direct system calls, `ctypes`, interpreter compromise,
  and kernel compromise are outside scope.
- Installed third-party framework code is trusted for this boundary.
- Allowlisted framework/fixed-adapter imports and lazy framework metadata reads
  occur before the fixture filesystem guard; fixture application preparation
  occurs under it.
- POSIX resource-limit availability varies by kernel and invocation authority.
- Symlink testing can be unavailable on Windows without suitable privileges.
- A killed child cannot supply trustworthy child-side policy state; the parent
  reports child attestation as unavailable while still reporting its own
  timeout and cleanup result.
