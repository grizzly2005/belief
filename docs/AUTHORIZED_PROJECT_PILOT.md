# Locally opted-in real-project pilot

## Scope

BELIEF exposes one explicit real-project adapter:

```text
adapter_id: flask_jwt_extended_authorized_pilot_v1
project: github.com/vimalloc/flask-jwt-extended
revision: 1910726f152016c3e48d61792983eebe11f54ac2
source SHA-256: 4e42c82b7d0a210350cc99fcc698e478f1b62b76785a413d40525b0555b70c52
source files: 79
source bytes: 300343
```

The source digest is a canonical SHA-256 over the sorted non-Git filesystem
inventory. Each row binds the relative POSIX path, byte length, and file
SHA-256. Adding, deleting, renaming, or changing any source file invalidates
the adapter.

This is a static-only pilot. It does not import the target, start its
application, run its tests, execute a validation plan against it, use its
configuration, or write to it.

## Explicit local-operator opt-in

The adapter is unavailable unless the local operator provides a distinct
startup opt-in:

```text
BELIEF_MCP_FLASKJWT_PILOT_AUTHORIZED=true
BELIEF_MCP_FLASKJWT_PILOT_AUTHORIZATION_ID=auth_<64 lowercase hex characters>
```

The authorization-shaped identifier is supplied again to the tool with the
exact adapter ID, revision, source digest, and a literal boolean
acknowledgement. The tool verifies that all fields match the startup opt-in.
This is a local consent gate only. It is not authentication, cryptographic
authorization, or proof that the operator controls the upstream project.

The configured `BELIEF_MCP_WORKSPACE_ROOT` is the only workspace inspected.
The pilot tool itself accepts no path. It also accepts no module, callable,
source text, URL, command, host, port, import expression, or adapter
implementation.

## Tool request

`belief_prepare_authorized_project_pilot` accepts exactly:

```json
{
  "adapter_id": "flask_jwt_extended_authorized_pilot_v1",
  "authorization_id": "auth_<64 lowercase hex characters>",
  "source_revision": "1910726f152016c3e48d61792983eebe11f54ac2",
  "source_digest": "4e42c82b7d0a210350cc99fcc698e478f1b62b76785a413d40525b0555b70c52",
  "acknowledge_authorized_project_access": true
}
```

BELIEF performs the pilot in this order:

1. resolves Git `HEAD` using bounded direct reads of `.git/HEAD`, its local
   branch ref, or `packed-refs`;
2. rejects Git files, source files, directories, symlinks, or junctions that
   escape the configured workspace;
3. reads every bounded source file and compares the revision, file count, byte
   count, and digest with the built-in immutable adapter specification;
4. writes those already-attested bytes to a new temporary snapshot;
5. verifies the snapshot digest, analyzes the snapshot rather than the live
   workspace, and verifies the snapshot again after analysis;
6. re-attests the original workspace and refuses the result if any revision or
   source-inventory field changed.

The adapter uses no Git subprocess and performs no network request.

## Binding and abstention

Every generated static plan receives
`belief.authorized_project_binding.v1`, containing:

- the exact adapter and project IDs;
- run, case, and plan IDs;
- the canonical plan digest;
- the exact revision and source digest;
- source file and byte counts;
- the separate authorization ID and grant digest;
- `execution_scope = authorized_real_project_static_only`;
- `dynamic_execution_authorized = false`.

These bindings are deliberately not executable by `belief_validate_plan`.
The existing worker continues to accept only
`registered_transparent_fixture_only` bindings.

Every projected pilot result therefore states:

```text
outcome = inconclusive
execution_status = abstained
maturity = statically_supported
target_vulnerability_confirmed = false
human_confirmation_required = true
human_confirmed = false
report_ready = false
confirmed_vulnerability = false
```

The result store remains empty because no dynamic validation result was
produced. Static candidates and plans remain available through the ordinary
in-memory run resources for human review.

## Residual limitations

- The local operator and Python interpreter remain trusted.
- The startup opt-in is not a cryptographic authorization mechanism or an
  external proof of authority.
- Direct Git metadata reading supports an in-place `.git` directory, a detached
  revision, a loose local branch ref, or `packed-refs`; linked worktrees and
  submodule-style `.git` files are rejected.
- The adapter proves byte identity with the pinned local snapshot, not the
  authenticity of a remote hosting account or deployment.
- Static analysis consumes a temporary copy of the attested bytes. The live
  workspace is read for pre/post attestation but is not analyzed in place.
- Static analysis can produce false positives and false negatives.
- Dynamic confirmation of the real target remains deferred to a future,
  separately reviewed target-specific harness.
