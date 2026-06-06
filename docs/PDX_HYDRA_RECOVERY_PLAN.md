# PDX / HYDRA Recovery Plan

This document records what BELIEF may safely recover from local PDX/HYDRA
research notes without importing the runtime.

## Keep

- Scope policy concepts -> `belief/scope`.
- Burp HTTP observations -> passive HAR/Burp importers and access observations.
- PDX deltas -> `ExternalFinding` and `AccessObservation`.
- DataRouter concepts -> future BELIEF HTTP capture router design notes only.
- Passive/imported-output first workflows.

## Do Not Import

- HYDRA runtime.
- Binary PDX parser or ctypes bindings.
- SSH honeypot code.
- Personas, lures, WebChat, cloud sync, API engines, or real sessions.
- Active validation, exploit payloads, browser automation, or network scanning.

## Current Safe Path

BELIEF v1 orchestration now uses:

```text
scope JSON -> target profile -> tool profile -> availability -> run plan -> safe executor -> normalized imports
```

The bridge stays local-only and conservative. Imported evidence remains
candidate evidence until a human validates it in authorized scope.
