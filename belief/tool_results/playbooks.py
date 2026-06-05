"""Safe validation playbooks for report-ready BELIEF audit candidates."""

from __future__ import annotations

from typing import Any


_PLAYBOOKS: dict[str, list[str]] = {
    "access_control": [
        "Create or identify the object as User A.",
        "Authenticate as User B with the same privilege level and authorized scope.",
        "Replay the same request shape using User A's object identifier as a placeholder value.",
        "Expected secure behavior: 403, 404, or scoped lookup failure.",
        "Candidate becomes reportable only if User B can read, modify, delete, cancel, approve, refund, or export User A's object.",
    ],
    "mass_assignment": [
        "Identify a create or update endpoint and the server-side model it writes.",
        "Review sensitive fields such as role, is_admin, price, status, tenant_id, owner_id, quota, or workflow state.",
        "In an authorized test environment, check whether unexpected sensitive fields are accepted and persisted.",
        "Candidate becomes reportable only if client-controlled privilege, ownership, price, quota, or workflow state fields are honored.",
    ],
    "path_traversal": [
        "Identify the user-controlled path fragment and the file read/write sink.",
        "Review whether the code normalizes the path before enforcing a base-directory boundary.",
        "Verify whether absolute paths, parent-directory traversal, and symlink boundary escapes are rejected.",
        "Candidate becomes reportable only if authorized validation confirms access outside the intended directory boundary.",
    ],
    "unsafe_deserialization": [
        "Identify whether serialized data can be influenced by an untrusted actor.",
        "Identify the deserialization sink and the accepted data format.",
        "Check for signing, MAC verification, trusted-source guarantees, or strict type allowlists.",
        "Candidate becomes reportable only if untrusted serialized data reaches the sink without a strong guarantee.",
    ],
    "ssrf": [
        "Identify whether the outbound URL host, scheme, or path is user-controlled.",
        "Review whether the code enforces a host allowlist and rejects internal, metadata, and loopback destinations.",
        "Check whether redirects are constrained by the same outbound policy.",
        "Candidate becomes reportable only after authorized validation confirms an unintended outbound request path.",
    ],
    "command_injection": [
        "Identify whether command arguments can be influenced by an untrusted actor.",
        "Review whether shell execution is used and whether arguments are passed as a safe argument list.",
        "Check for strict allowlists, fixed command templates, and removal of shell metacharacter interpretation.",
        "Candidate becomes reportable only if authorized validation confirms command behavior can be changed by input.",
    ],
    "sql_injection": [
        "Identify whether SQL fragments include attacker-controlled data.",
        "Review whether parameterized queries or ORM binding are enforced for every dynamic value.",
        "Check whether string formatting or concatenation reaches a query execution sink.",
        "Candidate becomes reportable only if authorized validation confirms query semantics can be influenced by input.",
    ],
    "xss": [
        "Identify whether rendered output contains user-controlled data.",
        "Review whether the rendering context has automatic escaping or explicit output encoding.",
        "Check whether safe-markup bypasses are fed by untrusted values.",
        "Candidate becomes reportable only if authorized validation confirms untrusted scriptable content can render.",
    ],
}


def playbook_for_category(category: str) -> list[str]:
    normalized = _normalize_category(category)
    return list(_PLAYBOOKS.get(normalized, [
        "Review the imported evidence in authorized scope.",
        "Identify the affected route, object, source, sink, and existing guard.",
        "Collect missing proof before treating the candidate as reportable.",
    ]))


def playbook_for_case(case: Any) -> list[str]:
    metadata = getattr(case, "metadata", {}) if hasattr(case, "metadata") else {}
    category = ""
    if isinstance(metadata, dict):
        category = str(metadata.get("category") or "")
    category = category or str(getattr(case, "case_type", ""))
    return playbook_for_category(category)


def _normalize_category(value: str) -> str:
    text = str(value or "").lower()
    if any(token in text for token in ("idor", "bola", "authz", "authorization", "access_control")):
        return "access_control"
    if "mass" in text and "assign" in text:
        return "mass_assignment"
    if "path" in text or "traversal" in text:
        return "path_traversal"
    if "deserial" in text or "pickle" in text:
        return "unsafe_deserialization"
    if "ssrf" in text or "server_side_request" in text:
        return "ssrf"
    if "command" in text or "shell" in text:
        return "command_injection"
    if "sql" in text:
        return "sql_injection"
    if "xss" in text or "cross_site" in text:
        return "xss"
    return text or "unknown"


__all__ = ["playbook_for_case", "playbook_for_category"]
