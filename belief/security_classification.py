"""Shared classification of explicit security findings for hypothesis/triage."""

from __future__ import annotations

import re

from .models import Finding


_AUTHORIZATION_CWES = frozenset({"CWE-639", "CWE-862", "CWE-863"})
_NON_SECURITY_CATEGORIES = frozenset({"structural", "temporal", "cycles"})
_AUTHORIZATION_LABEL = re.compile(
    r"(?<![a-z0-9])(?:idor|bola|access[\s_-]+control|authorization[\s_-]+bypass)(?![a-z0-9])",
    re.IGNORECASE,
)


def is_authorization_finding(finding: Finding) -> bool:
    """Recognize a security classification without promoting code identifiers.

    A CWE is authoritative. Untyped scanner findings may use explicit security
    labels, but raw evidence and structural variable observations cannot supply
    an authorization category. Actual request-to-resource flows are handled by
    the detectors/dataflow layer, independently of this label fallback.
    """
    cwe = str(finding.cwe or "").strip().upper()
    if cwe:
        return cwe in _AUTHORIZATION_CWES
    category = str(finding.metadata.get("category") or "").lower()
    if category in _NON_SECURITY_CATEGORIES or finding.source.lower() in _NON_SECURITY_CATEGORIES:
        return False
    return any(
        _AUTHORIZATION_LABEL.search(str(label or ""))
        for label in (finding.rule_id, finding.title, finding.description)
    )
