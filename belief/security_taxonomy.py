"""Central source/sink/sanitizer/guarantee taxonomy for BELIEF v4.

The entries here are deliberately small and deterministic. They consolidate
patterns BELIEF already used locally, plus high-level ideas observed in
permissively licensed tools such as Bandit and framework route examples. No
external project code is copied.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class SourcePattern:
    name: str
    category: str
    risk_level: str = "medium"
    frameworks: tuple[str, ...] = ()


@dataclass(frozen=True)
class SinkPattern:
    name: str
    category: str
    cwe: str
    severity: str = "medium"


@dataclass(frozen=True)
class SanitizerPattern:
    name: str
    category: str
    strength: str = "medium"


@dataclass(frozen=True)
class GuaranteePattern:
    name: str
    category: str
    expression: str
    strength: str = "medium"


SOURCE_PATTERNS: tuple[SourcePattern, ...] = (
    SourcePattern("input", "user_input", "high"),
    SourcePattern("request.form", "user_input", "high", ("flask",)),
    SourcePattern("request.args", "user_input", "high", ("flask",)),
    SourcePattern("request.files", "user_input", "high", ("flask",)),
    SourcePattern("request.json", "user_input", "high", ("flask",)),
    SourcePattern("request.data", "user_input", "high", ("flask",)),
    SourcePattern("request.headers", "user_input", "medium", ("flask",)),
    SourcePattern("request.cookies", "user_input", "medium", ("flask",)),
    SourcePattern("flask.request.form", "user_input", "high", ("flask",)),
    SourcePattern("flask.request.args", "user_input", "high", ("flask",)),
    SourcePattern("fastapi.path_param", "user_input", "medium", ("fastapi",)),
    SourcePattern("fastapi.query_param", "user_input", "medium", ("fastapi",)),
    SourcePattern("fastapi.body_param", "user_input", "high", ("fastapi",)),
    SourcePattern("os.environ", "environment", "medium"),
    SourcePattern("os.environ.get", "environment", "medium"),
    SourcePattern("os.getenv", "environment", "medium"),
    SourcePattern("cache_file.read", "file", "medium"),
    SourcePattern("file.read", "file", "medium"),
    SourcePattern("db.fetchone", "database", "medium"),
    SourcePattern("db.fetchall", "database", "medium"),
)


SINK_PATTERNS: tuple[SinkPattern, ...] = (
    SinkPattern("open", "path", "CWE-22", "high"),
    SinkPattern("os.remove", "path", "CWE-22", "high"),
    SinkPattern("os.unlink", "path", "CWE-22", "high"),
    SinkPattern("shutil.rmtree", "path", "CWE-22", "high"),
    SinkPattern("subprocess.run", "command", "CWE-78", "critical"),
    SinkPattern("subprocess.call", "command", "CWE-78", "critical"),
    SinkPattern("subprocess.Popen", "command", "CWE-78", "critical"),
    SinkPattern("os.system", "command", "CWE-78", "critical"),
    SinkPattern("os.popen", "command", "CWE-78", "critical"),
    SinkPattern("pickle.load", "deserialization", "CWE-502", "critical"),
    SinkPattern("pickle.loads", "deserialization", "CWE-502", "critical"),
    SinkPattern("yaml.load", "deserialization", "CWE-502", "high"),
    SinkPattern("yaml.unsafe_load", "deserialization", "CWE-502", "critical"),
    SinkPattern("marshal.loads", "deserialization", "CWE-502", "critical"),
    SinkPattern("Markup", "xss", "CWE-79", "high"),
    SinkPattern("render_template_string", "xss", "CWE-79", "high"),
    SinkPattern("mark_safe", "xss", "CWE-79", "high"),
    SinkPattern("requests.get", "ssrf", "CWE-918", "high"),
    SinkPattern("requests.post", "ssrf", "CWE-918", "high"),
    SinkPattern("httpx.get", "ssrf", "CWE-918", "high"),
    SinkPattern("execute", "sql", "CWE-89", "high"),
    SinkPattern("raw_sql", "sql", "CWE-89", "high"),
    SinkPattern("filter_by", "object_lookup", "CWE-639", "high"),
    SinkPattern("get", "object_lookup", "CWE-639", "high"),
)


SANITIZER_PATTERNS: tuple[SanitizerPattern, ...] = (
    SanitizerPattern("escape", "xss", "high"),
    SanitizerPattern("html.escape", "xss", "high"),
    SanitizerPattern("markupsafe.escape", "xss", "high"),
    SanitizerPattern("Markup.escape", "xss", "high"),
    SanitizerPattern("secure_filename", "path", "high"),
    SanitizerPattern("safe_join", "path", "high"),
    SanitizerPattern("os.path.basename", "path", "medium"),
    SanitizerPattern("basename", "path", "medium"),
    SanitizerPattern("pydantic.BaseModel", "schema_validation", "weak"),
    SanitizerPattern("Depends", "dependency_validation", "weak"),
)


GUARANTEE_PATTERNS: tuple[GuaranteePattern, ...] = (
    GuaranteePattern(
        "Storage.path",
        "path_boundary",
        "storage.path.enforces_store_boundary == true",
        "strong",
    ),
    GuaranteePattern("commonpath", "path_boundary", "path.is_within_store == true", "strong"),
    GuaranteePattern("realpath", "path_normalization", "path.is_normalized == true", "medium"),
    GuaranteePattern("abspath", "path_normalization", "path.is_normalized == true", "medium"),
    GuaranteePattern(
        "secure_filename",
        "filename_validation",
        "filename.matches_allowed_pattern == true",
        "strong",
    ),
    GuaranteePattern("uuid4", "server_generated_value", "identifier.server_generated == true", "strong"),
    GuaranteePattern("login_required", "authorization", "route.requires_login == true", "strong"),
    GuaranteePattern("admin_required", "authorization", "route.requires_admin == true", "strong"),
    GuaranteePattern(
        "permission_required",
        "authorization",
        "route.requires_permission == true",
        "strong",
    ),
    GuaranteePattern(
        "source_id",
        "ownership_scope",
        "query.scoped_to_current_source == true",
        "strong",
    ),
    GuaranteePattern("user_id", "ownership_scope", "query.scoped_to_current_user == true", "strong"),
    GuaranteePattern("owner_id", "ownership_scope", "query.scoped_to_current_user == true", "strong"),
    GuaranteePattern("tenant_id", "ownership_scope", "query.scoped_to_current_tenant == true", "strong"),
    GuaranteePattern(
        "html_output.user_values_escaped",
        "escaping",
        "html_output.user_values_escaped == true",
        "strong",
    ),
    GuaranteePattern(
        "deserialization.input_trusted",
        "serialization_safety",
        "deserialization.input_trusted == true",
        "strong",
    ),
    GuaranteePattern("signed", "signed_value", "input.signature_verified == true", "medium"),
)


def source_names() -> tuple[str, ...]:
    return tuple(pattern.name for pattern in SOURCE_PATTERNS)


def sink_names(category: str | None = None) -> tuple[str, ...]:
    return tuple(
        pattern.name for pattern in SINK_PATTERNS
        if category is None or pattern.category == category
    )


def sanitizer_names(category: str | None = None) -> tuple[str, ...]:
    return tuple(
        pattern.name for pattern in SANITIZER_PATTERNS
        if category is None or pattern.category == category
    )


def guarantee_expressions(category: str | None = None) -> tuple[str, ...]:
    return tuple(
        pattern.expression for pattern in GUARANTEE_PATTERNS
        if category is None or pattern.category == category
    )


def find_sink(name: str) -> SinkPattern | None:
    lowered = (name or "").lower()
    for pattern in SINK_PATTERNS:
        pname = pattern.name.lower()
        if lowered == pname or lowered.endswith("." + pname) or pname in lowered:
            return pattern
    return None


def is_ownership_guarantee(text: str) -> bool:
    lowered = (text or "").lower()
    return any(token in lowered for token in [
        "source_id",
        "source_uuid",
        "user_id",
        "owner_id",
        "tenant_id",
        "current_user",
        "logged_in_source",
        "session",
    ])


def is_path_boundary_guarantee(text: str) -> bool:
    lowered = (text or "").lower()
    return any(token in lowered for token in [
        "storage.path",
        "commonpath",
        "path.is_within_store",
        "enforces_store_boundary",
        "safe_join",
    ])


def contains_pattern(value: str, patterns: Iterable[str]) -> bool:
    lowered = (value or "").lower()
    return any(pattern.lower() in lowered for pattern in patterns)


__all__ = [
    "SourcePattern",
    "SinkPattern",
    "SanitizerPattern",
    "GuaranteePattern",
    "SOURCE_PATTERNS",
    "SINK_PATTERNS",
    "SANITIZER_PATTERNS",
    "GUARANTEE_PATTERNS",
    "source_names",
    "sink_names",
    "sanitizer_names",
    "guarantee_expressions",
    "find_sink",
    "is_ownership_guarantee",
    "is_path_boundary_guarantee",
]
