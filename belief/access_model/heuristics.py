"""Conservative Python access-control heuristics."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import (
    AccessHypothesis,
    Actor,
    AuthorizationEvidence,
    ObjectAction,
    ProtectedObject,
)


OBJECT_ID_NAMES = {
    "account_id", "document_id", "file_id", "invoice_id", "order_id",
    "org_id", "organization_id", "project_id", "subscription_id",
    "tenant_id", "user_id",
}
SENSITIVE_OBJECTS = {
    "account", "admin", "document", "file", "invoice", "order", "organization",
    "payment", "permission", "project", "role", "secret", "subscription", "tenant",
    "token", "user",
}


def infer_access_hypotheses_from_source_tree(target: Path) -> list[AccessHypothesis]:
    root = Path(target)
    files = [root] if root.is_file() else sorted(root.rglob("*.py"))
    hypotheses: list[AccessHypothesis] = []
    for path in files:
        if _skip_path(path):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                hypothesis = _function_hypothesis(node, source, str(path))
                if hypothesis:
                    hypotheses.append(hypothesis)
    return sorted(hypotheses, key=lambda item: (item.route or "", item.title))


def _function_hypothesis(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
    file_path: str,
) -> AccessHypothesis | None:
    names = _names(node)
    object_id = _object_id(node, names)
    if not object_id:
        return None
    action = _action(node.name)
    if action.name == "unknown":
        return None
    guards = _guards(node, source, file_path)
    strong_guards = [guard for guard in guards if guard.strength == "strong"]
    if strong_guards:
        return None

    detected = guards
    route = _route(node) or node.name
    obj = ProtectedObject(
        type_name=_object_type(object_id, node.name),
        id_name=object_id,
        owner_field="owner_id" if "owner" in names else None,
        tenant_field="tenant_id" if "tenant_id" in names else None,
    )
    missing = ["owner_or_tenant_scoped_lookup"]
    if any(guard.strength == "weak" for guard in guards):
        missing.append("authorization_beyond_login")
    title = f"Candidate object authorization gap on {route}"
    return AccessHypothesis(
        title=title,
        actor=_actor(names),
        object=obj,
        action=action,
        route=route,
        missing_guards=missing,
        detected_guards=detected,
        validation_steps=_validation_steps(obj, action),
        confidence="high" if any(guard.strength == "weak" for guard in guards) else "medium",
    )


def _names(node: ast.AST) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
        elif isinstance(child, ast.arg):
            names.add(child.arg)
        elif isinstance(child, ast.Attribute):
            names.add(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            names.add(child.value)
    return names


def _object_id(node: ast.FunctionDef | ast.AsyncFunctionDef, names: set[str]) -> str | None:
    arg_names = [arg.arg for arg in node.args.args]
    candidates = [name for name in arg_names + sorted(names) if name in OBJECT_ID_NAMES or name.endswith("_id")]
    if not candidates:
        return None
    return sorted(candidates, key=lambda value: (value not in OBJECT_ID_NAMES, value))[0]


def _guards(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
    file_path: str,
) -> list[AuthorizationEvidence]:
    segment = ast.get_source_segment(source, node) or ""
    lowered = segment.lower()
    guards: list[AuthorizationEvidence] = []

    decorators = [_decorator_name(dec) for dec in node.decorator_list]
    for decorator in decorators:
        if any(token in decorator for token in ("admin", "permission", "role_required")):
            guards.append(AuthorizationEvidence("decorator", decorator, "strong", file_path, node.lineno))
        elif any(token in decorator for token in ("login_required", "authenticated", "current_user")):
            guards.append(AuthorizationEvidence("decorator", decorator, "weak", file_path, node.lineno))

    strong_patterns = [
        r"filter_by\s*\([^)]*(user_id|owner_id)\s*=\s*current_user\.id",
        r"filter_by\s*\([^)]*tenant_id\s*=\s*current_user\.tenant_id",
        r"(user_id|owner_id)\s*==\s*current_user\.id",
        r"tenant_id\s*==\s*current_user\.tenant_id",
    ]
    for pattern in strong_patterns:
        if re.search(pattern, lowered):
            guards.append(AuthorizationEvidence("owner_tenant_scope", pattern, "strong", file_path, node.lineno))
    if "abort(403" in lowered or "httpexception(status_code=403" in lowered:
        guards.append(AuthorizationEvidence("explicit_deny", "403 deny path", "medium", file_path, node.lineno))
    if "if user:" in lowered or "if current_user:" in lowered:
        guards.append(AuthorizationEvidence("truthiness", "loose user truthiness", "weak", file_path, node.lineno))
    return guards


def _decorator_name(node: ast.AST) -> str:
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ""


def _route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for decorator in node.decorator_list:
        try:
            text = ast.unparse(decorator)
        except Exception:
            continue
        match = re.search(r"""['"]([^'"]*/[^'"]*)['"]""", text)
        if match:
            return match.group(1)
    return None


def _actor(names: set[str]) -> Actor | None:
    actor_names = ["current_user", "request.user", "g.user", "session"]
    for name in actor_names:
        if name.split(".")[-1] in names or name in names:
            return Actor(name=name, role=None, source="python_heuristic")
    return None


def _action(name: str) -> ObjectAction:
    lowered = name.lower()
    if any(token in lowered for token in ("delete", "remove", "cancel", "refund", "approve", "ship", "fulfill", "pay")):
        return ObjectAction(name=lowered, mutates_state=True)
    if any(token in lowered for token in ("update", "edit", "patch", "assign", "invite", "promote")):
        return ObjectAction(name=lowered, mutates_state=True)
    if any(token in lowered for token in ("read", "show", "get", "export", "download", "view")):
        return ObjectAction(name=lowered, mutates_state=False, reads_sensitive_data=True)
    return ObjectAction(name="unknown", mutates_state=False)


def _object_type(object_id: str, function_name: str) -> str:
    base = object_id.removesuffix("_id")
    if base in {"id", "pk"}:
        tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", function_name.lower()) if token]
        for token in tokens:
            if token in SENSITIVE_OBJECTS:
                return token
        return "object"
    return base


def _validation_steps(obj: ProtectedObject, action: ObjectAction) -> list[str]:
    object_name = obj.type_name or "object"
    id_name = obj.id_name or "object_id"
    return [
        f"Create or identify {object_name} as User A.",
        "Authenticate as User B with the same privilege level.",
        f"Replay the request using User A's {id_name}.",
        "Expected secure behavior: 403, 404, or scoped lookup failure.",
        (
            "Reportability increases if User B can "
            f"{'modify' if action.mutates_state else 'read'} User A's {object_name}."
        ),
    ]


def _skip_path(path: Path) -> bool:
    excluded = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "env", "node_modules"}
    return any(part in excluded for part in path.parts)


__all__ = ["infer_access_hypotheses_from_source_tree"]
