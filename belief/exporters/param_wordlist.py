"""High-value parameter wordlist exporter for passive bridge workflows."""

from __future__ import annotations

from pathlib import Path


PARAM_MINER_WORDS = [
    "account_id",
    "admin",
    "amount",
    "balance",
    "credit",
    "discount",
    "is_admin",
    "org_id",
    "organization_id",
    "owner_id",
    "payment_status",
    "permission",
    "plan",
    "price",
    "project_id",
    "quota",
    "role",
    "roles",
    "scope",
    "state",
    "status",
    "tenant_id",
    "user_id",
]


def render_param_wordlist(extra_words: list[str] | None = None) -> str:
    words = sorted(set(PARAM_MINER_WORDS + list(extra_words or [])))
    return "\n".join(words) + "\n"


def write_param_wordlist(path: str | Path, extra_words: list[str] | None = None) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_param_wordlist(extra_words), encoding="utf-8")
    return output


__all__ = ["PARAM_MINER_WORDS", "render_param_wordlist", "write_param_wordlist"]
