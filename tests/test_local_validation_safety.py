"""Negative controls proving the local engine does not use unsafe surfaces."""

from __future__ import annotations

import importlib
import os
import socket
import subprocess

import pytest

from belief.validation.execution_models import ValidationExecutionContext
from belief.validation.plans import build_validation_plan
from belief.validation.runner import run_validation_plan


pytestmark = pytest.mark.security


def _plan(case_type: str):
    return build_validation_plan({
        "case_id": f"safety_{case_type}",
        "case_type": case_type,
        "status": "needs_review",
        "review_priority": "high",
        "source": "controlled_input",
        "sink": "local_sink",
        "route_context": {"route": "/local"},
        "structured_dataflow": {
            "source": {"symbol": "controlled_input"},
            "sink": {"symbol": "local_sink"},
        },
    })


def _context(plan, adapter: str):
    return ValidationExecutionContext.for_plan(
        plan,
        fixture_id=f"safety_{adapter}",
        adapter=adapter,
        source_revision="safety-fixture-v1",
    )


def test_default_executors_never_use_network_process_shell_or_import(
    monkeypatch,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("unsafe execution surface was used")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(importlib, "import_module", forbidden)

    path = _plan("path_traversal_possible")
    idor = _plan("idor_bola_possible")

    path_result = run_validation_plan(
        path,
        context=_context(path, "path_resolve_enforced"),
    )
    idor_result = run_validation_plan(
        idor,
        context=_context(idor, "idor_owner_tenant_enforced"),
    )

    assert path_result.outcome == "enforced"
    assert idor_result.outcome == "enforced"
