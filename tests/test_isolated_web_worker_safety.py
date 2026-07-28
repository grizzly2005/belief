"""Process and capability boundaries for the isolated web worker."""

from __future__ import annotations

import os
import multiprocessing
import socket
import subprocess

import pytest

from belief.validation.worker import process as worker_process
from belief.validation.worker.contracts import WorkerRequest
from belief.validation.worker.entrypoint import (
    WorkerCapabilityDenied,
    _minimal_environment_values,
    capability_guard,
    execute_registered_request,
)
from belief.validation.worker.process import run_worker_request
from belief.validation.worker.process import (
    run_isolated_web_validation_plan,
)
from belief.validation.worker.registry import (
    FixtureSpec,
    OptionalWebDependencyUnavailable,
)
from belief.validation.plans import build_validation_plan
from belief.validation.web import optional_framework_available


pytestmark = pytest.mark.security


def _request(
    fixture_id: str = "flask_path_traversal_protected_v1",
    *,
    timeout_ms: int = 5_000,
) -> WorkerRequest:
    return WorkerRequest(
        fixture_id=fixture_id,
        validation_plan_id="vp_0123456789abcdef",
        validation_plan_digest="a" * 64,
        source_revision="fixture-source-v1",
        timeout_ms=timeout_ms,
        correlation_id="corr_safety",
    )


def _plan():
    return build_validation_plan({
        "case_id": "isolated_worker_failure",
        "case_type": "path_traversal_possible",
        "status": "needs_review",
        "review_priority": "high",
        "source": "controlled_input",
        "sink": "registered_fixture",
        "route_context": {"route": "/local-test-client"},
        "structured_dataflow": {
            "source": {"symbol": "controlled_input"},
            "sink": {"symbol": "registered_fixture"},
        },
    })


def test_worker_always_uses_spawn_on_windows_and_linux():
    assert worker_process._spawn_context().get_start_method() == "spawn"


def test_worker_environment_is_minimal_and_temp_scoped(tmp_path):
    values = _minimal_environment_values(
        {
            "SYSTEMROOT": r"C:\Windows",
            "SECRET_TOKEN": "must-not-cross",
            "USERPROFILE": r"C:\Users\example",
        },
        tmp_path,
    )

    assert "SECRET_TOKEN" not in values
    assert "USERPROFILE" not in values
    assert values["SYSTEMROOT"] == r"C:\Windows"
    assert values["TMP"] == str(tmp_path)
    assert values["TEMP"] == str(tmp_path)
    assert values["TMPDIR"] == str(tmp_path)
    assert values["BELIEF_VALIDATION_WORKER"] == "1"


def test_capability_guard_blocks_network_listener_subprocess_and_shell():
    network_socket = socket.socket()
    try:
        with capability_guard():
            with pytest.raises(WorkerCapabilityDenied, match="listener"):
                network_socket.bind(("127.0.0.1", 0))
            with pytest.raises(WorkerCapabilityDenied, match="network"):
                network_socket.connect(("127.0.0.1", 9))
            with pytest.raises(WorkerCapabilityDenied, match="subprocess"):
                subprocess.run(["python", "--version"], check=False)
            with pytest.raises(WorkerCapabilityDenied, match="shell"):
                os.system("exit 0")
    finally:
        network_socket.close()


def test_unknown_fixture_is_an_explicit_spawned_abstention():
    response = run_worker_request(_request("unknown_fixture_v1"))

    assert response.worker_status == "unsupported"
    assert response.baseline is None
    assert [error.code for error in response.errors] == ["unknown_fixture"]
    assert response.observations == ()


def test_hard_timeout_terminates_worker_and_remains_inconclusive():
    response = run_worker_request(_request(timeout_ms=1))

    assert response.worker_status == "timed_out"
    assert response.baseline is None
    assert [error.code for error in response.errors] == ["worker_timeout"]
    assert response.capabilities.status == "unavailable"

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id="flask_path_traversal_protected_v1",
        source_revision="fixture-source-v1",
        timeout_ms=1,
    )
    assert result.outcome == "inconclusive"
    assert result.metadata["baseline_functional"] is None
    assert result.metadata["execution"]["executed"] is False


class _FakeConnection:
    def send_bytes(self, _message):
        return None

    def poll(self, _timeout):
        return False

    def close(self):
        return None


class _CrashedProcess:
    exitcode = 23

    def start(self):
        return None

    def is_alive(self):
        return False

    def join(self, timeout=None):
        return None

    def close(self):
        return None


class _CrashContext:
    def Pipe(self, duplex=True):
        return _FakeConnection(), _FakeConnection()

    def Process(self, **_kwargs):
        return _CrashedProcess()


def _crash_immediately(*_args):
    os._exit(23)


class _RealCrashContext:
    def __init__(self):
        self._delegate = multiprocessing.get_context("spawn")

    def Pipe(self, duplex=True):
        return self._delegate.Pipe(duplex=duplex)

    def Process(self, **kwargs):
        kwargs["target"] = _crash_immediately
        return self._delegate.Process(**kwargs)


def test_real_spawned_worker_crash_is_detected(monkeypatch):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _RealCrashContext(),
    )

    response = run_worker_request(_request())

    assert response.worker_status == "crashed"
    assert response.baseline is None
    assert [error.code for error in response.errors] == ["worker_crash"]


def test_worker_crash_is_normalized_and_never_becomes_a_security_verdict(
    monkeypatch,
):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _CrashContext(),
    )

    response = run_worker_request(_request())

    assert response.worker_status == "crashed"
    assert response.baseline is None
    assert response.observations == ()
    assert [error.code for error in response.errors] == ["worker_crash"]

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id="flask_path_traversal_protected_v1",
        source_revision="fixture-source-v1",
    )
    assert result.outcome == "inconclusive"
    assert result.metadata["baseline_functional"] is None
    assert result.metadata["execution"]["executed"] is False


def test_missing_framework_is_an_explicit_unsupported_result(
    monkeypatch,
    tmp_path,
):
    def unavailable(_spec, _root, _parameters):
        raise OptionalWebDependencyUnavailable("flask")

    spec = FixtureSpec(
        fixture_id="flask_path_traversal_protected_v1",
        framework="flask",
        case_type="path_traversal_possible",
        vulnerable=False,
        runner=unavailable,
    )
    monkeypatch.setattr(
        "belief.validation.worker.entrypoint.get_fixture_spec",
        lambda _fixture_id: spec,
    )

    response = execute_registered_request(
        _request(),
        temporary_root=tmp_path,
    )

    assert response.worker_status == "unsupported"
    assert response.baseline is None
    assert response.limitations == (
        "optional_dependency_unavailable:flask",
    )
    assert [error.code for error in response.errors] == [
        "optional_dependency_unavailable"
    ]


@pytest.mark.parametrize(
    ("framework", "fixture_id"),
    (
        ("flask", "flask_path_traversal_protected_v1"),
        ("fastapi", "fastapi_path_traversal_protected_v1"),
    ),
)
def test_actually_absent_framework_is_a_spawned_abstention(
    framework,
    fixture_id,
):
    if optional_framework_available(framework):
        pytest.skip(f"optional dependency installed: {framework}")

    response = run_worker_request(_request(fixture_id))

    assert response.worker_status == "unsupported"
    assert response.baseline is None
    assert [error.code for error in response.errors] == [
        "optional_dependency_unavailable"
    ]
    assert response.limitations == (
        f"optional_dependency_unavailable:{framework}",
    )

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id=fixture_id,
        source_revision="fixture-source-v1",
    )
    assert result.outcome == "inconclusive"
    assert result.metadata["baseline_functional"] is None
    assert result.metadata["execution"]["supported"] is False
