"""Process and capability boundaries for the isolated web worker."""

from __future__ import annotations

import multiprocessing
import os
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
    OptionalWebDependencyUnavailable,
    execution_bundle_identity,
    get_fixture_spec,
    prepare_execution_bundle,
)
from belief.validation.plans import build_validation_plan
from belief.validation.web import optional_framework_available


pytestmark = pytest.mark.security


def _request(
    fixture_id: str = "fx_18a4e9_v1",
    *,
    timeout_ms: int = 5_000,
) -> WorkerRequest:
    spec = get_fixture_spec(fixture_id)
    identity = (
        execution_bundle_identity(prepare_execution_bundle(spec))
        if spec is not None
        else {
            "fixture_registry_digest": "0" * 64,
            "fixture_source_digest": "0" * 64,
            "fixture_descriptor_digest": "0" * 64,
            "fixture_execution_bundle_digest": "0" * 64,
            "fixture_code_object_digest": "0" * 64,
        }
    )
    return WorkerRequest(
        fixture_id=fixture_id,
        validation_plan_id="vp_0123456789abcdef",
        validation_plan_digest="a" * 64,
        source_revision="fixture-source-v1",
        **identity,
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
    assert values["USERPROFILE"] == str(tmp_path / "home")
    assert values["HOME"] == str(tmp_path / "home")
    assert values["APPDATA"] == str(tmp_path / "appdata")
    assert values["LOCALAPPDATA"] == str(tmp_path / "localappdata")
    assert values["XDG_CONFIG_HOME"] == str(tmp_path / "config")
    assert values["XDG_CACHE_HOME"] == str(tmp_path / "cache")
    assert values["SYSTEMROOT"] == r"C:\Windows"
    assert values["TMP"] == str(tmp_path / "tmp")
    assert values["TEMP"] == str(tmp_path / "tmp")
    assert values["TMPDIR"] == str(tmp_path / "tmp")
    assert values["BELIEF_VALIDATION_WORKER"] == "1"


def test_capability_guard_blocks_network_listener_subprocess_and_shell():
    network_socket = socket.socket()
    try:
        with capability_guard():
            with pytest.raises(WorkerCapabilityDenied, match="bind"):
                network_socket.bind(("127.0.0.1", 0))
            with pytest.raises(WorkerCapabilityDenied, match="connect"):
                network_socket.connect(("127.0.0.1", 9))
            with pytest.raises(WorkerCapabilityDenied, match="subprocess_run"):
                subprocess.run(["python", "--version"], check=False)
            with pytest.raises(WorkerCapabilityDenied, match="os_system"):
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
    response = run_worker_request(_request(timeout_ms=100))

    assert response.worker_status == "timed_out"
    assert response.baseline is None
    assert [error.code for error in response.errors] == ["timeout"]
    assert response.attestation.environment_policy_installed is None
    assert response.attestation.cleanup_completed is True

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id="fx_18a4e9_v1",
        source_revision="fixture-source-v1",
        timeout_ms=100,
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

    def Event(self):
        return multiprocessing.get_context("spawn").Event()


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

    def Event(self):
        return self._delegate.Event()


def test_real_spawned_worker_crash_is_detected(monkeypatch):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _RealCrashContext(),
    )

    response = run_worker_request(_request())

    assert response.worker_status == "crashed"
    assert response.baseline is None
    assert [error.code for error in response.errors] == ["child_crash"]


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
    assert [error.code for error in response.errors] == ["child_crash"]

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id="fx_18a4e9_v1",
        source_revision="fixture-source-v1",
    )
    assert result.outcome == "inconclusive"
    assert result.metadata["baseline_functional"] is None
    assert result.metadata["execution"]["executed"] is False


def test_missing_framework_is_an_explicit_unsupported_result(
    monkeypatch,
    tmp_path,
):
    def unavailable(_spec, _bundle):
        raise OptionalWebDependencyUnavailable("flask")

    monkeypatch.setattr(
        "belief.validation.worker.entrypoint.load_fixture_runner",
        unavailable,
    )

    response = execute_registered_request(
        _request(),
        temporary_root=tmp_path,
    )

    assert response.worker_status == "unsupported"
    assert response.baseline is None
    assert response.limitations == (
        "dependency_unavailable",
    )
    assert [error.code for error in response.errors] == [
        "dependency_unavailable"
    ]


@pytest.mark.parametrize(
    ("framework", "fixture_id"),
    (
        ("flask", "fx_18a4e9_v1"),
        ("fastapi", "fx_5b9c20_v1"),
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
        "dependency_unavailable"
    ]
    assert response.limitations == (
        f"dependency_unavailable:{framework}",
        "dependency_unavailable",
    )

    result = run_isolated_web_validation_plan(
        _plan(),
        fixture_id=fixture_id,
        source_revision="fixture-source-v1",
    )
    assert result.outcome == "inconclusive"
    assert result.metadata["baseline_functional"] is None
    assert result.metadata["execution"]["supported"] is False
