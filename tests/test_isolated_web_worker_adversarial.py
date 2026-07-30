"""Adversarial confinement and lifecycle coverage for the isolated worker."""

from __future__ import annotations

import ast
import builtins
import concurrent.futures
import contextlib
import http.client
import inspect
import multiprocessing
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest
import httpx
import requests

from belief.validation.worker import process as worker_process
from belief.validation.worker.bootstrap import (
    _BoundedTextCapture,
    _validated_worker_root,
    sanitize_diagnostic,
    worker_bootstrap,
)
from belief.validation.worker.contracts import (
    MAX_WORKER_DIAGNOSTIC_CHARS,
    MAX_WORKER_RESPONSE_BYTES,
    WorkerProtocolError,
    WorkerRequest,
)
from belief.validation.worker.entrypoint import execute_worker_message
from belief.validation.worker.policies import (
    WorkerPolicyState,
    WorkerPolicyViolation,
    filesystem_policy,
    preliminary_policy,
)
from belief.validation.worker.process import (
    IsolatedWebValidationExecutor,
    run_worker_request,
    start_worker_request,
)
from belief.validation.worker.registry import (
    get_fixture_spec,
    load_fixture_runner,
)


pytestmark = pytest.mark.security


def _request(
    fixture_id: str = "fx_18a4e9_v1",
    *,
    timeout_ms: int = 5_000,
) -> WorkerRequest:
    return WorkerRequest(
        fixture_id=fixture_id,
        validation_plan_id="vp_0123456789abcdef",
        validation_plan_digest="a" * 64,
        source_revision="fixture-source-v1",
        timeout_ms=timeout_ms,
        correlation_id="corr_adversarial",
    )


_EXTERNAL_FILESYSTEM_OPERATIONS = (
    "rename_source",
    "rename_destination",
    "replace_source",
    "replace_destination",
    "remove",
    "unlink",
    "mkdir",
    "makedirs",
    "rmdir",
    "removedirs",
    "renames",
    "symlink_source",
    "symlink_destination",
    "link_source",
    "link_destination",
    "listdir",
    "scandir",
    "stat",
    "lstat",
    "readlink",
    "truncate",
    "chmod",
    "copy_source",
    "copy_destination",
    "copy2_source",
    "copy2_destination",
    "copyfile_source",
    "copyfile_destination",
    "copytree_source",
    "move_source",
    "move_destination",
    "move_root",
    "rmtree",
    "rename_root",
    "rmdir_root",
    "rmtree_root",
)


def _invoke_external_filesystem_operation(
    action: str,
    *,
    root: Path,
    sibling: Path,
) -> None:
    inside_file = root / "inside.txt"
    outside_file = sibling / "outside.txt"
    outside_empty = sibling / "empty"
    outside_tree = sibling / "tree"
    operations = {
        "rename_source": lambda: os.rename(
            outside_file,
            root / "renamed.txt",
        ),
        "rename_destination": lambda: os.rename(
            inside_file,
            sibling / "renamed.txt",
        ),
        "replace_source": lambda: os.replace(
            outside_file,
            root / "replaced.txt",
        ),
        "replace_destination": lambda: os.replace(
            inside_file,
            sibling / "replaced.txt",
        ),
        "remove": lambda: os.remove(outside_file),
        "unlink": lambda: os.unlink(outside_file),
        "mkdir": lambda: os.mkdir(sibling / "new-directory"),
        "makedirs": lambda: os.makedirs(sibling / "nested" / "directory"),
        "rmdir": lambda: os.rmdir(outside_empty),
        "removedirs": lambda: os.removedirs(outside_empty),
        "renames": lambda: os.renames(
            inside_file,
            sibling / "renamed" / "inside.txt",
        ),
        "symlink_source": lambda: os.symlink(
            outside_file,
            root / "outside-symlink",
        ),
        "symlink_destination": lambda: os.symlink(
            inside_file,
            sibling / "inside-symlink",
        ),
        "link_source": lambda: os.link(
            outside_file,
            root / "outside-hardlink",
        ),
        "link_destination": lambda: os.link(
            inside_file,
            sibling / "inside-hardlink",
        ),
        "listdir": lambda: os.listdir(sibling),
        "scandir": lambda: list(os.scandir(sibling)),
        "stat": lambda: os.stat(outside_file),
        "lstat": lambda: os.lstat(outside_file),
        "readlink": lambda: os.readlink(outside_file),
        "truncate": lambda: os.truncate(outside_file, 0),
        "chmod": lambda: os.chmod(outside_file, 0o600),
        "copy_source": lambda: shutil.copy(
            outside_file,
            root / "copied.txt",
        ),
        "copy_destination": lambda: shutil.copy(
            inside_file,
            sibling / "copied.txt",
        ),
        "copy2_source": lambda: shutil.copy2(
            outside_file,
            root / "copied2.txt",
        ),
        "copy2_destination": lambda: shutil.copy2(
            inside_file,
            sibling / "copied2.txt",
        ),
        "copyfile_source": lambda: shutil.copyfile(
            outside_file,
            root / "copyfile.txt",
        ),
        "copyfile_destination": lambda: shutil.copyfile(
            inside_file,
            sibling / "copyfile.txt",
        ),
        "copytree_source": lambda: shutil.copytree(
            outside_tree,
            root / "tree-copy",
        ),
        "move_source": lambda: shutil.move(
            outside_file,
            root / "moved.txt",
        ),
        "move_destination": lambda: shutil.move(
            inside_file,
            sibling / "moved.txt",
        ),
        "move_root": lambda: shutil.move(
            root,
            sibling / "moved-root",
        ),
        "rmtree": lambda: shutil.rmtree(outside_tree),
        "rename_root": lambda: os.rename(root, sibling / "stolen-root"),
        "rmdir_root": lambda: os.rmdir(root),
        "rmtree_root": lambda: shutil.rmtree(root),
    }
    operations[action]()


def test_filesystem_policy_denies_external_reads_writes_and_symlink_escape(
    tmp_path,
    monkeypatch,
):
    root = tmp_path / "worker"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    inside = root / "inside.txt"
    link = root / "outside-link.txt"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        link = None
    monkeypatch.chdir(root)
    state = WorkerPolicyState()

    candidates = [
        outside,
        Path(__file__).resolve().parents[1] / "README.md",
        Path("..") / "outside.txt",
    ]
    etc_hosts = Path("/etc/hosts")
    if etc_hosts.exists():
        candidates.append(etc_hosts)
    windows_root = os.environ.get("SYSTEMROOT")
    if windows_root:
        windows_hosts = (
            Path(windows_root)
            / "System32"
            / "drivers"
            / "etc"
            / "hosts"
        )
        if windows_hosts.exists():
            candidates.append(windows_hosts)

    with filesystem_policy(root, state):
        inside.write_text("inside", encoding="utf-8")
        assert inside.read_text(encoding="utf-8") == "inside"
        with builtins.open(inside, encoding="utf-8") as handle:
            assert handle.read() == "inside"
        descriptor = os.open(inside, os.O_RDONLY)
        os.close(descriptor)
        for candidate in candidates:
            with pytest.raises(WorkerPolicyViolation, match="filesystem"):
                candidate.read_text(encoding="utf-8")
            with pytest.raises(WorkerPolicyViolation, match="filesystem"):
                builtins.open(candidate, encoding="utf-8")
            with pytest.raises(WorkerPolicyViolation, match="filesystem"):
                os.open(candidate, os.O_RDONLY)
        with pytest.raises(WorkerPolicyViolation, match="filesystem"):
            outside.write_text("tampered", encoding="utf-8")
        if link is not None:
            with pytest.raises(WorkerPolicyViolation, match="filesystem"):
                link.read_text(encoding="utf-8")

    assert outside.read_text(encoding="utf-8") == "outside"
    assert state.filesystem_policy_installed is True
    assert any(item.startswith("filesystem:") for item in state.io_policy_violations)


@pytest.mark.parametrize("action", _EXTERNAL_FILESYSTEM_OPERATIONS)
def test_filesystem_policy_denies_external_metadata_and_mutation_operations(
    tmp_path,
    action,
):
    root = tmp_path / "worker"
    root.mkdir()
    inside = root / "inside.txt"
    inside.write_text("inside", encoding="utf-8")
    sibling = tmp_path / "sibling"
    sibling.mkdir()
    outside = sibling / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (sibling / "empty").mkdir()
    outside_tree = sibling / "tree"
    outside_tree.mkdir()
    (outside_tree / "payload.txt").write_text("tree", encoding="utf-8")
    state = WorkerPolicyState()

    with filesystem_policy(root, state):
        with pytest.raises(WorkerPolicyViolation, match="filesystem"):
            _invoke_external_filesystem_operation(
                action,
                root=root,
                sibling=sibling,
            )

    assert root.is_dir()
    assert inside.read_text(encoding="utf-8") == "inside"
    assert sibling.is_dir()
    assert outside.read_text(encoding="utf-8") == "outside"
    assert (outside_tree / "payload.txt").read_text(encoding="utf-8") == "tree"
    assert state.io_policy_violations


def test_filesystem_policy_allows_a_complete_inside_lifecycle(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    state = WorkerPolicyState()

    with filesystem_policy(root, state):
        nested = root / "nested"
        os.makedirs(nested / "child")
        source = nested / "source.txt"
        source.write_text("payload", encoding="utf-8")
        assert os.stat(source).st_size == 7
        assert source.name in os.listdir(nested)
        with os.scandir(nested) as entries:
            assert source.name in {entry.name for entry in entries}
        renamed = nested / "renamed.txt"
        os.rename(source, renamed)
        copied = nested / "copied.txt"
        shutil.copyfile(renamed, copied)
        os.truncate(copied, 4)
        assert copied.read_text(encoding="utf-8") == "payl"
        moved = nested / "child" / "moved.txt"
        shutil.move(copied, moved)
        os.unlink(renamed)
        shutil.rmtree(nested / "child")
        os.rmdir(nested)

    assert state.filesystem_policy_installed is True
    assert state.io_policy_violations == []
    assert list(root.iterdir()) == []


def test_pathlike_reentrancy_cannot_read_a_sibling(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    inside = root / "inside.txt"
    inside.write_text("inside", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    state = WorkerPolicyState()

    class ReentrantPath:
        def __fspath__(self):
            outside.read_text(encoding="utf-8")
            return str(inside)

    with filesystem_policy(root, state):
        with pytest.raises(WorkerPolicyViolation, match="filesystem"):
            builtins.open(ReentrantPath(), encoding="utf-8")

    assert outside.read_text(encoding="utf-8") == "outside"
    assert "filesystem:read_text" in state.io_policy_violations


def test_filesystem_policy_denies_repository_listing_and_stat(tmp_path):
    root = tmp_path / "worker"
    root.mkdir()
    repository = Path(__file__).resolve().parents[1]
    state = WorkerPolicyState()

    with filesystem_policy(root, state):
        with pytest.raises(WorkerPolicyViolation, match="filesystem"):
            os.listdir(repository)
        with pytest.raises(WorkerPolicyViolation, match="filesystem"):
            os.stat(repository)

    assert {
        "filesystem:listdir",
        "filesystem:stat",
    } <= set(state.io_policy_violations)


def test_network_policy_denies_tcp_udp_dns_http_and_async_entrypoints():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection = http.client.HTTPConnection("127.0.0.1", 9)
    state = WorkerPolicyState()
    try:
        with preliminary_policy(state):
            with pytest.raises(WorkerPolicyViolation):
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with pytest.raises(WorkerPolicyViolation):
                tcp.bind(("127.0.0.1", 0))
            with pytest.raises(WorkerPolicyViolation):
                tcp.connect(("127.0.0.1", 9))
            with pytest.raises(WorkerPolicyViolation):
                udp.sendto(b"x", ("127.0.0.1", 9))
            with pytest.raises(WorkerPolicyViolation):
                socket.getaddrinfo("example.invalid", 443)
            with pytest.raises(WorkerPolicyViolation):
                urllib.request.urlopen("http://127.0.0.1:9/", timeout=0.1)
            with pytest.raises(WorkerPolicyViolation):
                connection.connect()
            with pytest.raises(WorkerPolicyViolation):
                requests.get("http://127.0.0.1:9/", timeout=0.1)
            with pytest.raises(WorkerPolicyViolation):
                httpx.get("http://127.0.0.1:9/", timeout=0.1)
            with pytest.raises(WorkerPolicyViolation):
                import_asyncio_open_connection()
    finally:
        tcp.close()
        udp.close()
        connection.close()

    assert state.network_policy_installed is True
    assert {
        "network:inet_socket",
        "network:bind",
        "network:connect",
        "network:sendto",
        "network:dns_lookup",
        "network:urlopen",
        "network:http_connect",
        "network:requests_dispatch",
        "network:httpx_dispatch",
        "network:async_open_connection",
    } <= set(state.io_policy_violations)


def import_asyncio_open_connection():
    import asyncio

    return asyncio.open_connection("127.0.0.1", 9)


def test_process_policy_denies_shell_exec_spawn_nested_process_and_pool():
    state = WorkerPolicyState()
    nested = multiprocessing.get_context("spawn").Process(target=time.sleep, args=(1,))
    with preliminary_policy(state):
        with pytest.raises(WorkerPolicyViolation):
            subprocess.run([sys.executable, "--version"], check=False)
        with pytest.raises(WorkerPolicyViolation):
            os.system("exit 0")
        with pytest.raises(WorkerPolicyViolation):
            os.popen("echo denied")
        if hasattr(os, "spawnv"):
            with pytest.raises(WorkerPolicyViolation):
                os.spawnv(os.P_WAIT, sys.executable, [sys.executable, "--version"])
        with pytest.raises(WorkerPolicyViolation):
            os.execv(sys.executable, [sys.executable, "--version"])
        with pytest.raises(WorkerPolicyViolation):
            nested.start()
        with pytest.raises(WorkerPolicyViolation):
            concurrent.futures.ProcessPoolExecutor()

    assert state.process_policy_installed is True
    assert len(state.io_policy_violations) >= 6
    response = run_worker_request(_request())
    assert response.worker_status == "completed"
    assert response.attestation.io_policy_violations == ()


def test_parent_secrets_are_removed_before_fixture_execution(monkeypatch):
    secrets = {
        "OPENAI_API_KEY": "sk-parent-secret-value",
        "AWS_SECRET_ACCESS_KEY": "aws-parent-secret-value",
        "GITHUB_TOKEN": "github-parent-secret-value",
        "CUSTOM_PASSWORD": "password-parent-secret-value",
    }
    for name, value in secrets.items():
        monkeypatch.setenv(name, value)

    response = run_worker_request(_request())

    assert response.worker_status == "completed"
    assert response.attestation.environment_policy_installed is True
    assert response.attestation.environment_secret_probe_passed is True
    rendered = str(response.to_dict())
    for value in secrets.values():
        assert value not in rendered


def test_spawn_bootstrap_has_only_top_level_standard_library_imports():
    source_path = Path(worker_bootstrap.__code__.co_filename)
    module = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = [
        node
        for node in module.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]

    assert imports
    for node in imports:
        if isinstance(node, ast.Import):
            names = [alias.name.split(".", 1)[0] for alias in node.names]
        else:
            assert node.level == 0
            names = [(node.module or "").split(".", 1)[0]]
        assert all(
            name == "__future__" or name in sys.stdlib_module_names
            for name in names
        )


def test_resource_limits_and_filesystem_policy_precede_fixture_preparation():
    source = inspect.getsource(execute_worker_message)

    limits = source.index("apply_resource_limits(")
    filesystem = source.index("with filesystem_policy(")
    preparation = source.index("prepared_fixture = prepare_fixture(")
    execution = source.index("prepared_fixture()")
    assert limits < filesystem < preparation < execution


def test_bootstrap_accepts_only_the_fixed_child_of_a_temporary_container(
    tmp_path,
):
    container, child = worker_process._create_worker_roots()
    try:
        assert _validated_worker_root(str(child)) == child
        with pytest.raises(ValueError, match="invalid worker root"):
            _validated_worker_root(str(container))
        decoy = tmp_path / container.name / "child"
        decoy.mkdir(parents=True)
        with pytest.raises(ValueError, match="invalid worker root"):
            _validated_worker_root(str(decoy))
    finally:
        assert worker_process._cleanup_worker_root(container) is True


def test_bounded_output_capture_blocks_protocol_injection_and_redacts():
    stdout = _BoundedTextCapture()
    stderr = _BoundedTextCapture()
    fake_root = Path(tempfile.gettempdir()) / "belief-isolated-web-worker-fake"
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        print('{"jsonrpc":"2.0","id":99,"result":{"injected":true}}')
        print("\x1b[31mOPENAI_API_KEY=sk-test-secret-token\x1b[0m")
        print(str(fake_root))
        print("x" * (MAX_WORKER_DIAGNOSTIC_CHARS * 2))
        print("stderr-password=top-secret", file=sys.stderr)

    normalized_stdout = sanitize_diagnostic(
        stdout.getvalue(),
        temporary_root=fake_root,
    )
    normalized_stderr = sanitize_diagnostic(
        stderr.getvalue(),
        temporary_root=fake_root,
    )
    assert stdout.truncated is True
    assert len(normalized_stdout) <= MAX_WORKER_DIAGNOSTIC_CHARS
    assert "\x1b" not in normalized_stdout
    assert "sk-test-secret-token" not in normalized_stdout
    assert str(fake_root) not in normalized_stdout
    assert "<worker_root>" in normalized_stdout
    assert "top-secret" not in normalized_stderr


def _receive_request(request_connection):
    try:
        request_connection.recv_bytes(16 * 1024)
    except (EOFError, OSError):
        pass


def _infinite_target(request_connection, _response, _root, _cancel):
    _receive_request(request_connection)
    while True:
        pass


def _sleep_target(request_connection, _response, _root, _cancel):
    _receive_request(request_connection)
    time.sleep(30)


def _exit_target(request_connection, _response, _root, _cancel):
    _receive_request(request_connection)
    os._exit(23)


def _rename_then_sleep_target(
    request_connection,
    _response,
    root,
    _cancel,
):
    _receive_request(request_connection)
    child = Path(root)
    child.rename(child.with_name("renamed-child"))
    time.sleep(30)


def _rename_then_exit_target(
    request_connection,
    _response,
    root,
    _cancel,
):
    _receive_request(request_connection)
    child = Path(root)
    child.rename(child.with_name("renamed-child"))
    os._exit(23)


def _exception_target(request_connection, _response, _root, _cancel):
    _receive_request(request_connection)
    raise RuntimeError("untrusted exception text must not cross")


def _malformed_target(request_connection, response, _root, _cancel):
    _receive_request(request_connection)
    response.send_bytes(b"{}")


def _oversized_target(request_connection, response, _root, _cancel):
    _receive_request(request_connection)
    response.send_bytes(b"x" * (MAX_WORKER_RESPONSE_BYTES + 1))


def _multiple_target(request_connection, response, _root, _cancel):
    _receive_request(request_connection)
    response.send_bytes(b"{}")
    response.send_bytes(b"{}")


class _TargetContext:
    def __init__(self, target):
        self._delegate = multiprocessing.get_context("spawn")
        self._target = target

    def Pipe(self, duplex=True):
        return self._delegate.Pipe(duplex=duplex)

    def Event(self):
        return self._delegate.Event()

    def Process(self, **kwargs):
        kwargs["target"] = self._target
        return self._delegate.Process(**kwargs)


@pytest.mark.parametrize("target", (_infinite_target, _sleep_target))
def test_timeout_targets_are_killed_and_cleaned(monkeypatch, target):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _TargetContext(target),
    )
    handle = start_worker_request(_request(timeout_ms=100))
    root = handle.temporary_root
    container = handle.container_root

    response = handle.wait()

    assert response.worker_status == "timed_out"
    assert [error.code for error in response.errors] == ["timeout"]
    assert response.attestation.cleanup_completed is True
    assert not root.exists()
    assert not container.exists()
    assert response.observations == ()


@pytest.mark.parametrize("target", (_exit_target, _exception_target))
def test_crash_targets_are_normalized_without_exception_text(monkeypatch, target):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _TargetContext(target),
    )
    response = run_worker_request(_request())

    assert response.worker_status == "crashed"
    assert [error.code for error in response.errors] == ["child_crash"]
    assert "untrusted exception text" not in str(response.to_dict())
    assert response.attestation.cleanup_completed is True
    assert response.diagnostics.child_exit_code not in {0, None}


@pytest.mark.parametrize(
    ("target", "error_code"),
    (
        (_malformed_target, "malformed_response"),
        (_oversized_target, "response_too_large"),
        (_multiple_target, "malformed_response"),
    ),
)
def test_invalid_child_output_is_rejected_and_cleaned(
    monkeypatch,
    target,
    error_code,
):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _TargetContext(target),
    )
    handle = start_worker_request(_request())
    root = handle.temporary_root
    container = handle.container_root

    response = handle.wait()

    assert response.worker_status == "inconclusive"
    assert [error.code for error in response.errors] == [error_code]
    assert response.attestation.cleanup_completed is True
    assert not root.exists()
    assert not container.exists()


@pytest.mark.parametrize(
    ("target", "timeout_ms", "expected_status"),
    (
        (_rename_then_sleep_target, 100, "timed_out"),
        (_rename_then_exit_target, 5_000, "crashed"),
    ),
)
def test_parent_container_cleanup_survives_child_root_rename(
    monkeypatch,
    target,
    timeout_ms,
    expected_status,
):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _TargetContext(target),
    )
    handle = start_worker_request(_request(timeout_ms=timeout_ms))
    child = handle.temporary_root
    container = handle.container_root
    renamed = container / "renamed-child"

    response = handle.wait()

    assert response.worker_status == expected_status
    assert response.attestation.cleanup_completed is True
    assert not child.exists()
    assert not renamed.exists()
    assert not container.exists()


def test_cancellation_before_start_and_during_execution_releases_everything(
    monkeypatch,
):
    monkeypatch.setattr(
        worker_process,
        "_spawn_context",
        lambda: _TargetContext(_infinite_target),
    )
    before_start = start_worker_request(_request())
    before_root = before_start.temporary_root
    before_container = before_start.container_root
    assert before_start.cancel("cancel before start") is True
    before_response = before_start.wait()
    assert before_response.worker_status == "cancelled"
    assert not before_root.exists()
    assert not before_container.exists()

    active = start_worker_request(_request())
    active_root = active.temporary_root
    active_container = active.container_root
    active.start()
    assert active.cancel("cancel during execution") is True
    active_response = active.wait()
    assert active_response.worker_status == "cancelled"
    assert [error.code for error in active_response.errors] == ["cancelled"]
    assert active_response.attestation.cleanup_completed is True
    assert not active_root.exists()
    assert not active_container.exists()
    assert active._request_receive.closed
    assert active._request_send.closed
    assert active._response_receive.closed
    assert active._response_send.closed


def test_twenty_sequential_runs_leave_no_children_or_temporary_roots():
    before_children = {child.pid for child in multiprocessing.active_children()}
    temp_parent = Path(tempfile.gettempdir())
    before_roots = set(temp_parent.glob("belief-isolated-web-worker-*"))

    responses = [
        run_worker_request(_request("fx_18a4e9_v1"))
        for _index in range(20)
    ]

    after_children = {child.pid for child in multiprocessing.active_children()}
    after_roots = set(temp_parent.glob("belief-isolated-web-worker-*"))
    assert all(response.worker_status == "completed" for response in responses)
    assert after_children == before_children
    assert after_roots == before_roots
    assert all(
        response.attestation.cleanup_completed is True
        for response in responses
    )


def test_cleanup_refuses_an_unregistered_prefix_matching_directory():
    with tempfile.TemporaryDirectory(
        prefix="belief-isolated-web-worker-"
    ) as unowned:
        path = Path(unowned).resolve()
        assert worker_process._cleanup_worker_root(path) is False
        assert path.exists()


def test_resource_limit_attestation_does_not_overclaim_cross_platform():
    response = run_worker_request(_request())
    controls = response.attestation.resource_limits

    assert set(controls) == {
        "cpu",
        "open_files",
        "file_size",
        "child_processes",
    }
    if os.name == "nt":
        assert set(controls.values()) == {None}
        assert "posix_resource_limits_not_available" in response.attestation.limitations
    else:
        assert all(value in {True, False, None} for value in controls.values())


def test_attestation_source_or_plan_binding_mismatch_is_rejected():
    response = run_worker_request(_request())
    tampered = replace(
        response,
        attestation=replace(
            response.attestation,
            fixture_source_digest="b" * 64,
        ),
        evidence_digest="",
        attestation_digest="",
        response_digest="",
        semantic_digest="",
    )

    with pytest.raises(WorkerProtocolError) as error:
        worker_process._validate_response_binding(_request(), tampered)
    assert error.value.code == "binding_mismatch"


def test_fixture_id_and_evaluator_label_swaps_do_not_change_observations(
    tmp_path,
):
    original = get_fixture_spec("fx_01d7c2_v1")
    renamed = replace(
        original,
        fixture_id="fx_opaque_copy_v1",
    )

    def execute(spec, root, evaluator_label):
        del evaluator_label
        return load_fixture_runner(spec)(root, {})()

    original_result = execute(
        original,
        tmp_path / "original",
        "bypassed",
    )
    renamed_result = execute(
        renamed,
        tmp_path / "renamed",
        "bypassed",
    )
    relabelled_result = execute(
        original,
        tmp_path / "relabelled",
        "enforced",
    )
    assert original_result.observations == renamed_result.observations
    assert original_result.observations == relabelled_result.observations
    failed = [
        item
        for item in original_result.observations
        if item.oracle_passed is False
    ]
    assert failed
    executor_source = inspect.getsource(IsolatedWebValidationExecutor.execute)
    assert "evaluator_label" not in executor_source
    assert '"vulnerable"' not in executor_source
