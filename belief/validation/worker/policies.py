"""Python-level policies installed inside the isolated worker process."""

from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import contextlib
import http.client
import io
import math
import multiprocessing.process
import os
import shutil
import socket
import subprocess
import threading
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


_NETWORK_FAMILIES = frozenset({socket.AF_INET, socket.AF_INET6})
_MAX_POLICY_EVENTS = 16
_MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024
_MAX_OPEN_FILES = 64


class WorkerPolicyViolation(RuntimeError):
    """A fixture attempted an operation forbidden by an installed policy."""

    def __init__(self, category: str, action: str) -> None:
        super().__init__(f"worker {category} policy denied {action}")
        self.category = category
        self.action = action


@dataclass
class WorkerPolicyState:
    """Mutable child-local state later projected into an attestation."""

    environment_policy_installed: bool | None = None
    environment_secret_probe_passed: bool | None = None
    filesystem_policy_installed: bool | None = None
    network_policy_installed: bool | None = None
    process_policy_installed: bool | None = None
    timeout_enforced: bool | None = True
    resource_limits: dict[str, bool | None] = field(
        default_factory=lambda: {
            "cpu": None,
            "open_files": None,
            "file_size": None,
            "child_processes": None,
        }
    )
    io_policy_violations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def deny(self, category: str, action: str) -> None:
        event = f"{category}:{action}"
        if (
            event not in self.io_policy_violations
            and len(self.io_policy_violations) < _MAX_POLICY_EVENTS
        ):
            self.io_policy_violations.append(event)
        raise WorkerPolicyViolation(category, action)

    def limit(self, value: str) -> None:
        if value not in self.limitations and len(self.limitations) < _MAX_POLICY_EVENTS:
            self.limitations.append(value)


class _PatchSet:
    def __init__(self) -> None:
        self._originals: list[tuple[Any, str, Any]] = []

    def set(self, owner: Any, name: str, replacement: Any) -> None:
        if not hasattr(owner, name):
            return
        self._originals.append((owner, name, getattr(owner, name)))
        setattr(owner, name, replacement)

    def restore(self) -> None:
        for owner, name, original in reversed(self._originals):
            setattr(owner, name, original)
        self._originals.clear()


@contextlib.contextmanager
def preliminary_policy(state: WorkerPolicyState) -> Iterator[None]:
    """Install network and process controls before third-party imports."""

    patches = _PatchSet()
    try:
        _install_network_policy(patches, state)
        state.network_policy_installed = True
        _install_process_policy(patches, state)
        state.process_policy_installed = True
        yield
    finally:
        patches.restore()


@contextlib.contextmanager
def filesystem_policy(
    root: Path,
    state: WorkerPolicyState,
) -> Iterator[None]:
    """Confine Python-level fixture filesystem operations to one child root."""

    allowed_root = root.resolve(strict=True)
    patches = _PatchSet()
    guard_state = threading.local()

    original_builtin_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open
    original_path_open = Path.open
    original_path_read_text = Path.read_text
    original_path_read_bytes = Path.read_bytes
    original_path_write_text = Path.write_text
    original_path_write_bytes = Path.write_bytes
    original_path_resolve = Path.resolve
    original_chdir = os.chdir
    original_rename = os.rename
    original_replace = os.replace
    original_remove = os.remove
    original_unlink = os.unlink
    original_mkdir = os.mkdir
    original_makedirs = os.makedirs
    original_rmdir = os.rmdir
    original_symlink = os.symlink
    original_link = os.link
    original_listdir = os.listdir
    original_scandir = os.scandir
    original_stat = os.stat
    original_lstat = os.lstat
    original_readlink = os.readlink
    original_truncate = os.truncate
    original_chmod = os.chmod
    original_copy = shutil.copy
    original_copy2 = shutil.copy2
    original_copyfile = shutil.copyfile
    original_copytree = shutil.copytree
    original_move = shutil.move
    original_rmtree = shutil.rmtree

    def guard(
        path: Any,
        *,
        action: str,
        allow_fd: bool = False,
        forbid_root: bool = False,
    ) -> Path | None:
        if isinstance(path, int):
            if allow_fd:
                return None
            state.deny("filesystem", f"{action}_file_descriptor")
        try:
            normalized_path = os.fsdecode(os.fspath(path))
            if "\x00" in normalized_path:
                raise ValueError
        except (OSError, TypeError, ValueError):
            state.deny("filesystem", action)
        if getattr(guard_state, "active", False):
            return None
        guard_state.active = True
        try:
            resolved = _guard_path(
                normalized_path,
                allowed_root,
                state,
                action=action,
            )
            if forbid_root and resolved == allowed_root:
                state.deny("filesystem", f"{action}_root")
            return resolved
        finally:
            guard_state.active = False

    def reject_dir_fd(action: str, values: Mapping[str, Any]) -> None:
        if any(
            values.get(name) is not None
            for name in ("dir_fd", "src_dir_fd", "dst_dir_fd")
        ):
            state.deny("filesystem", f"{action}_dir_fd")

    def guarded_builtin_open(
        file: Any,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        closefd: bool = True,
        opener: Callable[..., Any] | None = None,
    ) -> Any:
        if isinstance(file, int):
            return original_builtin_open(
                file,
                mode,
                buffering,
                encoding,
                errors,
                newline,
                closefd,
                opener,
            )
        if opener is not None:
            state.deny("filesystem", "custom_opener")
        guard(file, action="open")
        return original_builtin_open(
            file,
            mode,
            buffering,
            encoding,
            errors,
            newline,
            closefd,
            opener,
        )

    def guarded_io_open(
        file: Any,
        mode: str = "r",
        buffering: int = -1,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
        closefd: bool = True,
        opener: Callable[..., Any] | None = None,
    ) -> Any:
        if isinstance(file, int):
            return original_io_open(
                file,
                mode,
                buffering,
                encoding,
                errors,
                newline,
                closefd,
                opener,
            )
        if opener is not None:
            state.deny("filesystem", "custom_opener")
        guard(file, action="open")
        return original_io_open(
            file,
            mode,
            buffering,
            encoding,
            errors,
            newline,
            closefd,
            opener,
        )

    def guarded_os_open(
        path: Any,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        reject_dir_fd("os_open", {"dir_fd": dir_fd})
        guard(path, action="os_open")
        return original_os_open(path, flags, mode)

    def guarded_path_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        guard(path, action="path_open")
        return original_path_open(path, *args, **kwargs)

    def guarded_read_text(path: Path, *args: Any, **kwargs: Any) -> str:
        guard(path, action="read_text")
        return original_path_read_text(path, *args, **kwargs)

    def guarded_read_bytes(path: Path, *args: Any, **kwargs: Any) -> bytes:
        guard(path, action="read_bytes")
        return original_path_read_bytes(path, *args, **kwargs)

    def guarded_write_text(path: Path, *args: Any, **kwargs: Any) -> int:
        guard(path, action="write_text")
        return original_path_write_text(path, *args, **kwargs)

    def guarded_write_bytes(path: Path, *args: Any, **kwargs: Any) -> int:
        guard(path, action="write_bytes")
        return original_path_write_bytes(path, *args, **kwargs)

    def guarded_path_resolve(
        path: Path,
        strict: bool = False,
    ) -> Path:
        if getattr(guard_state, "active", False):
            return original_path_resolve(path, strict=strict)
        try:
            raw = os.fsdecode(os.fspath(path))
            if "\x00" in raw:
                raise ValueError
            lexical = Path(os.path.abspath(os.path.normpath(raw)))
            lexical.relative_to(allowed_root)
        except (OSError, RuntimeError, TypeError, ValueError):
            state.deny("filesystem", "path_resolve")
        guard_state.active = True
        try:
            resolved = original_path_resolve(path, strict=strict)
        finally:
            guard_state.active = False
        try:
            resolved.relative_to(allowed_root)
        except ValueError:
            state.deny("filesystem", "path_resolve")
        return resolved

    def guarded_chdir(path: Any) -> None:
        guard(path, action="chdir")
        original_chdir(path)

    def guarded_rename(
        source: Any,
        destination: Any,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd(
            "rename",
            {"src_dir_fd": src_dir_fd, "dst_dir_fd": dst_dir_fd},
        )
        guard(source, action="rename_source", forbid_root=True)
        guard(destination, action="rename_destination")
        original_rename(source, destination)

    def guarded_replace(
        source: Any,
        destination: Any,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd(
            "replace",
            {"src_dir_fd": src_dir_fd, "dst_dir_fd": dst_dir_fd},
        )
        guard(source, action="replace_source", forbid_root=True)
        guard(destination, action="replace_destination")
        original_replace(source, destination)

    def guarded_remove(
        path: Any,
        *,
        dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd("remove", {"dir_fd": dir_fd})
        guard(path, action="remove", forbid_root=True)
        original_remove(path)

    def guarded_unlink(
        path: Any,
        *,
        dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd("unlink", {"dir_fd": dir_fd})
        guard(path, action="unlink", forbid_root=True)
        original_unlink(path)

    def guarded_mkdir(
        path: Any,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd("mkdir", {"dir_fd": dir_fd})
        guard(path, action="mkdir")
        original_mkdir(path, mode)

    def guarded_makedirs(
        name: Any,
        mode: int = 0o777,
        exist_ok: bool = False,
    ) -> None:
        guard(name, action="makedirs")
        original_makedirs(name, mode=mode, exist_ok=exist_ok)

    def guarded_rmdir(
        path: Any,
        *,
        dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd("rmdir", {"dir_fd": dir_fd})
        guard(path, action="rmdir", forbid_root=True)
        original_rmdir(path)

    def deny_removedirs(path: Any) -> None:
        guard(path, action="removedirs", forbid_root=True)
        state.deny("filesystem", "removedirs")

    def deny_renames(source: Any, destination: Any) -> None:
        guard(source, action="renames_source", forbid_root=True)
        guard(destination, action="renames_destination")
        state.deny("filesystem", "renames")

    def guarded_symlink(
        source: Any,
        destination: Any,
        target_is_directory: bool = False,
        *,
        dir_fd: int | None = None,
    ) -> None:
        reject_dir_fd("symlink", {"dir_fd": dir_fd})
        destination_path = guard(
            destination,
            action="symlink_destination",
        )
        source_path = Path(os.fsdecode(os.fspath(source)))
        if source_path.is_absolute():
            guard(source_path, action="symlink_source")
        elif destination_path is not None:
            guard(
                destination_path.parent / source_path,
                action="symlink_source",
            )
        original_symlink(
            source,
            destination,
            target_is_directory=target_is_directory,
        )

    def guarded_link(
        source: Any,
        destination: Any,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        reject_dir_fd(
            "link",
            {"src_dir_fd": src_dir_fd, "dst_dir_fd": dst_dir_fd},
        )
        guard(source, action="link_source")
        guard(destination, action="link_destination")
        original_link(
            source,
            destination,
            follow_symlinks=follow_symlinks,
        )

    def guarded_listdir(path: Any = ".") -> list[str]:
        guard(path, action="listdir", allow_fd=True)
        return original_listdir(path)

    def guarded_scandir(path: Any = ".") -> Any:
        guard(path, action="scandir", allow_fd=True)
        return original_scandir(path)

    def guarded_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(guard_state, "active", False):
            return original_stat(path, *args, **kwargs)
        reject_dir_fd("stat", kwargs)
        guard(path, action="stat", allow_fd=True)
        return original_stat(path, *args, **kwargs)

    def guarded_lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(guard_state, "active", False):
            return original_lstat(path, *args, **kwargs)
        reject_dir_fd("lstat", kwargs)
        guard(path, action="lstat", allow_fd=True)
        return original_lstat(path, *args, **kwargs)

    def guarded_readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
        if getattr(guard_state, "active", False):
            return original_readlink(path, *args, **kwargs)
        reject_dir_fd("readlink", kwargs)
        guard(path, action="readlink")
        return original_readlink(path, *args, **kwargs)

    def guarded_truncate(path: Any, length: int) -> None:
        guard(path, action="truncate", allow_fd=True)
        original_truncate(path, length)

    def guarded_chmod(
        path: Any,
        mode: int,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        reject_dir_fd("chmod", {"dir_fd": dir_fd})
        guard(path, action="chmod", allow_fd=True)
        original_chmod(path, mode, follow_symlinks=follow_symlinks)

    def guard_copy(
        original: Callable[..., Any],
        action: str,
    ) -> Callable[..., Any]:
        def guarded(source: Any, destination: Any, *args: Any, **kwargs: Any) -> Any:
            guard(source, action=f"{action}_source")
            guard(destination, action=f"{action}_destination")
            return original(source, destination, *args, **kwargs)

        return guarded

    def guarded_rmtree(path: Any, *args: Any, **kwargs: Any) -> None:
        if kwargs.get("dir_fd") is not None:
            state.deny("filesystem", "rmtree_dir_fd")
        guard(path, action="rmtree", forbid_root=True)
        original_rmtree(path, *args, **kwargs)

    try:
        patches.set(builtins, "open", guarded_builtin_open)
        patches.set(io, "open", guarded_io_open)
        patches.set(os, "open", guarded_os_open)
        patches.set(Path, "open", guarded_path_open)
        patches.set(Path, "read_text", guarded_read_text)
        patches.set(Path, "read_bytes", guarded_read_bytes)
        patches.set(Path, "write_text", guarded_write_text)
        patches.set(Path, "write_bytes", guarded_write_bytes)
        patches.set(Path, "resolve", guarded_path_resolve)
        patches.set(os, "chdir", guarded_chdir)
        patches.set(os, "rename", guarded_rename)
        patches.set(os, "replace", guarded_replace)
        patches.set(os, "remove", guarded_remove)
        patches.set(os, "unlink", guarded_unlink)
        patches.set(os, "mkdir", guarded_mkdir)
        patches.set(os, "makedirs", guarded_makedirs)
        patches.set(os, "rmdir", guarded_rmdir)
        patches.set(os, "removedirs", deny_removedirs)
        patches.set(os, "renames", deny_renames)
        patches.set(os, "symlink", guarded_symlink)
        patches.set(os, "link", guarded_link)
        patches.set(os, "listdir", guarded_listdir)
        patches.set(os, "scandir", guarded_scandir)
        patches.set(os, "stat", guarded_stat)
        patches.set(os, "lstat", guarded_lstat)
        patches.set(os, "readlink", guarded_readlink)
        patches.set(os, "truncate", guarded_truncate)
        patches.set(os, "chmod", guarded_chmod)
        patches.set(
            shutil,
            "copy",
            guard_copy(original_copy, "copy"),
        )
        patches.set(
            shutil,
            "copy2",
            guard_copy(original_copy2, "copy2"),
        )
        patches.set(
            shutil,
            "copyfile",
            guard_copy(original_copyfile, "copyfile"),
        )
        patches.set(
            shutil,
            "copytree",
            guard_copy(original_copytree, "copytree"),
        )
        patches.set(
            shutil,
            "move",
            guard_copy(original_move, "move"),
        )
        patches.set(shutil, "rmtree", guarded_rmtree)
        state.filesystem_policy_installed = True
        yield
    finally:
        patches.restore()


def apply_resource_limits(
    state: WorkerPolicyState,
    *,
    timeout_ms: int,
) -> None:
    """Apply conservative POSIX limits and report unsupported platforms."""

    try:
        import resource
    except ImportError:
        state.limit("posix_resource_limits_not_available")
        return

    cpu_seconds = max(2, math.ceil(timeout_ms / 1_000) + 2)
    specifications = (
        ("cpu", getattr(resource, "RLIMIT_CPU", None), cpu_seconds),
        ("open_files", getattr(resource, "RLIMIT_NOFILE", None), _MAX_OPEN_FILES),
        ("file_size", getattr(resource, "RLIMIT_FSIZE", None), _MAX_FILE_SIZE_BYTES),
        ("child_processes", getattr(resource, "RLIMIT_NPROC", None), 0),
    )
    for name, resource_name, requested in specifications:
        if resource_name is None:
            state.resource_limits[name] = None
            state.limit(f"resource_limit_{name}_not_available")
            continue
        try:
            current_soft, current_hard = resource.getrlimit(resource_name)
            infinity = resource.RLIM_INFINITY
            hard = requested if current_hard == infinity else min(current_hard, requested)
            soft = hard if current_soft == infinity else min(current_soft, hard)
            resource.setrlimit(resource_name, (soft, hard))
        except (OSError, ValueError):
            state.resource_limits[name] = False
            state.limit(f"resource_limit_{name}_installation_failed")
        else:
            state.resource_limits[name] = True


def _install_network_policy(
    patches: _PatchSet,
    state: WorkerPolicyState,
) -> None:
    original_socket_class = socket.socket
    original_connect = original_socket_class.connect
    original_connect_ex = original_socket_class.connect_ex
    original_bind = original_socket_class.bind
    original_listen = original_socket_class.listen
    original_send = original_socket_class.send
    original_sendall = original_socket_class.sendall
    original_sendto = original_socket_class.sendto

    class GuardedSocket(original_socket_class):
        def __init__(
            self,
            family: int = socket.AF_INET,
            type: int = socket.SOCK_STREAM,
            proto: int = 0,
            fileno: int | None = None,
        ) -> None:
            if family in _NETWORK_FAMILIES:
                state.deny("network", "inet_socket")
            super().__init__(family, type, proto, fileno)

    def guard_socket_operation(
        original: Callable[..., Any],
        action: str,
    ) -> Callable[..., Any]:
        def guarded(sock: socket.socket, *args: Any, **kwargs: Any) -> Any:
            if getattr(sock, "family", None) in _NETWORK_FAMILIES:
                state.deny("network", action)
            return original(sock, *args, **kwargs)

        return guarded

    def deny_network(action: str) -> Callable[..., Any]:
        def denied(*_args: Any, **_kwargs: Any) -> Any:
            state.deny("network", action)

        return denied

    patches.set(
        original_socket_class,
        "connect",
        guard_socket_operation(original_connect, "connect"),
    )
    patches.set(
        original_socket_class,
        "connect_ex",
        guard_socket_operation(original_connect_ex, "connect_ex"),
    )
    patches.set(socket, "create_connection", deny_network("create_connection"))
    patches.set(socket, "getaddrinfo", deny_network("dns_lookup"))
    patches.set(asyncio, "open_connection", deny_network("async_open_connection"))
    patches.set(asyncio, "start_server", deny_network("async_start_server"))
    patches.set(urllib.request, "urlopen", deny_network("urlopen"))
    patches.set(http.client.HTTPConnection, "connect", deny_network("http_connect"))
    patches.set(http.client.HTTPSConnection, "connect", deny_network("https_connect"))

    _install_requests_policy(patches, state)
    _install_httpx_policy(patches, state)
    patches.set(
        original_socket_class,
        "bind",
        guard_socket_operation(original_bind, "bind"),
    )
    patches.set(
        original_socket_class,
        "listen",
        guard_socket_operation(original_listen, "listen"),
    )
    patches.set(
        original_socket_class,
        "send",
        guard_socket_operation(original_send, "send"),
    )
    patches.set(
        original_socket_class,
        "sendall",
        guard_socket_operation(original_sendall, "sendall"),
    )
    patches.set(
        original_socket_class,
        "sendto",
        guard_socket_operation(original_sendto, "sendto"),
    )
    if hasattr(original_socket_class, "sendmsg"):
        original_sendmsg = original_socket_class.sendmsg
        patches.set(
            original_socket_class,
            "sendmsg",
            guard_socket_operation(original_sendmsg, "sendmsg"),
        )
    patches.set(socket, "socket", GuardedSocket)


def _install_requests_policy(
    patches: _PatchSet,
    state: WorkerPolicyState,
) -> None:
    try:
        import requests.sessions
    except ImportError:
        return

    def deny_requests(*_args: Any, **_kwargs: Any) -> Any:
        state.deny("network", "requests_dispatch")

    patches.set(requests.sessions.Session, "request", deny_requests)
    patches.set(requests.sessions.Session, "send", deny_requests)


def _install_httpx_policy(
    patches: _PatchSet,
    state: WorkerPolicyState,
) -> None:
    try:
        import httpx
    except ImportError:
        return

    original_client_send = httpx.Client.send
    original_async_send = httpx.AsyncClient.send

    def guarded_client_send(client: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(getattr(client, "_transport", None), httpx.ASGITransport):
            return original_client_send(client, *args, **kwargs)
        state.deny("network", "httpx_dispatch")

    async def guarded_async_send(client: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(getattr(client, "_transport", None), httpx.ASGITransport):
            return await original_async_send(client, *args, **kwargs)
        state.deny("network", "httpx_async_dispatch")

    patches.set(httpx.Client, "send", guarded_client_send)
    patches.set(httpx.AsyncClient, "send", guarded_async_send)


def _install_process_policy(
    patches: _PatchSet,
    state: WorkerPolicyState,
) -> None:
    def deny_process(action: str) -> Callable[..., Any]:
        def denied(*_args: Any, **_kwargs: Any) -> Any:
            state.deny("process", action)

        return denied

    for name in (
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
    ):
        patches.set(subprocess, name, deny_process(f"subprocess_{name.lower()}"))
    patches.set(os, "system", deny_process("os_system"))
    patches.set(os, "popen", deny_process("os_popen"))
    patches.set(os, "startfile", deny_process("os_startfile"))
    for name in sorted(dir(os)):
        if (
            name.startswith("spawn")
            or name.startswith("exec")
            or name in {"fork", "forkpty", "posix_spawn", "posix_spawnp"}
        ) and callable(getattr(os, name, None)):
            patches.set(os, name, deny_process(f"os_{name}"))
    patches.set(
        asyncio,
        "create_subprocess_exec",
        deny_process("asyncio_subprocess_exec"),
    )
    patches.set(
        asyncio,
        "create_subprocess_shell",
        deny_process("asyncio_subprocess_shell"),
    )
    patches.set(
        multiprocessing.process.BaseProcess,
        "start",
        deny_process("multiprocessing_start"),
    )
    patches.set(
        concurrent.futures,
        "ProcessPoolExecutor",
        deny_process("process_pool_executor"),
    )
    try:
        import pty
    except ImportError:
        return
    patches.set(pty, "spawn", deny_process("pty_spawn"))


def _guard_path(
    supplied: Any,
    allowed_root: Path,
    state: WorkerPolicyState,
    *,
    action: str,
) -> Path:
    try:
        raw = os.fsdecode(os.fspath(supplied))
        if "\x00" in raw:
            raise ValueError
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve(strict=False)
        relative = resolved.relative_to(allowed_root)
        if any(":" in part for part in relative.parts):
            raise ValueError
    except (OSError, RuntimeError, TypeError, ValueError):
        state.deny("filesystem", action)
    return resolved


__all__ = [
    "WorkerPolicyState",
    "WorkerPolicyViolation",
    "apply_resource_limits",
    "filesystem_policy",
    "preliminary_policy",
]
