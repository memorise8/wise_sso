"""Owned development runtime for a future isolated Phase 7 collector.

The direct backend in this module starts a real child daemon and proves its local
lifecycle properties.  It is deliberately never qualifying evidence: an approved
disposable namespace/VM backend and its policy inputs do not exist yet.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, Self

DEVELOPMENT_BACKEND: Final = "development-direct-v1"
LIVE_BACKEND: Final = "isolated-live-v1"
DAEMON_SOCKET_ARGUMENT: Final = "{daemon_socket}"
DATA_ROOT_ARGUMENT: Final = "{data_root}"

_HASH = re.compile(r"[0-9a-f]{64}")
_NAMESPACES = ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts")
_FORBIDDEN_AMBIENT = (
    "ALL_PROXY",
    "CONTAINER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)
_SOCKET_PATH_MAX_BYTES = 100
_TIMEOUT_MAXIMUMS = MappingProxyType(
    {
        "startup-timeout": 300.0,
        "maximum-runtime": 86_400.0,
        "drain-timeout": 60.0,
    }
)


class RuntimeRefused(RuntimeError):
    """The owned runtime could not establish or retain its development contract."""


@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    """Reviewed local inputs; never construct this from collected evidence."""

    xdg_runtime_root: Path
    exec_root: Path
    executable: Path
    executable_sha256: str
    arguments: tuple[str, ...]
    backend: str = DEVELOPMENT_BACKEND
    startup_timeout_seconds: float = 5.0
    maximum_runtime_seconds: float = 30.0
    drain_timeout_seconds: float = 2.0


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    pid: int
    start_time_ticks: int
    process_group: int
    session: int
    socket_peer_pid: int
    namespaces: Mapping[str, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    pid: int
    state: str
    parent_pid: int
    process_group: int
    session: int
    start_time_ticks: int


def _positive_seconds(value: float, label: str) -> float:
    maximum = _TIMEOUT_MAXIMUMS.get(label)
    if maximum is None:
        raise RuntimeRefused("runtime:unknown-timeout-policy")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        or value > maximum
    ):
        raise RuntimeRefused(f"runtime:invalid-{label}")
    return float(value)


def _absolute_clean(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw.startswith(os.sep) or "\x00" in raw:
        raise RuntimeRefused(f"runtime:invalid-{label}")
    normalized = os.path.normpath(raw)
    if raw != normalized or normalized == os.sep:
        raise RuntimeRefused(f"runtime:invalid-{label}")
    current = Path(os.sep)
    try:
        for part in Path(normalized).parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                raise RuntimeRefused(f"runtime:symlink-{label}")
    except OSError as exc:
        raise RuntimeRefused(f"runtime:unsafe-{label}") from exc
    return Path(normalized)


def _safe_directory(path: Path, label: str, *, exact_mode: int | None = None) -> Path:
    checked = _absolute_clean(path, label)
    metadata = checked.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (exact_mode is not None and mode != exact_mode)
        or (exact_mode is None and mode & 0o022 != 0)
    ):
        raise RuntimeRefused(f"runtime:unsafe-{label}")
    return checked


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return child != parent


def _sha256(path: Path, maximum: int = 128 * 1024 * 1024) -> str:
    before = path.stat()
    if before.st_size <= 0 or before.st_size > maximum:
        raise RuntimeRefused("runtime:unsafe-executable")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(min(1024 * 1024, maximum + 1 - total)):
            total += len(chunk)
            if total > maximum:
                raise RuntimeRefused("runtime:unsafe-executable")
            digest.update(chunk)
    after = path.stat()
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise RuntimeRefused("runtime:changed-executable")
    return digest.hexdigest()


def _pinned_executable(path: Path, expected_sha256: str) -> int:
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeRefused("runtime:nofollow-unavailable")
    descriptor = -1
    try:
        descriptor = os.open(path, flags | nofollow)
        opened = os.fstat(descriptor)
        bound = path.stat(follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (bound.st_dev, bound.st_ino):
            raise RuntimeRefused("runtime:changed-executable")
        digest = hashlib.sha256()
        offset = 0
        while offset < opened.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, opened.st_size - offset), offset)
            if not chunk:
                raise RuntimeRefused("runtime:changed-executable")
            digest.update(chunk)
            offset += len(chunk)
        if os.fstat(descriptor) != opened or digest.hexdigest() != expected_sha256:
            raise RuntimeRefused("runtime:changed-executable")
        result = descriptor
        descriptor = -1
        return result
    except RuntimeRefused:
        raise
    except OSError as exc:
        raise RuntimeRefused("runtime:unsafe-executable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_policy(policy: RuntimePolicy) -> tuple[Path, Path, Path]:
    if policy.backend == LIVE_BACKEND:
        raise RuntimeRefused("runtime:live-backend-not-configured")
    if policy.backend != DEVELOPMENT_BACKEND:
        raise RuntimeRefused("runtime:unsupported-backend")
    for name in _FORBIDDEN_AMBIENT:
        if os.environ.get(name):
            raise RuntimeRefused(f"runtime:ambient-{name.lower().replace('_', '-')}")
    xdg_root = _safe_directory(policy.xdg_runtime_root, "xdg-runtime-root", exact_mode=0o700)
    if xdg_root.stat().st_uid != os.geteuid():
        raise RuntimeRefused("runtime:unsafe-xdg-runtime-root")
    exec_root = _safe_directory(policy.exec_root, "exec-root")
    executable = _absolute_clean(policy.executable, "executable")
    if not _within(executable, exec_root):
        raise RuntimeRefused("runtime:executable-outside-exec-root")
    metadata = executable.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o100 == 0
    ):
        raise RuntimeRefused("runtime:unsafe-executable")
    if (
        not isinstance(policy.executable_sha256, str)
        or _HASH.fullmatch(policy.executable_sha256) is None
    ):
        raise RuntimeRefused("runtime:invalid-executable-sha256")
    if _sha256(executable) != policy.executable_sha256:
        raise RuntimeRefused("runtime:executable-sha256")
    if not policy.arguments or DAEMON_SOCKET_ARGUMENT not in policy.arguments:
        raise RuntimeRefused("runtime:daemon-socket-argument-required")
    if any(not isinstance(value, str) or "\x00" in value for value in policy.arguments):
        raise RuntimeRefused("runtime:invalid-arguments")
    _positive_seconds(policy.startup_timeout_seconds, "startup-timeout")
    _positive_seconds(policy.maximum_runtime_seconds, "maximum-runtime")
    _positive_seconds(policy.drain_timeout_seconds, "drain-timeout")
    return xdg_root, exec_root, executable


def _proc_identity(pid: int) -> _ProcessIdentity:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        _, separator, fields_raw = raw.rpartition(") ")
        if not separator:
            raise ValueError
        fields = fields_raw.split()
        return _ProcessIdentity(
            pid=pid,
            state=fields[0],
            parent_pid=int(fields[1]),
            process_group=int(fields[2]),
            session=int(fields[3]),
            start_time_ticks=int(fields[19]),
        )
    except (OSError, ValueError, IndexError) as exc:
        raise RuntimeRefused("runtime:process-identity") from exc


def _namespaces(pid: int) -> Mapping[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    try:
        for name in _NAMESPACES:
            metadata = Path(f"/proc/{pid}/ns/{name}").stat()
            result[name] = (metadata.st_dev, metadata.st_ino)
    except OSError as exc:
        raise RuntimeRefused("runtime:namespace-identity") from exc
    return MappingProxyType(result)


def _socket_peer(path: Path, expected_pid: int) -> int:
    metadata = path.lstat()
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeRefused("runtime:unsafe-daemon-socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.25)
        client.connect(os.fspath(path))
        credentials = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
    if peer_pid != expected_pid or peer_uid != os.geteuid() or peer_gid != os.getegid():
        raise RuntimeRefused("runtime:daemon-peer")
    return int(peer_pid)


def _wait_for_exit(pidfd: int, timeout: float) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(round(timeout * 1000)))


def _group_members(process_group: int, leader: int) -> tuple[int, ...]:
    result: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal() or int(entry.name) == leader:
            continue
        try:
            identity = _proc_identity(int(entry.name))
        except RuntimeRefused:
            continue
        if identity.process_group == process_group and identity.state != "Z":
            result.append(identity.pid)
    return tuple(result)


def _terminate_process_group(process: subprocess.Popen[bytes], pidfd: int, timeout: float) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if not _wait_for_exit(pidfd, timeout):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if not _wait_for_exit(pidfd, timeout):
            raise RuntimeRefused("runtime:process-group-not-drained")

    # The unreaped leader pins its numeric PID/PGID until all signaling is done.
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + timeout
    while _group_members(process_group, process.pid) and time.monotonic() < deadline:
        time.sleep(0.01)
    if _group_members(process_group, process.pid):
        raise RuntimeRefused("runtime:process-group-not-drained")
    try:
        process.wait(timeout=0)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeRefused("runtime:leader-reap-failed") from exc


def _terminate_before_pidfd(process: subprocess.Popen[bytes], timeout: float) -> None:
    """Stop a just-spawned leader without ever signaling after it is reaped."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if _proc_identity(process.pid).state == "Z":
                break
        except RuntimeRefused as exc:
            raise RuntimeRefused("runtime:pre-pidfd-termination-not-proven") from exc
        time.sleep(0.01)
    else:
        raise RuntimeRefused("runtime:pre-pidfd-termination-not-proven")
    if _group_members(process.pid, process.pid):
        raise RuntimeRefused("runtime:pre-pidfd-group-not-drained")
    try:
        process.wait(timeout=0)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeRefused("runtime:leader-reap-failed") from exc


def _directory_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeRefused("runtime:nofollow-unavailable")
    return int(os.O_RDONLY | os.O_DIRECTORY | nofollow | int(getattr(os, "O_CLOEXEC", 0)))


def _clear_directory(descriptor: int) -> None:
    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise RuntimeRefused("runtime:cleanup-failed") from exc
    for name in names:
        child_fd = -1
        try:
            before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                child_fd = os.open(name, _directory_flags(), dir_fd=descriptor)
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise RuntimeRefused("runtime:cleanup-race")
                _clear_directory(child_fd)
                rebound = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (rebound.st_dev, rebound.st_ino) != (opened.st_dev, opened.st_ino):
                    raise RuntimeRefused("runtime:cleanup-race")
                os.rmdir(name, dir_fd=descriptor)
            else:
                os.unlink(name, dir_fd=descriptor)
        except RuntimeRefused:
            raise
        except OSError as exc:
            raise RuntimeRefused("runtime:cleanup-failed") from exc
        finally:
            if child_fd >= 0:
                os.close(child_fd)


def _remove_runtime_root(
    *,
    parent_fd: int,
    root_fd: int,
    root_name: str,
    expected_identity: tuple[int, int],
) -> None:
    try:
        metadata = os.fstat(root_fd)
    except OSError as exc:
        raise RuntimeRefused("runtime:cleanup-failed") from exc
    if (metadata.st_dev, metadata.st_ino) != expected_identity:
        raise RuntimeRefused("runtime:changed-runtime-root")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RuntimeRefused("runtime:unsafe-runtime-root")
    try:
        _clear_directory(root_fd)
        rebound = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        if (rebound.st_dev, rebound.st_ino) != expected_identity:
            raise RuntimeRefused("runtime:changed-runtime-root")
        os.rmdir(root_name, dir_fd=parent_fd)
    except OSError as exc:
        raise RuntimeRefused("runtime:cleanup-failed") from exc


def _remove_startup_root(
    *,
    parent_fd: int,
    root_fd: int,
    root_name: str,
    expected_identity: tuple[int, int],
) -> None:
    if root_fd >= 0:
        _remove_runtime_root(
            parent_fd=parent_fd,
            root_fd=root_fd,
            root_name=root_name,
            expected_identity=expected_identity,
        )
        return
    try:
        rebound = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        if (rebound.st_dev, rebound.st_ino) != expected_identity:
            raise RuntimeRefused("runtime:changed-runtime-root")
        os.rmdir(root_name, dir_fd=parent_fd)
    except RuntimeRefused:
        raise
    except OSError as exc:
        raise RuntimeRefused("runtime:cleanup-failed") from exc


class CollectorRuntime:
    """Own a direct development daemon until deterministic teardown completes."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        pidfd: int,
        runtime_root: Path,
        runtime_parent_fd: int,
        runtime_root_fd: int,
        runtime_root_identity: tuple[int, int],
        data_root: Path,
        daemon_socket: Path,
        identity: RuntimeIdentity,
        executable: Path,
        maximum_runtime_seconds: float,
        drain_timeout_seconds: float,
    ) -> None:
        self._process = process
        self._pidfd = pidfd
        self._runtime_root = runtime_root
        self._runtime_parent_fd = runtime_parent_fd
        self._runtime_root_fd = runtime_root_fd
        self._runtime_root_identity = runtime_root_identity
        self._data_root = data_root
        self._daemon_socket = daemon_socket
        self._identity = identity
        self._executable = executable
        self._drain_timeout_seconds = drain_timeout_seconds
        self._state = "open"
        self._expired = False
        self._terminal_error: str | None = None
        self._drained = False
        self._condition = threading.Condition()
        self._timer = threading.Timer(maximum_runtime_seconds, self._expire)
        self._timer.daemon = True

    def _arm_timeout(self) -> None:
        self._timer.start()

    def __enter__(self) -> Self:
        self.revalidate()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @property
    def data_root(self) -> Path:
        self.revalidate()
        return self._data_root

    @property
    def daemon_socket(self) -> Path:
        self.revalidate()
        return self._daemon_socket

    def describe(self) -> Mapping[str, object]:
        self.revalidate()
        return MappingProxyType(
            {
                "status": "DEVELOPMENT_ONLY",
                "backend": DEVELOPMENT_BACKEND,
                "qualificationEligible": False,
                "pid": self._identity.pid,
                "startTimeTicks": self._identity.start_time_ticks,
                "socketPeerPid": self._identity.socket_peer_pid,
                "ownedProcessGroup": self._identity.process_group,
                "ownedSession": self._identity.session,
                "namespaceIds": dict(self._identity.namespaces),
                "limitations": (
                    "current namespaces are observed, not isolated",
                    "network default-deny is not established by this backend",
                    "descendants that escape the original process group are not contained",
                    "this runtime cannot emit qualifying collector attestation",
                ),
            }
        )

    def revalidate(self) -> None:
        with self._condition:
            while self._state == "closing":
                self._condition.wait()
            if self._state == "failed":
                if self._terminal_error is None:
                    raise RuntimeRefused("runtime:invalid-lifecycle-state")
                raise RuntimeRefused(self._terminal_error)
            if self._state == "closed":
                reason = "runtime:expired" if self._expired else "runtime:closed"
                raise RuntimeRefused(reason)
            current = _proc_identity(self._identity.pid)
            if current.state == "Z":
                raise RuntimeRefused("runtime:daemon-exited")
            if (
                current.parent_pid != os.getpid()
                or current.start_time_ticks != self._identity.start_time_ticks
                or current.process_group != self._identity.process_group
                or current.session != self._identity.session
                or current.process_group != current.pid
                or current.session != current.pid
                or dict(_namespaces(current.pid)) != dict(self._identity.namespaces)
            ):
                raise RuntimeRefused("runtime:changed-process-identity")
            if _socket_peer(self._daemon_socket, current.pid) != self._identity.socket_peer_pid:
                raise RuntimeRefused("runtime:changed-daemon-peer")
            cwd = Path(f"/proc/{current.pid}/cwd").resolve(strict=True)
            if cwd != self._data_root:
                raise RuntimeRefused("runtime:changed-data-root")
            running_executable = Path(f"/proc/{current.pid}/exe").resolve(strict=True)
            if running_executable != self._executable:
                raise RuntimeRefused("runtime:changed-exec-root")

    def _expire(self) -> None:
        try:
            self._stop(expired=True)
        except RuntimeRefused:
            # _stop records a stable failure for observers and a later retry.
            pass

    def _stop(self, *, expired: bool) -> None:
        with self._condition:
            waited = False
            while self._state == "closing":
                waited = True
                self._condition.wait()
            if self._state == "closed":
                return
            if waited and self._state == "failed":
                if self._terminal_error is None:
                    raise RuntimeRefused("runtime:invalid-lifecycle-state")
                raise RuntimeRefused(self._terminal_error)
            self._state = "closing"
            self._terminal_error = None
            self._expired = self._expired or expired
            self._timer.cancel()
        try:
            if not self._drained:
                _terminate_process_group(self._process, self._pidfd, self._drain_timeout_seconds)
                self._drained = True
                pidfd = self._pidfd
                self._pidfd = -1
                try:
                    os.close(pidfd)
                except OSError:
                    pass
            self._cleanup()
        except BaseException as exc:
            failure = (
                exc
                if isinstance(exc, RuntimeRefused)
                else RuntimeRefused("runtime:lifecycle-cleanup-failed")
            )
            with self._condition:
                self._state = "failed"
                self._terminal_error = str(failure)
                self._condition.notify_all()
            if failure is exc:
                raise
            raise failure from exc
        with self._condition:
            self._state = "closed"
            self._condition.notify_all()

    def _cleanup(self) -> None:
        if self._process.returncode is None:
            raise RuntimeRefused("runtime:cleanup-incomplete")
        _remove_runtime_root(
            parent_fd=self._runtime_parent_fd,
            root_fd=self._runtime_root_fd,
            root_name=self._runtime_root.name,
            expected_identity=self._runtime_root_identity,
        )
        descriptors = (self._runtime_root_fd, self._runtime_parent_fd)
        self._runtime_root_fd = -1
        self._runtime_parent_fd = -1
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def close(self) -> None:
        self._stop(expired=False)


def start_runtime(policy: RuntimePolicy) -> CollectorRuntime:
    """Start and authenticate an owned, non-qualifying development daemon."""
    xdg_root, _exec_root, executable = _validate_policy(policy)
    pidfd_open = getattr(os, "pidfd_open", None)
    if pidfd_open is None:
        raise RuntimeRefused("runtime:pidfd-unavailable")
    runtime_root: Path | None = None
    root_identity: tuple[int, int] | None = None
    runtime_parent_fd = -1
    runtime_root_fd = -1
    process: subprocess.Popen[bytes] | None = None
    pidfd = -1
    result: CollectorRuntime | None = None
    try:
        runtime_parent_fd = os.open(xdg_root, _directory_flags())
        while True:
            root_name = f"phase7-collector-{secrets.token_hex(16)}"
            runtime_root = xdg_root / root_name
            try:
                os.mkdir(root_name, mode=0o700, dir_fd=runtime_parent_fd)
            except FileExistsError:
                runtime_root = None
                continue
            except OSError:
                runtime_root = None
                raise
            break
        root_metadata = runtime_root.lstat()
        root_identity = (root_metadata.st_dev, root_metadata.st_ino)
        runtime_root.chmod(0o700)
        runtime_root_fd = os.open(runtime_root.name, _directory_flags(), dir_fd=runtime_parent_fd)
        opened_root = os.fstat(runtime_root_fd)
        if (opened_root.st_dev, opened_root.st_ino) != root_identity:
            raise RuntimeRefused("runtime:changed-runtime-root")
        data_root = runtime_root / "data"
        data_root.mkdir(mode=0o700)
        daemon_socket = runtime_root / "daemon.sock"
        if len(os.fsencode(daemon_socket)) > _SOCKET_PATH_MAX_BYTES:
            raise RuntimeRefused("runtime:daemon-socket-path-too-long")
        arguments = tuple(
            value.replace(DAEMON_SOCKET_ARGUMENT, os.fspath(daemon_socket)).replace(
                DATA_ROOT_ARGUMENT, os.fspath(data_root)
            )
            for value in policy.arguments
        )
        command: Sequence[str] = (os.fspath(executable), *arguments)
        child_env = {
            "HOME": os.fspath(data_root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": os.fspath(data_root),
            "XDG_RUNTIME_DIR": os.fspath(runtime_root),
        }
        executable_fd = _pinned_executable(executable, policy.executable_sha256)
        try:
            process = subprocess.Popen(  # noqa: S603 - exec uses the pinned, rehashed FD.
                command,
                executable=f"/proc/self/fd/{executable_fd}",
                cwd=data_root,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(executable_fd,),
                start_new_session=True,
            )
        finally:
            os.close(executable_fd)
        try:
            pidfd = pidfd_open(process.pid, 0)
        except OSError as exc:
            raise RuntimeRefused("runtime:pidfd-unavailable") from exc
        deadline = time.monotonic() + _positive_seconds(
            policy.startup_timeout_seconds, "startup-timeout"
        )
        peer_pid: int | None = None
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if _proc_identity(process.pid).state == "Z":
                raise RuntimeRefused("runtime:daemon-exited-during-startup")
            try:
                peer_pid = _socket_peer(daemon_socket, process.pid)
                break
            except (FileNotFoundError, ConnectionError, OSError, RuntimeRefused) as exc:
                last_error = exc
                time.sleep(0.01)
        if peer_pid is None:
            raise RuntimeRefused("runtime:daemon-startup-timeout") from last_error
        current = _proc_identity(process.pid)
        if (
            current.parent_pid != os.getpid()
            or current.process_group != process.pid
            or current.session != process.pid
        ):
            raise RuntimeRefused("runtime:unowned-process")
        identity = RuntimeIdentity(
            pid=process.pid,
            start_time_ticks=current.start_time_ticks,
            process_group=current.process_group,
            session=current.session,
            socket_peer_pid=peer_pid,
            namespaces=_namespaces(process.pid),
        )
        result = CollectorRuntime(
            process=process,
            pidfd=pidfd,
            runtime_root=runtime_root,
            runtime_parent_fd=runtime_parent_fd,
            runtime_root_fd=runtime_root_fd,
            runtime_root_identity=root_identity,
            data_root=data_root,
            daemon_socket=daemon_socket,
            identity=identity,
            executable=executable,
            maximum_runtime_seconds=_positive_seconds(
                policy.maximum_runtime_seconds, "maximum-runtime"
            ),
            drain_timeout_seconds=_positive_seconds(policy.drain_timeout_seconds, "drain-timeout"),
        )
        result.revalidate()
        result._arm_timeout()
        return result
    except BaseException as original:
        cleanup_error: BaseException | None = None
        try:
            if result is not None:
                result.close()
            elif process is not None:
                if pidfd < 0:
                    _terminate_before_pidfd(process, 1.0)
                else:
                    _terminate_process_group(process, pidfd, 1.0)
            if result is None and runtime_root is not None:
                if root_identity is None:
                    runtime_root_fd = os.open(
                        runtime_root.name, _directory_flags(), dir_fd=runtime_parent_fd
                    )
                    pending = os.fstat(runtime_root_fd)
                    root_identity = (pending.st_dev, pending.st_ino)
                _remove_startup_root(
                    parent_fd=runtime_parent_fd,
                    root_fd=runtime_root_fd,
                    root_name=runtime_root.name,
                    expected_identity=root_identity,
                )
        except BaseException as exc:
            cleanup_error = exc
        finally:
            if result is None:
                for descriptor in (pidfd, runtime_root_fd, runtime_parent_fd):
                    if descriptor >= 0:
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
        if cleanup_error is not None:
            detail = (
                str(cleanup_error)
                if isinstance(cleanup_error, RuntimeRefused)
                else type(cleanup_error).__name__
            )
            raise RuntimeRefused(
                f"runtime:startup-cleanup-failed:{detail}:original-{type(original).__name__}"
            ) from cleanup_error
        raise
