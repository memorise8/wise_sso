#!/usr/bin/env python3
"""Own test runtimes that deliver auth mail to a private loopback capture.

This is a development-only launcher.  It does not produce qualifying evidence:
the owned process, loopback SMTP socket, ephemeral CA, and destructive token
consumer exist only to connect the HTTP flow driver to real runtime mail paths.
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import math
import os
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, Self, cast
from urllib import parse


class _CaptureModule(Protocol):
    CaptureError: type[Exception]
    PrivateMailCaptureServer: type[Any]


class _RuntimeModule(Protocol):
    RuntimeRefused: type[Exception]

    def _terminate_process_group(
        self, process: subprocess.Popen[bytes], pidfd: int, timeout: float
    ) -> None: ...

    def _terminate_before_pidfd(
        self, process: subprocess.Popen[bytes], timeout: float
    ) -> None: ...

    def _wait_for_exit(self, pidfd: int, timeout: float) -> bool: ...

    def _group_members(self, process_group: int, leader: int) -> tuple[int, ...]: ...


def _load_capture() -> _CaptureModule:
    module_path = Path(__file__).with_name("private_mail_capture.py")
    spec = importlib.util.spec_from_file_location(
        "private_mail_flow_capture", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load private mail capture from {module_path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_CaptureModule, module)


capture = _load_capture()


def _load_runtime() -> _RuntimeModule:
    module_path = (
        Path(__file__).resolve().parents[2]
        / "fastapi-auth-server"
        / "ops"
        / "phase7"
        / "collector_runtime.py"
    )
    spec = importlib.util.spec_from_file_location(
        "private_mail_owned_runtime", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load owned runtime helpers from {module_path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_RuntimeModule, module)


runtime_helpers = _load_runtime()

_RESERVED_ENVIRONMENT = {
    "CONTRACT_PRIVATE_MAIL_CAPTURE",
    "CONTRACT_PRIVATE_MAIL_CA_SHA256",
    "CONTRACT_SERVER_MAIL_MODE",
    "MAIL_PROVIDER",
    "NODE_EXTRA_CA_CERTS",
    "SMTP_HOST",
    "SMTP_PASSWORD",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SSL_CERT_FILE",
}


class LaunchError(RuntimeError):
    """An owned runtime could not be safely started, observed, or drained."""


class LaunchCleanupError(LaunchError):
    """Owned runtime cleanup failed after all bounded drain attempts."""


@dataclass(frozen=True, slots=True)
class RuntimeSpec:
    name: str
    command: tuple[str, ...]
    cwd: Path
    health_url: str
    environment: Mapping[str, str]

    @classmethod
    def create(
        cls,
        *,
        name: str,
        command: Sequence[str],
        cwd: Path,
        health_url: str,
        environment: Mapping[str, str] | None = None,
    ) -> RuntimeSpec:
        if not name or not name.replace("-", "").replace("_", "").isalnum():
            raise LaunchError("runtime name has an invalid shape")
        resolved = cwd.resolve()
        if not resolved.is_dir():
            raise LaunchError("runtime cwd must be an existing directory")
        values = tuple(command)
        if not values or any(
            not isinstance(value, str) or not value for value in values
        ):
            raise LaunchError("runtime command must contain non-empty arguments")
        normalized_health = _loopback_health_url(health_url)
        overlay = dict(environment or {})
        if any(key in _RESERVED_ENVIRONMENT for key in overlay):
            raise LaunchError(
                "runtime environment may not override private mail controls"
            )
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in overlay.items()
        ):
            raise LaunchError("runtime environment must contain strings")
        return cls(name, values, resolved, normalized_health, overlay)


@dataclass(frozen=True, slots=True, repr=False)
class PrivateMailSessionBinding:
    """Opaque launcher-issued capability used to bind fixture subprocesses."""

    environment: Mapping[str, str]
    runtime_name: str
    process_pid: int
    health_origin: str

    def __repr__(self) -> str:
        return "PrivateMailSessionBinding([REDACTED])"


def _loopback_health_url(value: str) -> str:
    try:
        parsed = parse.urlparse(value)
        _ = parsed.port
    except ValueError as exc:
        raise LaunchError("runtime health URL has an invalid port") from exc
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}:
        raise LaunchError("runtime health URL must use a literal loopback address")
    if parsed.username or parsed.fragment:
        raise LaunchError(
            "runtime health URL must not contain credentials or a fragment"
        )
    return value


def _listening_socket_inodes(port: int, hostname: str) -> set[str]:
    inodes: set[str] = set()
    table_path, loopback_address = (
        (Path("/proc/net/tcp"), "0100007F")
        if hostname == "127.0.0.1"
        else (Path("/proc/net/tcp6"), "00000000000000000000000001000000")
    )
    try:
        lines = table_path.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return inodes
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "0A":
            continue
        address, separator, raw_port = fields[1].rpartition(":")
        if separator and address == loopback_address and int(raw_port, 16) == port:
            inodes.add(fields[9])
    return inodes


def _owned_socket_inodes(process: subprocess.Popen[bytes]) -> set[str]:
    owned: set[str] = set()
    process_ids = (
        process.pid,
        *runtime_helpers._group_members(process.pid, process.pid),
    )
    for process_id in process_ids:
        descriptor_root = Path("/proc") / str(process_id) / "fd"
        try:
            descriptors = tuple(descriptor_root.iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:["):
                owned.add(target[8:-1])
    return owned


def _runtime_owns_health_listener(
    runtime: RuntimeSpec, process: subprocess.Popen[bytes]
) -> bool:
    parsed = parse.urlparse(runtime.health_url)
    assert parsed.hostname is not None
    inodes = _listening_socket_inodes(parsed.port or 80, parsed.hostname)
    if not inodes:
        return False
    return inodes.issubset(_owned_socket_inodes(process))


def _runtime_owns_connection(
    runtime: RuntimeSpec,
    process: subprocess.Popen[bytes],
    client_port: int,
) -> bool:
    parsed = parse.urlparse(runtime.health_url)
    assert parsed.hostname is not None
    table_path, loopback_address = (
        (Path("/proc/net/tcp"), "0100007F")
        if parsed.hostname == "127.0.0.1"
        else (Path("/proc/net/tcp6"), "00000000000000000000000001000000")
    )
    try:
        lines = table_path.read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        return False
    server_port = parsed.port or 80
    owned = _owned_socket_inodes(process)
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or fields[3] != "01":
            continue
        local_address, _, local_port = fields[1].rpartition(":")
        peer_address, _, peer_port = fields[2].rpartition(":")
        if (
            local_address == loopback_address
            and peer_address == loopback_address
            and int(local_port, 16) == server_port
            and int(peer_port, 16) == client_port
            and fields[9] in owned
        ):
            return True
    return False


def _owned_health_status(runtime: RuntimeSpec, process: subprocess.Popen[bytes]) -> int:
    parsed = parse.urlparse(runtime.health_url)
    assert parsed.hostname is not None
    connection = http.client.HTTPConnection(
        parsed.hostname, parsed.port or 80, timeout=0.5
    )
    try:
        connection.connect()
        assert connection.sock is not None
        client_address = connection.sock.getsockname()
        client_port = int(client_address[1])
        deadline = time.monotonic() + 0.25
        while not _runtime_owns_connection(runtime, process, client_port):
            if time.monotonic() >= deadline:
                raise LaunchError("health connection is not owned by the runtime")
            time.sleep(0.005)
        path = parse.urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
        connection.request("GET", path, headers={"connection": "close"})
        response = connection.getresponse()
        response.read(65_537)
        return response.status
    finally:
        connection.close()


def _owned_file_digest(path: Path) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise LaunchError("private mail CA secure open is unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise LaunchError("private mail CA must be an owned mode-0600 regular file")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, 1_048_577 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 1_048_576:
                raise LaunchError("private mail CA exceeds the bounded read limit")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mode) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
        ) or len(data) != before.st_size:
            raise LaunchError("private mail CA changed while being read")
        return hashlib.sha256(data).hexdigest()
    finally:
        os.close(descriptor)


class PrivateMailFlowLauncher:
    """Own a private capture and every runtime configured to use it."""

    def __init__(
        self,
        *,
        directory: Path,
        run_id: str,
        recipients: Mapping[str, str],
        runtimes: Sequence[RuntimeSpec],
        ttl_seconds: float = 300.0,
        readiness_timeout: float = 15.0,
    ) -> None:
        if not runtimes:
            raise LaunchError("at least one owned runtime is required")
        names = [runtime.name for runtime in runtimes]
        if len(names) != len(set(names)):
            raise LaunchError("owned runtime names must be unique")
        if readiness_timeout <= 0 or readiness_timeout > 60:
            raise LaunchError(
                "readiness timeout must be greater than zero and at most 60"
            )
        self._runtimes = tuple(runtimes)
        self._readiness_timeout = readiness_timeout
        if (
            not isinstance(readiness_timeout, (int, float))
            or isinstance(readiness_timeout, bool)
            or not math.isfinite(readiness_timeout)
            or readiness_timeout <= 0
            or readiness_timeout > 60
        ):
            raise LaunchError("readiness timeout must be finite and in (0, 60]")
        self._processes: list[tuple[subprocess.Popen[bytes], int]] = []
        self._ready = False
        self._closed = False
        try:
            self._server = capture.PrivateMailCaptureServer(
                directory=directory,
                run_id=run_id,
                recipients=dict(recipients),
                ttl_seconds=ttl_seconds,
            )
        except capture.CaptureError as exc:
            raise LaunchError("private mail capture could not be created") from exc
        self.run_id = run_id
        self._session_path = directory.resolve() / "launcher-session.json"
        self._binding: PrivateMailSessionBinding | None = None

    def _mail_environment(self) -> dict[str, str]:
        values = self._server.smtp_launcher_environment()
        certificate = Path(values["SSL_CERT_FILE"])
        digest = _owned_file_digest(certificate)
        environment = {
            **values,
            "CONTRACT_SERVER_MAIL_MODE": "private-loopback-smtp",
            "CONTRACT_PRIVATE_MAIL_CA_SHA256": digest,
        }
        if self._binding is None:
            capability = secrets.token_hex(32)
            document = {
                "version": 1,
                "runId": self.run_id,
                "launcherPid": os.getpid(),
                "smtpHost": values["SMTP_HOST"],
                "smtpPort": values["SMTP_PORT"],
                "caSha256": digest,
                "capability": capability,
            }
            descriptor = os.open(
                self._session_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, separators=(",", ":"), sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            environment.update(
                CONTRACT_PRIVATE_MAIL_SESSION_FILE=str(self._session_path),
                CONTRACT_PRIVATE_MAIL_SESSION_CAPABILITY=capability,
            )
            self._binding = PrivateMailSessionBinding(
                dict(environment), "unbound", 0, "http://127.0.0.1:1"
            )
        return dict(self._binding.environment)

    def binding(self, runtime_name: str) -> PrivateMailSessionBinding:
        if self._binding is None or not self._processes or not self._ready:
            raise LaunchError("private mail session binding is not active")
        for runtime, (process, _pidfd) in zip(
            self._runtimes, self._processes, strict=True
        ):
            if runtime.name == runtime_name:
                parsed = parse.urlparse(runtime.health_url)
                host = (
                    f"[{parsed.hostname}]"
                    if parsed.hostname and ":" in parsed.hostname
                    else parsed.hostname
                )
                origin = f"http://{host}:{parsed.port or 80}"
                return PrivateMailSessionBinding(
                    dict(self._binding.environment),
                    runtime.name,
                    process.pid,
                    origin,
                )
        raise LaunchError("private mail runtime binding does not exist")

    def start(self) -> Self:
        if self._closed:
            raise LaunchError("private mail launcher is closed")
        if self._processes:
            raise LaunchError("private mail launcher is already started")
        unclaimed_process: subprocess.Popen[bytes] | None = None
        unclaimed_pidfd = -1
        try:
            self._server.start()
            mail_environment = self._mail_environment()
            inherited = {
                key: value
                for key in ("LANG", "LC_ALL", "PATH", "SYSTEMROOT")
                if (value := os.environ.get(key)) is not None
            }
            for runtime in self._runtimes:
                parsed_health = parse.urlparse(runtime.health_url)
                assert parsed_health.hostname is not None
                if _listening_socket_inodes(
                    parsed_health.port or 80, parsed_health.hostname
                ):
                    raise LaunchError(
                        f"runtime health listener already exists: {runtime.name}"
                    )
            for runtime in self._runtimes:
                unclaimed_process = subprocess.Popen(
                    runtime.command,
                    cwd=runtime.cwd,
                    env={**inherited, **runtime.environment, **mail_environment},
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    unclaimed_pidfd = os.pidfd_open(unclaimed_process.pid, 0)
                except (AttributeError, OSError) as exc:
                    raise LaunchError("owned runtime pidfd is unavailable") from exc
                self._processes.append((unclaimed_process, unclaimed_pidfd))
                unclaimed_process = None
                unclaimed_pidfd = -1
            self._wait_until_ready()
            self._ready = True
            return self
        except BaseException as original:  # noqa: BLE001 - rollback on all exits
            self._ready = False
            if unclaimed_process is not None:
                self._processes.append((unclaimed_process, unclaimed_pidfd))
                unclaimed_process = None
                unclaimed_pidfd = -1
            self._bounded_drain(original)
            raise AssertionError("bounded drain must re-raise startup failure")

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + self._readiness_timeout
        pending = {runtime.name: runtime for runtime in self._runtimes}
        while pending and time.monotonic() < deadline:
            for (process, _pidfd), runtime in zip(
                self._processes, self._runtimes, strict=True
            ):
                if runtime_helpers._wait_for_exit(_pidfd, 0.0):
                    raise LaunchError(
                        f"owned runtime {runtime.name} exited before readiness"
                    )
                if runtime.name not in pending:
                    continue
                try:
                    status = _owned_health_status(runtime, process)
                    if 200 <= status < 300 and _runtime_owns_health_listener(
                        runtime, process
                    ):
                        pending.pop(runtime.name)
                except (OSError, http.client.HTTPException, LaunchError):
                    pass
            if pending:
                time.sleep(0.02)
        if pending:
            raise LaunchError(
                "owned runtime readiness timed out: " + ", ".join(sorted(pending))
            )

    def take(self, *, user_id: str, kind: Any) -> Any:
        if not self._processes or self._closed or not self._ready:
            raise LaunchError("private mail launcher is not active")
        if any(
            runtime_helpers._wait_for_exit(pidfd, 0.0)
            for _process, pidfd in self._processes
        ):
            raise LaunchError("an owned runtime exited before private mail consumption")
        if any(
            not _runtime_owns_health_listener(runtime, process)
            for runtime, (process, _pidfd) in zip(
                self._runtimes, self._processes, strict=True
            )
        ):
            raise LaunchError("an owned runtime lost its attributed health listener")
        try:
            self._server.assert_active()
            return self._server.mailbox.take(
                run_id=self.run_id,
                user_id=user_id,
                kind=kind,
            )
        except capture.CaptureError as exc:
            raise LaunchError("private mail consumption failed") from exc

    def public_summary(self) -> dict[str, Any]:
        return {
            **self._server.mailbox.public_summary(),
            "ownedRuntimeCount": len(self._processes),
            "qualifyingEvidence": False,
        }

    def close(self) -> None:
        if self._closed:
            return
        failures: list[BaseException] = []
        self._ready = False
        retained: list[tuple[subprocess.Popen[bytes], int]] = []
        for process, pidfd in reversed(self._processes):
            try:
                if pidfd < 0:
                    runtime_helpers._terminate_before_pidfd(process, 2.0)
                else:
                    runtime_helpers._terminate_process_group(process, pidfd, 2.0)
            except BaseException as exc:  # noqa: BLE001 - cleanup survives interrupts
                failures.append(exc)
                if process.returncode is None:
                    retained.append((process, pidfd))
                elif pidfd >= 0:
                    try:
                        os.close(pidfd)
                    except BaseException as close_error:  # noqa: BLE001 - consumed fd
                        failures.append(close_error)
            else:
                if pidfd >= 0:
                    try:
                        os.close(pidfd)
                    except BaseException as exc:  # noqa: BLE001 - consumed fd
                        failures.append(exc)
        self._processes = list(reversed(retained))
        if self._processes:
            if isinstance(failures[0], (KeyboardInterrupt, SystemExit)):
                raise failures[0]
            raise LaunchCleanupError(
                "private mail launcher process cleanup failed"
            ) from failures[0]
        capture_closed = False
        try:
            self._server.close()
            capture_closed = True
        except BaseException as exc:  # noqa: BLE001 - finish remaining cleanup phases
            failures.append(exc)
        session_removed = False
        try:
            self._session_path.unlink(missing_ok=True)
            session_removed = True
        except BaseException as exc:  # noqa: BLE001 - preserve primary after cleanup
            failures.append(exc)
        self._binding = None
        self._closed = capture_closed and session_removed
        if failures:
            if isinstance(failures[0], (KeyboardInterrupt, SystemExit)):
                raise failures[0]
            raise LaunchCleanupError(
                "private mail launcher cleanup failed"
            ) from failures[0]

    def __enter__(self) -> Self:
        return self.start()

    def _bounded_drain(self, primary: BaseException | None = None) -> None:
        deadline = time.monotonic() + 3.0
        attempts_remaining = 8
        pending_primary = primary
        last_cleanup_error: BaseException | None = None
        while True:
            try:
                self.close()
            except (KeyboardInterrupt, SystemExit) as exc:
                pending_primary = pending_primary or exc
                last_cleanup_error = exc
            except LaunchCleanupError as exc:
                last_cleanup_error = exc
            else:
                if pending_primary is not None:
                    raise pending_primary
                return
            attempts_remaining -= 1
            if self._closed:
                if pending_primary is not None:
                    raise pending_primary from last_cleanup_error
                assert last_cleanup_error is not None
                raise last_cleanup_error
            if attempts_remaining == 0 or time.monotonic() >= deadline:
                assert last_cleanup_error is not None
                exhausted = LaunchCleanupError("owned runtime bounded cleanup failed")
                if pending_primary is not None:
                    exhausted.add_note(
                        f"primary failure preserved: {type(pending_primary).__name__}: "
                        f"{pending_primary}"
                    )
                raise exhausted from last_cleanup_error
            time.sleep(0.02)

    def __exit__(self, _type: object, value: object, _traceback: object) -> None:
        primary = value if isinstance(value, BaseException) else None
        self._bounded_drain(primary)
