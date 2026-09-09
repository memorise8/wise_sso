#!/usr/bin/env python3
"""Own disposable mixed OAuth runtimes and their private provider record pipe."""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import os
import stat
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, Self, cast


class _MailLauncherModule(Protocol):
    LaunchError: type[Exception]
    RuntimeSpec: type[Any]
    runtime_helpers: Any

    def _listening_socket_inodes(self, port: int, hostname: str) -> set[str]: ...

    def _owned_health_status(
        self, runtime: Any, process: subprocess.Popen[bytes]
    ) -> int: ...

    def _runtime_owns_health_listener(
        self, runtime: Any, process: subprocess.Popen[bytes]
    ) -> bool: ...


class _RecordModule(Protocol):
    PrivateProviderRecordError: type[Exception]
    PrivateProviderRecordChannel: type[Any]


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load private OAuth dependency from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mail = cast(
    _MailLauncherModule,
    _load(
        "private_oauth_mail_ownership",
        Path(__file__).with_name("private_mail_flow_launcher.py"),
    ),
)
records = cast(
    _RecordModule,
    _load(
        "private_oauth_provider_records",
        Path(__file__).with_name("private_provider_record.py"),
    ),
)
RuntimeSpec = mail.RuntimeSpec

_RESERVED = {
    "WISEACCT_TEST_PROVIDER_RECORD_FD",
    "WISEACCT_TEST_PROVIDER_RUN_ID",
    "WISEACCT_TEST_PROVIDER_RUNTIME",
}


class OAuthLaunchError(RuntimeError):
    """A disposable OAuth runtime could not be owned or drained."""


class OAuthCleanupError(OAuthLaunchError):
    """Owned OAuth resources remain after bounded cleanup attempts."""


@dataclass(frozen=True, slots=True)
class OwnedRuntimeBinding:
    role: str
    origin: str
    pid: int
    process_group: int


def _explicit_executable(command: Sequence[str]) -> None:
    if not command:
        raise OAuthLaunchError("runtime command is empty")
    executable = Path(command[0])
    try:
        details = executable.lstat()
    except OSError as exc:
        raise OAuthLaunchError("runtime executable is unavailable") from exc
    if (
        not executable.is_absolute()
        or executable.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or not os.access(executable, os.X_OK)
    ):
        raise OAuthLaunchError("runtime executable must be an explicit executable file")


class PrivateOAuthFlowLauncher:
    """Own exactly one producer and one consumer process for a single trial."""

    def __init__(
        self,
        *,
        run_id: str,
        producer_role: str,
        producer: Any,
        consumer_role: str,
        consumer: Any,
        readiness_timeout: float = 15.0,
        provider: str = "google",
    ) -> None:
        if provider not in ("google", "naver", "kakao"):
            raise OAuthLaunchError("OAuth launcher provider is unsupported")
        if {producer_role, consumer_role} != {"express", "fastapi"}:
            raise OAuthLaunchError(
                "OAuth launcher requires one process for each runtime role"
            )
        if producer_role == consumer_role:
            raise OAuthLaunchError("OAuth launcher runtime roles must be distinct")
        if producer.name != producer_role or consumer.name != consumer_role:
            raise OAuthLaunchError(
                "runtime role does not match its declared process spec"
            )
        if self._origin(producer.health_url) == self._origin(consumer.health_url):
            raise OAuthLaunchError("OAuth runtime origins must be distinct")
        if not math.isfinite(readiness_timeout) or not 0 < readiness_timeout <= 60:
            raise OAuthLaunchError("readiness timeout must be finite and in (0, 60]")
        for runtime in (producer, consumer):
            _explicit_executable(runtime.command)
            if any(name in runtime.environment for name in _RESERVED):
                raise OAuthLaunchError(
                    "runtime environment overrides the private record binding"
                )
        self.run_id = run_id
        self.provider = provider
        self.producer_role = producer_role
        self.consumer_role = consumer_role
        self._producer = producer
        self._consumer = consumer
        self._readiness_timeout = readiness_timeout
        try:
            self._channel = records.PrivateProviderRecordChannel(
                run_id=run_id, runtime=producer_role
            )
        except records.PrivateProviderRecordError as exc:
            raise OAuthLaunchError(
                "private provider record channel could not be created"
            ) from exc
        self._processes: dict[str, tuple[subprocess.Popen[bytes], int]] = {}
        self._provider_snapshot: dict[str, object] | None = None
        self._terminal_cleanup_error: OAuthCleanupError | None = None
        self._started = False
        self._closed = False

    @property
    def origins(self) -> dict[str, str]:
        return {
            self.producer_role: self._origin(self._producer.health_url),
            self.consumer_role: self._origin(self._consumer.health_url),
        }

    @property
    def runtime_bindings(self) -> dict[str, OwnedRuntimeBinding]:
        if (
            not self._started
            or self._closed
            or set(self._processes)
            != {
                self.producer_role,
                self.consumer_role,
            }
        ):
            raise OAuthLaunchError("owned OAuth runtime bindings are not active")
        result: dict[str, OwnedRuntimeBinding] = {}
        specs = {self.producer_role: self._producer, self.consumer_role: self._consumer}
        for role, (process, pidfd) in self._processes.items():
            if mail.runtime_helpers._wait_for_exit(pidfd, 0.0):
                raise OAuthLaunchError("owned OAuth runtime exited before binding")
            if not mail._runtime_owns_health_listener(specs[role], process):
                raise OAuthLaunchError(
                    "owned OAuth runtime listener attribution failed"
                )
            try:
                process_group = os.getpgid(process.pid)
            except OSError as exc:
                raise OAuthLaunchError(
                    "owned OAuth process group is unavailable"
                ) from exc
            result[role] = OwnedRuntimeBinding(
                role, self.origins[role], process.pid, process_group
            )
        self._assert_independent(
            self._processes[self.producer_role][0],
            self._processes[self.consumer_role][0],
        )
        return result

    @staticmethod
    def _endpoint(health_url: str) -> tuple[str, int]:
        from urllib import parse

        try:
            parsed = parse.urlsplit(health_url)
            port = parsed.port
        except ValueError as exc:
            raise OAuthLaunchError("OAuth health URL is invalid") from exc
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or port is None
            or port == 0
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise OAuthLaunchError(
                "OAuth health URL requires literal loopback and explicit port"
            )
        return parsed.hostname, port

    @staticmethod
    def _origin(health_url: str) -> str:
        hostname, port = PrivateOAuthFlowLauncher._endpoint(health_url)
        host = f"[{hostname}]" if ":" in hostname else hostname
        return f"http://{host}:{port}"

    @staticmethod
    def _assert_independent(
        producer: subprocess.Popen[bytes], consumer: subprocess.Popen[bytes]
    ) -> None:
        if producer.pid == consumer.pid:
            raise OAuthLaunchError("OAuth runtime processes are not independent")
        try:
            identities = {
                (producer.pid, os.getpgid(producer.pid)),
                (consumer.pid, os.getpgid(consumer.pid)),
            }
        except OSError as exc:
            raise OAuthLaunchError(
                "OAuth runtime process identity is unavailable"
            ) from exc
        if len(identities) != 2 or any(pid != group for pid, group in identities):
            raise OAuthLaunchError("OAuth runtimes do not own distinct process groups")

    def start(self) -> Self:
        if self._closed or self._started:
            raise OAuthLaunchError(
                "OAuth launcher cannot be started in its current state"
            )
        binding: Any | None = None
        try:
            for runtime in (self._producer, self._consumer):
                hostname, port = self._endpoint(runtime.health_url)
                if mail._listening_socket_inodes(port, hostname):
                    raise OAuthLaunchError("OAuth runtime listener already exists")
            binding = self._channel.child_binding()
            self._spawn(
                self.producer_role, self._producer, binding.environment, (binding.fd,)
            )
            self._channel.handoff()
            binding = None
            self._spawn(self.consumer_role, self._consumer, {}, ())
            self._assert_independent(
                self._processes[self.producer_role][0],
                self._processes[self.consumer_role][0],
            )
            self._wait_ready()
            self._started = True
            return self
        except BaseException as primary:  # noqa: BLE001 - startup rollback owns children
            self._bounded_close(primary)
            raise AssertionError("bounded close must re-raise startup failure")

    def _spawn(
        self,
        role: str,
        runtime: Any,
        private_environment: Mapping[str, str],
        pass_fds: tuple[int, ...],
    ) -> None:
        inherited = {
            key: value
            for key in ("LANG", "LC_ALL", "PATH", "SYSTEMROOT")
            if (value := os.environ.get(key)) is not None
        }
        process = subprocess.Popen(
            runtime.command,
            cwd=runtime.cwd,
            env={**inherited, **runtime.environment, **private_environment},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            pass_fds=pass_fds,
        )
        try:
            pidfd = os.pidfd_open(process.pid, 0)
        except BaseException as primary:
            try:
                mail.runtime_helpers._terminate_before_pidfd(process, 2.0)
            except BaseException as cleanup:
                primary.add_note("oauth-runtime-pre-pidfd-cleanup-failure")
                raise primary from cleanup
            raise
        self._processes[role] = (process, pidfd)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self._readiness_timeout
        specs = {self.producer_role: self._producer, self.consumer_role: self._consumer}
        pending = set(specs)
        while pending and time.monotonic() < deadline:
            for role in tuple(pending):
                process, pidfd = self._processes[role]
                if mail.runtime_helpers._wait_for_exit(pidfd, 0.0):
                    raise OAuthLaunchError("OAuth runtime exited before readiness")
                try:
                    status = mail._owned_health_status(specs[role], process)
                    if status == 200 and mail._runtime_owns_health_listener(
                        specs[role], process
                    ):
                        pending.remove(role)
                except Exception as exc:  # noqa: BLE001 - bounded readiness retry
                    _ = exc
            if pending:
                time.sleep(0.02)
        if pending:
            raise OAuthLaunchError("OAuth runtime readiness timed out")

    def consume_provider_snapshot(self) -> dict[str, object]:
        if self._provider_snapshot is not None:
            raise OAuthLaunchError("provider snapshot was already consumed")
        if not self._started or self._closed:
            raise OAuthLaunchError("OAuth launcher is not active")
        self._drain_role(self.producer_role)
        try:
            snapshot = self._channel.consume(timeout_seconds=5.0)
        except records.PrivateProviderRecordError as exc:
            raise OAuthLaunchError(
                "private provider record consumption failed"
            ) from exc
        self._provider_snapshot = cast(dict[str, object], snapshot)
        return dict(self._provider_snapshot)

    def _drain_role(self, role: str) -> None:
        owned = self._processes.get(role)
        if owned is None:
            return
        process, pidfd = owned
        mail.runtime_helpers._terminate_process_group(process, pidfd, 2.0)
        del self._processes[role]
        try:
            os.close(pidfd)
        except OSError as exc:
            error = OAuthCleanupError("OAuth runtime pidfd close failed")
            self._terminal_cleanup_error = error
            raise error from exc

    def close(self) -> None:
        if self._closed:
            return
        failures: list[BaseException] = []
        for role in tuple(self._processes):
            try:
                self._drain_role(role)
            except BaseException as exc:  # noqa: BLE001 - drain all owned roles
                failures.append(exc)
        self._channel.close()
        if self._terminal_cleanup_error is not None:
            failures.append(self._terminal_cleanup_error)
        self._closed = not self._processes and self._terminal_cleanup_error is None
        if failures:
            if isinstance(failures[0], (KeyboardInterrupt, SystemExit)):
                raise failures[0]
            raise OAuthCleanupError("OAuth runtime cleanup failed") from failures[0]

    def _bounded_close(self, primary: BaseException | None = None) -> None:
        deadline = time.monotonic() + 3.0
        attempts = 8
        last_cleanup: BaseException | None = None
        while True:
            try:
                self.close()
            except BaseException as exc:  # noqa: BLE001 - bounded cleanup retry
                last_cleanup = exc
            else:
                if primary is not None:
                    raise primary
                return
            attempts -= 1
            if attempts == 0 or time.monotonic() >= deadline:
                assert last_cleanup is not None
                if primary is not None:
                    primary.add_note("oauth-launcher-cleanup-failure")
                    raise primary from last_cleanup
                if isinstance(last_cleanup, (KeyboardInterrupt, SystemExit)):
                    raise last_cleanup
                raise OAuthCleanupError(
                    "OAuth launcher bounded cleanup failed"
                ) from last_cleanup
            time.sleep(0.02)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, _type: object, value: object, _traceback: object) -> None:
        self._bounded_close(value if isinstance(value, BaseException) else None)


class OwnedOAuthFixtureAdapter:
    """Decorate a fixture adapter with launcher-owned provider evidence and cleanup."""

    def __init__(self, adapter: Any, launcher: PrivateOAuthFlowLauncher) -> None:
        self._adapter = adapter
        self._launcher = launcher
        self.refresh_secret = cast(str, adapter.refresh_secret)
        self.runtime_bindings = launcher.runtime_bindings

    def invoke(self, command: str, name: str) -> Any:
        provider = self._launcher.provider
        fixture_name = f"{provider}-oauth-user"
        if command in {"setup", "teardown"} and name != fixture_name:
            raise OAuthLaunchError("fixture provider scope does not match the launcher")
        if command == "snapshot" and name not in {
            f"oauth-{provider}-provider-invocations",
            f"oauth-{provider}-state",
            f"oauth-{provider}-residual",
        }:
            raise OAuthLaunchError(
                "snapshot provider scope does not match the launcher"
            )
        if command == "snapshot" and name == f"oauth-{provider}-provider-invocations":
            return self._launcher.consume_provider_snapshot()
        if command == "setup" and name == fixture_name:
            result = self._adapter.invoke(command, name)
            if (
                not isinstance(result, dict)
                or result.get("runId") != self._launcher.run_id
            ):
                raise OAuthLaunchError(
                    "fixture runId does not match the owned launcher"
                )
            return result
        if command == "teardown" and name == fixture_name:
            # Do not reset shared state while an owned writer can still mutate it.
            # On drain failure, leave the fixture intact and report cleanup failure.
            self._launcher._bounded_close()
            return self._adapter.invoke(command, name)
        return self._adapter.invoke(command, name)


def _load_config(path: Path) -> dict[str, Any]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OAuthLaunchError("launcher config secure open is unavailable")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | no_follow)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > 64 * 1024
        ):
            raise OAuthLaunchError("launcher config must be an owned private file")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(8192, 64 * 1024 + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 64 * 1024:
                raise OAuthLaunchError("launcher config is too large")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        ) or size != before.st_size:
            raise OAuthLaunchError("launcher config changed while being read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OAuthLaunchError("launcher config is invalid JSON") from exc
    if not isinstance(value, dict):
        raise OAuthLaunchError("launcher config is not an object")
    return value


def _runtime_from_config(value: object, role: str) -> Any:
    fields = {"command", "cwd", "healthUrl", "environment"}
    if not isinstance(value, dict) or set(value) != fields:
        raise OAuthLaunchError("launcher runtime config fields are not exact")
    command = value["command"]
    environment = value["environment"]
    if (
        not isinstance(command, list)
        or any(not isinstance(item, str) or not item for item in command)
        or not isinstance(value["cwd"], str)
        or not isinstance(value["healthUrl"], str)
        or not isinstance(environment, dict)
        or any(
            not isinstance(name, str) or not isinstance(item, str)
            for name, item in environment.items()
        )
    ):
        raise OAuthLaunchError("launcher runtime config is invalid")
    try:
        return RuntimeSpec.create(
            name=role,
            command=cast(list[str], command),
            cwd=Path(value["cwd"]),
            health_url=value["healthUrl"],
            environment=cast(dict[str, str], environment),
        )
    except mail.LaunchError as exc:
        raise OAuthLaunchError("launcher runtime config was refused") from exc


def _preflight_fixture(
    adapter: Any, environment: Mapping[str, str], *, provider: str = "google"
) -> None:
    from urllib import parse

    try:
        expected: dict[str, object] = {
            "status": "ok",
            "database": parse.urlsplit(
                environment["CONTRACT_DATABASE_URL"]
            ).path.lstrip("/"),
            "redisDatabase": int(
                parse.urlsplit(environment["CONTRACT_REDIS_URL"]).path.lstrip("/")
            ),
            "mailMode": environment["CONTRACT_SERVER_MAIL_MODE"],
            f"{provider}IdentitySchema": f"prisma-{provider}-compatible",
        }
    except (KeyError, ValueError) as exc:
        raise OAuthLaunchError(
            "OAuth fixture preflight configuration is invalid"
        ) from exc
    if environment.get("CONTRACT_FASTAPI_RUNTIME") == "1":
        expected.update(runtime="fastapi", schema="prisma-compatible")
    if adapter.invoke("preflight", f"{provider}-oauth-user") != expected:
        raise OAuthLaunchError("OAuth fixture preflight result did not match")


def _validate_launch_policy(
    config: dict[str, Any], *, provider: str = "google"
) -> None:
    policy = _load(
        "private_oauth_launch_policy",
        Path(__file__).with_name("oauth_launch_policy.py"),
    )
    try:
        policy.validate_launch_config(config, provider=provider)
    except (ValueError, OSError) as exc:
        raise OAuthLaunchError(
            "OAuth launch configuration was refused by pre-spawn policy"
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--provider", choices=("google", "naver", "kakao"), default="google"
    )
    args = parser.parse_args(argv)
    try:
        config = _load_config(args.config)
        fields = {
            "version",
            "runId",
            "producerRole",
            "consumerRole",
            "expectedIssuer",
            "producer",
            "consumer",
            "fixtureAdapter",
            "fixtureEnvironment",
        }
        if set(config) != fields or config["version"] != 1:
            raise OAuthLaunchError("launcher config fields are not exact")
        strings = (
            "runId",
            "producerRole",
            "consumerRole",
            "expectedIssuer",
            "fixtureAdapter",
        )
        if any(
            not isinstance(config[name], str) or not config[name] for name in strings
        ):
            raise OAuthLaunchError("launcher config string fields are invalid")
        fixture_environment = config["fixtureEnvironment"]
        if not isinstance(fixture_environment, dict) or any(
            not isinstance(name, str) or not isinstance(value, str)
            for name, value in fixture_environment.items()
        ):
            raise OAuthLaunchError("launcher fixture environment is invalid")
        _validate_launch_policy(config, provider=args.provider)
        producer_role = cast(str, config["producerRole"])
        consumer_role = cast(str, config["consumerRole"])
        producer = _runtime_from_config(config["producer"], producer_role)
        consumer = _runtime_from_config(config["consumer"], consumer_role)
        oauth_module = _load(
            "private_owned_oauth_google_flow",
            Path(__file__).with_name("oauth_google_flow.py"),
        )
        base_adapter = oauth_module.FixtureAdapter(
            Path(cast(str, config["fixtureAdapter"])),
            cast(dict[str, str], fixture_environment),
        )
        _preflight_fixture(
            base_adapter,
            cast(dict[str, str], fixture_environment),
            provider=args.provider,
        )
        with PrivateOAuthFlowLauncher(
            run_id=cast(str, config["runId"]),
            producer_role=producer_role,
            producer=producer,
            consumer_role=consumer_role,
            consumer=consumer,
            provider=args.provider,
        ) as launcher:
            adapter = OwnedOAuthFixtureAdapter(base_adapter, launcher)
            origins = launcher.origins
            result = oauth_module.run_provider_flow(
                origins[producer_role],
                origins[consumer_role],
                adapter,
                producer=producer_role,
                consumer=consumer_role,
                expected_issuer=cast(str, config["expectedIssuer"]),
                provider=args.provider,
            )
    except (OAuthLaunchError, OSError, RuntimeError) as exc:
        error = (
            str(exc)
            if isinstance(exc, (OAuthLaunchError, RuntimeError))
            else "oauth-launcher-local-io-failure"
        )
        print(json.dumps({"passed": False, "qualifying": False, "error": error}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
