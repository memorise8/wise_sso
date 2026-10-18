from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/phase7/collector_runtime.py"
spec = importlib.util.spec_from_file_location("phase7_collector_runtime_test", MODULE)
assert spec is not None and spec.loader is not None
runtime = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runtime
spec.loader.exec_module(runtime)

DAEMON = """
import os
import signal
import socket
import sys
import time

path = sys.argv[1]
behavior = sys.argv[2]
if behavior == "fork-peer":
    if os.fork() != 0:
        while True:
            time.sleep(1)
if behavior == "escape-session":
    escaped = os.fork()
    if escaped == 0:
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open("escaped.pid", "w", encoding="ascii") as target:
            target.write(str(os.getpid()))
        while True:
            time.sleep(1)
if behavior == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
os.chmod(path, 0o666 if behavior == "unsafe-mode" else 0o600)
server.listen(8)
accepted = 0
while True:
    connection, _ = server.accept()
    connection.close()
    accepted += 1
    if behavior == "exit-after-start" and accepted >= 2:
        time.sleep(0.05)
        raise SystemExit(0)
"""


@pytest.fixture(autouse=True)
def clean_ambient(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in runtime._FORBIDDEN_AMBIENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def runtime_inputs(
    tmp_path: Path,
) -> Iterator[tuple[Path, Path, Path, Callable[..., Any]]]:
    xdg_root = Path(tempfile.mkdtemp(prefix="p7x-"))
    xdg_root.chmod(0o700)
    executable = Path(sys.executable).resolve()
    exec_root = executable.parent
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    def policy(
        *,
        behavior: str = "normal",
        backend: str = runtime.DEVELOPMENT_BACKEND,
        digest_override: str | None = None,
        startup: float = 2.0,
        maximum: float = 10.0,
        drain: float = 0.2,
        executable_override: Path | None = None,
        arguments: tuple[str, ...] | None = None,
    ) -> Any:
        return runtime.RuntimePolicy(
            xdg_runtime_root=xdg_root,
            exec_root=exec_root,
            executable=executable_override or executable,
            executable_sha256=digest_override or digest,
            arguments=arguments or ("-c", DAEMON, runtime.DAEMON_SOCKET_ARGUMENT, behavior),
            backend=backend,
            startup_timeout_seconds=startup,
            maximum_runtime_seconds=maximum,
            drain_timeout_seconds=drain,
        )

    try:
        yield xdg_root, exec_root, executable, policy
    finally:
        if xdg_root.exists():
            shutil.rmtree(xdg_root)


def test_real_child_daemon_is_owned_but_never_qualifying(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-be-inherited")
    with runtime.start_runtime(policy()) as owned:
        description = owned.describe()
        pid = description["pid"]
        data_root = owned.data_root
        daemon_socket = owned.daemon_socket
        child_environment = Path(f"/proc/{pid}/environ").read_bytes()

        assert description["status"] == "DEVELOPMENT_ONLY"
        assert description["qualificationEligible"] is False
        assert description["socketPeerPid"] == pid
        assert description["ownedProcessGroup"] == pid
        assert description["ownedSession"] == pid
        assert set(description["namespaceIds"]) == set(runtime._NAMESPACES)
        assert data_root.parent.parent == xdg_root
        assert daemon_socket.parent == data_root.parent
        assert b"AWS_SECRET_ACCESS_KEY" not in child_environment
        assert set(item.split(b"=", 1)[0] for item in child_environment.split(b"\0") if item) == {
            b"HOME",
            b"LANG",
            b"LC_ALL",
            b"TMPDIR",
            b"XDG_RUNTIME_DIR",
        }
        owned.revalidate()

    assert not data_root.parent.exists()
    assert not Path(f"/proc/{pid}").exists()


def test_context_exception_still_drains_and_cleans(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(ValueError, match="consumer"), runtime.start_runtime(policy()) as owned:
        pid = owned.describe()["pid"]
        raise ValueError("consumer")
    assert not Path(f"/proc/{pid}").exists()
    assert list(xdg_root.iterdir()) == []


def test_unrelated_parent_descriptor_is_not_inherited(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]], tmp_path: Path
) -> None:
    _xdg_root, _exec_root, _executable, policy = runtime_inputs
    sentinel = tmp_path / "parent-only-secret"
    sentinel.write_text("not for child", encoding="utf-8")
    with sentinel.open("rb"), runtime.start_runtime(policy()) as owned:
        pid = owned.describe()["pid"]
        targets: list[str] = []
        for descriptor in Path(f"/proc/{pid}/fd").iterdir():
            try:
                targets.append(str(descriptor.resolve(strict=True)))
            except FileNotFoundError:
                continue
        assert str(sentinel) not in targets


def test_escaped_session_is_explicitly_outside_development_proof(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    _xdg_root, _exec_root, _executable, policy = runtime_inputs
    escaped_pid: int | None = None
    owned = runtime.start_runtime(policy(behavior="escape-session"))
    try:
        description = owned.describe()
        pid_file = owned.data_root / "escaped.pid"
        deadline = time.monotonic() + 2.0
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        escaped_pid = int(pid_file.read_text(encoding="ascii"))
        assert os.getpgid(escaped_pid) != description["ownedProcessGroup"]
        assert description["qualificationEligible"] is False
        assert any("escape" in item for item in description["limitations"])
        owned.close()
        os.kill(escaped_pid, 0)
    finally:
        if escaped_pid is not None:
            try:
                os.kill(escaped_pid, 9)
            except ProcessLookupError:
                pass
        try:
            owned.close()
        except runtime.RuntimeRefused:
            pass


def test_runtime_deadline_kills_stubborn_daemon_and_cleans(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    owned = runtime.start_runtime(policy(behavior="ignore-term", maximum=0.05, drain=0.05))
    pid = owned.describe()["pid"]
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:expired"):
        owned.revalidate()
    assert not Path(f"/proc/{pid}").exists()
    assert list(xdg_root.iterdir()) == []


@pytest.mark.parametrize("behavior", ["fork-peer", "unsafe-mode"])
def test_wrong_socket_peer_or_mode_is_refused_and_cleaned(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]], behavior: str
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(runtime.RuntimeRefused, match="runtime:daemon-startup-timeout"):
        runtime.start_runtime(policy(behavior=behavior, startup=0.1))
    assert list(xdg_root.iterdir()) == []


def test_ambient_runtime_context_is_refused_before_start(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    with pytest.raises(runtime.RuntimeRefused, match="runtime:ambient-docker-host"):
        runtime.start_runtime(policy())
    assert list(xdg_root.iterdir()) == []


def test_live_backend_cannot_be_enabled_by_caller_namespace_values(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(runtime.RuntimeRefused, match="runtime:live-backend-not-configured"):
        runtime.start_runtime(policy(backend=runtime.LIVE_BACKEND))
    assert list(xdg_root.iterdir()) == []
    assert "expected_namespaces" not in runtime.RuntimePolicy.__dataclass_fields__


def test_digest_substitution_is_refused_before_start(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(runtime.RuntimeRefused, match="runtime:executable-sha256"):
        runtime.start_runtime(policy(digest_override="0" * 64))
    assert list(xdg_root.iterdir()) == []


def test_executable_outside_reviewed_root_is_refused(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]], tmp_path: Path
) -> None:
    xdg_root, _exec_root, executable, policy = runtime_inputs
    outside = tmp_path / "outside"
    outside.write_bytes(executable.read_bytes())
    outside.chmod(0o500)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:executable-outside-exec-root"):
        runtime.start_runtime(policy(executable_override=outside))
    assert list(xdg_root.iterdir()) == []


def test_private_roots_and_socket_token_are_mandatory(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    xdg_root.chmod(0o755)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:unsafe-xdg-runtime-root"):
        runtime.start_runtime(policy())
    xdg_root.chmod(0o700)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:daemon-socket-argument-required"):
        runtime.start_runtime(policy(arguments=("-c", "pass")))


@pytest.mark.parametrize("maximum", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_deadlines_are_refused_before_start(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]], maximum: float
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(runtime.RuntimeRefused, match="runtime:invalid-maximum-runtime"):
        runtime.start_runtime(policy(maximum=maximum))
    assert list(xdg_root.iterdir()) == []


@pytest.mark.parametrize(
    ("overrides", "label"),
    [
        ({"startup": 1e300}, "startup-timeout"),
        ({"maximum": 1e300}, "maximum-runtime"),
        ({"drain": 1e300}, "drain-timeout"),
    ],
)
def test_unrepresentable_deadlines_are_refused_before_start(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    overrides: dict[str, float],
    label: str,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    with pytest.raises(runtime.RuntimeRefused, match=f"runtime:invalid-{label}"):
        runtime.start_runtime(policy(**overrides))
    assert list(xdg_root.iterdir()) == []


def test_cleanup_failure_is_stable_and_retryable(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _xdg_root, _exec_root, _executable, policy = runtime_inputs
    owned = runtime.start_runtime(policy())
    runtime_root = owned.data_root.parent
    original_cleanup = runtime.CollectorRuntime._cleanup

    def refused_cleanup(self: Any) -> None:
        raise runtime.RuntimeRefused("runtime:injected-cleanup-failure")

    monkeypatch.setattr(runtime.CollectorRuntime, "_cleanup", refused_cleanup)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:injected-cleanup-failure"):
        owned.close()
    with pytest.raises(runtime.RuntimeRefused, match="runtime:injected-cleanup-failure"):
        owned.revalidate()
    with pytest.raises(runtime.RuntimeRefused, match="runtime:injected-cleanup-failure"):
        owned.close()
    assert runtime_root.exists()

    monkeypatch.setattr(runtime.CollectorRuntime, "_cleanup", original_cleanup)
    owned.close()
    assert not runtime_root.exists()


def test_concurrent_close_waits_for_cleanup_and_receives_failure(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _xdg_root, _exec_root, _executable, policy = runtime_inputs
    owned = runtime.start_runtime(policy())
    original_cleanup = runtime.CollectorRuntime._cleanup
    entered = threading.Event()
    release = threading.Event()
    errors: list[str] = []

    def blocked_cleanup(self: Any) -> None:
        entered.set()
        assert release.wait(timeout=2.0)
        raise runtime.RuntimeRefused("runtime:concurrent-cleanup-failure")

    def close_runtime() -> None:
        try:
            owned.close()
        except runtime.RuntimeRefused as exc:
            errors.append(str(exc))

    monkeypatch.setattr(runtime.CollectorRuntime, "_cleanup", blocked_cleanup)
    first = threading.Thread(target=close_runtime)
    second = threading.Thread(target=close_runtime)
    first.start()
    assert entered.wait(timeout=2.0)
    second.start()
    time.sleep(0.02)
    assert second.is_alive()
    release.set()
    first.join(timeout=2.0)
    second.join(timeout=2.0)
    assert errors == ["runtime:concurrent-cleanup-failure"] * 2

    monkeypatch.setattr(runtime.CollectorRuntime, "_cleanup", original_cleanup)
    owned.close()


def test_startup_cleanup_failure_preserves_private_root(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs

    class StuckProcess:
        pid = 987_654_321

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def wait(timeout: float) -> None:
            raise runtime.subprocess.TimeoutExpired(("stuck",), timeout)

    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *args, **kwargs: StuckProcess())
    monkeypatch.setattr(runtime.os, "killpg", lambda process_group, sig: None)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:startup-cleanup-failed"):
        runtime.start_runtime(policy(startup=0.01))
    retained = list(xdg_root.iterdir())
    assert len(retained) == 1
    assert retained[0].stat().st_mode & 0o777 == 0o700


def test_root_replacement_race_never_deletes_replacement(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _xdg_root, _exec_root, _executable, policy = runtime_inputs
    owned = runtime.start_runtime(policy())
    runtime_root = owned.data_root.parent
    moved_root = runtime_root.with_name(f"{runtime_root.name}-moved")
    replacement_saved = runtime_root.with_name(f"{runtime_root.name}-replacement")
    sentinel = runtime_root / "unrelated-sentinel"
    expected_identity = owned._runtime_root_identity
    original_clear = runtime._clear_directory

    def swap_after_fd_bound_clear(descriptor: int) -> None:
        original_clear(descriptor)
        metadata = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino) == expected_identity and not moved_root.exists():
            runtime_root.rename(moved_root)
            runtime_root.mkdir(mode=0o700)
            sentinel.write_text("must survive", encoding="utf-8")

    monkeypatch.setattr(runtime, "_clear_directory", swap_after_fd_bound_clear)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:changed-runtime-root"):
        owned.close()
    assert sentinel.read_text(encoding="utf-8") == "must survive"

    runtime_root.rename(replacement_saved)
    moved_root.rename(runtime_root)
    monkeypatch.setattr(runtime, "_clear_directory", original_clear)
    owned.close()
    assert not runtime_root.exists()
    assert (replacement_saved / "unrelated-sentinel").read_text(encoding="utf-8") == "must survive"
    shutil.rmtree(replacement_saved)


def test_group_signaling_finishes_before_leader_is_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class ExitedProcess:
        pid = 43210

        @staticmethod
        def wait(timeout: float) -> int:
            events.append("wait")
            return 0

    monkeypatch.setattr(runtime, "_wait_for_exit", lambda pidfd, timeout: True)
    monkeypatch.setattr(runtime, "_group_members", lambda process_group, leader: ())
    monkeypatch.setattr(runtime.os, "killpg", lambda process_group, sig: events.append("kill"))
    runtime._terminate_process_group(ExitedProcess(), 99, 0.1)
    assert events[-1] == "wait"
    assert "kill" not in events[events.index("wait") + 1 :]


def test_post_start_exit_is_not_reaped_before_safe_close(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    owned = runtime.start_runtime(policy(behavior="exit-after-start"))
    deadline = time.monotonic() + 2.0
    while runtime._proc_identity(owned._identity.pid).state != "Z" and time.monotonic() < deadline:
        time.sleep(0.01)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:daemon-exited"):
        owned.revalidate()
    owned.close()
    assert list(xdg_root.iterdir()) == []


def test_early_exit_during_startup_is_reaped_and_cleaned(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    arguments = ("-c", "raise SystemExit(0)", runtime.DAEMON_SOCKET_ARGUMENT)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:daemon-exited-during-startup"):
        runtime.start_runtime(policy(arguments=arguments))
    assert list(xdg_root.iterdir()) == []


def test_base_exception_after_spawn_still_drains_and_cleans(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    monkeypatch.setattr(
        runtime,
        "_socket_peer",
        lambda path, expected_pid: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    with pytest.raises(KeyboardInterrupt):
        runtime.start_runtime(policy())
    assert list(xdg_root.iterdir()) == []


def test_pidfd_acquisition_failure_still_kills_real_child(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_popen = runtime.subprocess.Popen
    children: list[Any] = []

    def record_popen(*args: Any, **kwargs: Any) -> Any:
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    def fail_pidfd(pid: int, flags: int) -> int:
        raise OSError("injected pidfd failure")

    monkeypatch.setattr(runtime.subprocess, "Popen", record_popen)
    monkeypatch.setattr(runtime.os, "pidfd_open", fail_pidfd)
    with pytest.raises(runtime.RuntimeRefused, match="runtime:pidfd-unavailable"):
        runtime.start_runtime(policy())
    assert len(children) == 1
    assert children[0].returncode is not None
    assert not Path(f"/proc/{children[0].pid}").exists()
    assert list(xdg_root.iterdir()) == []


def test_root_fd_open_failure_leaks_neither_fd_nor_directory(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_open = runtime.os.open
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    def fail_root_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if kwargs.get("dir_fd") is not None and str(path).startswith("phase7-collector-"):
            raise OSError("injected root fd failure")
        return int(original_open(path, flags, *args, **kwargs))

    monkeypatch.setattr(runtime.os, "open", fail_root_open)
    with pytest.raises(OSError, match="injected root fd failure"):
        runtime.start_runtime(policy())
    assert len(list(descriptors.iterdir())) == before
    assert list(xdg_root.iterdir()) == []


def test_data_root_creation_failure_leaks_neither_fd_nor_directory(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_mkdir = runtime.Path.mkdir
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    def fail_data_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
        if path.name == "data":
            raise OSError("injected data mkdir failure")
        original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(runtime.Path, "mkdir", fail_data_mkdir)
    with pytest.raises(OSError, match="injected data mkdir failure"):
        runtime.start_runtime(policy())
    assert len(list(descriptors.iterdir())) == before
    assert list(xdg_root.iterdir()) == []


def test_unexpected_startup_cleanup_failure_closes_fds_and_preserves_root(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_popen = runtime.subprocess.Popen
    original_killpg = runtime.os.killpg
    children: list[Any] = []
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    def record_popen(*args: Any, **kwargs: Any) -> Any:
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    def deny_signal(process_group: int, sig: int) -> None:
        raise PermissionError("injected signal denial")

    monkeypatch.setattr(runtime.subprocess, "Popen", record_popen)
    monkeypatch.setattr(runtime.os, "killpg", deny_signal)
    monkeypatch.setattr(
        runtime,
        "_socket_peer",
        lambda path, expected_pid: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    try:
        with pytest.raises(runtime.RuntimeRefused, match="startup-cleanup-failed:PermissionError"):
            runtime.start_runtime(policy())
        assert len(children) == 1
        assert len(list(descriptors.iterdir())) == before
        assert len(list(xdg_root.iterdir())) == 1
    finally:
        monkeypatch.setattr(runtime.os, "killpg", original_killpg)
        for child in children:
            if child.returncode is None:
                try:
                    original_killpg(child.pid, 9)
                except ProcessLookupError:
                    pass
                child.wait(timeout=2.0)


def test_interruption_after_root_creation_recovers_pending_ownership(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_mkdir = runtime.os.mkdir
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    def create_then_interrupt(path: Any, *args: Any, **kwargs: Any) -> None:
        original_mkdir(path, *args, **kwargs)
        if kwargs.get("dir_fd") is not None and str(path).startswith("phase7-collector-"):
            raise KeyboardInterrupt

    monkeypatch.setattr(runtime.os, "mkdir", create_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        runtime.start_runtime(policy())
    assert len(list(descriptors.iterdir())) == before
    assert list(xdg_root.iterdir()) == []


def test_interruption_after_timer_arm_closes_transferred_runtime(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_popen = runtime.subprocess.Popen
    original_arm = runtime.CollectorRuntime._arm_timeout
    children: list[Any] = []

    def record_popen(*args: Any, **kwargs: Any) -> Any:
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    def arm_then_interrupt(self: Any) -> None:
        original_arm(self)
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime.subprocess, "Popen", record_popen)
    monkeypatch.setattr(runtime.CollectorRuntime, "_arm_timeout", arm_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        runtime.start_runtime(policy(maximum=0.05))
    assert len(children) == 1
    assert children[0].returncode is not None
    assert list(xdg_root.iterdir()) == []
    time.sleep(0.1)
    assert list(xdg_root.iterdir()) == []


def test_interruption_at_result_handoff_has_single_resource_owner(
    runtime_inputs: tuple[Path, Path, Path, Callable[..., Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    xdg_root, _exec_root, _executable, policy = runtime_inputs
    original_popen = runtime.subprocess.Popen
    children: list[Any] = []
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))

    def record_popen(*args: Any, **kwargs: Any) -> Any:
        child = original_popen(*args, **kwargs)
        children.append(child)
        return child

    def interrupt_handoff(self: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(runtime.subprocess, "Popen", record_popen)
    monkeypatch.setattr(runtime.CollectorRuntime, "revalidate", interrupt_handoff)
    with pytest.raises(KeyboardInterrupt):
        runtime.start_runtime(policy())
    assert len(children) == 1
    assert children[0].returncode is not None
    assert len(list(descriptors.iterdir())) == before
    assert list(xdg_root.iterdir()) == []
