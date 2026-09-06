from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RANDOM_SUFFIX = "012345abcdef012345abcdef"
COLLECTOR = ROOT / "ops" / "phase7" / "backup_restore_collector.py"
SPEC = importlib.util.spec_from_file_location("phase7_backup_restore_collector", COLLECTOR)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)


class FakeRunner:
    def __init__(
        self,
        *,
        fail_create: str | None = None,
        corrupt_restore: bool = False,
        fail_drop: str | None = None,
        fail_dump: bool = False,
        preexisting_candidate: bool = False,
        sticky_drop: bool = False,
        fail_reconciliation_probe: str | None = None,
    ) -> None:
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []
        self.created: list[str] = []
        self.dropped: list[str] = []
        self.live_databases: set[str] = set()
        self.fail_create = fail_create
        self.corrupt_restore = corrupt_restore
        self.fail_drop = fail_drop
        self.fail_dump = fail_dump
        self.preexisting_candidate = preexisting_candidate
        self.sticky_drop = sticky_drop
        self.fail_reconciliation_probe = fail_reconciliation_probe
        self.private_paths: list[Path] = []

    def run(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        stdin: bytes | None = None,
        timeout: int = 120,
    ) -> Any:
        del timeout
        self.commands.append(argv.copy())
        self.environments.append(environment.copy())
        name = Path(argv[0]).name
        if argv[1:] == ["--version"]:
            return collector.CommandResult(
                stdout=f"{name} (PostgreSQL) 17.2\n".encode(), stderr=b""
            )
        if name == "createdb":
            database = argv[-1]
            if self.fail_create == "first-after-create" and not self.created:
                self.created.append(database)
                self.live_databases.add(database)
                raise OSError("synthetic ambiguous create transport failure")
            if self.fail_create == "first-after-keyboard" and not self.created:
                self.created.append(database)
                self.live_databases.add(database)
                raise KeyboardInterrupt
            if self.fail_create == "first" and not self.created:
                raise collector.CollectorError("backend command failed: createdb")
            if self.fail_create == "second" and self.created:
                raise collector.CollectorError("backend command failed: createdb")
            self.created.append(database)
            self.live_databases.add(database)
            return collector.CommandResult(stdout=b"", stderr=b"")
        if name == "dropdb":
            self.dropped.append(argv[-1])
            if self.fail_drop == "all":
                raise collector.CollectorError("backend command failed: dropdb")
            if self.fail_drop == "first" and len(self.dropped) == 1:
                raise OSError("synthetic drop transport failure")
            if not self.sticky_drop:
                self.live_databases.discard(argv[-1])
            return collector.CommandResult(stdout=b"", stderr=b"")
        if name == "pg_dump":
            destination = Path(argv[argv.index("--file") + 1])
            self.private_paths.append(destination)
            if "--schema-only" in argv:
                destination.write_bytes(b"CREATE TABLE synthetic ();\n")
            else:
                destination.write_bytes(b"PGDMP\x01synthetic-custom-dump")
            os.chmod(destination, 0o600)
            if self.fail_dump and "--schema-only" not in argv:
                raise collector.CollectorError("backend command failed: pg_dump")
            return collector.CommandResult(stdout=b"", stderr=b"")
        if name == "pg_restore":
            restore_input = Path(argv[-1])
            self.private_paths.append(restore_input)
            assert restore_input.read_bytes() == b"PGDMP\x01synthetic-custom-dump"
            return collector.CommandResult(stdout=b"", stderr=b"")
        if name == "psql":
            if stdin is not None:
                assert b"phase7-user-0001" in stdin
                return collector.CommandResult(stdout=b"", stderr=b"")
            if "--file" in argv:
                return collector.CommandResult(stdout=b"", stderr=b"")
            command = argv[argv.index("--command") + 1]
            database = argv[argv.index("--dbname") + 1]
            if "FROM pg_database" in command:
                candidate = re.search(r"datname = '([a-z0-9_]+)'", command)
                assert candidate is not None
                if (
                    self.fail_reconciliation_probe == "after-create"
                    and self.live_databases
                    and not self.dropped
                ):
                    raise OSError("synthetic post-create probe failure")
                if self.fail_reconciliation_probe == "after-drop" and self.dropped:
                    raise OSError("synthetic post-drop probe failure")
                exists = self.preexisting_candidate or candidate.group(1) in self.live_databases
                return collector.CommandResult(stdout=b"1\n" if exists else b"", stderr=b"")
            table_match = re.search(r'FROM "([A-Za-z]+)"', command)
            assert table_match is not None
            table = table_match.group(1)
            rows = fixture_rows(table)
            if " WHERE " in command:
                id_match = re.search(r"= '([A-Za-z0-9-]+)'", command)
                assert id_match is not None
                rows = [row for row in rows if json.loads(row)["id"] == id_match.group(1)]
            if self.corrupt_restore and database.endswith("_test_restore") and table == "User":
                rows = ['{"id":"changed"}']
            return collector.CommandResult(
                stdout=("\n".join(rows) + ("\n" if rows else "")).encode(), stderr=b""
            )
        raise AssertionError(f"unexpected executable: {name}")


def fixture_rows(table: str) -> list[str]:
    values = {
        "User": ['{"id":"phase7-user-0001","emailVerified":true}'],
        "PasswordCredential": ['{"id":"phase7-credential-0001","userId":"phase7-user-0001"}'],
        "Role": ['{"id":"phase7-role-0001","name":"reader"}'],
        "RefreshToken": ['{"id":"phase7-session-0001","userId":"phase7-user-0001"}'],
        "UserRole": ['{"id":"phase7-user-role-0001","userId":"phase7-user-0001"}'],
    }
    return values.get(table, [])


def private_file(parent: Path, name: str, value: object) -> Path:
    parent.mkdir(mode=0o700)
    file_path = parent / name
    file_path.write_text(json.dumps(value), encoding="utf-8")
    os.chmod(file_path, 0o600)
    return file_path


def request(tmp_path: Path, *, host: str = "127.0.0.1") -> dict[str, object]:
    environment = private_file(
        tmp_path / "private",
        "postgres-environment.json",
        {
            "PGHOST": host,
            "PGPORT": "55432",
            "PGUSER": "phase7_collector",
            "PGPASSWORD": "test-only-secret-never-published",
            "PGSSLMODE": "disable",
        },
    )
    tool_root = tmp_path / "tools"
    tool_root.mkdir(mode=0o700)
    tools: dict[str, dict[str, str]] = {}
    for name in collector.REQUIRED_TOOLS:
        executable = tool_root / name
        executable.write_bytes(f"fake-{name}".encode())
        os.chmod(executable, 0o700)
        tools[name] = {
            "path": str(executable),
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        }
    return {
        "schemaVersion": 1,
        "runId": "r01-unit",
        "tools": tools,
        "environmentFile": str(environment),
    }


def test_collect_invokes_real_backend_shape_and_returns_only_nonqualifying_evidence(
    tmp_path: Path,
) -> None:
    fake = FakeRunner()
    report = collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)

    assert report["status"] == "DEVELOPMENT_EXERCISE_COMPLETE"
    assert report["qualificationEvidence"] is False
    assert report["reasonCodes"] == [
        "D1_ISOLATION_UNVERIFIED",
        "D4_POLICY_UNFROZEN",
        "CONSUMER_NOT_CONNECTED",
    ]
    assert report["cleanup"] == {
        "sourceDatabaseDropped": True,
        "restoreDatabaseDropped": True,
        "artifactRemoved": True,
        "plaintextRemoved": True,
        "privateTempRemoved": True,
        "candidateInventory": [],
    }
    assert len(report["verification"]["rowCounts"]) == 11
    assert len(report["verification"]["sentinels"]) == 4
    artifact = report["encryptedArtifact"]
    assert artifact["algorithm"] == "AES-256-GCM"
    assert artifact["ciphertextSha256"] != artifact["plaintextDumpSha256"]
    assert artifact["rawKeyPresent"] is False
    assert artifact["published"] is False
    assert artifact["retained"] is False
    assert len(fake.created) == 2
    assert fake.dropped == [fake.created[1], fake.created[0]]
    assert all("_test_" in database for database in fake.created)
    assert all(not candidate.exists() for candidate in fake.private_paths)
    serialized = json.dumps(report)
    assert "test-only-secret" not in serialized
    assert all(environment["PGHOST"] == "127.0.0.1" for environment in fake.environments)
    assert any(
        Path(command[0]).name == "pg_dump" and "--format=custom" in command
        for command in fake.commands
    )
    assert any(Path(command[0]).name == "pg_restore" for command in fake.commands)


def test_first_create_failure_never_drops_a_caller_named_database(tmp_path: Path) -> None:
    fake = FakeRunner(fail_create="first")
    with pytest.raises(collector.CollectorError, match="createdb"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.created == []
    assert fake.dropped == []


def test_post_create_transport_failure_removes_the_pending_random_candidate(
    tmp_path: Path,
) -> None:
    fake = FakeRunner(fail_create="first-after-create")
    with pytest.raises(OSError, match="ambiguous create transport"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.dropped == fake.created
    assert fake.live_databases == set()


def test_post_create_keyboard_interrupt_reconciles_candidate_before_reraise(
    tmp_path: Path,
) -> None:
    fake = FakeRunner(fail_create="first-after-keyboard")
    with pytest.raises(KeyboardInterrupt):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.dropped == fake.created
    assert fake.live_databases == set()


def test_pending_candidate_cleanup_failure_surfaces_exact_candidate(tmp_path: Path) -> None:
    fake = FakeRunner(fail_create="first-after-create", fail_drop="all")
    with pytest.raises(collector.AmbiguousCreate) as captured:
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert captured.value.candidates == tuple(fake.created)
    assert fake.live_databases == set(fake.created)


@pytest.mark.parametrize("failure_point", ["after-create", "after-drop"])
def test_reconciliation_probe_failure_surfaces_exact_candidate(
    tmp_path: Path, failure_point: str
) -> None:
    fake = FakeRunner(fail_create="first-after-create", fail_reconciliation_probe=failure_point)
    with pytest.raises(collector.AmbiguousCreate) as captured:
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert captured.value.candidates == tuple(fake.created)
    assert fake.live_databases == (set(fake.created) if failure_point == "after-create" else set())


def test_preexisting_random_candidate_is_never_treated_as_owned(tmp_path: Path) -> None:
    fake = FakeRunner(preexisting_candidate=True)
    with pytest.raises(collector.CollectorError, match="candidate already exists"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.created == []
    assert fake.dropped == []


def test_second_create_failure_drops_only_the_owned_source(tmp_path: Path) -> None:
    fake = FakeRunner(fail_create="second")
    with pytest.raises(collector.CollectorError, match="createdb"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert len(fake.created) == 1
    assert fake.dropped == fake.created


def test_restore_mismatch_fails_closed_and_cleans_both_owned_databases(tmp_path: Path) -> None:
    fake = FakeRunner(corrupt_restore=True)
    with pytest.raises(collector.CollectorError, match="restored table state"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert len(fake.created) == 2
    assert fake.dropped == [fake.created[1], fake.created[0]]
    assert all(not candidate.exists() for candidate in fake.private_paths)


def test_non_loopback_backend_is_refused_before_any_command(tmp_path: Path) -> None:
    fake = FakeRunner()
    with pytest.raises(collector.CollectorError, match="loopback"):
        collector.collect(
            request(tmp_path, host="database.internal"),
            runner=fake,
            random_suffix=RANDOM_SUFFIX,
        )
    assert fake.commands == []


def test_non_private_environment_file_is_refused_before_any_command(tmp_path: Path) -> None:
    raw = request(tmp_path)
    environment_file = Path(str(raw["environmentFile"]))
    os.chmod(environment_file, 0o644)
    fake = FakeRunner()
    with pytest.raises(collector.CollectorError, match="owned private files"):
        collector.collect(raw, runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.commands == []


def test_tool_digest_mismatch_is_refused_before_any_command(tmp_path: Path) -> None:
    raw = request(tmp_path)
    tools = raw["tools"]
    assert isinstance(tools, dict)
    pg_dump = tools["pg_dump"]
    assert isinstance(pg_dump, dict)
    pg_dump["sha256"] = "0" * 64
    fake = FakeRunner()
    with pytest.raises(collector.CollectorError, match="digest mismatch"):
        collector.collect(raw, runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.commands == []


def test_authenticated_encryption_rejects_a_changed_tag_without_plaintext(tmp_path: Path) -> None:
    source = tmp_path / "source.dump"
    encrypted = tmp_path / "source.dump.aes256gcm"
    restored = tmp_path / "restore.dump"
    source.write_bytes(b"PGDMP synthetic")
    key = b"k" * 32
    collector.encrypt_dump(source, encrypted, key, b"r01-test")
    changed = bytearray(encrypted.read_bytes())
    changed[-1] ^= 1
    encrypted.write_bytes(changed)

    with pytest.raises(collector.CollectorError, match="authentication failed"):
        collector.decrypt_dump(encrypted, restored, key, b"r01-test")
    assert not restored.exists()


def test_cleanup_failure_never_returns_a_success_report(tmp_path: Path) -> None:
    fake = FakeRunner(fail_drop="all")
    with pytest.raises(collector.CollectorError, match="cleanup failed"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert len(fake.dropped) == 2


def test_first_cleanup_oserror_does_not_skip_the_second_owned_database(tmp_path: Path) -> None:
    fake = FakeRunner(fail_drop="first")
    with pytest.raises(collector.CollectorError, match="cleanup failed"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert len(fake.created) == 2
    assert fake.dropped == [fake.created[1], fake.created[0]]


def test_successful_drop_without_observed_absence_never_returns_report(tmp_path: Path) -> None:
    fake = FakeRunner(sticky_drop=True)
    with pytest.raises(collector.CollectorError, match="database-still-present"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert fake.dropped == [fake.created[1], fake.created[0]]
    assert fake.live_databases == set(fake.created)


def test_private_file_unlink_failure_does_not_skip_owned_database_cleanup(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = FakeRunner(fail_dump=True)
    original_unlink = collector.Path.unlink

    def fail_dump_unlink(file_path: Path, *args: Any, **kwargs: Any) -> None:
        if file_path.name == "source.dump":
            raise OSError("synthetic unlink failure")
        original_unlink(file_path, *args, **kwargs)

    monkeypatch.setattr(collector.Path, "unlink", fail_dump_unlink)
    with pytest.raises(collector.CollectorError, match=r"private-file-remove-failed:source\.dump"):
        collector.collect(request(tmp_path), runner=fake, random_suffix=RANDOM_SUFFIX)
    assert len(fake.created) == 1
    assert fake.dropped == fake.created


def test_subprocess_runner_bounds_captured_output(tmp_path: Path, monkeypatch: Any) -> None:
    executable = tmp_path / "too-much-output"
    executable.write_text("#!/bin/sh\nprintf '12345678901'\n", encoding="utf-8")
    os.chmod(executable, 0o700)
    monkeypatch.setattr(collector, "MAX_COMMAND_OUTPUT_BYTES", 10)

    with pytest.raises(collector.CollectorError, match="output exceeded limit"):
        collector.SubprocessRunner().run([str(executable)], environment={"PATH": "/usr/bin:/bin"})


def test_subprocess_timeout_kills_the_descendant_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    executable = tmp_path / "spawn-child"
    executable.write_text(
        "#!/usr/bin/python3\n"
        "import pathlib, subprocess, sys\n"
        "child = subprocess.Popen(['/usr/bin/sleep', '30'])\n"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid))\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    os.chmod(executable, 0o700)

    with pytest.raises(collector.CollectorError, match="timed out"):
        collector.SubprocessRunner().run(
            [str(executable), str(pid_file)],
            environment={"PATH": "/usr/bin:/bin"},
            timeout=1,
        )
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    try:
        state = Path(f"/proc/{child_pid}/stat").read_text(encoding="utf-8").split()[2]
    except OSError:
        return
    assert state == "Z"


def test_process_group_cleanup_never_signals_after_the_leader_was_reaped(
    monkeypatch: Any,
) -> None:
    class ReapedProcess:
        returncode = 0
        pid = 12345

        def wait(self) -> int:
            raise AssertionError("reaped process must not be waited again")

    def unexpected_killpg(process_group: int, sent_signal: int) -> None:
        raise AssertionError(f"unexpected killpg({process_group}, {sent_signal})")

    monkeypatch.setattr(collector.os, "killpg", unexpected_killpg)
    collector.SubprocessRunner._kill_group(ReapedProcess())


def test_cli_defaults_to_refusing_an_unauthenticated_backend(tmp_path: Path) -> None:
    completed = subprocess.run(  # noqa: S603 - fixed checked-in collector
        [sys.executable, str(COLLECTOR), "--request", str(tmp_path / "missing.json")],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 3
    assert completed.stdout == b""
    assert completed.stderr == b"collector refused: authenticated D1 backend is not configured\n"
