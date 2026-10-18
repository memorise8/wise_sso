#!/usr/bin/env python3
"""Run a bounded, non-qualifying synthetic PostgreSQL backup/restore exercise.

This collector deliberately cannot mint Phase 7 qualification evidence.  It is
the backend-execution half of R01: it owns two randomly named loopback test
databases, applies the checked-in Prisma migrations, loads four synthetic
sentinels, invokes pg_dump/pg_restore, encrypts the custom dump with an
ephemeral AES-256-GCM key, compares every auth table, and cleans up what it
created.  D1 isolation/authentication and D4 recovery policy are still required
before a separate controller may treat a run as qualifying.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SCHEMA_VERSION = 1
COLLECTOR_VERSION = "0.1.0"
MAX_DUMP_BYTES = 67_108_864
MAX_COMMAND_OUTPUT_BYTES = 8_388_608
MAX_PRIVATE_JSON_BYTES = 1_048_576
TEST_DATABASE = re.compile(r"^[a-z][a-z0-9_]{2,62}_test_[a-z0-9_]{1,24}$")
SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SAFE_TOOL_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")
FORBIDDEN_DATABASE_WORD = re.compile(r"(?:^|_)(?:prod|production|live|primary)(?:_|$)")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TABLES = (
    "User",
    "PasswordCredential",
    "PendingPasswordCredential",
    "SubjectReservation",
    "SocialAccount",
    "RefreshToken",
    "EmailVerificationToken",
    "PasswordResetToken",
    "AuditLog",
    "Role",
    "UserRole",
)
ALLOWED_ENVIRONMENT = {"PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGSSLMODE"}
REQUIRED_TOOLS = {"createdb", "dropdb", "pg_dump", "pg_restore", "psql"}
MIGRATION_ROOT = Path(__file__).resolve().parents[3] / "auth-server" / "prisma" / "migrations"
FIXTURE_MANIFEST = (
    Path(__file__).with_name("backup_restore") / "backup-restore-fixture-manifest.json"
)


class CollectorError(RuntimeError):
    """The bounded exercise could not produce trustworthy development evidence."""


class AmbiguousCreate(CollectorError):
    """A random candidate exists, but exclusive-create ownership was not confirmed."""

    def __init__(self, database: str) -> None:
        self.candidates = (database,)
        super().__init__(f"database ownership is unresolved: {database}")


@dataclass(frozen=True)
class Tool:
    name: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes


class Runner(Protocol):
    def run(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        stdin: bytes | None = None,
        timeout: int = 120,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Exact-argv command runner; no shell or ambient startup environment."""

    def run(
        self,
        argv: list[str],
        *,
        environment: dict[str, str],
        stdin: bytes | None = None,
        timeout: int = 120,
    ) -> CommandResult:
        with tempfile.TemporaryFile() as standard_input:
            if stdin is not None:
                standard_input.write(stdin)
                standard_input.seek(0)
            process = subprocess.Popen(  # noqa: S603 - pinned absolute executable, exact argv
                argv,
                stdin=standard_input if stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=True,
            )
            try:
                stdout, stderr = self._bounded_output(process, timeout)
            except BaseException:
                self._kill_group(process)
                raise
        if process.returncode != 0:
            raise CollectorError(f"backend command failed: {Path(argv[0]).name}")
        return CommandResult(stdout=stdout, stderr=stderr)

    @staticmethod
    def _kill_group(process: subprocess.Popen[bytes]) -> None:
        # Before wait/reap, the leader PID still pins the process-group id even
        # if the direct child has exited. After wait, never risk a reused PGID.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    @classmethod
    def _bounded_output(cls, process: subprocess.Popen[bytes], timeout: int) -> tuple[bytes, bytes]:
        if process.stdout is None or process.stderr is None:
            raise CollectorError("backend output pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CollectorError("backend command timed out")
                for key, _ in selector.select(min(remaining, 0.25)):
                    block = os.read(key.fd, 65_536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    output = buffers[str(key.data)]
                    if len(output) + len(block) > MAX_COMMAND_OUTPUT_BYTES:
                        raise CollectorError("backend command output exceeded limit")
                    output.extend(block)
        finally:
            selector.close()
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def encrypt_dump(source: Path, destination: Path, key: bytes, associated_data: bytes) -> None:
    nonce = os.urandom(12)
    destination.write_bytes(
        nonce + AESGCM(key).encrypt(nonce, source.read_bytes(), associated_data)
    )
    os.chmod(destination, 0o600)


def decrypt_dump(source: Path, destination: Path, key: bytes, associated_data: bytes) -> None:
    encrypted = source.read_bytes()
    if len(encrypted) <= 28:
        raise CollectorError("encrypted artifact is truncated")
    try:
        plaintext = AESGCM(key).decrypt(encrypted[:12], encrypted[12:], associated_data)
    except InvalidTag as exc:
        if destination.exists():
            destination.unlink()
        raise CollectorError("encrypted artifact authentication failed") from exc
    destination.write_bytes(plaintext)
    os.chmod(destination, 0o600)


def private_json(file_path: Path) -> dict[str, Any]:
    parent = file_path.parent
    if (
        not file_path.is_absolute()
        or not parent.is_dir()
        or parent.is_symlink()
        or parent.resolve() != parent
        or parent.stat().st_uid != os.getuid()
        or stat.S_IMODE(parent.stat().st_mode) != 0o700
    ):
        raise CollectorError("request and environment must be owned private files")
    try:
        descriptor = os.open(file_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_PRIVATE_JSON_BYTES
            ):
                raise CollectorError("request and environment must be owned private files")
            raw = os.read(descriptor, MAX_PRIVATE_JSON_BYTES + 1)
            if len(raw) > MAX_PRIVATE_JSON_BYTES or os.read(descriptor, 1):
                raise CollectorError("private JSON exceeds size limit")
        finally:
            os.close(descriptor)
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("private JSON is unreadable") from exc
    if not isinstance(value, dict):
        raise CollectorError("private JSON must be an object")
    return value


def regular_owned_file(file_path: Path, expected_hash: str | None = None) -> None:
    if (
        not file_path.is_absolute()
        or not file_path.is_file()
        or file_path.is_symlink()
        or file_path.stat().st_nlink != 1
        or file_path.stat().st_uid not in {0, os.getuid()}
        or stat.S_IMODE(file_path.stat().st_mode) & 0o022
    ):
        raise CollectorError("executable or migration is not an owned immutable regular file")
    if expected_hash is not None and sha256_file(file_path) != expected_hash:
        raise CollectorError("executable digest mismatch")


def load_tools(value: object) -> dict[str, Tool]:
    if not isinstance(value, dict) or set(value) != REQUIRED_TOOLS:
        raise CollectorError("exact PostgreSQL tool set is required")
    tools: dict[str, Tool] = {}
    for name, raw in value.items():
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256"}:
            raise CollectorError("tool entry fields are invalid")
        raw_path, digest = raw["path"], raw["sha256"]
        if (
            not isinstance(raw_path, str)
            or not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
        ):
            raise CollectorError("tool entry is invalid")
        executable = Path(raw_path)
        regular_owned_file(executable, digest)
        tools[name] = Tool(name=name, path=executable, sha256=digest)
    return tools


def load_environment(file_path: Path) -> dict[str, str]:
    value = private_json(file_path)
    if set(value) - ALLOWED_ENVIRONMENT or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise CollectorError("PostgreSQL environment contains unsupported values")
    environment = {str(key): str(item) for key, item in value.items()}
    if environment.get("PGHOST") not in {"127.0.0.1", "::1"}:
        raise CollectorError("only an explicit loopback PostgreSQL backend is allowed")
    port = environment.get("PGPORT", "")
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise CollectorError("PostgreSQL port is invalid")
    if not environment.get("PGUSER"):
        raise CollectorError("PostgreSQL user is required")
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", **environment}


def validate_request(value: object) -> tuple[str, dict[str, Tool], Path]:
    if not isinstance(value, dict) or set(value) != {
        "schemaVersion",
        "runId",
        "tools",
        "environmentFile",
    }:
        raise CollectorError("collector request fields are invalid")
    run_id = value["runId"]
    environment_file = value["environmentFile"]
    if value["schemaVersion"] != SCHEMA_VERSION or not isinstance(run_id, str):
        raise CollectorError("collector request identity is invalid")
    if SAFE_RUN_ID.fullmatch(run_id) is None:
        raise CollectorError("run id is unsafe")
    if not isinstance(environment_file, str):
        raise CollectorError("environment file path is invalid")
    return run_id, load_tools(value["tools"]), Path(environment_file)


def database_names(run_id: str, random_suffix: str) -> tuple[str, str]:
    stem = re.sub(r"[^a-z0-9]", "_", run_id)[:16].strip("_") or "run"
    suffix = random_suffix.lower()
    if not re.fullmatch(r"[0-9a-f]{24}", suffix):
        raise CollectorError("database suffix is invalid")
    source = f"wiseacct_{stem}_{suffix}_test_source"
    restore = f"wiseacct_{stem}_{suffix}_test_restore"
    for name in (source, restore):
        if TEST_DATABASE.fullmatch(name) is None or FORBIDDEN_DATABASE_WORD.search(name):
            raise CollectorError("generated database name is unsafe")
    return source, restore


def run_command(
    runner: Runner,
    tool: Tool,
    arguments: list[str],
    environment: dict[str, str],
    *,
    stdin: bytes | None = None,
) -> CommandResult:
    return runner.run([str(tool.path), *arguments], environment=environment, stdin=stdin)


def postgres_version(runner: Runner, tool: Tool, environment: dict[str, str]) -> str:
    output = run_command(runner, tool, ["--version"], environment).stdout.decode("ascii", "strict")
    match = re.search(r"([0-9]+(?:\.[0-9]+){0,2})", output)
    if match is None or SAFE_TOOL_VERSION.fullmatch(match.group(1)) is None:
        raise CollectorError("PostgreSQL tool version is unavailable")
    return match.group(1)


def migration_files() -> list[Path]:
    migrations = sorted(MIGRATION_ROOT.glob("*/migration.sql"))
    if not migrations:
        raise CollectorError("checked-in Prisma migrations are missing")
    for migration in migrations:
        regular_owned_file(migration.resolve())
    return [migration.resolve() for migration in migrations]


def seed_sql() -> bytes:
    # Fixed synthetic values only. Password/token hashes are deliberately inert test strings.
    statements = (
        "BEGIN;",
        'INSERT INTO "User" '
        '("id","email","emailVerified","name","status","createdAt","updatedAt") VALUES '
        "('phase7-user-0001','phase7-user.invalid@example.invalid',TRUE,"
        "'Phase 7 Synthetic','ACTIVE','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');",
        'INSERT INTO "PasswordCredential" '
        '("id","userId","email","passwordHash","failedLoginCount",'
        '"passwordUpdatedAt","createdAt","updatedAt") VALUES '
        "('phase7-credential-0001','phase7-user-0001',"
        "'phase7-user.invalid@example.invalid','synthetic-not-a-real-password-hash',0,"
        "'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');",
        'INSERT INTO "Role" ("id","serviceKey","name") VALUES '
        "('phase7-role-0001','phase7-synthetic','reader');",
        'INSERT INTO "UserRole" ("id","userId","roleId") VALUES '
        "('phase7-user-role-0001','phase7-user-0001','phase7-role-0001');",
        'INSERT INTO "RefreshToken" '
        '("id","tokenHash","userId","audience","expiresAt","createdAt") VALUES '
        "('phase7-session-0001','synthetic-not-a-real-token-hash','phase7-user-0001',"
        "'temis','2027-01-01T00:00:00Z','2026-01-01T00:00:00Z');",
        "COMMIT;",
    )
    return ("\n".join(statements) + "\n").encode()


def psql(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
    *,
    command: str | None = None,
    file_path: Path | None = None,
    stdin: bytes | None = None,
) -> bytes:
    arguments = ["--no-psqlrc", "--set=ON_ERROR_STOP=1", "--dbname", database]
    if command is not None:
        arguments.extend(["--tuples-only", "--no-align", "--quiet", "--command", command])
    if file_path is not None:
        arguments.extend(["--file", str(file_path)])
    return run_command(runner, tools["psql"], arguments, environment, stdin=stdin).stdout


def database_exists(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
) -> bool:
    if TEST_DATABASE.fullmatch(database) is None:
        raise CollectorError("database candidate name is unsafe")
    query = f"SELECT 1 FROM pg_database WHERE datname = '{database}'"  # noqa: S608
    result = psql(runner, tools, environment, "postgres", command=query).strip()
    if result not in {b"", b"1"}:
        raise CollectorError("database existence check returned unexpected output")
    return result == b"1"


def create_owned_database(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
    owned_databases: set[str],
) -> None:
    if database_exists(runner, tools, environment, database):
        raise CollectorError("random database candidate already exists")
    try:
        run_command(runner, tools["createdb"], [database], environment)
        owned_databases.add(database)
    except BaseException as exc:
        # A transport timeout can occur after the server commits CREATE DATABASE.
        # The unannounced random name was proven absent immediately before this
        # single create attempt, so treat it as a pending collector candidate.
        try:
            candidate_exists = database_exists(runner, tools, environment, database)
        except BaseException as probe_exc:
            raise AmbiguousCreate(database) from probe_exc
        if candidate_exists:
            try:
                run_command(runner, tools["dropdb"], ["--if-exists", database], environment)
            except BaseException as cleanup_exc:
                raise AmbiguousCreate(database) from cleanup_exc
            try:
                candidate_remains = database_exists(runner, tools, environment, database)
            except BaseException as probe_exc:
                raise AmbiguousCreate(database) from probe_exc
            if candidate_remains:
                raise AmbiguousCreate(database) from exc
        raise


def table_rows(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
    table: str,
) -> list[bytes]:
    query = (
        f'COPY (SELECT row_to_json(t)::text FROM "{table}" AS t '  # noqa: S608
        "ORDER BY row_to_json(t)::text) TO STDOUT"
    )
    output = psql(runner, tools, environment, database, command=query)
    return [line for line in output.splitlines() if line]


def snapshot_database(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
) -> dict[str, dict[str, object]]:
    snapshot: dict[str, dict[str, object]] = {}
    for table in TABLES:
        rows = table_rows(runner, tools, environment, database, table)
        snapshot[table] = {"count": len(rows), "digest": sha256_bytes(b"\n".join(rows) + b"\n")}
    return snapshot


def schema_digest(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    database: str,
    destination: Path,
) -> str:
    run_command(
        runner,
        tools["pg_dump"],
        [
            "--schema-only",
            "--no-owner",
            "--no-privileges",
            "--file",
            str(destination),
            "--dbname",
            database,
        ],
        environment,
    )
    regular_owned_file(destination.resolve())
    if destination.stat().st_size > MAX_DUMP_BYTES:
        raise CollectorError("schema catalog output exceeded limit")
    # PostgreSQL 17 adds random psql \restrict tokens to otherwise identical
    # schema dumps. Comments and those client-only guards are not catalog state.
    normalized = b"\n".join(
        line
        for line in destination.read_bytes().splitlines()
        if not line.startswith((b"--", b"\\restrict ", b"\\unrestrict "))
    )
    return sha256_bytes(normalized + b"\n")


def fixture_sentinels() -> tuple[str, dict[str, dict[str, object]]]:
    raw = FIXTURE_MANIFEST.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict) or set(document) != {
        "schemaVersion",
        "fixtureId",
        "sentinels",
    }:
        raise CollectorError("fixture manifest is invalid")
    sentinels: dict[str, dict[str, object]] = {}
    items = document["sentinels"]
    if not isinstance(items, list) or len(items) != 4:
        raise CollectorError("fixture sentinel set is invalid")
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "table",
            "recordId",
            "count",
            "digest",
        }:
            raise CollectorError("fixture sentinel is invalid")
        identifier, table, record_id = item["id"], item["table"], item["recordId"]
        if not all(isinstance(part, str) for part in (identifier, table, record_id)):
            raise CollectorError("fixture sentinel identity is invalid")
        expected = sha256_bytes(canonical({"table": table, "recordId": record_id}))
        if item["count"] != 1 or item["digest"] != expected or table not in TABLES:
            raise CollectorError("fixture sentinel contract is invalid")
        sentinels[str(identifier)] = item
    return sha256_bytes(raw), sentinels


def verify_snapshots(
    source: dict[str, dict[str, object]], restore: dict[str, dict[str, object]]
) -> list[dict[str, object]]:
    if set(source) != set(TABLES) or source != restore:
        raise CollectorError("restored table state differs from source")
    return [
        {
            "table": table,
            "sourceCount": source[table]["count"],
            "restoreCount": restore[table]["count"],
            "sourceDigest": source[table]["digest"],
            "restoreDigest": restore[table]["digest"],
        }
        for table in TABLES
    ]


def verify_sentinels(
    runner: Runner,
    tools: dict[str, Tool],
    environment: dict[str, str],
    source_database: str,
    restore_database: str,
    sentinels: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    proofs: list[dict[str, object]] = []
    for identifier in sorted(sentinels):
        item = sentinels[identifier]
        table, record_id = str(item["table"]), str(item["recordId"])
        if re.fullmatch(r"[A-Za-z0-9-]{1,64}", record_id) is None:
            raise CollectorError("fixture record id is unsafe")
        query = (
            f'COPY (SELECT row_to_json(t)::text FROM "{table}" AS t '  # noqa: S608
            f"WHERE t.\"id\" = '{record_id}') TO STDOUT"
        )
        source_rows = [
            line
            for line in psql(
                runner, tools, environment, source_database, command=query
            ).splitlines()
            if line
        ]
        restore_rows = [
            line
            for line in psql(
                runner, tools, environment, restore_database, command=query
            ).splitlines()
            if line
        ]
        if len(source_rows) != 1 or source_rows != restore_rows:
            raise CollectorError("sentinel row is missing or changed")
        digest = str(item["digest"])
        proofs.append(
            {
                "id": identifier,
                "table": table,
                "sourceCount": 1,
                "restoreCount": 1,
                "sourceDigest": digest,
                "restoreDigest": digest,
            }
        )
    return proofs


def iso(now: dt.datetime) -> str:
    return now.astimezone(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def collect(
    request: dict[str, Any],
    *,
    runner: Runner,
    random_suffix: str | None = None,
) -> dict[str, object]:
    """Execute the exercise and return redacted development-only evidence."""
    run_id, tools, environment_file = validate_request(request)
    environment = load_environment(environment_file)
    source_database, restore_database = database_names(
        run_id, random_suffix if random_suffix is not None else secrets.token_hex(12)
    )
    versions = {
        name: postgres_version(runner, tools[name], environment)
        for name in ("pg_dump", "pg_restore")
    }
    fixture_hash, sentinels = fixture_sentinels()
    owned_databases: set[str] = set()
    artifact_removed = False
    plaintext_removed = False
    source_dropped = False
    restore_dropped = False
    report: dict[str, object] | None = None
    cleanup_errors: list[str] = []
    primary_error: BaseException | None = None
    started = dt.datetime.now(dt.UTC)
    with tempfile.TemporaryDirectory(prefix="wiseacct-phase7-backup-restore.") as temporary:
        private_root = Path(temporary)
        os.chmod(private_root, 0o700)
        dump_path = private_root / "source.dump"
        ciphertext_path = private_root / "source.dump.aes256gcm"
        restore_input = private_root / "restore.dump"
        source_schema = private_root / "source.schema.sql"
        restore_schema = private_root / "restore.schema.sql"
        try:
            # createdb is exclusive by default. Ownership is recorded only after success.
            create_owned_database(runner, tools, environment, source_database, owned_databases)
            for migration in migration_files():
                psql(runner, tools, environment, source_database, file_path=migration)
            psql(runner, tools, environment, source_database, stdin=seed_sql())
            source_snapshot = snapshot_database(runner, tools, environment, source_database)
            source_schema_hash = schema_digest(
                runner, tools, environment, source_database, source_schema
            )

            backup_started = dt.datetime.now(dt.UTC)
            backup_clock = time.monotonic_ns()
            run_command(
                runner,
                tools["pg_dump"],
                [
                    "--format=custom",
                    "--no-owner",
                    "--no-privileges",
                    "--file",
                    str(dump_path),
                    "--dbname",
                    source_database,
                ],
                environment,
            )
            backup_elapsed = (time.monotonic_ns() - backup_clock) // 1_000_000
            backup_ended = dt.datetime.now(dt.UTC)
            regular_owned_file(dump_path.resolve())
            dump_size = dump_path.stat().st_size
            if not 0 < dump_size <= MAX_DUMP_BYTES:
                raise CollectorError("custom dump size is invalid")
            plaintext_hash = sha256_file(dump_path)
            key = AESGCM.generate_key(bit_length=256)
            encrypt_dump(dump_path, ciphertext_path, key, run_id.encode())
            ciphertext_hash = sha256_file(ciphertext_path)
            ciphertext_size = ciphertext_path.stat().st_size
            dump_path.unlink()
            plaintext_removed = True
            decrypt_dump(ciphertext_path, restore_input, key, run_id.encode())
            key = b""  # Drop the only Python reference before invoking pg_restore.
            if sha256_file(restore_input) != plaintext_hash:
                raise CollectorError("decrypted restore input differs from dump")

            create_owned_database(runner, tools, environment, restore_database, owned_databases)
            restore_started = dt.datetime.now(dt.UTC)
            restore_clock = time.monotonic_ns()
            run_command(
                runner,
                tools["pg_restore"],
                [
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                    "--dbname",
                    restore_database,
                    str(restore_input),
                ],
                environment,
            )
            restore_elapsed = (time.monotonic_ns() - restore_clock) // 1_000_000
            restore_ended = dt.datetime.now(dt.UTC)
            restore_input.unlink()
            plaintext_removed = True
            restore_snapshot = snapshot_database(runner, tools, environment, restore_database)
            restore_schema_hash = schema_digest(
                runner, tools, environment, restore_database, restore_schema
            )
            if source_schema_hash != restore_schema_hash:
                raise CollectorError("restored schema catalog differs from source")
            rows = verify_snapshots(source_snapshot, restore_snapshot)
            sentinel_proofs = verify_sentinels(
                runner,
                tools,
                environment,
                source_database,
                restore_database,
                sentinels,
            )
            core_hash = sha256_bytes(canonical(rows))
            ciphertext_path.unlink()
            artifact_removed = True
            report = {
                "schemaVersion": SCHEMA_VERSION,
                "collector": {
                    "identity": "backup-restore-development",
                    "version": COLLECTOR_VERSION,
                },
                "runId": run_id,
                "status": "DEVELOPMENT_EXERCISE_COMPLETE",
                "qualificationEvidence": False,
                "reasonCodes": [
                    "D1_ISOLATION_UNVERIFIED",
                    "D4_POLICY_UNFROZEN",
                    "CONSUMER_NOT_CONNECTED",
                ],
                "databases": {
                    "source": source_database,
                    "restore": restore_database,
                    "collectorCreated": True,
                },
                "tools": {
                    "pgDump": {
                        "version": versions["pg_dump"],
                        "executableSha256": tools["pg_dump"].sha256,
                    },
                    "pgRestore": {
                        "version": versions["pg_restore"],
                        "executableSha256": tools["pg_restore"].sha256,
                    },
                },
                "encryptedArtifact": {
                    "algorithm": "AES-256-GCM",
                    "ciphertextSha256": ciphertext_hash,
                    "ciphertextSizeBytes": ciphertext_size,
                    "plaintextDumpSha256": plaintext_hash,
                    "plaintextDumpSizeBytes": dump_size,
                    "rawKeyPresent": False,
                    "published": False,
                    "retained": False,
                },
                "timing": {
                    "startedAt": iso(started),
                    "backupStartedAt": iso(backup_started),
                    "backupEndedAt": iso(backup_ended),
                    "backupDurationMs": int(backup_elapsed),
                    "restoreStartedAt": iso(restore_started),
                    "restoreEndedAt": iso(restore_ended),
                    "restoreDurationMs": int(restore_elapsed),
                    "rpoSeconds": None,
                    "rtoSeconds": None,
                },
                "verification": {
                    "fixtureManifestSha256": fixture_hash,
                    "schemaCatalog": {
                        "sourceSha256": source_schema_hash,
                        "restoreSha256": restore_schema_hash,
                    },
                    "rowCounts": rows,
                    "sentinels": sentinel_proofs,
                    "coreAuthState": {"sourceSha256": core_hash, "restoreSha256": core_hash},
                },
            }
        except BaseException as exc:
            primary_error = exc
        finally:
            for candidate in (
                dump_path,
                restore_input,
                ciphertext_path,
                source_schema,
                restore_schema,
            ):
                if candidate.exists() and candidate.is_file() and not candidate.is_symlink():
                    try:
                        candidate.unlink()
                    except BaseException:
                        cleanup_errors.append(f"private-file-remove-failed:{candidate.name}")
            plaintext_removed = not dump_path.exists() and not restore_input.exists()
            artifact_removed = not ciphertext_path.exists()
            if restore_database in owned_databases:
                try:
                    run_command(
                        runner, tools["dropdb"], ["--if-exists", restore_database], environment
                    )
                    if database_exists(runner, tools, environment, restore_database):
                        cleanup_errors.append("restore-database-still-present")
                    else:
                        restore_dropped = True
                except BaseException:
                    cleanup_errors.append("restore-database-drop-failed")
            if source_database in owned_databases:
                try:
                    run_command(
                        runner, tools["dropdb"], ["--if-exists", source_database], environment
                    )
                    if database_exists(runner, tools, environment, source_database):
                        cleanup_errors.append("source-database-still-present")
                    else:
                        source_dropped = True
                except BaseException:
                    cleanup_errors.append("source-database-drop-failed")
    if cleanup_errors:
        raise CollectorError(
            f"collector cleanup failed: {','.join(cleanup_errors)}"
        ) from primary_error
    if primary_error is not None:
        raise primary_error
    if report is None:
        raise CollectorError("collector did not complete")
    candidate_inventory = [
        database
        for database, dropped in (
            (source_database, source_dropped),
            (restore_database, restore_dropped),
        )
        if database in owned_databases and not dropped
    ]
    if candidate_inventory:
        raise CollectorError("collector cleanup observation is incomplete")
    report["cleanup"] = {
        "sourceDatabaseDropped": source_dropped,
        "restoreDatabaseDropped": restore_dropped,
        "artifactRemoved": artifact_removed,
        "plaintextRemoved": plaintext_removed,
        "privateTempRemoved": True,
        "candidateInventory": candidate_inventory,
    }
    return report


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument(
        "--development-local",
        action="store_true",
        help="explicitly run the non-qualifying loopback development backend",
    )
    arguments = parser.parse_args()
    if not arguments.development_local:
        print("collector refused: authenticated D1 backend is not configured", file=sys.stderr)
        return 3
    try:
        request = private_json(arguments.request)
        report = collect(request, runner=SubprocessRunner())
    except (CollectorError, OSError, subprocess.SubprocessError):
        print("collector failed: bounded backup/restore exercise did not complete", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical(report))
    return 3  # Development evidence is intentionally never a qualifying PASS.


if __name__ == "__main__":
    raise SystemExit(main())
