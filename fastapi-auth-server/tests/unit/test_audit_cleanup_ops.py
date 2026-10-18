import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

import wiseacct_sso.ops.audit_cleanup as audit_cleanup_module
from wiseacct_sso.ops.audit_cleanup import (
    AuditRetentionCleanupOptions,
    _database_url,
    cleanup_audit_logs,
    coerce_positive_js_integer,
    parse_args,
)

ROOT = Path(__file__).parents[2]


class RecordingStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []

    async def count_older_than(self, cutoff: datetime) -> int:
        self.calls.append(("count", cutoff))
        return 7

    async def delete_older_than(self, cutoff: datetime) -> int:
        self.calls.append(("delete", cutoff))
        return 5


@pytest.mark.anyio
async def test_cleanup_defaults_to_180_day_dry_run() -> None:
    store = RecordingStore()
    now = datetime(2026, 8, 31, 12, 0, 0)

    result = await cleanup_audit_logs(store, now=now)

    assert result.dry_run is True
    assert result.retention_days == 180
    assert result.deleted_count == 7
    assert result.cutoff == datetime(2026, 3, 4, 12, 0, 0)
    assert store.calls == [("count", result.cutoff)]


@pytest.mark.anyio
async def test_cleanup_deletes_only_with_explicit_execute() -> None:
    store = RecordingStore()
    now = datetime(2026, 8, 31, 12, 0, 0)

    result = await cleanup_audit_logs(
        store,
        AuditRetentionCleanupOptions(execute=True, retention_days=30),
        now=now,
    )

    assert result.dry_run is False
    assert result.deleted_count == 5
    assert store.calls == [("delete", datetime(2026, 8, 1, 12, 0, 0))]


def test_cli_arguments_match_express_contract() -> None:
    assert parse_args([]) == AuditRetentionCleanupOptions()
    assert parse_args(["--execute", "--retention-days", "45"]) == (
        AuditRetentionCleanupOptions(execute=True, retention_days=45)
    )


def test_ops_reads_only_database_url_and_sanitizes_invalid_values() -> None:
    assert _database_url({"DATABASE_URL": "postgres://user:secret@db/sso"}) == (
        "postgresql+asyncpg://user:secret@db/sso"
    )
    with pytest.raises(ValueError, match="DATABASE_URL is required"):
        _database_url({"JWT_REFRESH_SECRET": "must-not-be-read"})
    with pytest.raises(ValueError, match="must use PostgreSQL") as failure:
        _database_url({"DATABASE_URL": "mysql://user:do-not-report@db/sso"})
    assert "do-not-report" not in str(failure.value)


@pytest.mark.parametrize(("value", "expected"), [("1.0", 1), ("1e2", 100), ("0x10", 16)])
def test_cli_matches_zod_number_coercion(value: str, expected: int) -> None:
    assert coerce_positive_js_integer(value) == expected
    assert parse_args([f"--retention-days={value}"]).retention_days == expected


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "nope"])
def test_cli_rejects_non_positive_integer_retention(value: str) -> None:
    with pytest.raises(ValueError, match="retentionDays must be a positive integer"):
        parse_args(["--retention-days", value])


def test_cli_rejects_missing_retention_value_like_express() -> None:
    with pytest.raises(ValueError, match="--retention-days requires a value"):
        parse_args(["--retention-days", ""])


def test_dormant_cli_reports_only_failure_type(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def fail(_options: AuditRetentionCleanupOptions, *, database_url: str) -> object:
        assert "credential" in database_url
        raise ConnectionError("postgres://credential@private-host/sso")

    monkeypatch.setenv("DATABASE_URL", "postgres://credential@private-host/sso")
    monkeypatch.setattr(audit_cleanup_module, "_run", fail)

    with pytest.raises(SystemExit) as failure:
        audit_cleanup_module.cli([])

    evidence = capsys.readouterr().err
    assert failure.value.code == 1
    assert evidence == "audit-log-cleanup failed: ConnectionError\n"
    assert "credential" not in evidence
    assert "private-host" not in evidence


def test_dormant_module_execution_is_available_and_sanitized() -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "src"),
        "JWT_REFRESH_SECRET": "must-not-be-read-or-reported",
    }

    result = subprocess.run(
        [sys.executable, "-m", "wiseacct_sso.ops.audit_cleanup"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "audit-log-cleanup failed: DATABASE_URL is required\n"
    assert "must-not-be-read-or-reported" not in result.stderr
