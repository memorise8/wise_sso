import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql

from wiseacct_sso.ops.refresh_cleanup import (
    RefreshTokenCleanupOptions,
    _eligible,
    cleanup_refresh_tokens,
    parse_args,
)

ROOT = Path(__file__).parents[2]


class RecordingStore:
    def __init__(self) -> None:
        self.calls: list[tuple[str, datetime]] = []

    async def count_eligible(self, cutoff: datetime) -> int:
        self.calls.append(("count", cutoff))
        return 4

    async def delete_eligible(self, cutoff: datetime) -> int:
        self.calls.append(("delete", cutoff))
        return 3


@pytest.mark.anyio
async def test_refresh_cleanup_executes_by_default_at_30_days() -> None:
    store = RecordingStore()
    result = await cleanup_refresh_tokens(
        store,
        RefreshTokenCleanupOptions(),
        now=datetime(2026, 8, 31, 12, 0, 0),
    )

    assert result.dry_run is False
    assert result.deleted_count == 3
    assert result.cutoff == datetime(2026, 8, 1, 12, 0, 0)
    assert store.calls == [("delete", result.cutoff)]


@pytest.mark.anyio
async def test_refresh_cleanup_dry_run_counts_without_delete() -> None:
    store = RecordingStore()
    result = await cleanup_refresh_tokens(
        store,
        RefreshTokenCleanupOptions(dry_run=True, retention_days=45),
        now=datetime(2026, 8, 31, 12, 0, 0),
    )

    assert result.deleted_count == 4
    assert store.calls == [("count", result.cutoff)]


@pytest.mark.parametrize(("value", "expected"), [("1.0", 1), ("1e2", 100), ("0x10", 16)])
def test_refresh_cli_matches_zod_env_and_argument_coercion(value: str, expected: int) -> None:
    assert (
        parse_args([], {"REFRESH_TOKEN_CLEANUP_RETENTION_DAYS": value}).retention_days == expected
    )
    assert parse_args([f"--retention-days={value}"], {}).retention_days == expected


def test_refresh_cli_defaults_execute_and_argument_overrides_env() -> None:
    assert parse_args([], {}) == RefreshTokenCleanupOptions()
    assert parse_args(
        ["--dry-run", "--retention-days", "60"],
        {"REFRESH_TOKEN_CLEANUP_RETENTION_DAYS": "45"},
    ) == RefreshTokenCleanupOptions(dry_run=True, retention_days=60)


def test_refresh_cleanup_sql_matches_express_expired_or_revoked_predicate() -> None:
    predicate = str(
        _eligible(datetime(2026, 8, 1)).compile(
            dialect=postgresql.dialect(),  # type: ignore[no-untyped-call]
            compile_kwargs={"literal_binds": True},
        )
    )

    assert '"RefreshToken"."expiresAt" <' in predicate
    assert '"RefreshToken"."revokedAt" <' in predicate
    assert " OR " in predicate


def test_refresh_module_execution_is_dormant_and_sanitized() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wiseacct_sso.ops.refresh_cleanup", "--dry-run"],
        cwd=ROOT,
        env={
            "PATH": os.environ["PATH"],
            "PYTHONPATH": str(ROOT / "src"),
            "JWT_REFRESH_SECRET": "must-not-be-read-or-reported",
        },
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "refresh-token-cleanup failed: DATABASE_URL is required\n"
    assert "must-not-be-read-or-reported" not in result.stderr
