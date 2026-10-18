from datetime import datetime
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import ClauseElement, Executable

from wiseacct_sso.persistence.stores import (
    FailedLoginStore,
    RefreshReplacement,
    RefreshRotationConflict,
    RefreshRotationStore,
)

NOW = datetime(2026, 8, 31, 1, 2, 3, 456000)
LOCKED_UNTIL = datetime(2026, 8, 31, 1, 17, 3, 456000)
UPDATED_AT = datetime(2026, 8, 31, 1, 2, 3, 456000)


class FakeResult:
    def __init__(self, row: object | None = None, *, rowcount: int = 0) -> None:
        self._row = row
        self.rowcount = rowcount

    def one_or_none(self) -> object | None:
        return self._row


class FakeConnection:
    def __init__(self, results: list[FakeResult]) -> None:
        self.results = iter(results)
        self.statements: list[Executable] = []

    async def execute(self, statement: Executable) -> FakeResult:
        self.statements.append(statement)
        return next(self.results)


def sql(statement: Executable) -> str:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return " ".join(str(compiled).replace("\n", " ").split())


def params(statement: Executable) -> dict[str, object]:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return cast(dict[str, object], compiled.params)


@pytest.mark.anyio
async def test_failed_login_atomically_increments_then_conditionally_locks() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(failedLoginCount=5), rowcount=1),
            FakeResult(SimpleNamespace(lockedUntil=LOCKED_UNTIL), rowcount=1),
        ]
    )
    result = await FailedLoginStore().record_failure(
        cast(AsyncConnection, connection),
        user_id="user-1",
        locked_until=LOCKED_UNTIL,
        updated_at=UPDATED_AT,
    )

    assert result.found is True
    assert result.failed_login_count == 5
    assert result.locked_until == LOCKED_UNTIL
    increment_sql = sql(connection.statements[0])
    lock_sql = sql(connection.statements[1])
    assert increment_sql.startswith('UPDATE "PasswordCredential" SET "failedLoginCount"=')
    assert '"PasswordCredential"."failedLoginCount" + ' in increment_sql
    assert 'WHERE "PasswordCredential"."userId" =' in increment_sql
    assert 'RETURNING "PasswordCredential"."failedLoginCount"' in increment_sql
    assert '"updatedAt"=' in increment_sql
    assert UPDATED_AT in params(connection.statements[0]).values()
    assert LOCKED_UNTIL not in params(connection.statements[0]).values()
    assert "FOR UPDATE" not in increment_sql
    assert lock_sql.startswith('UPDATE "PasswordCredential" SET "lockedUntil"=')
    assert '"PasswordCredential"."failedLoginCount" >=' in lock_sql
    assert 'RETURNING "PasswordCredential"."lockedUntil"' in lock_sql
    assert '"updatedAt"=' in lock_sql
    assert UPDATED_AT in params(connection.statements[1]).values()
    assert LOCKED_UNTIL in params(connection.statements[1]).values()
    assert "FOR UPDATE" not in lock_sql


@pytest.mark.anyio
async def test_failed_login_preserves_no_lock_below_threshold_and_missing_is_noop() -> None:
    connection = FakeConnection(
        [FakeResult(SimpleNamespace(failedLoginCount=3), rowcount=1), FakeResult(None, rowcount=0)]
    )
    result = await FailedLoginStore().record_failure(
        cast(AsyncConnection, connection),
        user_id="user-1",
        locked_until=LOCKED_UNTIL,
        updated_at=UPDATED_AT,
    )
    assert result.failed_login_count == 3
    assert result.locked_until is None

    missing = FakeConnection([FakeResult(None, rowcount=0)])
    missing_result = await FailedLoginStore().record_failure(
        cast(AsyncConnection, missing),
        user_id="missing",
        locked_until=LOCKED_UNTIL,
        updated_at=UPDATED_AT,
    )
    assert missing_result.found is False
    assert len(missing.statements) == 1


@pytest.mark.anyio
async def test_failed_login_requires_locked_row_to_update_once() -> None:
    connection = FakeConnection([FakeResult(SimpleNamespace(failedLoginCount=1), rowcount=2)])
    with pytest.raises(RuntimeError, match="increment count was not one"):
        await FailedLoginStore().record_failure(
            cast(AsyncConnection, connection),
            user_id="user-1",
            locked_until=LOCKED_UNTIL,
            updated_at=UPDATED_AT,
        )


@pytest.mark.anyio
async def test_failed_login_refreshes_lock_timestamp_after_threshold() -> None:
    later_lock = datetime(2026, 8, 31, 1, 18, 3, 456000)
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(failedLoginCount=6), rowcount=1),
            FakeResult(SimpleNamespace(lockedUntil=later_lock), rowcount=1),
        ]
    )
    result = await FailedLoginStore().record_failure(
        cast(AsyncConnection, connection),
        user_id="user-1",
        locked_until=later_lock,
        updated_at=UPDATED_AT,
    )
    assert result.failed_login_count == 6
    assert result.locked_until == later_lock


@pytest.mark.anyio
async def test_refresh_rotation_has_explicit_read_lock_revoke_insert_order() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(userId="user-1", audience="temis")),
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
        ]
    )
    result = await RefreshRotationStore().rotate(
        cast(AsyncConnection, connection),
        old_token_hash="old-hash",
        expected_audience="temis",
        now=NOW,
        replacement=RefreshReplacement(
            id="new-id",
            token_hash="new-hash",
            expires_at=datetime(2026, 9, 30),
            created_at=NOW,
        ),
    )

    assert result is not None
    assert result.user_id == "user-1"
    rendered = [sql(statement) for statement in connection.statements]
    assert rendered[0].startswith('SELECT "RefreshToken"."userId"')
    assert rendered[1].startswith('SELECT "User".id')
    assert '"User".status =' in rendered[1]
    assert rendered[1].endswith("FOR UPDATE")
    assert rendered[2].startswith('UPDATE "RefreshToken" SET "revokedAt"=')
    assert '"RefreshToken"."revokedAt" IS NULL' in rendered[2]
    assert '"RefreshToken"."expiresAt" >' in rendered[2]
    assert rendered[3].startswith('INSERT INTO "RefreshToken"')


@pytest.mark.anyio
async def test_refresh_rotation_stops_on_audience_inactive_or_lost_conditional_update() -> None:
    wrong_audience = FakeConnection(
        [FakeResult(SimpleNamespace(userId="user-1", audience="other"))]
    )
    inactive = FakeConnection(
        [FakeResult(SimpleNamespace(userId="user-1", audience="temis")), FakeResult(None)]
    )
    replay = FakeConnection(
        [
            FakeResult(SimpleNamespace(userId="user-1", audience="temis")),
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(rowcount=0),
        ]
    )
    replacement = RefreshReplacement("new-id", "new-hash", datetime(2026, 9, 30), NOW)

    for connection, expected_statements in ((wrong_audience, 1), (inactive, 2)):
        result = await RefreshRotationStore().rotate(
            cast(AsyncConnection, connection),
            old_token_hash="old",
            expected_audience="temis",
            now=NOW,
            replacement=replacement,
        )
        assert result is None
        assert len(connection.statements) == expected_statements

    with pytest.raises(RefreshRotationConflict, match="count was not one"):
        await RefreshRotationStore().rotate(
            cast(AsyncConnection, replay),
            old_token_hash="old",
            expected_audience="temis",
            now=NOW,
            replacement=replacement,
        )
    assert len(replay.statements) == 3
