from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

import pytest
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from wiseacct_sso.persistence.database import (
    Database,
    DatabaseOnlyTransaction,
    database_only_transaction,
)


class PgError(Exception):
    def __init__(self, sqlstate: str) -> None:
        self.sqlstate = sqlstate


def db_error(sqlstate: str) -> DBAPIError:
    return DBAPIError("statement", {}, PgError(sqlstate), False)


class FakeEngine:
    def __init__(self) -> None:
        self.begin_calls = 0
        self.dispose_calls = 0

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncConnection]:
        self.begin_calls += 1
        yield cast(AsyncConnection, object())

    async def dispose(self) -> None:
        self.dispose_calls += 1


@pytest.mark.anyio
async def test_transaction_retries_only_serialization_and_deadlock_up_to_three() -> None:
    engine = FakeEngine()
    backoffs: list[int] = []

    async def backoff(attempt: int) -> None:
        backoffs.append(attempt)

    database = Database(engine=cast(AsyncEngine, engine), backoff=backoff)
    errors = iter((db_error("40001"), db_error("40P01")))

    async def work(_connection: AsyncConnection) -> str:
        if engine.begin_calls < 3:
            raise next(errors)
        return "committed"

    assert await database.transaction(database_only_transaction(work)) == "committed"
    assert engine.begin_calls == 3
    assert backoffs == [1, 2]


@pytest.mark.anyio
async def test_transaction_does_not_retry_other_database_errors() -> None:
    engine = FakeEngine()
    database = Database(engine=cast(AsyncEngine, engine))

    async def work(_connection: AsyncConnection) -> None:
        raise db_error("23505")

    with pytest.raises(DBAPIError):
        await database.transaction(database_only_transaction(work))
    assert engine.begin_calls == 1


@pytest.mark.anyio
async def test_transaction_stops_after_requested_attempt_limit() -> None:
    engine = FakeEngine()
    database = Database(engine=cast(AsyncEngine, engine))

    async def work(_connection: AsyncConnection) -> None:
        raise db_error("40001")

    with pytest.raises(DBAPIError):
        await database.transaction(database_only_transaction(work), max_attempts=2)
    assert engine.begin_calls == 2


@pytest.mark.anyio
async def test_close_is_idempotent_and_prevents_new_work() -> None:
    engine = FakeEngine()
    database = Database(engine=cast(AsyncEngine, engine))
    await database.close()
    await database.close()
    assert engine.dispose_calls == 1

    async def work(_connection: AsyncConnection) -> None:
        return None

    with pytest.raises(RuntimeError, match="closed"):
        await database.transaction(database_only_transaction(work))


def test_database_requires_exactly_one_engine_source() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        Database()
    with pytest.raises(ValueError, match="exactly one"):
        Database("postgresql+asyncpg://synthetic", engine=cast(AsyncEngine, FakeEngine()))


@pytest.mark.anyio
async def test_transaction_rejects_unbounded_retry_configuration() -> None:
    database = Database(engine=cast(AsyncEngine, FakeEngine()))

    async def work(_connection: AsyncConnection) -> None:
        return None

    with pytest.raises(ValueError, match="between 1 and 3"):
        await database.transaction(database_only_transaction(work), max_attempts=4)


@pytest.mark.anyio
async def test_transaction_rejects_unmarked_callbacks() -> None:
    database = Database(engine=cast(AsyncEngine, FakeEngine()))

    async def work(_connection: AsyncConnection) -> None:
        return None

    with pytest.raises(TypeError, match="database-only and retry-safe"):
        await database.transaction(cast(DatabaseOnlyTransaction[None], work))
