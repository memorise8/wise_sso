"""Async SQLAlchemy lifecycle with bounded PostgreSQL transaction retries."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TypeVar

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    create_async_engine,
)

T = TypeVar("T")
Backoff = Callable[[int], Awaitable[None]]
TransactionCallback = Callable[[AsyncConnection], Awaitable[T]]
RETRYABLE_SQLSTATES = frozenset({"40001", "40P01"})


@dataclass(frozen=True, slots=True)
class DatabaseOnlyTransaction[T]:
    """Explicitly mark retry-safe work whose effects are confined to the transaction.

    The callback may execute database statements through the supplied connection only.
    Network calls, filesystem writes, mail/message delivery, mutable external state, and
    other non-transactional effects are forbidden because PostgreSQL may retry it.
    """

    callback: TransactionCallback[T]


def database_only_transaction[T](
    callback: TransactionCallback[T],
) -> DatabaseOnlyTransaction[T]:
    """Declare a callback idempotent under rollback and safe for bounded DB retries."""

    return DatabaseOnlyTransaction(callback)


async def _default_backoff(retry_number: int) -> None:
    await asyncio.sleep(0.025 * (2 ** (retry_number - 1)))


def _sqlstate(error: DBAPIError) -> str | None:
    original = error.orig
    value = getattr(original, "sqlstate", None)
    if isinstance(value, str):
        return value
    value = getattr(original, "pgcode", None)
    return value if isinstance(value, str) else None


class Database:
    """Own an async engine; schema creation is intentionally not exposed."""

    def __init__(
        self,
        url: str | None = None,
        *,
        engine: AsyncEngine | None = None,
        backoff: Backoff = _default_backoff,
    ) -> None:
        if (url is None) == (engine is None):
            raise ValueError("provide exactly one of url or engine")
        if engine is not None:
            self._engine = engine
        else:
            if url is None:
                raise AssertionError("validated database URL unexpectedly missing")
            self._engine = create_async_engine(
                url,
                isolation_level="READ COMMITTED",
                pool_pre_ping=True,
            )
        self._backoff = backoff
        self._closed = False

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def ping(self) -> None:
        async with self.connection() as connection:
            await connection.execute(text("SELECT 1"))

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        if self._closed:
            raise RuntimeError("database is closed")
        async with self._engine.connect() as connection:
            yield connection

    async def transaction(self, work: DatabaseOnlyTransaction[T], *, max_attempts: int = 3) -> T:
        """Run explicitly marked database-only work, retrying the whole transaction.

        A retry re-executes the callback. Callers must prepare external inputs before
        marking the callback and perform external side effects only after this returns.
        """

        if not isinstance(work, DatabaseOnlyTransaction):
            raise TypeError("transaction work must be marked database-only and retry-safe")
        if self._closed:
            raise RuntimeError("database is closed")
        if not 1 <= max_attempts <= 3:
            raise ValueError("max_attempts must be between 1 and 3")

        for attempt in range(1, max_attempts + 1):
            try:
                async with self._engine.begin() as connection:
                    return await work.callback(connection)
            except DBAPIError as error:
                if _sqlstate(error) not in RETRYABLE_SQLSTATES or attempt == max_attempts:
                    raise
                await self._backoff(attempt)
        raise AssertionError("transaction retry loop exhausted unexpectedly")

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self._engine.dispose()
