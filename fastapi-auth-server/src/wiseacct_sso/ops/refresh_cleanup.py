"""Dormant refresh-token cleanup matching the active Express maintenance command."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.elements import ColumnElement

from wiseacct_sso.domain.admin import AuditRetentionCleanupConfigurationError
from wiseacct_sso.ops.audit_cleanup import (
    _async_postgres_url,
    _database_url,
    coerce_positive_js_integer,
)
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import RefreshToken, utc_now_ms

DEFAULT_REFRESH_RETENTION_DAYS = 30


class RefreshTokenCleanupConfigurationError(ValueError):
    pass


class RefreshTokenCleanupStore(Protocol):
    async def count_eligible(self, cutoff: datetime) -> int: ...

    async def delete_eligible(self, cutoff: datetime) -> int: ...


@dataclass(frozen=True, slots=True)
class RefreshTokenCleanupOptions:
    dry_run: bool = False
    retention_days: int = DEFAULT_REFRESH_RETENTION_DAYS


@dataclass(frozen=True, slots=True)
class RefreshTokenCleanupResult:
    cutoff: datetime
    deleted_count: int
    dry_run: bool
    retention_days: int


def _eligible(cutoff: datetime) -> ColumnElement[bool]:
    return or_(RefreshToken.c.expiresAt < cutoff, RefreshToken.c.revokedAt < cutoff)


class SqlAlchemyRefreshTokenCleanupStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def count_eligible(self, cutoff: datetime) -> int:
        async with self._database.connection() as connection:
            result = await connection.execute(
                select(func.count()).select_from(RefreshToken).where(_eligible(cutoff))
            )
            return int(result.scalar_one())

    async def delete_eligible(self, cutoff: datetime) -> int:
        async def operation(connection: AsyncConnection) -> int:
            result = await connection.execute(delete(RefreshToken).where(_eligible(cutoff)))
            return int(result.rowcount)

        return await self._database.transaction(database_only_transaction(operation))


async def cleanup_refresh_tokens(
    store: RefreshTokenCleanupStore,
    options: RefreshTokenCleanupOptions,
    *,
    now: datetime | None = None,
) -> RefreshTokenCleanupResult:
    if isinstance(options.retention_days, bool) or options.retention_days < 1:
        raise RefreshTokenCleanupConfigurationError("retentionDays must be a positive integer")
    cutoff = (now or utc_now_ms()) - timedelta(days=options.retention_days)
    deleted_count = (
        await store.count_eligible(cutoff)
        if options.dry_run
        else await store.delete_eligible(cutoff)
    )
    return RefreshTokenCleanupResult(
        cutoff=cutoff,
        deleted_count=deleted_count,
        dry_run=options.dry_run,
        retention_days=options.retention_days,
    )


def _retention_days(value: str) -> int:
    try:
        return coerce_positive_js_integer(value)
    except ValueError as error:
        raise RefreshTokenCleanupConfigurationError(
            "retentionDays must be a positive integer"
        ) from error


def parse_args(
    argv: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> RefreshTokenCleanupOptions:
    env = os.environ if environment is None else environment
    retention_days = _retention_days(
        env.get("REFRESH_TOKEN_CLEANUP_RETENTION_DAYS", str(DEFAULT_REFRESH_RETENTION_DAYS))
    )
    dry_run = False
    arguments = list(argv or ())
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--dry-run":
            dry_run = True
        elif argument == "--retention-days":
            index += 1
            if index >= len(arguments) or not arguments[index]:
                raise RefreshTokenCleanupConfigurationError("--retention-days requires a value")
            retention_days = _retention_days(arguments[index])
        elif argument.startswith("--retention-days="):
            retention_days = _retention_days(argument.partition("=")[2])
        else:
            raise RefreshTokenCleanupConfigurationError(f"Unknown option: {argument}")
        index += 1
    return RefreshTokenCleanupOptions(dry_run=dry_run, retention_days=retention_days)


async def _run(
    options: RefreshTokenCleanupOptions, *, database_url: str
) -> RefreshTokenCleanupResult:
    database = Database(_async_postgres_url(database_url))
    try:
        return await cleanup_refresh_tokens(SqlAlchemyRefreshTokenCleanupStore(database), options)
    finally:
        await database.close()


def cli(argv: Sequence[str] | None = None) -> None:
    try:
        options = parse_args(sys.argv[1:] if argv is None else argv, os.environ)
        result = asyncio.run(_run(options, database_url=_database_url(os.environ)))
    except Exception as error:
        detail = (
            str(error)
            if isinstance(
                error,
                (
                    RefreshTokenCleanupConfigurationError,
                    AuditRetentionCleanupConfigurationError,
                ),
            )
            else type(error).__name__
        )
        sys.stderr.write(f"refresh-token-cleanup failed: {detail}\n")
        raise SystemExit(1) from None
    action = "would delete" if result.dry_run else "deleted"
    cutoff = (
        result.cutoff.replace(tzinfo=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    print(
        f"refresh-token-cleanup {action} {result.deleted_count} token rows older than "
        f"{cutoff} (retentionDays={result.retention_days})"
    )


if __name__ == "__main__":
    cli()
