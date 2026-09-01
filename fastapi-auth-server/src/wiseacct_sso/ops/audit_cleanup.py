"""Dry-run-by-default audit retention command matching the Express ops contract."""

from __future__ import annotations

import asyncio
import math
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import delete, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.admin import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    AuditRetentionCleanupConfigurationError,
    AuditRetentionCleanupResult,
    audit_retention_cutoff,
)
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import AuditLog, utc_now_ms


class AuditRetentionCleanupStore(Protocol):
    async def count_older_than(self, cutoff: datetime) -> int: ...

    async def delete_older_than(self, cutoff: datetime) -> int: ...


@dataclass(frozen=True, slots=True)
class AuditRetentionCleanupOptions:
    execute: bool = False
    retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS


class SqlAlchemyAuditRetentionCleanupStore:
    """DML-only adapter over the Prisma-owned ``AuditLog`` table."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def count_older_than(self, cutoff: datetime) -> int:
        async with self._database.connection() as connection:
            result = await connection.execute(
                select(func.count()).select_from(AuditLog).where(AuditLog.c.createdAt < cutoff)
            )
            return int(result.scalar_one())

    async def delete_older_than(self, cutoff: datetime) -> int:
        async def operation(connection: AsyncConnection) -> int:
            result = await connection.execute(delete(AuditLog).where(AuditLog.c.createdAt < cutoff))
            return int(result.rowcount)

        return await self._database.transaction(database_only_transaction(operation))


async def cleanup_audit_logs(
    store: AuditRetentionCleanupStore,
    options: AuditRetentionCleanupOptions | None = None,
    *,
    now: datetime | None = None,
) -> AuditRetentionCleanupResult:
    resolved_options = options or AuditRetentionCleanupOptions()
    cutoff = audit_retention_cutoff(
        now=now or utc_now_ms(), retention_days=resolved_options.retention_days
    )
    dry_run = not resolved_options.execute
    deleted_count = (
        await store.count_older_than(cutoff) if dry_run else await store.delete_older_than(cutoff)
    )
    return AuditRetentionCleanupResult(
        cutoff=cutoff,
        deleted_count=deleted_count,
        dry_run=dry_run,
        retention_days=resolved_options.retention_days,
    )


_JS_DECIMAL_NUMBER = re.compile(r"^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$")


def coerce_positive_js_integer(value: str) -> int:
    """Match the bounded JavaScript ``Number`` coercion used by Zod."""

    normalized = value.strip()
    try:
        if not normalized:
            parsed = 0
        elif normalized.lower().startswith(("0x", "0b", "0o")):
            parsed = int(float(int(normalized, 0)))
        elif _JS_DECIMAL_NUMBER.fullmatch(normalized):
            numeric = float(normalized)
            if not math.isfinite(numeric) or not numeric.is_integer():
                raise ValueError
            parsed = int(numeric)
        else:
            raise ValueError
    except (OverflowError, ValueError) as error:
        raise AuditRetentionCleanupConfigurationError(
            "retentionDays must be a positive integer"
        ) from error
    if parsed < 1:
        raise AuditRetentionCleanupConfigurationError("retentionDays must be a positive integer")
    return parsed


def parse_args(argv: Sequence[str] | None = None) -> AuditRetentionCleanupOptions:
    arguments = list(argv or ())
    execute = False
    retention_days = DEFAULT_AUDIT_RETENTION_DAYS
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--execute":
            execute = True
        elif argument == "--retention-days":
            index += 1
            if index >= len(arguments) or not arguments[index]:
                raise AuditRetentionCleanupConfigurationError("--retention-days requires a value")
            retention_days = coerce_positive_js_integer(arguments[index])
        elif argument.startswith("--retention-days="):
            retention_days = coerce_positive_js_integer(argument.partition("=")[2])
        else:
            raise AuditRetentionCleanupConfigurationError(f"Unknown option: {argument}")
        index += 1
    return AuditRetentionCleanupOptions(execute=execute, retention_days=retention_days)


def _async_postgres_url(value: str) -> str:
    try:
        url = make_url(value)
    except Exception:
        raise AuditRetentionCleanupConfigurationError(
            "DATABASE_URL must be a valid PostgreSQL URL"
        ) from None
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+asyncpg")
    elif url.drivername != "postgresql+asyncpg":
        raise AuditRetentionCleanupConfigurationError("DATABASE_URL must use PostgreSQL")
    return url.render_as_string(hide_password=False)


def _database_url(environment: Mapping[str, str]) -> str:
    value = environment.get("DATABASE_URL")
    if value is None or not value.strip():
        raise AuditRetentionCleanupConfigurationError("DATABASE_URL is required")
    return _async_postgres_url(value)


async def _run(
    options: AuditRetentionCleanupOptions, *, database_url: str
) -> AuditRetentionCleanupResult:
    database = Database(_async_postgres_url(database_url))
    try:
        return await cleanup_audit_logs(
            SqlAlchemyAuditRetentionCleanupStore(database),
            options,
        )
    finally:
        await database.close()


def cli(argv: Sequence[str] | None = None) -> None:
    try:
        options = parse_args(sys.argv[1:] if argv is None else argv)
        result = asyncio.run(_run(options, database_url=_database_url(os.environ)))
    except Exception as error:
        detail = (
            str(error)
            if isinstance(error, AuditRetentionCleanupConfigurationError)
            else type(error).__name__
        )
        sys.stderr.write(f"audit-log-cleanup failed: {detail}\n")
        raise SystemExit(1) from None
    action = "dry-run" if result.dry_run else "deleted"
    cutoff = (
        result.cutoff.replace(tzinfo=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    print(f"audit-log-cleanup {action} count={result.deleted_count} cutoff={cutoff}")


if __name__ == "__main__":
    cli()
