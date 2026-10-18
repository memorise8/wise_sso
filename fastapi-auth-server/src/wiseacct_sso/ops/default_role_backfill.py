"""Dormant, atomic counterpart of Express backfill-default-roles; never scheduled."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import func, literal, select, text
from sqlalchemy.dialects.postgresql import Insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.config import get_settings
from wiseacct_sso.domain.admin import AuditRetentionCleanupConfigurationError
from wiseacct_sso.ops.audit_cleanup import _async_postgres_url, _database_url
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import Role, User, UserRole, application_uuid
from wiseacct_sso.persistence.stores import DefaultRole


class BackfillConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DefaultRoleBackfillResult:
    default_role: DefaultRole
    assigned_user_role_count: int

    @property
    def roleless_user_count(self) -> int:
        # Express reports rows actually inserted, not a separate preflight count.
        return self.assigned_user_role_count


class DefaultRoleBackfillStore(Protocol):
    async def backfill(self, default_role: DefaultRole) -> int: ...


def roleless_assignment_statement(role_id: str) -> Insert:
    """Match Prisma's deterministic ID and all-role NOT EXISTS guard."""
    roleless = ~select(UserRole.c.id).where(UserRole.c.userId == User.c.id).exists()
    rows = select(
        func.concat(literal("default-role-"), func.md5(User.c.id + literal(role_id))),
        User.c.id,
        literal(role_id),
    ).where(roleless)
    return (
        postgresql_insert(UserRole)
        .from_select(["id", "userId", "roleId"], rows)
        .on_conflict_do_nothing(index_elements=[UserRole.c.userId, UserRole.c.roleId])
    )


class SqlAlchemyDefaultRoleBackfillStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def backfill(self, default_role: DefaultRole) -> int:
        async def operation(connection: AsyncConnection) -> int:
            # Must be the first statement, before any role read/write. The shared
            # retry runner repeats this entire DB-only transaction at most 3 times.
            await connection.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            for service_key, name in (
                ("temis", "pending"),
                ("temis", "user"),
                ("temis", "admin"),
                (default_role.service_key, default_role.name),
            ):
                await connection.execute(
                    postgresql_insert(Role)
                    .values(id=application_uuid(), serviceKey=service_key, name=name)
                    .on_conflict_do_nothing(index_elements=[Role.c.serviceKey, Role.c.name])
                )
            row = (
                await connection.execute(
                    select(Role.c.id).where(
                        Role.c.serviceKey == default_role.service_key,
                        Role.c.name == default_role.name,
                    )
                )
            ).one()
            result = await connection.execute(roleless_assignment_statement(str(row.id)))
            return int(result.rowcount)

        return await self._database.transaction(database_only_transaction(operation))


async def backfill_default_roles(
    store: DefaultRoleBackfillStore, default_role: DefaultRole
) -> DefaultRoleBackfillResult:
    # Settings permits only pending/user for the required first TEMIS client.
    if default_role.service_key != "temis" or default_role.name not in {"pending", "user"}:
        raise BackfillConfigurationError("Invalid TEMIS default role")
    count = await store.backfill(default_role)
    if type(count) is not int or count < 0:
        raise RuntimeError("backfill returned an invalid assignment count")
    return DefaultRoleBackfillResult(default_role, count)


def parse_args(argv: Sequence[str] | None = None) -> None:
    if argv:
        raise BackfillConfigurationError("backfill-default-roles does not accept arguments")


async def _run(database_url: str, default_role: DefaultRole) -> DefaultRoleBackfillResult:
    database = Database(_async_postgres_url(database_url))
    try:
        return await backfill_default_roles(
            SqlAlchemyDefaultRoleBackfillStore(database), default_role
        )
    finally:
        await database.close()


def cli(argv: Sequence[str] | None = None) -> None:
    try:
        parse_args(sys.argv[1:] if argv is None else argv)
        database_url = _database_url(os.environ)
        # Reuse the validated client policy rather than inventing a second parser
        # or silently substituting 'user' for the configured least-privilege role.
        policy = get_settings().auth_clients[0].default_role
        result = asyncio.run(_run(database_url, DefaultRole(policy.service_key, policy.name)))
    except Exception as error:
        detail = (
            str(error)
            if isinstance(
                error, (BackfillConfigurationError, AuditRetentionCleanupConfigurationError)
            )
            else type(error).__name__
        )
        sys.stderr.write(f"backfill-default-roles failed: {detail}\n")
        raise SystemExit(1) from None
    print(
        "backfill-default-roles success "
        f"defaultRole={result.default_role.service_key}:{result.default_role.name} "
        f"rolelessUserCount={result.roleless_user_count} "
        f"assignedUserRoleCount={result.assigned_user_role_count}"
    )


if __name__ == "__main__":
    cli()
