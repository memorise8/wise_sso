"""Dormant first-admin bootstrap with one atomic PostgreSQL transaction."""

from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, TypeVar

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.admin import AuditRetentionCleanupConfigurationError
from wiseacct_sso.ops.audit_cleanup import _async_postgres_url, _database_url
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import (
    AuditLog,
    RefreshToken,
    Role,
    User,
    UserRole,
    UserStatus,
    application_uuid,
    utc_now_ms,
)

_EMAIL = re.compile(
    r"^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-.]*)[A-Z0-9_+\-]@"
    r"([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$",
    re.IGNORECASE | re.ASCII,
)


class GrantAdminConfigurationError(ValueError):
    pass


class ActiveUserNotFoundError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GrantFirstAdminInput:
    email: str
    now: datetime | None = None


@dataclass(frozen=True, slots=True)
class GrantFirstAdminResult:
    user_id: str
    role_assigned: bool
    revoked_refresh_token_count: int


class FirstAdminTransaction(Protocol):
    async def find_active_user_by_email(self, email: str) -> str | None: ...

    async def upsert_admin_role(self) -> tuple[str, str, str]: ...

    async def assign_role(self, *, user_id: str, role_id: str) -> bool: ...

    async def revoke_refresh_tokens(self, *, user_id: str, revoked_at: datetime) -> int: ...

    async def create_audit(
        self, *, user_id: str, service_key: str, role_name: str, created_at: datetime
    ) -> None: ...


T = TypeVar("T")
TransactionWork = Callable[[FirstAdminTransaction], Awaitable[T]]


class FirstAdminStore(Protocol):
    async def run_in_transaction(self, work: TransactionWork[T]) -> T: ...


class _SqlAlchemyFirstAdminTransaction:
    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    async def find_active_user_by_email(self, email: str) -> str | None:
        row = (
            await self._connection.execute(
                select(User.c.id)
                .where(User.c.email == email, User.c.status == UserStatus.ACTIVE)
                .limit(1)
            )
        ).one_or_none()
        return None if row is None else str(row.id)

    async def upsert_admin_role(self) -> tuple[str, str, str]:
        statement = postgresql_insert(Role).values(
            id=application_uuid(), serviceKey="temis", name="admin"
        )
        row = (
            await self._connection.execute(
                statement.on_conflict_do_update(
                    index_elements=[Role.c.serviceKey, Role.c.name],
                    set_={"serviceKey": statement.excluded.serviceKey},
                ).returning(Role.c.id, Role.c.serviceKey, Role.c.name)
            )
        ).one()
        return str(row.id), str(row.serviceKey), str(row.name)

    async def assign_role(self, *, user_id: str, role_id: str) -> bool:
        result = await self._connection.execute(
            postgresql_insert(UserRole)
            .values(id=application_uuid(), userId=user_id, roleId=role_id)
            .on_conflict_do_nothing(index_elements=[UserRole.c.userId, UserRole.c.roleId])
        )
        return result.rowcount == 1

    async def revoke_refresh_tokens(self, *, user_id: str, revoked_at: datetime) -> int:
        locked = (
            await self._connection.execute(
                select(User.c.id).where(User.c.id == user_id).with_for_update()
            )
        ).one_or_none()
        if locked is None:
            return 0
        result = await self._connection.execute(
            update(RefreshToken)
            .where(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None))
            .values(revokedAt=revoked_at)
        )
        return int(result.rowcount)

    async def create_audit(
        self, *, user_id: str, service_key: str, role_name: str, created_at: datetime
    ) -> None:
        await self._connection.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType="admin_user_role_assigned",
                outcome="success",
                userId=user_id,
                actorUserId=None,
                targetUserId=user_id,
                reasonCode="OPS_BOOTSTRAP_ADMIN",
                detailsJson={"serviceKey": service_key, "roleName": role_name},
                createdAt=created_at,
            )
        )


class SqlAlchemyFirstAdminStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def run_in_transaction(self, work: TransactionWork[T]) -> T:
        async def operation(connection: AsyncConnection) -> T:
            return await work(_SqlAlchemyFirstAdminTransaction(connection))

        return await self._database.transaction(database_only_transaction(operation))


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if _EMAIL.fullmatch(email) is None:
        raise GrantAdminConfigurationError("Invalid email")
    return email


async def grant_first_admin(
    store: FirstAdminStore, input: GrantFirstAdminInput
) -> GrantFirstAdminResult:
    email = _normalize_email(input.email)
    revoked_at = input.now or utc_now_ms()

    async def provision(transaction: FirstAdminTransaction) -> GrantFirstAdminResult:
        user_id = await transaction.find_active_user_by_email(email)
        if user_id is None:
            raise ActiveUserNotFoundError("No active user found")
        role_id, service_key, role_name = await transaction.upsert_admin_role()
        assigned = await transaction.assign_role(user_id=user_id, role_id=role_id)
        revoked = await transaction.revoke_refresh_tokens(user_id=user_id, revoked_at=revoked_at)
        await transaction.create_audit(
            user_id=user_id,
            service_key=service_key,
            role_name=role_name,
            created_at=revoked_at,
        )
        return GrantFirstAdminResult(user_id, assigned, revoked)

    return await store.run_in_transaction(provision)


def parse_args(argv: Sequence[str] | None = None) -> GrantFirstAdminInput:
    arguments = list(argv or ())
    email: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--email":
            index += 1
            if index >= len(arguments) or not arguments[index]:
                raise GrantAdminConfigurationError("--email requires a value")
            email = arguments[index]
        elif argument.startswith("--email="):
            email = argument.partition("=")[2]
        else:
            raise GrantAdminConfigurationError(f"Unknown option: {argument}")
        index += 1
    if not email:
        raise GrantAdminConfigurationError("--email is required")
    return GrantFirstAdminInput(email=_normalize_email(email))


async def _run(input: GrantFirstAdminInput, *, database_url: str) -> GrantFirstAdminResult:
    database = Database(_async_postgres_url(database_url))
    try:
        return await grant_first_admin(SqlAlchemyFirstAdminStore(database), input)
    finally:
        await database.close()


def cli(argv: Sequence[str] | None = None) -> None:
    try:
        input = parse_args(sys.argv[1:] if argv is None else argv)
        result = asyncio.run(_run(input, database_url=_database_url(os.environ)))
    except Exception as error:
        detail = (
            str(error)
            if isinstance(
                error,
                (
                    GrantAdminConfigurationError,
                    ActiveUserNotFoundError,
                    AuditRetentionCleanupConfigurationError,
                ),
            )
            else type(error).__name__
        )
        sys.stderr.write(f"grant-admin failed: {detail}\n")
        raise SystemExit(1) from None
    assigned = str(result.role_assigned).lower()
    print(
        f"grant-admin success userId={result.user_id} roleAssigned={assigned} "
        f"revokedRefreshTokenCount={result.revoked_refresh_token_count} "
        "reasonCode=OPS_BOOTSTRAP_ADMIN"
    )


if __name__ == "__main__":
    cli()
