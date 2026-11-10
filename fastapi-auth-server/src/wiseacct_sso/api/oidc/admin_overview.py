"""Read-only summary numbers and the role catalogue for the admin portal."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.api.routes.admin import AdminActor
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.external_accounts import EXTERNAL_ALLOWED_ROLES
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmployeeInvitation,
    PasswordCredential,
    Role,
    User,
    UserStatus,
    utc_now_ms,
)

USER_TYPES = ("EMPLOYEE", "CUSTOMER", "EXTERNAL", "UNCLASSIFIED")
LOGIN_FAILURE_EVENTS = ("login_failure", "lockout", "oidc_authorize")


async def _scalar(connection: AsyncConnection, statement: object) -> int:
    return int((await connection.execute(statement)).scalar_one())  # type: ignore[call-overload]


async def summary_numbers(connection: AsyncConnection, now: datetime) -> dict[str, object]:
    by_type = dict.fromkeys(USER_TYPES, 0)
    rows = await connection.execute(
        select(User.c.userType, func.count())
        .where(User.c.status == UserStatus.ACTIVE)
        .group_by(User.c.userType)
    )
    for user_type, count in rows.all():
        by_type[str(user_type) if user_type is not None else "UNCLASSIFIED"] = int(count)
    by_status = {
        str(status): int(count)
        for status, count in (
            await connection.execute(select(User.c.status, func.count()).group_by(User.c.status))
        ).all()
    }

    active_external = and_(
        User.c.userType == "EXTERNAL",
        User.c.status == UserStatus.ACTIVE,
        User.c.accountExpiresAt.is_not(None),
    )

    def expiring_within(days: int) -> object:
        return select(func.count()).where(
            active_external,
            User.c.accountExpiresAt > now,
            User.c.accountExpiresAt <= now + timedelta(days=days),
        )

    since = now - timedelta(hours=24)
    return {
        "activeUsersByType": by_type,
        "usersByStatus": by_status,
        "external": {
            "expiringIn7Days": await _scalar(connection, expiring_within(7)),
            "expiringIn30Days": await _scalar(connection, expiring_within(30)),
        },
        "invitations": {
            "pending": await _scalar(
                connection,
                select(func.count()).where(
                    EmployeeInvitation.c.status == "PENDING", EmployeeInvitation.c.expiresAt > now
                ),
            ),
            "expiredUnaccepted": await _scalar(
                connection,
                select(func.count()).where(
                    EmployeeInvitation.c.status == "PENDING",
                    EmployeeInvitation.c.expiresAt <= now,
                ),
            ),
        },
        "last24Hours": {
            "loginFailures": await _scalar(
                connection,
                select(func.count()).where(
                    AuditLog.c.createdAt >= since,
                    AuditLog.c.outcome == "failure",
                    AuditLog.c.eventType.in_(LOGIN_FAILURE_EVENTS),
                ),
            ),
        },
        "lockedAccounts": await _scalar(
            connection,
            select(func.count()).where(PasswordCredential.c.lockedUntil > now),
        ),
    }


async def role_catalogue(connection: AsyncConnection) -> list[dict[str, object]]:
    rows = await connection.execute(
        select(Role.c.id, Role.c.serviceKey, Role.c.name).order_by(Role.c.serviceKey, Role.c.name)
    )
    return [
        {
            "id": str(row.id),
            "serviceKey": str(row.serviceKey),
            "name": str(row.name),
            "externalAllowed": (row.serviceKey, row.name) in EXTERNAL_ALLOWED_ROLES,
        }
        for row in rows.all()
    ]


def register_overview_routes(
    api: FastAPI,
    admin: Phase6AdminService,
    database: Callable[[], Database],
    clock: Callable[[], datetime] = utc_now_ms,
) -> None:
    async def authorized(request: Request, actor: str) -> None:
        # The browser session proves who is calling; the role is re-read from the DB.
        await admin.authorize_admin(actor, route=request.url.path, method=request.method)

    @api.get("/summary")
    async def summary(request: Request, actor: AdminActor) -> dict[str, object]:
        await authorized(request, actor)
        async with database().connection() as connection:
            return await summary_numbers(connection, clock())

    @api.get("/roles")
    async def roles(request: Request, actor: AdminActor) -> dict[str, object]:
        await authorized(request, actor)
        async with database().connection() as connection:
            return {"items": await role_catalogue(connection)}


__all__ = ["register_overview_routes", "role_catalogue", "summary_numbers"]
