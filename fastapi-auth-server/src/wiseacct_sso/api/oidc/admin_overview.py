"""Read-only summary numbers and the role catalogue for the admin portal."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from fastapi import FastAPI, Request
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.api.routes.admin import AdminActor
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.external_accounts import EXTERNAL_ALLOWED_ROLES, is_expired
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmployeeInvitation,
    PasswordCredential,
    Role,
    User,
    UserRole,
    UserStatus,
    utc_now_ms,
)

USER_TYPES = ("EMPLOYEE", "CUSTOMER", "EXTERNAL", "UNCLASSIFIED")
SERVICE_LABELS = {
    "gitlab-temis": "GitLab",
    "agent-hub-dash": "에이전트 허브",
    "agent-hub-preview": "에이전트 허브 (미리보기)",
    "fantra-oidc": "Fantra",
}
MAX_ACCESS_USERS = 100
LOGIN_FAILURE_EVENTS = ("login_failure", "lockout", "oidc_authorize")


async def _scalar(connection: AsyncConnection, statement: object) -> int:
    return int((await connection.execute(statement)).scalar_one())  # type: ignore[call-overload]


async def summary_numbers(connection: AsyncConnection, now: datetime) -> dict[str, object]:
    by_type = dict.fromkeys(USER_TYPES, 0)
    rows = await connection.execute(
        select(User.c.userType, func.count())
        .where(
            User.c.status == UserStatus.ACTIVE,
            # An external account past its term is not usable even before the sweep runs.
            or_(User.c.accountExpiresAt.is_(None), User.c.accountExpiresAt > now),
        )
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


def client_access(
    client: OidcClientPolicy,
    *,
    status: object,
    email_verified: bool,
    user_type: str | None,
    expires_at: datetime | None,
    roles: set[tuple[str, str]],
    now: datetime,
) -> tuple[bool, str]:
    """Mirror OidcService._eligible_identity and the required-role gate, in the same order."""

    if status != UserStatus.ACTIVE:
        return False, "계정 정지·비활성"
    if is_expired(expires_at, now):
        return False, "기한 만료"
    if not email_verified:
        return False, "이메일 미인증"
    if client.allowed_user_types is not None and (user_type or "UNCLASSIFIED") not in (
        client.allowed_user_types
    ):
        return False, "허용되지 않은 유형"
    if any((r.service_key, r.name) in roles for r in client.required_roles):
        return True, "역할 있음"
    if client.allow_without_required_role:
        return True, "역할 없이 허용"
    needed = ", ".join(f"{r.service_key}:{r.name}" for r in client.required_roles)
    return False, f"{needed} 필요"


async def service_access(
    connection: AsyncConnection,
    clients: OidcClientRegistry,
    user_ids: list[str],
    now: datetime,
) -> dict[str, object]:
    users = (
        await connection.execute(
            select(
                User.c.id,
                User.c.status,
                User.c.emailVerified,
                User.c.userType,
                User.c.accountExpiresAt,
            ).where(User.c.id.in_(user_ids))
        )
    ).all()
    held: dict[str, set[tuple[str, str]]] = {str(user.id): set() for user in users}
    for row in (
        await connection.execute(
            select(UserRole.c.userId, Role.c.serviceKey, Role.c.name)
            .select_from(UserRole.join(Role, Role.c.id == UserRole.c.roleId))
            .where(UserRole.c.userId.in_(user_ids))
        )
    ).all():
        held[str(row.userId)].add((str(row.serviceKey), str(row.name)))

    result: dict[str, object] = {}
    for user in users:
        roles = held[str(user.id)]
        entries: list[dict[str, object]] = []
        for client in clients.clients:
            allowed, reason = client_access(
                client,
                status=user.status,
                email_verified=bool(user.emailVerified),
                user_type=None if user.userType is None else str(user.userType),
                expires_at=user.accountExpiresAt,
                roles=roles,
                now=now,
            )
            entries.append(
                {
                    "service": SERVICE_LABELS.get(client.client_id, client.client_id),
                    "allowed": allowed,
                    "reason": reason,
                }
            )
        active = user.status == UserStatus.ACTIVE and not is_expired(user.accountExpiresAt, now)
        # TEMIS/Fantra still use the legacy login, which only checks the temis:user role.
        entries.append(
            {
                "service": "Fantra·TEMIS",
                "allowed": active and ("temis", "user") in roles,
                "reason": "temis:user 있음" if ("temis", "user") in roles else "temis:user 필요",
            }
        )
        entries.append(
            {
                "service": "SSO 관리자",
                "allowed": active and ("sso", "admin") in roles,
                "reason": "sso:admin 있음" if ("sso", "admin") in roles else "sso:admin 필요",
            }
        )
        result[str(user.id)] = entries
    return {"users": result}


SERVICE_NOTES = {
    "agent-hub-dash": (
        "역할이 없어도 SSO 로그인은 되고, 실제 사용 여부는 허브의 초대·명단이 정합니다. "
        "agent-hub:user가 있으면 직원으로 들어갑니다."
    ),
    "gitlab-temis": (
        "gitlab:user가 있어야 로그인됩니다. 프로젝트 접근 권한은 GitLab에서 따로 줍니다."
    ),
}


def managed_services(clients: OidcClientRegistry) -> list[dict[str, object]]:
    """OIDC services whose access an admin grants through roles (TEMIS/Fantra use open sign-up)."""

    return [
        {
            "clientId": client.client_id,
            "label": SERVICE_LABELS.get(client.client_id, client.client_id),
            "roles": [f"{r.service_key}:{r.name}" for r in client.required_roles],
            "allowWithoutRequiredRole": client.allow_without_required_role,
            "note": SERVICE_NOTES.get(client.client_id, ""),
        }
        for client in clients.clients
        if client.required_roles
        and not any(r.service_key == "temis" for r in client.required_roles)
    ]


def register_overview_routes(
    api: FastAPI,
    admin: Phase6AdminService,
    database: Callable[[], Database],
    clients: OidcClientRegistry,
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

    @api.get("/services")
    async def services(request: Request, actor: AdminActor) -> dict[str, object]:
        await authorized(request, actor)
        return {"items": managed_services(clients)}

    @api.get("/service-access")
    async def access(request: Request, actor: AdminActor) -> dict[str, object]:
        await authorized(request, actor)
        ids = [value for value in request.query_params.getlist("id") if value][:MAX_ACCESS_USERS]
        if not ids:
            return {"users": {}}
        async with database().connection() as connection:
            return await service_access(connection, clients, ids, clock())


__all__ = [
    "client_access",
    "managed_services",
    "register_overview_routes",
    "role_catalogue",
    "service_access",
    "summary_numbers",
]
