"""Read the administrator's view of one user and their live refresh sessions."""

from datetime import UTC, datetime
from typing import cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.oidc import OidcUserRecord
from wiseacct_sso.persistence.stores import RoleAssignment

_USER = text("""
SELECT u.id, u.email, u.name, u.status, u."emailVerified", u."userType",
       u."createdAt", u."accountExpiresAt",
       COALESCE((
           SELECT jsonb_agg(
               jsonb_build_object('id', r.id, 'serviceKey', r."serviceKey", 'name', r.name)
               ORDER BY r."serviceKey", r.name, r.id
           )
           FROM "UserRole" ur
           JOIN "Role" r ON r.id = ur."roleId"
           WHERE ur."userId" = u.id
       ), '[]'::jsonb) AS roles
FROM "User" u
WHERE u.id = :user_id
""")

_SESSIONS = text("""
WITH groups AS (
    SELECT audience, count(*) AS count,
           min("expiresAt") AT TIME ZONE 'UTC' AS "earliestExpiresAt",
           max("expiresAt") AT TIME ZONE 'UTC' AS "latestExpiresAt"
    FROM "RefreshToken"
    WHERE "userId" = :user_id
      AND "revokedAt" IS NULL
      AND "expiresAt" > (statement_timestamp() AT TIME ZONE 'UTC')
    GROUP BY audience
),
page_rows AS (
    SELECT * FROM groups ORDER BY audience LIMIT :page_size OFFSET :offset
)
SELECT jsonb_build_object(
    'items', COALESCE(
        (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.audience) FROM page_rows p), '[]'::jsonb
    ),
    'total', (SELECT count(*) FROM groups),
    'activeSessionCount', COALESCE((SELECT sum(count) FROM groups), 0),
    'page', CAST(:page AS bigint),
    'pageSize', CAST(:page_size AS bigint)
)
FROM "User"
WHERE id = :user_id
""")


_LOGIN_ACTIVITY = text("""
WITH logins AS (
    SELECT id, "createdAt", "ipAddress",
           CASE WHEN "eventType" = 'oidc_token'
                THEN COALESCE(
                    CASE WHEN jsonb_typeof("detailsJson" -> 'clientId') = 'string'
                         THEN NULLIF("detailsJson" ->> 'clientId', '') END,
                    "serviceKey"
                )
                ELSE "serviceKey"
           END AS service,
           CASE WHEN "eventType" = 'login_success'
                     OR ("eventType" = 'oidc_token' AND outcome = 'success')
                THEN 'success'
                ELSE 'failure'
           END AS outcome
    FROM "AuditLog"
    WHERE "userId" = :user_id
      AND "eventType" IN ('login_success', 'login_failure', 'lockout', 'oidc_token')
      AND outcome IN ('success', 'failure')
),
history_page AS (
    SELECT id, "createdAt", "ipAddress", service, outcome
    FROM logins
    ORDER BY "createdAt" DESC, id DESC
    LIMIT :page_size OFFSET :history_offset
),
last_by_service AS (
    SELECT DISTINCT ON (service) service, "createdAt", "ipAddress"
    FROM logins
    WHERE outcome = 'success' AND service IS NOT NULL
    ORDER BY service, "createdAt" DESC, id DESC
),
service_page AS (
    SELECT service, "createdAt", "ipAddress"
    FROM last_by_service
    ORDER BY service
    LIMIT :page_size OFFSET :service_offset
)
SELECT jsonb_build_object(
    'loginHistory', jsonb_build_object(
        'items', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'service', service,
                'createdAt', "createdAt" AT TIME ZONE 'UTC',
                'ipAddress', "ipAddress",
                'outcome', outcome
            ) ORDER BY "createdAt" DESC, id DESC)
            FROM history_page
        ), '[]'::jsonb),
        'total', (SELECT count(*) FROM logins),
        'page', CAST(:history_page AS bigint),
        'pageSize', CAST(:page_size AS bigint)
    ),
    'lastLoginByService', jsonb_build_object(
        'items', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'service', service,
                'createdAt', "createdAt" AT TIME ZONE 'UTC',
                'ipAddress', "ipAddress"
            ) ORDER BY service)
            FROM service_page
        ), '[]'::jsonb),
        'total', (SELECT count(*) FROM last_by_service),
        'page', CAST(:service_page AS bigint),
        'pageSize', CAST(:page_size AS bigint)
    )
)
""")


async def read_user_login_activity(
    connection: AsyncConnection,
    user_id: str,
    *,
    history_page: int,
    service_page: int,
    page_size: int,
) -> dict[str, object]:
    result = await connection.execute(
        _LOGIN_ACTIVITY,
        {
            "user_id": user_id,
            "history_page": history_page,
            "service_page": service_page,
            "page_size": page_size,
            "history_offset": (history_page - 1) * page_size,
            "service_offset": (service_page - 1) * page_size,
        },
    )
    return cast(dict[str, object], result.scalar_one())


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


async def read_user_detail(
    connection: AsyncConnection,
    user_id: str,
    *,
    role_page: int,
    page_size: int,
) -> tuple[OidcUserRecord, dict[str, object]] | None:
    row = (await connection.execute(_USER, {"user_id": user_id})).one_or_none()
    if row is None:
        return None

    roles = cast(list[dict[str, str]], row.roles)
    user = OidcUserRecord(
        id=row.id,
        email=row.email,
        name=row.name,
        status=UserStatus(row.status),
        email_verified=row.emailVerified,
        user_type=row.userType,
        account_expires_at=row.accountExpiresAt,
        roles=tuple(
            RoleAssignment(service_key=role["serviceKey"], name=role["name"]) for role in roles
        ),
    )
    offset = (role_page - 1) * page_size
    return user, {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "status": user.status.value,
        "userType": user.user_type,
        "createdAt": _iso_utc(row.createdAt),
        "accountExpiresAt": _iso_utc(user.account_expires_at),
        "roles": {
            "items": roles[offset : offset + page_size],
            "total": len(roles),
            "page": role_page,
            "pageSize": page_size,
        },
    }


async def read_user_sessions(
    connection: AsyncConnection, user_id: str, *, page: int, page_size: int
) -> dict[str, object] | None:
    result = await connection.execute(
        _SESSIONS,
        {
            "user_id": user_id,
            "page": page,
            "page_size": page_size,
            "offset": (page - 1) * page_size,
        },
    )
    return cast(dict[str, object] | None, result.scalar_one_or_none())
