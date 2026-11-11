"""Database aggregates for the administrator dashboard."""

from typing import cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_SUMMARY = text("""
WITH bounds AS (
    SELECT statement_timestamp() AT TIME ZONE 'UTC' AS now_utc
),
users AS (
    SELECT
        jsonb_build_object(
            'EMPLOYEE', count(*) FILTER (WHERE "userType" = 'EMPLOYEE'),
            'CUSTOMER', count(*) FILTER (WHERE "userType" = 'CUSTOMER'),
            'EXTERNAL', count(*) FILTER (WHERE "userType" = 'EXTERNAL'),
            'UNCLASSIFIED', count(*) FILTER (WHERE "userType" IS NULL)
        ) AS by_type,
        jsonb_build_object(
            'ACTIVE', count(*) FILTER (WHERE status = 'ACTIVE'),
            'PENDING_EMAIL_VERIFICATION',
                count(*) FILTER (WHERE status = 'PENDING_EMAIL_VERIFICATION'),
            'SUSPENDED', count(*) FILTER (WHERE status = 'SUSPENDED'),
            'DELETED', count(*) FILTER (WHERE status = 'DELETED')
        ) AS by_status,
        count(*) FILTER (
            WHERE "userType" = 'EXTERNAL'
              AND "accountExpiresAt" > now_utc
              AND "accountExpiresAt" <= now_utc + interval '7 days'
        ) AS expires_7d,
        count(*) FILTER (
            WHERE "userType" = 'EXTERNAL'
              AND "accountExpiresAt" > now_utc
              AND "accountExpiresAt" <= now_utc + interval '30 days'
        ) AS expires_30d
    FROM "User" CROSS JOIN bounds
),
invitations AS (
    SELECT
        count(*) FILTER (
            WHERE status = 'PENDING' AND "expiresAt" > now_utc
        ) AS pending,
        count(*) FILTER (
            WHERE status = 'EXPIRED' OR (status = 'PENDING' AND "expiresAt" <= now_utc)
        ) AS expired
    FROM "EmployeeInvitation" CROSS JOIN bounds
),
logins AS (
    -- Portal (OIDC) sign-ins count too; "sso" is a silent reuse of an existing session.
    SELECT
        count(*) FILTER (
            WHERE "eventType" = 'login_success'
               OR ("eventType" = 'oidc_authorize' AND outcome = 'success'
                   AND "detailsJson" ->> 'loginMethod' IN ('password', 'oauth'))
        ) AS succeeded,
        count(*) FILTER (
            WHERE "eventType" IN ('login_failure', 'lockout')
               OR ("eventType" = 'oidc_authorize' AND outcome = 'failure')
        ) AS failed
    FROM "AuditLog" CROSS JOIN bounds
    WHERE "createdAt" >= now_utc - interval '24 hours'
      AND "createdAt" <= now_utc
      AND "eventType" IN ('login_success', 'login_failure', 'lockout', 'oidc_authorize')
),
services AS (
    SELECT "detailsJson" ->> 'clientId' AS client_id, count(DISTINCT "userId") AS user_count
    FROM "AuditLog" CROSS JOIN bounds
    WHERE "eventType" = 'oidc_token'
      AND outcome = 'success'
      AND "userId" IS NOT NULL
      AND "createdAt" >= now_utc - interval '7 days'
      AND "createdAt" <= now_utc
      AND jsonb_typeof("detailsJson" -> 'clientId') = 'string'
      AND "detailsJson" ->> 'clientId' <> ''
    GROUP BY 1
)
SELECT jsonb_build_object(
    'usersByType', by_type,
    'usersByStatus', by_status,
    'externalExpiring', jsonb_build_object('within7Days', expires_7d, 'within30Days', expires_30d),
    'invitations', jsonb_build_object('pending', pending, 'expired', expired),
    'logins24h', jsonb_build_object('success', succeeded, 'failure', failed),
    'lockedAccounts', (
        SELECT count(*) FROM "PasswordCredential" CROSS JOIN bounds WHERE "lockedUntil" > now_utc
    ),
    'serviceLoginUsers7d', COALESCE(
        (SELECT jsonb_object_agg(client_id, user_count) FROM services), '{}'::jsonb
    )
)
FROM users CROSS JOIN invitations CROSS JOIN logins
""")


async def read_admin_summary(connection: AsyncConnection) -> dict[str, object]:
    result = await connection.execute(_SUMMARY)
    return cast(dict[str, object], result.scalar_one())
