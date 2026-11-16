"""Read paginated security views for the administrator portal."""

from __future__ import annotations

from datetime import UTC, timedelta
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.persistence.models import utc_now_ms

SecurityView = Literal["failure-ip", "failure-account", "locked", "inactive"]

_FAILURES = """
WITH recent AS (
    SELECT {group_column} AS group_key, "createdAt",
           count(*) OVER (
               PARTITION BY {group_column}
               ORDER BY "createdAt"
               RANGE BETWEEN INTERVAL '10 minutes' PRECEDING AND CURRENT ROW
           ) AS window_count
    FROM "AuditLog"
    WHERE outcome = 'failure' AND "eventType" IN ('login_failure', 'lockout')
      AND "createdAt" >= :recent_since AND "createdAt" <= :now
      AND {group_column} IS NOT NULL
)
SELECT recent.group_key AS "{key_name}", count(*) AS "failureCount",
       max(recent."createdAt") AS "lastFailedAt",
       max(recent.window_count) >= 5 AS "concentrated"
FROM recent
GROUP BY recent.group_key
ORDER BY "concentrated" DESC, "failureCount" DESC, "lastFailedAt" DESC, recent.group_key
LIMIT :limit OFFSET :offset
"""

_QUERIES = {
    "failure-ip": text(_FAILURES.format(group_column='"ipAddress"', key_name="ipAddress")),
    "failure-account": text(_FAILURES.format(group_column='"userId"', key_name="userId")),
    "locked": text("""
        SELECT u.id AS "userId", u.email, p."lockedUntil", p."failedLoginCount"
        FROM "PasswordCredential" p
        JOIN "User" u ON u.id = p."userId"
        WHERE p."lockedUntil" > :now
        ORDER BY p."lockedUntil" DESC, u.id
        LIMIT :limit OFFSET :offset
    """),
    "inactive": text("""
        SELECT u.id AS "userId", u.email, u."createdAt",
               activity."lastLoginAt"
        FROM "User" u
        LEFT JOIN LATERAL (
            SELECT a."createdAt" AS "lastLoginAt"
            FROM "AuditLog" a
            WHERE a."userId" = u.id AND a.outcome = 'success'
              AND a."eventType" IN ('login_success', 'oidc_token', 'admin_browser_login')
            ORDER BY a."createdAt" DESC
            LIMIT 1
        ) activity ON true
        WHERE u.status = 'ACTIVE'
          AND COALESCE(activity."lastLoginAt", u."createdAt") <= :inactive_since
        ORDER BY COALESCE(activity."lastLoginAt", u."createdAt"), u.id
        LIMIT :limit OFFSET :offset
    """),
}


async def read_admin_security(
    connection: AsyncConnection, *, view: SecurityView, page: int
) -> dict[str, object]:
    now = utc_now_ms()
    page_size = 25
    result = await connection.execute(
        _QUERIES[view],
        {
            "now": now,
            "recent_since": now - timedelta(hours=24),
            "inactive_since": now - timedelta(days=90),
            "limit": page_size + 1,
            "offset": (page - 1) * page_size,
        },
    )
    rows = result.mappings().all()
    items = []
    for row in rows[:page_size]:
        item = dict(row)
        for key in ("createdAt", "lastLoginAt", "lastFailedAt", "lockedUntil"):
            if item.get(key) is not None:
                item[key] = item[key].replace(tzinfo=UTC).isoformat()
        items.append(item)
    return {"items": items, "page": page, "pageSize": page_size, "hasMore": len(rows) > page_size}
