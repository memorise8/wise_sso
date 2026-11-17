"""Read the last successful external account cleanup run."""

from __future__ import annotations

from datetime import UTC

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.persistence.models import AuditLog


async def read_last_expiry_cleanup(connection: AsyncConnection) -> dict[str, object] | None:
    result = await connection.execute(
        select(AuditLog.c.createdAt, AuditLog.c.detailsJson)
        .where(
            AuditLog.c.eventType == "external_account_cleanup_completed",
            AuditLog.c.outcome == "success",
        )
        .order_by(AuditLog.c.createdAt.desc(), AuditLog.c.id.desc())
        .limit(1)
    )
    row = result.one_or_none()
    if row is None:
        return None
    return {
        "completedAt": row.createdAt.replace(tzinfo=UTC).isoformat(),
        "processedCount": row.detailsJson["processedCount"],
    }
