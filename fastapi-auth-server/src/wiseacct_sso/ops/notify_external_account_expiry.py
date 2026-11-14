"""Notify the inviting administrator of external account expiry."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta, timezone
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import text

from wiseacct_sso.config import get_settings
from wiseacct_sso.infrastructure.mail import SmtpMailService, create_mail_service
from wiseacct_sso.ops.audit_cleanup import _database_url
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import utc_now_ms

_KST = timezone(timedelta(hours=9))

_DUE = text("""
SELECT guest.id, guest."accountExpiresAt" AS expiry, inviter.id AS inviter_id,
       inviter.email AS recipient
FROM "User" guest
JOIN "User" inviter ON inviter.id = guest."externalInvitedById"
WHERE guest."userType" = 'EXTERNAL' AND guest.status = 'ACTIVE'
  AND guest."accountExpiresAt" > :now AND guest."accountExpiresAt" <= :until
  AND inviter."userType" = 'EMPLOYEE' AND inviter.status = 'ACTIVE'
  AND inviter."emailVerified" AND NULLIF(trim(inviter.email), '') IS NOT NULL
  AND inviter.id <> guest.id
  AND lower(trim(inviter.email)) IS DISTINCT FROM lower(trim(guest.email))
  AND EXISTS (
      SELECT 1 FROM "UserRole" ur JOIN "Role" r ON r.id = ur."roleId"
      WHERE ur."userId" = inviter.id AND r."serviceKey" = 'sso' AND r.name = 'admin'
  )
ORDER BY guest."accountExpiresAt", guest.id
""")

_CLAIM = text("""
INSERT INTO "AuditLog"
    (id, "eventType", outcome, "actorUserId", "targetUserId", "reasonCode", "createdAt")
VALUES
    (:id, 'external_account_expiry_notice', 'request', :inviter, :guest,
     'EXTERNAL_ACCOUNT_EXPIRY_NOTICE', :now)
ON CONFLICT (id) DO NOTHING
RETURNING id
""")

_FINISH = text('UPDATE "AuditLog" SET outcome = :outcome WHERE id = :id')


class ExpiryMailer(Protocol):
    async def send_external_expiry_notice(self, *, to: str, expires_kst: str) -> None: ...


async def notify_due_accounts(
    database: Database, mail: ExpiryMailer, *, now: datetime | None = None
) -> tuple[int, int]:
    now = now if now is not None else utc_now_ms()
    async with database.engine.begin() as connection:
        rows = (
            await connection.execute(_DUE, {"now": now, "until": now + timedelta(days=7)})
        ).all()

    sent = failed = 0
    for row in rows:
        expiry = row.expiry
        key = str(uuid5(NAMESPACE_URL, f"wise-sso:expiry-notice:{row.id}:{expiry.isoformat()}"))
        # Commit the claim before contacting SMTP. An uncertain attempt is never replayed.
        async with database.engine.begin() as connection:
            claim = await connection.execute(
                _CLAIM, {"id": key, "inviter": row.inviter_id, "guest": row.id, "now": now}
            )
            claimed = claim.scalar_one_or_none() is not None
        if not claimed:
            continue

        expires_kst = expiry.replace(tzinfo=UTC).astimezone(_KST).strftime("%Y-%m-%d %H:%M KST")
        try:
            await mail.send_external_expiry_notice(to=row.recipient, expires_kst=expires_kst)
        except Exception:
            failed += 1
            outcome = "failure"
        else:
            sent += 1
            outcome = "success"

        async with database.engine.begin() as connection:
            await connection.execute(_FINISH, {"id": key, "outcome": outcome})

    return sent, failed


async def _run() -> int:
    settings = get_settings()
    if settings.mail_provider == "dev":
        print("expiry-notices: skipped (MAIL_PROVIDER=dev)")
        return 0

    mail = create_mail_service(settings)
    if not isinstance(mail, SmtpMailService):
        raise TypeError("Expiry notifications require an SMTP mail adapter")

    database = Database(_database_url(os.environ))
    try:
        sent, failed = await notify_due_accounts(database, mail)
    finally:
        await database.close()
    print(f"expiry-notices: sent={sent} failed={failed}")
    return int(failed != 0)


def cli() -> None:
    try:
        status = asyncio.run(_run())
    except Exception as error:
        sys.stderr.write(f"expiry-notices failed: {type(error).__name__}\\n")
        raise SystemExit(1) from None
    raise SystemExit(status)


if __name__ == "__main__":
    cli()
