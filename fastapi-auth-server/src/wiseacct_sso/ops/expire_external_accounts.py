"""Revoke what expired external accounts still hold and record each expiry.

Authentication already rejects expired accounts on every path; this command only
cleans up refresh tokens and central SSO sessions and writes the audit record.
Run it periodically (for example every 10 minutes). It is idempotent.
"""

from __future__ import annotations

import asyncio
import os
import sys

from wiseacct_sso.application.external_accounts import expire_due_accounts
from wiseacct_sso.ops.audit_cleanup import _database_url
from wiseacct_sso.persistence.database import Database


async def _run(database_url: str) -> int:
    database = Database(database_url)
    try:
        return await expire_due_accounts(database)
    finally:
        await database.close()


def cli() -> None:
    try:
        count = asyncio.run(_run(_database_url(os.environ)))
    except Exception as error:
        sys.stderr.write(f"expire-external-accounts failed: {type(error).__name__}\n")
        raise SystemExit(1) from None
    print(f"expire-external-accounts recorded {count} newly expired accounts")


if __name__ == "__main__":
    cli()
