"""Service-requested password changes against a real, migrated, disposable PostgreSQL.

Run with WISEACCT_SERVICE_PASSWORD_DATABASE_URL (or WISEACCT_SERVICE_INVITE_DATABASE_URL)
pointing at a throwaway database on localhost whose name contains _test_ (all Prisma
migrations applied).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import pytest
from sqlalchemy import delete, insert, select

from wiseacct_sso.application.service_password_change import (
    PASSWORD_CHANGE_MAX_FAILURES,
    ServicePasswordChangeRequest,
    ServicePasswordChangeService,
)
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    PasswordCredential,
    RefreshToken,
    SocialAccount,
    User,
)

URL = os.getenv("WISEACCT_SERVICE_PASSWORD_DATABASE_URL") or os.getenv(
    "WISEACCT_SERVICE_INVITE_DATABASE_URL", ""
)
NOW = datetime(2026, 11, 18, 1, 0)
CLIENT = "agent-hub-service"
CURRENT = "current-password-1"
NEW = "brand-new-password-2"


def _disposable(raw: str) -> bool:
    parsed = urlparse(raw)
    return parsed.hostname in {"127.0.0.1", "localhost"} and "_test_" in parsed.path


pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not URL or not _disposable(URL), reason="needs a disposable test DB"),
]

HASHER = AsyncPasswordHasher()


class FakeRedis:
    def __init__(self) -> None:
        self.counters: dict[Any, int] = {}

    async def get_raw(self, key: str | bytes) -> bytes | None:
        value = self.counters.get(key)
        return None if value is None else str(value).encode()

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    db = Database(URL)
    async with db.engine.begin() as conn:
        for table in (AuditLog, RefreshToken, SocialAccount, PasswordCredential):
            await conn.execute(delete(table))
        await conn.execute(delete(User))
    try:
        yield db
    finally:
        await db.close()


def service(
    db: Database, redis: FakeRedis | None = None, clock: list[datetime] | None = None
) -> tuple[ServicePasswordChangeService, FakeRedis]:
    fake = redis or FakeRedis()
    now = clock or [NOW]
    return (
        ServicePasswordChangeService(
            database=lambda: db,
            redis=fake,
            passwords=HASHER,
            policy=PasswordPolicy(min_length=8, allowed_email_domain=None),
            clock=lambda: now[0],
        ),
        fake,
    )


async def seed(
    db: Database,
    *,
    user_id: str = "user-1",
    email: str = "member@wise.test",
    password: str | None = CURRENT,
    status: str = "ACTIVE",
    expires_at: datetime | None = None,
    locked_until: datetime | None = None,
) -> str:
    async with db.engine.begin() as conn:
        await conn.execute(
            insert(User).values(
                id=user_id,
                email=email,
                status=status,
                emailVerified=True,
                accountExpiresAt=expires_at,
                createdAt=NOW,
                updatedAt=NOW,
            )
        )
        if password is not None:
            await conn.execute(
                insert(PasswordCredential).values(
                    id=f"cred-{user_id}",
                    userId=user_id,
                    email=email,
                    passwordHash=await HASHER.hash_password(password),
                    failedLoginCount=2,
                    lockedUntil=locked_until,
                    updatedAt=NOW,
                )
            )
        await conn.execute(
            insert(RefreshToken).values(
                id=f"rt-{user_id}",
                tokenHash=f"hash-{user_id}",
                userId=user_id,
                expiresAt=NOW + timedelta(days=7),
                createdAt=NOW,
            )
        )
    return user_id


def change(
    email: str = "member@wise.test", current: str = CURRENT, new: str = NEW
) -> ServicePasswordChangeRequest:
    return ServicePasswordChangeRequest(email=email, current_password=current, new_password=new)


async def credential(db: Database, user_id: str = "user-1") -> Any:
    async with db.connection() as conn:
        return (
            await conn.execute(
                select(PasswordCredential).where(PasswordCredential.c.userId == user_id)
            )
        ).one()


async def audits(db: Database) -> list[Any]:
    async with db.connection() as conn:
        return list(
            (await conn.execute(select(AuditLog).order_by(AuditLog.c.createdAt))).mappings().all()
        )


async def code_of(svc: ServicePasswordChangeService, request: ServicePasswordChangeRequest) -> str:
    with pytest.raises(DomainError) as caught:
        await svc.change(CLIENT, request)
    return caught.value.code


async def test_success_sets_new_hash_and_revokes_sessions(database: Database) -> None:
    await seed(database)
    svc, _ = service(database)

    await svc.change(CLIENT, change(email=" Member@Wise.TEST "))

    row = await credential(database)
    assert await HASHER.verify_password(row.passwordHash, NEW)
    assert not await HASHER.verify_password(row.passwordHash, CURRENT)
    assert row.failedLoginCount == 0 and row.lockedUntil is None
    assert row.passwordUpdatedAt == NOW
    async with database.connection() as conn:
        version = (
            await conn.execute(select(User.c.ssoSessionVersion).where(User.c.id == "user-1"))
        ).scalar_one()
        revoked = (
            await conn.execute(
                select(RefreshToken.c.revokedAt).where(RefreshToken.c.userId == "user-1")
            )
        ).scalar_one()
    assert version == 1 and revoked == NOW
    events = await audits(database)
    assert [(e["eventType"], e["outcome"]) for e in events] == [
        ("service_password_change", "success")
    ]
    assert events[0]["userId"] == "user-1" and events[0]["targetUserId"] == "user-1"
    assert events[0]["detailsJson"] == {"clientId": CLIENT}
    # Passwords never reach the audit trail.
    assert CURRENT not in str(events) and NEW not in str(events)


async def test_wrong_and_unknown_look_the_same(database: Database) -> None:
    await seed(database)
    svc, _ = service(database)
    assert await code_of(svc, change(current="wrong-password")) == "invalid_current_password"
    assert await code_of(svc, change(email="nobody@wise.test")) == "invalid_current_password"
    row = await credential(database)
    assert await HASHER.verify_password(row.passwordHash, CURRENT)
    # A wrong guess on a real account counts toward the login lockout, like the login page.
    assert row.failedLoginCount == 3
    events = await audits(database)
    assert [(e["outcome"], e["reasonCode"]) for e in events] == [
        ("failure", "INVALID_CURRENT_PASSWORD"),
        ("failure", "INVALID_CURRENT_PASSWORD"),
    ]
    assert "wrong-password" not in str(events)


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "SUSPENDED"},
        {"status": "PENDING_EMAIL_VERIFICATION"},
        {"expires_at": NOW - timedelta(seconds=1)},
        {"locked_until": NOW + timedelta(minutes=5)},
    ],
)
async def test_inactive_expired_or_locked_accounts_are_rejected(
    database: Database, overrides: dict[str, Any]
) -> None:
    await seed(database, **overrides)
    svc, _ = service(database)
    assert await code_of(svc, change()) == "invalid_current_password"
    assert await HASHER.verify_password((await credential(database)).passwordHash, CURRENT)


async def test_unexpired_external_account_can_change(database: Database) -> None:
    await seed(database, expires_at=NOW + timedelta(days=3))
    svc, _ = service(database)
    await svc.change(CLIENT, change())
    assert await HASHER.verify_password((await credential(database)).passwordHash, NEW)


async def test_social_only_account_has_no_password(database: Database) -> None:
    await seed(database, password=None, email="social@wise.test", user_id="social-1")
    await seed(
        database, password=None, email="gone@wise.test", user_id="social-2", status="SUSPENDED"
    )
    svc, _ = service(database)
    assert await code_of(svc, change(email="social@wise.test")) == "no_password"
    # Inactive social accounts look like any unknown address.
    assert await code_of(svc, change(email="gone@wise.test")) == "invalid_current_password"


async def test_same_and_weak_passwords(database: Database) -> None:
    await seed(database)
    svc, _ = service(database)
    assert await code_of(svc, change(new=CURRENT)) == "same_password"
    assert await code_of(svc, change(new="short")) == "weak_password"
    # A wrong current password is reported first, so the new-password checks reveal nothing.
    assert await code_of(svc, change(current="wrong", new="short")) == "invalid_current_password"
    assert await HASHER.verify_password((await credential(database)).passwordHash, CURRENT)


async def test_failed_attempts_are_throttled_per_email(database: Database) -> None:
    await seed(database)
    await seed(database, user_id="user-2", email="other@wise.test")
    svc, redis = service(database)
    for _ in range(PASSWORD_CHANGE_MAX_FAILURES):
        assert await code_of(svc, change(current="wrong")) == "invalid_current_password"
    # Even the right password is refused while throttled.
    assert await code_of(svc, change()) == "rate_limited"
    for _ in range(PASSWORD_CHANGE_MAX_FAILURES):
        await code_of(svc, change(email="ghost@wise.test", current="wrong"))
    assert await code_of(svc, change(email="ghost@wise.test")) == "rate_limited"
    # Other addresses are unaffected.
    await svc.change(CLIENT, change(email="other@wise.test"))
    assert all(b"member@wise.test" not in str(key).encode() for key in redis.counters)
    reasons = [e["reasonCode"] for e in await audits(database)]
    assert reasons.count("RATE_LIMITED") == 2
