"""Password changes requested by a trusted service (dot-office hub) on a signed-in user's behalf.

The service relays the user's current and new password. The current password is verified with
the same hasher and lockout rules as the SSO login page, the new one must pass the same policy
as password-reset confirm, and success has the same effects as a reset: the hash is replaced,
the login lockout is cleared, every SSO session is ended and every refresh token is revoked.
Unknown, inactive, expired and locked accounts all answer ``invalid_current_password``.
Passwords are never logged or written to the audit trail.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from typing import NoReturn, Protocol

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.auth import PasswordPolicy, normalize_email
from wiseacct_sso.domain.external_accounts import is_expired
from wiseacct_sso.domain.password_reset import assert_reset_password_policy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import (
    AuditLog,
    PasswordCredential,
    RefreshToken,
    User,
    UserStatus,
    application_uuid,
    utc_now_ms,
)
from wiseacct_sso.persistence.stores import FailedLoginStore

PASSWORD_CHANGE_MAX_FAILURES = 5
PASSWORD_CHANGE_FAILURE_WINDOW_SECONDS = 15 * 60
LOGIN_LOCK_DURATION = timedelta(minutes=15)
EVENT_TYPE = "service_password_change"
_FAILURE_PREFIX = "wise:svc:pwchange:fail:"


class FailureCounter(Protocol):
    async def get_raw(self, key: str | bytes) -> bytes | None: ...

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int: ...


class PasswordVerifier(Protocol):
    async def hash_password(self, password: str) -> str: ...

    async def verify_password(self, password_hash: str, password: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class ServicePasswordChangeRequest:
    email: str
    current_password: str
    new_password: str

    def __repr__(self) -> str:
        return f"ServicePasswordChangeRequest(email={self.email!r}, passwords=<redacted>)"


def _invalid() -> DomainError:
    return DomainError(400, "invalid_current_password", "The current password is not correct")


class ServicePasswordChangeService:
    def __init__(
        self,
        *,
        database: Callable[[], Database],
        redis: FailureCounter,
        passwords: PasswordVerifier,
        policy: PasswordPolicy,
        clock: Callable[[], datetime] = utc_now_ms,
    ) -> None:
        self.database = database
        self.redis = redis
        self.passwords = passwords
        # Exactly the policy password-reset confirm applies (no company-domain rule).
        self.policy = PasswordPolicy(min_length=policy.min_length, allowed_email_domain=None)
        self.clock = clock
        self._failed_logins = FailedLoginStore()

    async def change(self, client_id: str, request: ServicePasswordChangeRequest) -> None:
        email = normalize_email(request.email)
        throttle_key = _FAILURE_PREFIX + sha256(email.encode("utf-8")).hexdigest()
        failures = await self.redis.get_raw(throttle_key)
        if failures is not None and int(failures) >= PASSWORD_CHANGE_MAX_FAILURES:
            await self._audit(client_id, None, "failure", "RATE_LIMITED")
            raise DomainError(429, "rate_limited", "Too many failed attempts; try again later")

        now = self.clock()
        async with self.database().connection() as conn:
            credential = (
                await conn.execute(
                    select(
                        PasswordCredential.c.userId,
                        PasswordCredential.c.passwordHash,
                        PasswordCredential.c.lockedUntil,
                        User.c.status,
                        User.c.accountExpiresAt,
                    )
                    .select_from(
                        PasswordCredential.join(User, PasswordCredential.c.userId == User.c.id)
                    )
                    .where(PasswordCredential.c.email == email)
                    .limit(1)
                )
            ).one_or_none()
            social_user = (
                None
                if credential is not None
                else (
                    await conn.execute(
                        select(User.c.id, User.c.status, User.c.accountExpiresAt)
                        .where(User.c.email == email)
                        .limit(1)
                    )
                ).one_or_none()
            )
        # Always pay for one hash check so unknown addresses are not distinguishable by timing.
        expected = DUMMY_PASSWORD_HASH if credential is None else str(credential.passwordHash)
        verified = await self.passwords.verify_password(expected, request.current_password)

        if credential is None:
            if (
                social_user is not None
                and social_user.status == UserStatus.ACTIVE
                and not is_expired(social_user.accountExpiresAt, now)
            ):
                await self._audit(client_id, str(social_user.id), "failure", "NO_PASSWORD")
                raise DomainError(
                    409, "no_password", "This account signs in without an SSO password"
                )
            await self._fail(client_id, throttle_key, None)

        user_id = str(credential.userId)
        active = credential.status == UserStatus.ACTIVE and not is_expired(
            credential.accountExpiresAt, now
        )
        locked = credential.lockedUntil is not None and credential.lockedUntil > now
        if not active or locked or not verified:
            if active and not locked:
                await self._record_login_failure(user_id, now)
            await self._fail(client_id, throttle_key, user_id)

        if request.new_password == request.current_password:
            await self._audit(client_id, user_id, "failure", "SAME_PASSWORD")
            raise DomainError(
                400, "same_password", "The new password must differ from the current one"
            )
        try:
            assert_reset_password_policy("", request.new_password, self.policy)
        except DomainError as error:
            await self._audit(client_id, user_id, "failure", "WEAK_PASSWORD")
            raise DomainError(400, "weak_password", error.message) from None

        new_hash = await self.passwords.hash_password(request.new_password)
        current_hash = str(credential.passwordHash)

        async def replace(conn: AsyncConnection) -> bool:
            locked_user = (
                await conn.execute(select(User.c.id).where(User.c.id == user_id).with_for_update())
            ).one_or_none()
            if locked_user is None:
                return False
            # Only replace the hash that was verified; a concurrent change wins.
            updated = await conn.execute(
                update(PasswordCredential)
                .where(
                    PasswordCredential.c.userId == user_id,
                    PasswordCredential.c.passwordHash == current_hash,
                )
                .values(
                    passwordHash=new_hash,
                    failedLoginCount=0,
                    lockedUntil=None,
                    passwordUpdatedAt=now,
                    updatedAt=now,
                )
            )
            if updated.rowcount != 1:
                return False
            await conn.execute(
                update(User)
                .where(User.c.id == user_id)
                .values(ssoSessionVersion=User.c.ssoSessionVersion + 1)
            )
            await conn.execute(
                update(RefreshToken)
                .where(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None))
                .values(revokedAt=now)
            )
            await self._insert_audit(conn, client_id, user_id, "success", None)
            return True

        if not await self.database().transaction(database_only_transaction(replace)):
            await self._fail(client_id, throttle_key, user_id)

    async def _fail(self, client_id: str, throttle_key: str, user_id: str | None) -> NoReturn:
        await self.redis.increment_with_ttl(throttle_key, PASSWORD_CHANGE_FAILURE_WINDOW_SECONDS)
        await self._audit(client_id, user_id, "failure", "INVALID_CURRENT_PASSWORD")
        raise _invalid()

    async def _record_login_failure(self, user_id: str, now: datetime) -> None:
        async def record(conn: AsyncConnection) -> None:
            await self._failed_logins.record_failure(
                conn, user_id=user_id, locked_until=now + LOGIN_LOCK_DURATION, updated_at=now
            )

        await self.database().transaction(database_only_transaction(record))

    async def _audit(
        self, client_id: str, user_id: str | None, outcome: str, reason: str | None
    ) -> None:
        async def write(conn: AsyncConnection) -> None:
            await self._insert_audit(conn, client_id, user_id, outcome, reason)

        await self.database().transaction(database_only_transaction(write))

    async def _insert_audit(
        self,
        conn: AsyncConnection,
        client_id: str,
        user_id: str | None,
        outcome: str,
        reason: str | None,
    ) -> None:
        await conn.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType=EVENT_TYPE,
                outcome=outcome,
                userId=user_id,
                targetUserId=user_id,
                reasonCode=reason,
                detailsJson={"clientId": client_id},
                createdAt=self.clock(),
            )
        )
