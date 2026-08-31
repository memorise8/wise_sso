"""Concurrency-sensitive SQL primitives shared with the Express implementation."""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.persistence.models import (
    PasswordCredential,
    RefreshToken,
    User,
    UserStatus,
)


@dataclass(frozen=True, slots=True)
class FailedLoginResult:
    found: bool
    failed_login_count: int | None
    locked_until: datetime | None


class FailedLoginStore:
    """Mirror Prisma's atomic increment then conditional threshold update."""

    async def record_failure(
        self,
        connection: AsyncConnection,
        *,
        user_id: str,
        locked_until: datetime,
        updated_at: datetime,
        threshold: int = 5,
    ) -> FailedLoginResult:
        if threshold < 1:
            raise ValueError("threshold must be positive")
        incremented = await connection.execute(
            update(PasswordCredential)
            .where(PasswordCredential.c.userId == user_id)
            .values(
                failedLoginCount=PasswordCredential.c.failedLoginCount + 1,
                updatedAt=updated_at,
            )
            .returning(PasswordCredential.c.failedLoginCount)
        )
        if incremented.rowcount == 0:
            return FailedLoginResult(False, None, None)
        if incremented.rowcount != 1:
            raise RuntimeError("password credential increment count was not one")
        incremented_row = incremented.one_or_none()
        if incremented_row is None:
            raise RuntimeError("password credential increment did not return its count")

        locked = await connection.execute(
            update(PasswordCredential)
            .where(
                PasswordCredential.c.userId == user_id,
                PasswordCredential.c.failedLoginCount >= threshold,
            )
            .values(lockedUntil=locked_until, updatedAt=updated_at)
            .returning(PasswordCredential.c.lockedUntil)
        )
        if locked.rowcount not in {0, 1}:
            raise RuntimeError("password credential lock update count exceeded one")
        locked_row = locked.one_or_none()
        if locked.rowcount == 1 and locked_row is None:
            raise RuntimeError("password credential lock update did not return its timestamp")
        return FailedLoginResult(
            True,
            int(incremented_row.failedLoginCount),
            None if locked_row is None else locked_row.lockedUntil,
        )


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    user_id: str
    audience: str


@dataclass(frozen=True, slots=True)
class RefreshReplacement:
    id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime


class RefreshRotationConflict(RuntimeError):
    """Signal a lost conditional revoke so the enclosing transaction rolls back."""


class RefreshRotationStore:
    """Perform the Express-compatible read→user lock→conditional revoke→insert order."""

    async def rotate(
        self,
        connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: RefreshReplacement,
    ) -> RefreshTokenRecord | None:
        stored = (
            await connection.execute(
                select(RefreshToken.c.userId, RefreshToken.c.audience)
                .where(RefreshToken.c.tokenHash == old_token_hash)
                .limit(1)
            )
        ).one_or_none()
        if stored is None or stored.audience != expected_audience:
            return None

        locked_user = (
            await connection.execute(
                select(User.c.id)
                .where(User.c.id == stored.userId, User.c.status == UserStatus.ACTIVE)
                .with_for_update()
            )
        ).one_or_none()
        if locked_user is None:
            return None

        revoked = await connection.execute(
            update(RefreshToken)
            .where(
                RefreshToken.c.tokenHash == old_token_hash,
                RefreshToken.c.revokedAt.is_(None),
                RefreshToken.c.expiresAt > now,
            )
            .values(revokedAt=now)
        )
        if revoked.rowcount != 1:
            raise RefreshRotationConflict("refresh token conditional revoke count was not one")

        await connection.execute(
            insert(RefreshToken).values(
                id=replacement.id,
                tokenHash=replacement.token_hash,
                userId=stored.userId,
                audience=stored.audience,
                expiresAt=replacement.expires_at,
                createdAt=replacement.created_at,
            )
        )
        return RefreshTokenRecord(user_id=stored.userId, audience=stored.audience)
