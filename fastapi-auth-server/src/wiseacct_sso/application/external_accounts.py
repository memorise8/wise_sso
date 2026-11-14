"""Administration of time-limited external accounts.

Creation goes through the invitation flow (kind EXTERNAL). Every authentication path
rejects an account once `accountExpiresAt` passes; `expire_due_accounts` also revokes
what was issued before expiry and records the expiry once.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import cast

from sqlalchemy import and_, exists, insert, select, update
from sqlalchemy import func as sql_count
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.external_accounts import extended_expiry
from wiseacct_sso.domain.users import DomainError, UserStatus, UserType
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    RefreshToken,
    Role,
    User,
    UserRole,
    application_uuid,
    utc_now_ms,
)

EXTERNAL_ACCOUNT_LIST_LIMIT = 50


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat(timespec="milliseconds") + "Z"


def _reason(reason: str) -> str:
    reason = reason.strip()
    if not reason or len(reason) > 128:
        raise DomainError(400, "INVALID_REQUEST", "A reason is required")
    return reason


class ExternalAccountService:
    def __init__(
        self,
        *,
        database: Callable[[], Database],
        admin: Phase6AdminService,
        clock: Callable[[], datetime] = utc_now_ms,
    ) -> None:
        self.database, self.admin, self.clock = database, admin, clock

    async def list_accounts(
        self, actor: str, *, page: int = 1, expires_within: int | None = None
    ) -> dict[str, object]:
        if page < 1 or expires_within not in {None, 7, 30}:
            raise DomainError(400, "INVALID_REQUEST", "Invalid external account filters")
        now = self.clock()
        conditions = [User.c.userType == UserType.EXTERNAL]
        if expires_within is not None:
            conditions.extend(
                (
                    User.c.accountExpiresAt > now,
                    User.c.accountExpiresAt <= now + timedelta(days=expires_within),
                )
            )
        async with self.database().engine.begin() as conn:
            await self.admin._authorize_mutation(conn, actor, actor)
            total = (
                await conn.execute(select(sql_count.count()).select_from(User).where(*conditions))
            ).scalar_one()
            inviter = User.alias("external_inviter")
            users = (
                await conn.execute(
                    select(
                        User.c.id,
                        User.c.email,
                        User.c.name,
                        User.c.status,
                        User.c.accountExpiresAt,
                        User.c.createdAt,
                        User.c.externalInvitedById,
                        User.c.externalCompany,
                        User.c.externalProject,
                        inviter.c.email.label("inviterEmail"),
                    )
                    .select_from(
                        User.outerjoin(inviter, User.c.externalInvitedById == inviter.c.id)
                    )
                    .where(*conditions)
                    .order_by(User.c.accountExpiresAt.asc(), User.c.id.asc())
                    .limit(EXTERNAL_ACCOUNT_LIST_LIMIT)
                    .offset((page - 1) * EXTERNAL_ACCOUNT_LIST_LIMIT)
                )
            ).all()
            roles = (
                await conn.execute(
                    select(UserRole.c.userId, Role.c.serviceKey, Role.c.name)
                    .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
                    .where(UserRole.c.userId.in_([str(user.id) for user in users]))
                )
            ).all()
        items = [
            {
                "id": str(user.id),
                "email": user.email,
                "name": user.name,
                "status": str(user.status),
                "accountExpiresAt": _iso(user.accountExpiresAt),
                "expired": user.accountExpiresAt is not None and user.accountExpiresAt <= now,
                "createdAt": _iso(user.createdAt),
                "invitedById": user.externalInvitedById,
                "inviterEmail": user.inviterEmail,
                "company": user.externalCompany,
                "project": user.externalProject,
                "roles": sorted(
                    f"{role.serviceKey}:{role.name}" for role in roles if role.userId == user.id
                ),
            }
            for user in users
        ]
        return {
            "items": items,
            "total": total,
            "page": page,
            "pageSize": EXTERNAL_ACCOUNT_LIST_LIMIT,
        }

    async def extend(self, actor: str, user_id: str, days: int, reason: str) -> datetime:
        reason = _reason(reason)
        now = self.clock()
        async with self.database().engine.begin() as conn:
            return await self._extend_in_transaction(conn, actor, user_id, days, reason, now)

    async def extend_many(
        self, actor: str, user_ids: list[str], days: int, reason: str
    ) -> dict[str, datetime]:
        reason = _reason(reason)
        if (
            not 1 <= len(user_ids) <= 100
            or len(set(user_ids)) != len(user_ids)
            or any(not user_id.strip() for user_id in user_ids)
        ):
            raise DomainError(400, "INVALID_REQUEST", "Select 1 to 100 distinct accounts")

        now = self.clock()
        async with self.database().engine.begin() as conn:
            extended: dict[str, datetime] = {}
            # Lock targets in the same order across overlapping requests.
            for user_id in sorted(user_ids):
                extended[user_id] = await self._extend_in_transaction(
                    conn, actor, user_id, days, reason, now
                )
            return extended

    async def _extend_in_transaction(
        self,
        conn: AsyncConnection,
        actor: str,
        user_id: str,
        days: int,
        reason: str,
        now: datetime,
    ) -> datetime:
        user_type, _ = await self.admin._authorize_mutation(conn, actor, user_id)
        if user_type != UserType.EXTERNAL:
            raise DomainError(409, "NOT_EXTERNAL_ACCOUNT", "Only external accounts have a term")
        current = cast(
            datetime | None,
            (
                await conn.execute(select(User.c.accountExpiresAt).where(User.c.id == user_id))
            ).scalar_one(),
        )
        expiry = extended_expiry(now, current, days)
        await conn.execute(
            update(User).where(User.c.id == user_id).values(accountExpiresAt=expiry, updatedAt=now)
        )
        await conn.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType="external_account_extended",
                outcome="success",
                userId=actor,
                actorUserId=actor,
                targetUserId=user_id,
                reasonCode=reason,
                detailsJson={
                    "days": days,
                    "previousAccountExpiresAt": _iso(current),
                    "accountExpiresAt": _iso(expiry),
                },
                createdAt=now,
            )
        )
        return expiry

    async def update_memo(
        self, actor: str, user_id: str, *, company: str, project: str, reason: str
    ) -> None:
        reason = _reason(reason)
        company, project = company.strip(), project.strip()
        if len(company) > 200 or len(project) > 200:
            raise DomainError(400, "INVALID_REQUEST", "Memo fields must be at most 200 characters")

        now = self.clock()
        async with self.database().engine.begin() as conn:
            user_type, _ = await self.admin._authorize_mutation(conn, actor, user_id)
            if user_type != UserType.EXTERNAL:
                raise DomainError(409, "NOT_EXTERNAL_ACCOUNT", "Only external accounts have a memo")
            await conn.execute(
                update(User)
                .where(User.c.id == user_id)
                .values(
                    externalCompany=company or None, externalProject=project or None, updatedAt=now
                )
            )
            await conn.execute(
                insert(AuditLog).values(
                    id=application_uuid(),
                    eventType="external_account_memo_updated",
                    outcome="success",
                    userId=actor,
                    actorUserId=actor,
                    targetUserId=user_id,
                    reasonCode=reason,
                    createdAt=now,
                )
            )

    async def set_suspended(self, actor: str, user_id: str, suspended: bool, reason: str) -> None:
        reason = _reason(reason)
        async with self.database().engine.begin() as conn:
            user_type, _ = await self.admin._authorize_mutation(conn, actor, user_id)
        if user_type != UserType.EXTERNAL:
            raise DomainError(
                409, "NOT_EXTERNAL_ACCOUNT", "Only external accounts are managed here"
            )
        # The shared status change revokes refresh tokens and the central SSO session.
        await self.admin.set_user_status(
            actor_user_id=actor,
            target_user_id=user_id,
            status=UserStatus.SUSPENDED if suspended else UserStatus.ACTIVE,
            reason_code=reason,
            details={"externalAccount": True},
        )


async def expire_due_accounts(database: Database, now: datetime | None = None) -> int:
    """Revoke sessions of newly expired accounts and record each expiry once."""

    now = now or utc_now_ms()
    expired = 0
    async with database.engine.begin() as conn:
        already_recorded = exists().where(
            AuditLog.c.eventType == "external_account_expired",
            AuditLog.c.targetUserId == User.c.id,
            AuditLog.c.createdAt >= User.c.accountExpiresAt,
        )
        due = (
            await conn.execute(
                select(User.c.id, User.c.accountExpiresAt)
                .where(
                    User.c.userType == UserType.EXTERNAL,
                    User.c.accountExpiresAt <= now,
                    ~already_recorded,
                )
                .with_for_update(skip_locked=True)
            )
        ).all()
        for user in due:
            await _revoke(conn, str(user.id), now)
            await conn.execute(
                insert(AuditLog).values(
                    id=application_uuid(),
                    eventType="external_account_expired",
                    outcome="success",
                    userId=None,
                    actorUserId=None,
                    targetUserId=str(user.id),
                    reasonCode="ACCOUNT_TERM_ENDED",
                    detailsJson={"accountExpiresAt": _iso(user.accountExpiresAt)},
                    createdAt=now,
                )
            )
            expired += 1
    return expired


async def _revoke(conn: AsyncConnection, user_id: str, now: datetime) -> None:
    await conn.execute(
        update(User)
        .where(User.c.id == user_id)
        .values(ssoSessionVersion=User.c.ssoSessionVersion + 1)
    )
    await conn.execute(
        update(RefreshToken)
        .where(and_(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None)))
        .values(revokedAt=now)
    )
