"""Employee invitations: no account linking, plaintext token storage, or admin passwords."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Protocol, cast

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.auth import PasswordPolicy, assert_password_policy, normalize_email
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmployeeInvitation,
    PasswordCredential,
    Role,
    User,
    UserRole,
    UserStatus,
    application_uuid,
    utc_now_ms,
)

INVITATION_TTL = timedelta(hours=72)
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class InvitationMailer(Protocol):
    async def send_employee_invitation(self, *, to: str, invitation_url: str) -> None: ...


def validate_roles(roles: list[dict[str, str]]) -> list[dict[str, str]]:
    if not 1 <= len(roles) <= 32:
        raise DomainError(400, "INVALID_ROLE", "Select 1 to 32 service roles")
    normalized: list[dict[str, str]] = []
    for role in roles:
        key, name = role.get("serviceKey", ""), role.get("name", "")
        if any(not v or v != v.strip() or len(v) > 64 or ":" in v for v in (key, name)):
            raise DomainError(400, "INVALID_ROLE", "Invalid service role")
        if (key, name) == ("temis", "admin"):
            raise DomainError(
                403, "LEGACY_ADMIN_ROLE_DISABLED", "New temis:admin grants are disabled"
            )
        if role in normalized:
            raise DomainError(400, "INVALID_ROLE", "Duplicate role")
        normalized.append({"serviceKey": key, "name": name})
    return normalized


def token_hash(token: str) -> str:
    if not _TOKEN.fullmatch(token):
        raise DomainError(400, "INVALID_INVITATION", "Invitation is invalid or expired")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def require_pending(row: Mapping[str, object], now: datetime) -> None:
    if row["status"] != "PENDING" or cast(datetime, row["expiresAt"]) <= now:
        raise DomainError(400, "INVALID_INVITATION", "Invitation is invalid or expired")


class EmployeeInvitationService:
    def __init__(
        self,
        *,
        database: Callable[[], Database],
        admin: Phase6AdminService,
        mail: InvitationMailer,
        origin: str,
        policy: PasswordPolicy,
        clock: Callable[[], datetime] = utc_now_ms,
    ) -> None:
        self.database, self.admin, self.mail = database, admin, mail
        self.origin, self.policy, self.clock = origin, policy, clock
        self.passwords = AsyncPasswordHasher()

    async def _audit(
        self,
        connection: AsyncConnection,
        action: str,
        invitation_id: str,
        actor: str | None,
        *,
        target: str | None = None,
        outcome: str = "success",
    ) -> None:
        await connection.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType="employee_invitation_" + action,
                outcome=outcome,
                userId=actor,
                actorUserId=actor,
                targetUserId=target,
                reasonCode="EMPLOYEE_INVITATION",
                detailsJson={"invitationId": invitation_id},
                createdAt=self.clock(),
            )
        )

    async def list_invitations(self, actor: str) -> list[dict[str, object]]:
        async with self.database().engine.begin() as conn:
            await self.admin._authorize_mutation(conn, actor, actor)
            rows = (
                (
                    await conn.execute(
                        select(
                            EmployeeInvitation.c.id,
                            EmployeeInvitation.c.email,
                            EmployeeInvitation.c.name,
                            EmployeeInvitation.c.roles,
                            EmployeeInvitation.c.status,
                            EmployeeInvitation.c.expiresAt,
                            EmployeeInvitation.c.deliveredAt,
                        )
                        .order_by(EmployeeInvitation.c.createdAt.desc())
                        .limit(100)
                    )
                )
                .mappings()
                .all()
            )
            return [
                {k: v.isoformat() if isinstance(v, datetime) else v for k, v in row.items()}
                for row in rows
            ]

    async def create(
        self,
        actor: str,
        email: str,
        name: str,
        roles: list[dict[str, str]],
    ) -> str:
        email = normalize_email(email)
        if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) is None or len(email) > 320:
            raise DomainError(400, "INVALID_EMAIL", "Invalid email")
        if not name.strip() or len(name) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise DomainError(400, "INVALID_REQUEST", "Name is required")
        roles = validate_roles(roles)
        invitation_id, token, now = application_uuid(), secrets.token_urlsafe(32), self.clock()
        async with self.database().engine.begin() as conn:
            await self.admin._authorize_mutation(conn, actor, actor)
            if (await conn.execute(select(User.c.id).where(User.c.email == email))).first():
                raise DomainError(409, "ACCOUNT_EXISTS", "Use the existing account management flow")
            pending = (
                await conn.execute(
                    select(EmployeeInvitation.c.id).where(
                        EmployeeInvitation.c.email == email,
                        EmployeeInvitation.c.status == "PENDING",
                        EmployeeInvitation.c.expiresAt > now,
                    )
                )
            ).first()
            if pending:
                raise DomainError(
                    409, "INVITATION_EXISTS", "Resend or cancel the existing invitation"
                )
            await conn.execute(
                insert(EmployeeInvitation).values(
                    id=invitation_id,
                    email=email,
                    name=name.strip(),
                    roles=roles,
                    tokenHash=token_hash(token),
                    status="PENDING",
                    expiresAt=now + INVITATION_TTL,
                    createdAt=now,
                    updatedAt=now,
                )
            )
            await self._audit(conn, "created", invitation_id, actor)
        await self._deliver(invitation_id, email, token)
        return invitation_id

    async def resend(self, actor: str, invitation_id: str) -> None:
        token, now = secrets.token_urlsafe(32), self.clock()
        async with self.database().engine.begin() as conn:
            await self.admin._authorize_mutation(conn, actor, actor)
            row = await self._locked(conn, invitation_id)
            if row["status"] != "PENDING":
                raise DomainError(409, "INVITATION_CLOSED", "Invitation is closed")
            if (await conn.execute(select(User.c.id).where(User.c.email == row["email"]))).first():
                raise DomainError(409, "ACCOUNT_EXISTS", "Use the existing account management flow")
            other = (
                await conn.execute(
                    select(EmployeeInvitation.c.id).where(
                        EmployeeInvitation.c.email == row["email"],
                        EmployeeInvitation.c.id != invitation_id,
                        EmployeeInvitation.c.status == "PENDING",
                        EmployeeInvitation.c.expiresAt > now,
                    )
                )
            ).first()
            if other:
                raise DomainError(409, "INVITATION_EXISTS", "Use the more recent invitation")
            await conn.execute(
                update(EmployeeInvitation)
                .where(EmployeeInvitation.c.id == invitation_id)
                .values(
                    tokenHash=token_hash(token),
                    expiresAt=now + INVITATION_TTL,
                    deliveredAt=None,
                    updatedAt=now,
                )
            )
            await self._audit(conn, "resent", invitation_id, actor)
        await self._deliver(invitation_id, str(row["email"]), token)

    async def cancel(self, actor: str, invitation_id: str) -> None:
        async with self.database().engine.begin() as conn:
            await self.admin._authorize_mutation(conn, actor, actor)
            row = await self._locked(conn, invitation_id)
            if row["status"] != "PENDING":
                raise DomainError(409, "INVITATION_CLOSED", "Invitation is closed")
            await conn.execute(
                update(EmployeeInvitation)
                .where(EmployeeInvitation.c.id == invitation_id)
                .values(
                    status="CANCELLED",
                    updatedAt=self.clock(),
                )
            )
            await self._audit(conn, "cancelled", invitation_id, actor)

    async def _locked(self, conn: AsyncConnection, invitation_id: str) -> Mapping[str, object]:
        row = (
            (
                await conn.execute(
                    select(EmployeeInvitation)
                    .where(EmployeeInvitation.c.id == invitation_id)
                    .with_for_update()
                )
            )
            .mappings()
            .first()
        )
        if row is None:
            raise DomainError(404, "INVITATION_NOT_FOUND", "Invitation not found")
        return dict(row)

    async def _deliver(self, invitation_id: str, email: str, token: str) -> None:
        try:
            await self.mail.send_employee_invitation(
                to=email,
                invitation_url=self.origin + "/oauth2/invitations/accept#token=" + token,
            )
        except Exception:
            async with self.database().engine.begin() as conn:
                await self._audit(conn, "delivery_failed", invitation_id, None, outcome="failure")
            raise DomainError(
                503,
                "INVITATION_DELIVERY_FAILED",
                "Resend the invitation after checking mail delivery",
            ) from None
        async with self.database().engine.begin() as conn:
            await conn.execute(
                update(EmployeeInvitation)
                .where(
                    EmployeeInvitation.c.id == invitation_id,
                    EmployeeInvitation.c.tokenHash == token_hash(token),
                    EmployeeInvitation.c.status == "PENDING",
                )
                .values(deliveredAt=self.clock())
            )

    async def accept(self, token: str, password: str) -> None:
        digest = token_hash(token)
        # Validate the token before doing memory-hard password work.
        async with self.database().connection() as conn:
            row = (
                (
                    await conn.execute(
                        select(EmployeeInvitation).where(EmployeeInvitation.c.tokenHash == digest)
                    )
                )
                .mappings()
                .first()
            )
            if row is None:
                raise DomainError(400, "INVALID_INVITATION", "Invitation is invalid or expired")
            require_pending(dict(row), self.clock())
            email = str(row["email"])
            assert_password_policy(email, password, self.policy)
        password_hash = await self.passwords.hash_password(password)
        try:
            async with self.database().engine.begin() as conn:
                row = (
                    (
                        await conn.execute(
                            select(EmployeeInvitation)
                            .where(EmployeeInvitation.c.tokenHash == digest)
                            .with_for_update()
                        )
                    )
                    .mappings()
                    .first()
                )
                if row is None:
                    raise DomainError(400, "INVALID_INVITATION", "Invitation is invalid or expired")
                now = self.clock()
                require_pending(dict(row), now)
                if row["deliveredAt"] is None:
                    raise DomainError(
                        400, "INVALID_INVITATION", "Invitation has not been delivered"
                    )
                if (await conn.execute(select(User.c.id).where(User.c.email == email))).first():
                    raise DomainError(
                        409, "ACCOUNT_EXISTS", "Use the existing account management flow"
                    )
                user_id = application_uuid()
                await conn.execute(
                    insert(User).values(
                        id=user_id,
                        email=email,
                        name=row["name"],
                        userType="EMPLOYEE",
                        status=UserStatus.ACTIVE,
                        emailVerified=True,
                        createdAt=now,
                        updatedAt=now,
                    )
                )
                await conn.execute(
                    insert(PasswordCredential).values(
                        id=application_uuid(),
                        userId=user_id,
                        email=email,
                        passwordHash=password_hash,
                        passwordUpdatedAt=now,
                        createdAt=now,
                        updatedAt=now,
                    )
                )
                roles = validate_roles(cast(list[dict[str, str]], row["roles"]))
                for role in roles:
                    await conn.execute(
                        pg_insert(Role)
                        .values(
                            id=application_uuid(), serviceKey=role["serviceKey"], name=role["name"]
                        )
                        .on_conflict_do_nothing(index_elements=[Role.c.serviceKey, Role.c.name])
                    )
                    role_id = (
                        await conn.execute(
                            select(Role.c.id).where(
                                Role.c.serviceKey == role["serviceKey"], Role.c.name == role["name"]
                            )
                        )
                    ).scalar_one()
                    await conn.execute(
                        insert(UserRole).values(
                            id=application_uuid(), userId=user_id, roleId=role_id
                        )
                    )
                await conn.execute(
                    update(EmployeeInvitation)
                    .where(EmployeeInvitation.c.id == row["id"])
                    .values(status="ACCEPTED", updatedAt=now)
                )
                await self._audit(conn, "accepted", str(row["id"]), None, target=user_id)
        except IntegrityError:
            raise DomainError(
                409, "ACCOUNT_EXISTS", "Use the existing account management flow"
            ) from None
