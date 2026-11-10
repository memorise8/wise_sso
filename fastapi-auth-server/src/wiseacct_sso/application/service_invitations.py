"""External-account invitations requested by a trusted service (agent-hub) on someone's behalf.

Same rules as the admin portal's external-account panel: whole-day terms up to 365 days and
only gitlab:user as a service role. The calling service is recorded in every audit entry.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol, cast
from urllib.parse import urlsplit

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.invitations import (
    INVITATION_TTL,
    EmployeeInvitationService,
    token_hash,
)
from wiseacct_sso.domain.auth import normalize_email
from wiseacct_sso.domain.external_accounts import assert_term_days, initial_expiry
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmployeeInvitation,
    Role,
    User,
    UserRole,
    application_uuid,
)

ServiceInviteStatus = Literal["invited", "exists_external", "exists_employee"]
GITLAB_ROLE = {"serviceKey": "gitlab", "name": "user"}
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


class ServiceNoticeMailer(Protocol):
    async def send_service_access_notice(self, *, to: str, service_url: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ServiceInvitationRequest:
    email: str
    days: int
    gitlab: bool
    return_to: str
    invited_by: str
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ServiceInvitationResult:
    status: ServiceInviteStatus
    invitation_id: str | None = None
    expires_at: datetime | None = None
    account_type: str | None = None
    account_status: str | None = None


def allowed_return_to(url: str, prefixes: tuple[str, ...]) -> bool:
    if len(url) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 or c == "\\" for c in url):
        return False
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        return False
    return any(url.startswith(prefix) for prefix in prefixes)


def _clean_text(value: str, limit: int, field: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > limit or any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
        raise DomainError(400, "INVALID_REQUEST", f"Invalid {field}")
    return cleaned


class ServiceInvitationService:
    def __init__(
        self,
        invitations: EmployeeInvitationService,
        notices: ServiceNoticeMailer,
        return_to_prefixes: tuple[str, ...],
    ) -> None:
        self.invitations = invitations
        self.notices = notices
        self.return_to_prefixes = return_to_prefixes

    @property
    def clock(self) -> Callable[[], datetime]:
        return self.invitations.clock

    async def invite(
        self, client_id: str, request: ServiceInvitationRequest
    ) -> ServiceInvitationResult:
        email = normalize_email(request.email)
        if _EMAIL.fullmatch(email) is None or len(email) > 320:
            raise DomainError(400, "INVALID_REQUEST", "Invalid email")
        assert_term_days(request.days)
        if not allowed_return_to(request.return_to, self.return_to_prefixes):
            raise DomainError(400, "INVALID_RETURN_TO", "return_to is not an allowed address")
        invited_by = _clean_text(request.invited_by, 200, "invited_by")
        note = (
            None
            if request.note is None or not request.note.strip()
            else _clean_text(request.note, 500, "note")
        )
        now = self.clock()
        requested_expiry = initial_expiry(now, request.days)
        details: dict[str, object] = {
            "clientId": client_id,
            "invitedBy": invited_by,
            "returnTo": request.return_to,
            "days": request.days,
            "gitlab": request.gitlab,
            **({"note": note} if note else {}),
        }
        token = secrets.token_urlsafe(32)
        async with self.invitations.database().engine.begin() as conn:
            user = (
                await conn.execute(
                    select(User.c.id, User.c.userType, User.c.status, User.c.accountExpiresAt)
                    .where(User.c.email == email)
                    .with_for_update()
                )
            ).first()
            if user is not None:
                if user.userType != "EXTERNAL":
                    account_type = str(user.userType).lower() if user.userType else "unclassified"
                    await self._audit(conn, "skipped", details, target=str(user.id))
                    return ServiceInvitationResult(
                        "exists_employee",
                        account_type=account_type,
                        account_status=str(user.status),
                    )
                current = cast(datetime | None, user.accountExpiresAt)
                expiry = requested_expiry if current is None else max(current, requested_expiry)
                if expiry != current:
                    await conn.execute(
                        update(User)
                        .where(User.c.id == user.id)
                        .values(accountExpiresAt=expiry, updatedAt=now)
                    )
                gitlab_added = request.gitlab and await self._grant_gitlab(conn, str(user.id))
                await self._audit(
                    conn,
                    "account_extended",
                    {
                        **details,
                        "previousExpiresAt": None if current is None else current.isoformat() + "Z",
                        "accountExpiresAt": expiry.isoformat() + "Z",
                        "gitlabAdded": gitlab_added,
                    },
                    target=str(user.id),
                )
                result = ServiceInvitationResult(
                    "exists_external",
                    expires_at=expiry,
                    account_type="external",
                    account_status=str(user.status),
                )
                notice_to = email
            else:
                pending = (
                    await conn.execute(
                        select(
                            EmployeeInvitation.c.id,
                            EmployeeInvitation.c.kind,
                            EmployeeInvitation.c.roles,
                            EmployeeInvitation.c.accountExpiresAt,
                        )
                        .where(
                            EmployeeInvitation.c.email == email,
                            EmployeeInvitation.c.status == "PENDING",
                            EmployeeInvitation.c.expiresAt > now,
                        )
                        .with_for_update()
                    )
                ).first()
                if pending is not None and pending.kind != "EXTERNAL":
                    await self._audit(conn, "skipped", {**details, "pendingInvitation": "EMPLOYEE"})
                    return ServiceInvitationResult("exists_employee", account_type="employee")
                roles = [GITLAB_ROLE] if request.gitlab else []
                if pending is not None:
                    invitation_id = str(pending.id)
                    previous = cast(datetime, pending.accountExpiresAt)
                    expiry = max(previous, requested_expiry)
                    held = cast(list[dict[str, str]], pending.roles)
                    merged = held + [role for role in roles if role not in held]
                    await conn.execute(
                        update(EmployeeInvitation)
                        .where(EmployeeInvitation.c.id == invitation_id)
                        .values(
                            tokenHash=token_hash(token),
                            roles=merged,
                            accountExpiresAt=expiry,
                            returnTo=request.return_to,
                            expiresAt=now + INVITATION_TTL,
                            deliveredAt=None,
                            updatedAt=now,
                        )
                    )
                    action = "resent"
                else:
                    invitation_id, expiry = application_uuid(), requested_expiry
                    await conn.execute(
                        insert(EmployeeInvitation).values(
                            id=invitation_id,
                            email=email,
                            name=email.split("@", 1)[0],
                            roles=roles,
                            kind="EXTERNAL",
                            accountExpiresAt=expiry,
                            returnTo=request.return_to,
                            tokenHash=token_hash(token),
                            status="PENDING",
                            expiresAt=now + INVITATION_TTL,
                            createdAt=now,
                            updatedAt=now,
                        )
                    )
                    action = "created"
                await self._audit(
                    conn,
                    "invitation_" + action,
                    {
                        **details,
                        "invitationId": invitation_id,
                        "accountExpiresAt": expiry.isoformat() + "Z",
                    },
                )
                result = ServiceInvitationResult(
                    "invited", invitation_id=invitation_id, expires_at=expiry
                )
                notice_to = None
        if notice_to is not None:
            await self._notify(notice_to, request.return_to, details)
        elif result.invitation_id is not None:
            await self.invitations._deliver(result.invitation_id, email, token, "EXTERNAL")
        return result

    async def _grant_gitlab(self, conn: AsyncConnection, user_id: str) -> bool:
        await conn.execute(
            pg_insert(Role)
            .values(id=application_uuid(), **GITLAB_ROLE)
            .on_conflict_do_nothing(index_elements=[Role.c.serviceKey, Role.c.name])
        )
        role_id = (
            await conn.execute(
                select(Role.c.id).where(Role.c.serviceKey == "gitlab", Role.c.name == "user")
            )
        ).scalar_one()
        inserted = await conn.execute(
            pg_insert(UserRole)
            .values(id=application_uuid(), userId=user_id, roleId=role_id)
            .on_conflict_do_nothing(index_elements=[UserRole.c.userId, UserRole.c.roleId])
            .returning(UserRole.c.id)
        )
        return inserted.first() is not None

    async def _notify(self, email: str, url: str, details: dict[str, object]) -> None:
        try:
            await self.notices.send_service_access_notice(to=email, service_url=url)
        except Exception:
            async with self.invitations.database().engine.begin() as conn:
                await self._audit(conn, "notice_failed", details, outcome="failure")
            raise DomainError(
                503, "NOTICE_DELIVERY_FAILED", "The account was updated but the mail was not sent"
            ) from None

    async def _audit(
        self,
        conn: AsyncConnection,
        action: str,
        details: dict[str, object],
        *,
        target: str | None = None,
        outcome: str = "success",
    ) -> None:
        await conn.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType="service_external_" + action,
                outcome=outcome,
                targetUserId=target,
                reasonCode="SERVICE_INVITE",
                detailsJson=details,
                createdAt=self.clock(),
            )
        )
