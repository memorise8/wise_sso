"""Service-issued external invitations against a real, migrated, disposable PostgreSQL.

Run with WISEACCT_SERVICE_INVITE_DATABASE_URL pointing at a throwaway database on localhost
whose name contains _test_ (all Prisma migrations applied).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import cast
from urllib.parse import urlparse

import pytest
from sqlalchemy import delete, insert, select, text

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.application.invitations import EmployeeInvitationService
from wiseacct_sso.application.service_invitations import (
    ServiceInvitationRequest,
    ServiceInvitationService,
)
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.external_accounts import initial_expiry
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.mail import FakeMailService
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmployeeInvitation,
    User,
    UserRole,
)

URL = os.getenv("WISEACCT_SERVICE_INVITE_DATABASE_URL", "")
RETURN = "https://dash.temis.me/invite/abc"
NOW = datetime(2026, 11, 11, 1, 0)


def _disposable(raw: str) -> bool:
    parsed = urlparse(raw)
    return parsed.hostname in {"127.0.0.1", "localhost"} and "_test_" in parsed.path


pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not URL or not _disposable(URL), reason="needs a disposable test DB"),
]


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    db = Database(URL)
    async with db.engine.begin() as conn:
        for table in (AuditLog, UserRole, EmployeeInvitation):
            await conn.execute(delete(table))
        await conn.execute(text('DELETE FROM "PasswordCredential"'))
        await conn.execute(delete(User))
    try:
        yield db
    finally:
        await db.close()


class Passwords:
    async def hash_password(self, value: str) -> str:
        return "argon2-test-hash"


def services(
    db: Database, clock: list[datetime]
) -> tuple[ServiceInvitationService, EmployeeInvitationService, FakeMailService]:
    mail = FakeMailService()
    invitations = EmployeeInvitationService(
        database=lambda: db,
        admin=cast(Phase6AdminService, object()),
        mail=mail,
        origin="https://auth.example.test",
        policy=PasswordPolicy(min_length=8, allowed_email_domain=None),
        clock=lambda: clock[0],
        return_to_prefixes=("https://dash.temis.me/invite/",),
    )
    invitations.passwords = cast(object, Passwords())  # type: ignore[assignment]
    return (
        ServiceInvitationService(invitations, mail, invitations.return_to_prefixes),
        invitations,
        mail,
    )


def request(**overrides: object) -> ServiceInvitationRequest:
    values: dict[str, object] = {
        "email": "Dev@Partner.test",
        "days": 30,
        "gitlab": True,
        "return_to": RETURN,
        "invited_by": "ruci@hub",
    }
    values.update(overrides)
    return ServiceInvitationRequest(**values)  # type: ignore[arg-type]


async def audit_events(db: Database) -> list[tuple[str, dict[str, object]]]:
    async with db.connection() as conn:
        rows = await conn.execute(
            select(AuditLog.c.eventType, AuditLog.c.detailsJson).order_by(AuditLog.c.createdAt)
        )
        return [(row.eventType, row.detailsJson) for row in rows]


async def test_invite_reuse_accept_then_extend(database: Database) -> None:
    clock = [NOW]
    service, invitations, mail = services(database, clock)

    first = await service.invite("agent-hub-service", request())
    assert first.status == "invited" and first.expires_at == initial_expiry(NOW, 30)
    assert (
        mail.messages[-1].kind == "employee-invitation"
        and mail.messages[-1].to == "dev@partner.test"
    )

    clock[0] = NOW + timedelta(hours=1)
    again = await service.invite(
        "agent-hub-service", request(days=60, gitlab=False, return_to=RETURN + "2")
    )
    assert again.status == "invited" and again.invitation_id == first.invitation_id
    assert again.expires_at == initial_expiry(clock[0], 60)
    async with database.connection() as conn:
        rows = (await conn.execute(select(EmployeeInvitation))).mappings().all()
    assert len(rows) == 1
    assert rows[0]["returnTo"] == RETURN + "2" and rows[0]["roles"] == [
        {"serviceKey": "gitlab", "name": "user"}
    ]
    old_token = mail.messages[0].link.split("#token=")[1]
    with pytest.raises(DomainError):
        await invitations.accept(old_token, "a-strong-password")
    token = mail.messages[-1].link.split("#token=")[1]
    assert await invitations.accept(token, "a-strong-password") == RETURN + "2"

    clock[0] = NOW + timedelta(days=1)
    shorter = await service.invite("agent-hub-service", request(days=5, gitlab=True))
    assert shorter.status == "exists_external"
    assert shorter.expires_at == again.expires_at  # never shortened
    assert shorter.account_status == "ACTIVE"
    notice = mail.messages[-1]
    assert str(notice.kind) == "service-access-notice"
    assert notice.link == RETURN
    longer = await service.invite("agent-hub-service", request(days=200))
    assert longer.expires_at == initial_expiry(clock[0], 200)

    events = [event for event, _ in await audit_events(database)]
    assert events[:2] == [
        "service_external_invitation_created",
        "service_external_invitation_resent",
    ]
    assert events.count("service_external_account_extended") == 2
    details = (await audit_events(database))[0][1]
    assert details["clientId"] == "agent-hub-service" and details["invitedBy"] == "ruci@hub"


async def test_existing_non_external_accounts_are_left_alone(database: Database) -> None:
    clock = [NOW]
    service, _, mail = services(database, clock)
    async with database.engine.begin() as conn:
        await conn.execute(
            insert(User).values(
                id="emp-1",
                email="staff@partner.test",
                status="ACTIVE",
                userType="EMPLOYEE",
                emailVerified=True,
                createdAt=NOW,
                updatedAt=NOW,
            )
        )
        await conn.execute(
            insert(User).values(
                id="cust-1",
                email="customer@partner.test",
                status="ACTIVE",
                emailVerified=True,
                createdAt=NOW,
                updatedAt=NOW,
            )
        )
    employee = await service.invite("agent-hub-service", request(email="staff@partner.test"))
    customer = await service.invite("agent-hub-service", request(email="customer@partner.test"))
    assert (employee.status, employee.account_type) == ("exists_employee", "employee")
    assert (customer.status, customer.account_type) == ("exists_employee", "unclassified")
    assert not mail.messages
    async with database.connection() as conn:
        assert (await conn.execute(select(EmployeeInvitation))).first() is None
        assert (await conn.execute(select(UserRole))).first() is None


async def test_external_gitlab_role_is_added_once(database: Database) -> None:
    clock = [NOW]
    service, _, _ = services(database, clock)
    expiry = initial_expiry(NOW, 10)
    async with database.engine.begin() as conn:
        await conn.execute(
            insert(User).values(
                id="ext-1",
                email="guest@partner.test",
                status="SUSPENDED",
                userType="EXTERNAL",
                accountExpiresAt=expiry,
                emailVerified=True,
                createdAt=NOW,
                updatedAt=NOW,
            )
        )
    for _ in range(2):
        result = await service.invite("agent-hub-service", request(email="guest@partner.test"))
        assert result.status == "exists_external" and result.account_status == "SUSPENDED"
    async with database.connection() as conn:
        roles = (await conn.execute(select(UserRole).where(UserRole.c.userId == "ext-1"))).all()
        status = (
            await conn.execute(select(User.c.status).where(User.c.id == "ext-1"))
        ).scalar_one()
    assert len(roles) == 1 and status == "SUSPENDED"


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"return_to": "https://evil.test/invite/"}, "INVALID_RETURN_TO"),
        ({"return_to": "https://dash.temis.me/other"}, "INVALID_RETURN_TO"),
        ({"return_to": "https://dash.temis.me/invite/\nx"}, "INVALID_RETURN_TO"),
        ({"days": 0}, "INVALID_ACCOUNT_TERM"),
        ({"days": 366}, "INVALID_ACCOUNT_TERM"),
        ({"email": "not-an-email"}, "INVALID_REQUEST"),
        ({"invited_by": " "}, "INVALID_REQUEST"),
    ],
)
async def test_requests_are_validated(
    database: Database, overrides: dict[str, object], code: str
) -> None:
    service, _, _ = services(database, [NOW])
    with pytest.raises(DomainError) as caught:
        await service.invite("agent-hub-service", request(**overrides))
    assert caught.value.code == code
