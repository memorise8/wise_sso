from __future__ import annotations

import copy
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Literal, cast
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy.sql import operators
from sqlalchemy.sql.dml import Insert, Update

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.application.invitations import (
    INVITATION_TTL,
    EmployeeInvitationService,
    token_hash,
    validate_roles,
)
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.mail import FakeMailService
from wiseacct_sso.persistence.database import Database

NOW = datetime(2026, 11, 4)
ROLES = [{"serviceKey": "gitlab", "name": "user"}]


class Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def first(self) -> dict[str, Any] | None:
        return self.rows[0] if self.rows else None

    def mappings(self) -> Result:
        return self

    def all(self) -> list[dict[str, Any]]:
        return self.rows

    def scalar_one(self) -> str:
        return str(self.rows[0]["id"])


class MemoryDatabase:
    """Transactional test adapter: execute real SQLAlchemy statements and record their values."""

    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {
            name: []
            for name in (
                "EmployeeInvitation",
                "User",
                "PasswordCredential",
                "Role",
                "UserRole",
                "AuditLog",
            )
        }
        self.engine = self
        self.fail_audit = False

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[MemoryDatabase]:
        snapshot = copy.deepcopy(self.tables)
        try:
            yield self
        except Exception:
            self.tables = snapshot
            raise

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[MemoryDatabase]:
        yield self

    async def execute(self, statement: Any) -> Result:
        params = statement.compile().params
        if isinstance(statement, Insert):
            name = cast(Any, statement.table).name
            if name == "AuditLog" and self.fail_audit:
                raise RuntimeError("audit unavailable")
            if name != "Role" or not any(
                r["serviceKey"] == params["serviceKey"] and r["name"] == params["name"]
                for r in self.tables[name]
            ):
                self.tables[name].append(dict(params))
            return Result([])
        name = (
            cast(Any, statement.table).name
            if isinstance(statement, Update)
            else cast(Any, statement.get_final_froms()[0]).name
        )
        rows = list(self.tables[name])
        # Named comparison binds come from real SQLAlchemy clauses, not interpolated SQL.
        for column in ("id", "email", "tokenHash", "status", "serviceKey", "name"):
            key = column + "_1"
            if key in params:
                not_equal = any(
                    getattr(getattr(c, "left", None), "key", None) == column
                    and getattr(c, "operator", None) is operators.ne
                    for c in statement._where_criteria
                )
                rows = (
                    [r for r in rows if (r.get(column) != params[key]) if not_equal]
                    if not_equal
                    else [r for r in rows if r.get(column) == params[key]]
                )
        if "expiresAt_1" in params:
            rows = [r for r in rows if r["expiresAt"] > params["expiresAt_1"]]
        if isinstance(statement, Update):
            values = {k: v for k, v in params.items() if not k.endswith("_1")}
            for row in rows:
                row.update(values)
        if not isinstance(statement, Update):
            keys = [c.key for c in statement.selected_columns]
            rows = [{k: row.get(k) for k in keys} for row in rows]
        return Result(rows)


class Admin:
    allowed = True

    async def _authorize_mutation(self, *args: object) -> None:
        if not self.allowed:
            raise DomainError(403, "FORBIDDEN", "Denied")


class Passwords:
    async def hash_password(self, value: str) -> str:
        return "argon2-test-hash"


def fixture() -> tuple[EmployeeInvitationService, MemoryDatabase, FakeMailService, list[datetime]]:
    db, mail, now = MemoryDatabase(), FakeMailService(), [NOW]
    service = EmployeeInvitationService(
        database=lambda: cast(Database, db),
        admin=cast(Phase6AdminService, Admin()),
        mail=mail,
        origin="https://sso.example.test",
        policy=PasswordPolicy(12, None),
        clock=lambda: now[0],
    )
    service.passwords = cast(Any, Passwords())
    return service, db, mail, now


def mail_token(mail: FakeMailService) -> str:
    return parse_qs(urlsplit(mail.messages[-1].link).fragment)["token"][0]


@pytest.mark.anyio
async def test_invitation_lifecycle_hash_only_employee_creation_and_replay() -> None:
    service, db, mail, _ = fixture()
    identifier = (await service.create("admin", " Employee@Example.test ", "Employee", ROLES)).id
    token = mail_token(mail)
    row = db.tables["EmployeeInvitation"][0]
    assert row["tokenHash"] == token_hash(token) and token not in str(db.tables)
    assert row["expiresAt"] - NOW == INVITATION_TTL
    assert not db.tables["User"]
    assert "tokenHash" not in (await service.list_invitations("admin"))[0]
    await service.resend("admin", identifier)
    new = mail_token(mail)
    assert new != token
    with pytest.raises(DomainError):
        await service.accept(token, "long-password-value")
    await service.accept(new, "long-password-value")
    user = db.tables["User"][0]
    assert user["userType"] == "EMPLOYEE" and user["status"] == "ACTIVE" and user["emailVerified"]
    assert db.tables["PasswordCredential"][0]["passwordHash"] == "argon2-test-hash"
    assert db.tables["UserRole"][0]["userId"] == user["id"]
    assert db.tables["EmployeeInvitation"][0]["status"] == "ACCEPTED"
    with pytest.raises(DomainError):
        await service.accept(new, "long-password-value")
    assert [e["eventType"] for e in db.tables["AuditLog"]] == [
        "employee_invitation_created",
        "employee_invitation_resent",
        "employee_invitation_accepted",
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("action", ["cancel", "expire", "account_exists", "audit_failure"])
async def test_invitation_failure_never_creates_or_elevates_an_account(action: str) -> None:
    service, db, mail, now = fixture()
    identifier = (await service.create("admin", "employee@example.test", "Employee", ROLES)).id
    token = mail_token(mail)
    if action == "cancel":
        await service.cancel("admin", identifier)
        assert db.tables["AuditLog"][-1]["eventType"] == "employee_invitation_cancelled"
    elif action == "expire":
        now[0] += INVITATION_TTL
    elif action == "account_exists":
        db.tables["User"].append(
            {"id": "customer", "email": "employee@example.test", "userType": "CUSTOMER"}
        )
    else:
        db.fail_audit = True
    with pytest.raises((DomainError, RuntimeError)):
        await service.accept(token, "long-password-value")
    assert not db.tables["PasswordCredential"] and not db.tables["UserRole"]
    if action == "account_exists":
        assert db.tables["User"][0]["userType"] == "CUSTOMER"
    if action == "audit_failure":
        assert not db.tables["User"] and db.tables["EmployeeInvitation"][0]["status"] == "PENDING"


@pytest.mark.anyio
async def test_unauthorized_create_and_mail_failure_are_safe() -> None:
    service, db, _, _ = fixture()
    service.admin.allowed = False  # type: ignore[attr-defined]
    with pytest.raises(DomainError):
        await service.create("actor", "employee@example.test", "Employee", ROLES)
    assert not db.tables["EmployeeInvitation"]
    service.admin.allowed = True  # type: ignore[attr-defined]

    class BrokenMail:
        async def send_employee_invitation(self, **kwargs: str) -> None:
            raise RuntimeError("SMTP failed")

    service.mail = BrokenMail()
    with pytest.raises(DomainError) as caught:
        await service.create("actor", "employee@example.test", "Employee", ROLES)
    assert caught.value.code == "INVITATION_DELIVERY_FAILED"
    assert not db.tables["User"]
    assert db.tables["AuditLog"][-1]["eventType"] == "employee_invitation_delivery_failed"


def test_invitation_input_and_legacy_roles_rejected() -> None:
    with pytest.raises(DomainError):
        validate_roles([{"serviceKey": "temis", "name": "admin"}])
    with pytest.raises(DomainError):
        validate_roles(ROLES * 2)
    with pytest.raises(DomainError):
        token_hash("bad")
    assert len(token_hash(secrets.token_urlsafe(32))) == 64


GITLAB = [{"serviceKey": "gitlab", "name": "user"}]


@pytest.mark.anyio
async def test_external_invitation_by_link_creates_a_time_limited_account() -> None:
    service, db, mail, _ = fixture()
    issued = await service.create(
        "admin", "guest@example.test", "Guest", GITLAB, kind="EXTERNAL", days=90, delivery="link"
    )
    assert not mail.messages
    assert issued.url is not None
    assert issued.url.startswith("https://sso.example.test/oauth2/invitations/accept#token=")
    assert issued.account_expires_at == datetime(2027, 2, 2, 14, 59, 59, 999000)
    token = issued.url.split("#token=", 1)[1]
    row = db.tables["EmployeeInvitation"][0]
    assert row["kind"] == "EXTERNAL" and row["deliveredAt"] == NOW
    assert row["tokenHash"] == token_hash(token) and token not in str(db.tables)

    await service.accept(token, "long-password-value")
    user = db.tables["User"][0]
    assert user["userType"] == "EXTERNAL"
    assert user["accountExpiresAt"] == issued.account_expires_at
    assert [e["eventType"] for e in db.tables["AuditLog"]] == [
        "external_invitation_created",
        "external_invitation_accepted",
    ]
    assert db.tables["AuditLog"][0]["detailsJson"]["accountExpiresAt"] == (
        "2027-02-02T14:59:59.999000Z"
    )


@pytest.mark.anyio
async def test_external_invitation_without_roles_and_new_link_on_resend() -> None:
    service, _, mail, _ = fixture()
    issued = await service.create(
        "admin", "guest@example.test", "Guest", [], kind="EXTERNAL", days=30, delivery="link"
    )
    relinked = await service.resend("admin", issued.id, "link")
    assert relinked.url is not None and relinked.url != issued.url and not mail.messages
    await service.resend("admin", issued.id)
    assert mail.messages[-1].to == "guest@example.test"


@pytest.mark.anyio
async def test_external_invitation_cannot_be_accepted_after_its_term_ends() -> None:
    service, db, _, now = fixture()
    issued = await service.create(
        "admin", "guest@example.test", "Guest", [], kind="EXTERNAL", days=1, delivery="link"
    )
    assert issued.url is not None and issued.account_expires_at is not None
    now[0] = issued.account_expires_at
    with pytest.raises(DomainError):
        await service.accept(issued.url.split("#token=", 1)[1], "long-password-value")
    assert not db.tables["User"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("roles", "kind", "days", "code"),
    [
        (
            [{"serviceKey": "agent-hub", "name": "user"}],
            "EXTERNAL",
            90,
            "EXTERNAL_ROLE_NOT_ALLOWED",
        ),
        ([], "EXTERNAL", None, "INVALID_ACCOUNT_TERM"),
        ([], "EXTERNAL", 366, "INVALID_ACCOUNT_TERM"),
        (ROLES, "EMPLOYEE", 90, "INVALID_ACCOUNT_TERM"),
        ([], "EMPLOYEE", None, "INVALID_ROLE"),
    ],
)
async def test_invitation_kind_term_and_role_rules(
    roles: list[dict[str, str]], kind: Literal["EMPLOYEE", "EXTERNAL"], days: int | None, code: str
) -> None:
    service, db, _, _ = fixture()
    with pytest.raises(DomainError) as caught:
        await service.create(
            "admin",
            "guest@example.test",
            "Guest",
            roles,
            kind=kind,
            days=days,
        )
    assert caught.value.code == code
    assert not db.tables["EmployeeInvitation"]
