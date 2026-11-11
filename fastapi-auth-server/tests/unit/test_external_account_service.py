from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import ClauseElement
from sqlalchemy.sql.dml import Insert, Update

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.application.external_accounts import (
    ExternalAccountService,
    expire_due_accounts,
)
from wiseacct_sso.domain.external_accounts import initial_expiry
from wiseacct_sso.domain.users import DomainError, UserStatus
from wiseacct_sso.persistence.database import Database

NOW = datetime(2026, 11, 4, 0, 0)


class Result:
    def __init__(self, scalar: object = None, rows: list[object] | None = None) -> None:
        self.scalar, self.rows = scalar, rows or []

    def scalar_one(self) -> object:
        return self.scalar

    def all(self) -> list[object]:
        return self.rows


class Connection:
    def __init__(self, results: list[Result]) -> None:
        self.results = results
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> Result:
        self.statements.append(statement)
        if isinstance(statement, (Insert, Update)):
            return Result()
        return self.results.pop(0)

    def params(self, kind: type) -> list[dict[str, Any]]:
        return [
            cast(ClauseElement, s).compile().params for s in self.statements if isinstance(s, kind)
        ]


class FakeDatabase:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.engine = self

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[Connection]:
        yield self.connection


class Admin:
    def __init__(self, user_type: str | None) -> None:
        self.user_type = user_type
        self.status_changes: list[dict[str, object]] = []

    async def _authorize_mutation(self, *_args: object) -> tuple[str | None, UserStatus]:
        return self.user_type, UserStatus.ACTIVE

    async def set_user_status(self, **kwargs: object) -> None:
        self.status_changes.append(kwargs)


def build(
    user_type: str | None, results: list[Result]
) -> tuple[ExternalAccountService, Connection, Admin]:
    connection, admin = Connection(results), Admin(user_type)
    service = ExternalAccountService(
        database=lambda: cast(Database, FakeDatabase(connection)),
        admin=cast(Phase6AdminService, admin),
        clock=lambda: NOW,
    )
    return service, connection, admin


@pytest.mark.anyio
async def test_extension_adds_days_and_is_audited() -> None:
    current = initial_expiry(NOW, 10)
    service, connection, _ = build("EXTERNAL", [Result(current)])
    expiry = await service.extend("admin", "guest", 30, " 프로젝트 연장 ")
    assert expiry == initial_expiry(NOW, 40)
    assert connection.params(Update)[0]["accountExpiresAt"] == expiry
    audit = connection.params(Insert)[0]
    assert audit["eventType"] == "external_account_extended"
    assert audit["reasonCode"] == "프로젝트 연장"
    assert audit["detailsJson"]["days"] == 30


@pytest.mark.anyio
@pytest.mark.parametrize("user_type", ["EMPLOYEE", "CUSTOMER", None])
async def test_only_external_accounts_have_a_term(user_type: str | None) -> None:
    service, connection, admin = build(user_type, [])
    with pytest.raises(DomainError) as caught:
        await service.extend("admin", "user", 30, "reason")
    assert caught.value.code == "NOT_EXTERNAL_ACCOUNT"
    with pytest.raises(DomainError):
        await service.set_suspended("admin", "user", True, "reason")
    assert not connection.params(Update) and not admin.status_changes


@pytest.mark.anyio
async def test_extension_and_suspension_require_a_reason() -> None:
    service, _, _ = build("EXTERNAL", [Result(None)])
    for call in (
        service.extend("admin", "guest", 30, " "),
        service.set_suspended("admin", "guest", True, ""),
    ):
        with pytest.raises(DomainError) as caught:
            await call
        assert caught.value.code == "INVALID_REQUEST"


@pytest.mark.anyio
async def test_suspension_uses_the_shared_revoking_status_change() -> None:
    service, _, admin = build("EXTERNAL", [])
    await service.set_suspended("admin", "guest", True, "contract ended")
    await service.set_suspended("admin", "guest", False, "contract renewed")
    assert [c["status"] for c in admin.status_changes] == [UserStatus.SUSPENDED, UserStatus.ACTIVE]
    assert admin.status_changes[0]["reason_code"] == "contract ended"


@pytest.mark.anyio
async def test_expiry_sweep_revokes_sessions_and_records_once() -> None:
    expired_at = datetime(2026, 11, 3, 14, 59, 59, 999000)
    connection = Connection(
        [Result(rows=[SimpleNamespace(id="guest", accountExpiresAt=expired_at)])]
    )
    count = await expire_due_accounts(cast(Database, FakeDatabase(connection)), NOW)
    assert count == 1
    select_sql = str(
        connection.statements[0].compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]
    )
    assert '"User"."userType" = ' in select_sql and "NOT (EXISTS" in select_sql
    assert "FOR UPDATE SKIP LOCKED" in select_sql
    updates = [str(s) for s in connection.statements if isinstance(s, Update)]
    assert any('"ssoSessionVersion"' in s for s in updates)
    assert any('"RefreshToken"' in s for s in updates)
    audit = connection.params(Insert)[0]
    assert audit["eventType"] == "external_account_expired"
    assert audit["actorUserId"] is None and audit["targetUserId"] == "guest"
