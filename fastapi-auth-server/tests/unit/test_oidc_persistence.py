from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import ClauseElement, Executable

from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.oidc import OidcIdentityStore


class FakeResult:
    def __init__(self, row: object | None = None, *, rows: tuple[object, ...] = ()) -> None:
        self._row = row
        self._rows = rows

    def one_or_none(self) -> object | None:
        return self._row

    def all(self) -> tuple[object, ...]:
        return self._rows


class FakeConnection:
    def __init__(self, results: list[FakeResult]) -> None:
        self.results = iter(results)
        self.statements: list[Executable] = []

    async def execute(self, statement: Executable) -> FakeResult:
        self.statements.append(statement)
        return next(self.results)


def sql(statement: Executable) -> str:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return " ".join(str(compiled).replace("\n", " ").split())


@pytest.mark.anyio
async def test_oidc_identity_locks_user_before_plain_role_read() -> None:
    connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="user-1",
                    email="person@example.test",
                    emailVerified=True,
                    name="Person",
                    status=UserStatus.ACTIVE,
                )
            ),
            FakeResult(
                rows=(
                    SimpleNamespace(serviceKey="agent-hub", name="user"),
                    SimpleNamespace(serviceKey="temis", name="admin"),
                )
            ),
        ]
    )

    user = await OidcIdentityStore().lock_user(cast(AsyncConnection, connection), user_id="user-1")

    assert user is not None and user.email_verified
    assert [(role.service_key, role.name) for role in user.roles] == [
        ("agent-hub", "user"),
        ("temis", "admin"),
    ]
    assert "FOR UPDATE" in sql(connection.statements[0])
    assert "FOR UPDATE" not in sql(connection.statements[1])
    assert 'FROM "UserRole" JOIN "Role"' in sql(connection.statements[1])


@pytest.mark.anyio
async def test_oidc_identity_does_not_read_roles_when_user_missing() -> None:
    connection = FakeConnection([FakeResult()])
    user = await OidcIdentityStore().lock_user(cast(AsyncConnection, connection), user_id="missing")
    assert user is None
    assert len(connection.statements) == 1


@pytest.mark.anyio
async def test_oidc_social_identity_lookup_never_creates_or_links() -> None:
    connection = FakeConnection([FakeResult(SimpleNamespace(userId="user-1"))])
    user_id = await OidcIdentityStore().find_existing_social_user_id(
        cast(AsyncConnection, connection),
        provider="google",
        provider_user_id="provider-user-1",
    )
    assert user_id == "user-1"
    rendered = sql(connection.statements[0])
    assert rendered.startswith('SELECT "SocialAccount"."userId"')
    assert "INSERT" not in rendered and "UPDATE" not in rendered
