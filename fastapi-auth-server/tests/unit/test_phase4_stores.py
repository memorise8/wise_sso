from datetime import datetime
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import ClauseElement, Executable

from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.stores import (
    AuditEventInsert,
    AuditStore,
    LogoutStore,
    PasswordAuthStore,
    PasswordRegistration,
    PendingPasswordUpsert,
    RefreshReplacement,
    RefreshRotationStore,
    RefreshTokenInsert,
    RefreshTokenRecord,
    TokenIssueStore,
    UserReadStore,
)

NOW = datetime(2026, 8, 31, 2, 3, 4, 567000)
EXPIRES_AT = datetime(2026, 9, 30, 2, 3, 4, 567000)


class FakeResult:
    def __init__(
        self,
        row: object | None = None,
        *,
        rows: tuple[object, ...] = (),
        rowcount: int = 0,
    ) -> None:
        self._row = row
        self._rows = rows
        self.rowcount = rowcount

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


def params(statement: Executable) -> dict[str, object]:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return cast(dict[str, object], compiled.params)


@pytest.mark.anyio
async def test_password_lookup_and_active_current_user_map_roles() -> None:
    credential_connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    userId="user-1",
                    email="user@example.com",
                    passwordHash="argon-hash",
                    failedLoginCount=2,
                    lockedUntil=None,
                    userStatus=UserStatus.ACTIVE,
                )
            )
        ]
    )
    credential = await PasswordAuthStore().find_credential_by_email(
        cast(AsyncConnection, credential_connection), email="user@example.com"
    )
    assert credential is not None
    assert credential.user_id == "user-1"
    assert credential.user_status is UserStatus.ACTIVE
    credential_sql = sql(credential_connection.statements[0])
    assert 'FROM "PasswordCredential" JOIN "User"' in credential_sql
    assert '"PasswordCredential".email =' in credential_sql

    user_connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="user-1",
                    email="user@example.com",
                    emailVerified=True,
                    name="User",
                    status=UserStatus.ACTIVE,
                )
            ),
            FakeResult(
                rows=(
                    SimpleNamespace(serviceKey="temis", name="user"),
                    SimpleNamespace(serviceKey="ledger", name="reader"),
                )
            ),
        ]
    )
    user = await UserReadStore().find_current_active(
        cast(AsyncConnection, user_connection), user_id="user-1"
    )
    assert user is not None
    assert [(role.service_key, role.name) for role in user.roles] == [
        ("temis", "user"),
        ("ledger", "reader"),
    ]
    assert '"User".status =' in sql(user_connection.statements[0])
    role_sql = sql(user_connection.statements[1])
    assert 'FROM "UserRole" JOIN "Role"' in role_sql
    assert "ORDER BY" not in role_sql


@pytest.mark.anyio
async def test_password_registration_upsert_and_success_reset_have_exact_counts() -> None:
    registration = PasswordRegistration(
        user_id="user-1",
        credential_id="credential-1",
        email="User@Example.com",
        name="User",
        password_hash="argon-hash",
        status=UserStatus.PENDING_EMAIL_VERIFICATION,
        created_at=NOW,
        updated_at=NOW,
    )
    registration_connection = FakeConnection([FakeResult(rowcount=1), FakeResult(rowcount=1)])
    await PasswordAuthStore().create_user_with_password(
        cast(AsyncConnection, registration_connection), registration=registration
    )
    rendered = [sql(statement) for statement in registration_connection.statements]
    assert rendered[0].startswith('INSERT INTO "User"')
    assert rendered[1].startswith('INSERT INTO "PasswordCredential"')
    assert "user@example.com" in params(registration_connection.statements[1]).values()

    failed_registration = FakeConnection([FakeResult(rowcount=1), FakeResult(rowcount=0)])
    with pytest.raises(RuntimeError, match="password credential insert count was not one"):
        await PasswordAuthStore().create_user_with_password(
            cast(AsyncConnection, failed_registration), registration=registration
        )

    pending = PendingPasswordUpsert(
        id="pending-1",
        user_id="user-1",
        email="User@Example.com",
        password_hash="new-hash",
        expires_at=EXPIRES_AT,
        created_at=NOW,
        updated_at=NOW,
    )
    update_connection = FakeConnection([FakeResult(rowcount=1), FakeResult(rowcount=1)])
    await PasswordAuthStore().upsert_pending_password(
        cast(AsyncConnection, update_connection), pending=pending
    )
    await PasswordAuthStore().mark_login_success(
        cast(AsyncConnection, update_connection), user_id="user-1", updated_at=NOW
    )
    upsert_sql = sql(update_connection.statements[0])
    assert upsert_sql.startswith('INSERT INTO "PendingPasswordCredential"')
    assert 'ON CONFLICT ("userId") DO UPDATE SET' in upsert_sql
    reset_sql = sql(update_connection.statements[1])
    assert reset_sql.startswith('UPDATE "PasswordCredential" SET "failedLoginCount"=')
    assert '"lockedUntil"=' in reset_sql


@pytest.mark.anyio
async def test_token_issue_locks_active_user_reads_roles_then_inserts_refresh() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(
                SimpleNamespace(
                    id="user-1",
                    email="user@example.com",
                    emailVerified=True,
                    name="User",
                    status=UserStatus.ACTIVE,
                )
            ),
            FakeResult(rows=(SimpleNamespace(serviceKey="temis", name="user"),)),
            FakeResult(rowcount=1),
        ]
    )
    user = await TokenIssueStore().issue_for_active_user(
        cast(AsyncConnection, connection),
        user_id="user-1",
        refresh=RefreshTokenInsert(
            id="refresh-1",
            token_hash="hash-1",
            audience="ledger-api",
            expires_at=EXPIRES_AT,
            created_at=NOW,
        ),
    )
    assert user is not None
    rendered = [sql(statement) for statement in connection.statements]
    assert rendered[0].endswith("FOR UPDATE")
    assert '"User".status =' in rendered[0]
    assert rendered[1].startswith('SELECT "User".id')
    assert rendered[2].startswith('SELECT "Role"."serviceKey"')
    assert rendered[3].startswith('INSERT INTO "RefreshToken"')
    assert "ledger-api" in params(connection.statements[3]).values()

    inactive = FakeConnection([FakeResult(None)])
    assert (
        await TokenIssueStore().issue_for_active_user(
            cast(AsyncConnection, inactive),
            user_id="inactive",
            refresh=RefreshTokenInsert("id", "hash", "temis", EXPIRES_AT, NOW),
        )
        is None
    )
    assert len(inactive.statements) == 1


@pytest.mark.anyio
async def test_refresh_rotation_factory_uses_stored_user_and_audience() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(userId="user-1", audience="ledger-api")),
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
        ]
    )
    observed: list[tuple[str, str]] = []

    def factory(record: RefreshTokenRecord) -> RefreshReplacement:
        observed.append((record.user_id, record.audience))
        return RefreshReplacement("new-id", "new-hash", EXPIRES_AT, NOW)

    result = await RefreshRotationStore().rotate(
        cast(AsyncConnection, connection),
        old_token_hash="old-hash",
        expected_audience="ledger-api",
        now=NOW,
        replacement_factory=factory,
    )
    assert result is not None
    assert observed == [("user-1", "ledger-api")]
    inserted_params = params(connection.statements[3])
    assert "user-1" in inserted_params.values()
    assert "ledger-api" in inserted_params.values()

    with pytest.raises(ValueError, match="exactly one"):
        await RefreshRotationStore().rotate(
            cast(AsyncConnection, FakeConnection([])),
            old_token_hash="old",
            expected_audience="temis",
            now=NOW,
        )


@pytest.mark.anyio
async def test_logout_always_runs_nontransactional_update_after_find() -> None:
    found = FakeConnection([FakeResult(SimpleNamespace(userId="user-1")), FakeResult(rowcount=1)])
    user_id = await LogoutStore().revoke(
        cast(AsyncConnection, found), token_hash="hash", revoked_at=NOW
    )
    assert user_id == "user-1"
    assert sql(found.statements[0]).startswith('SELECT "RefreshToken"."userId"')
    assert sql(found.statements[1]).startswith('UPDATE "RefreshToken" SET "revokedAt"=')

    missing = FakeConnection([FakeResult(None), FakeResult(rowcount=0)])
    assert (
        await LogoutStore().revoke(
            cast(AsyncConnection, missing), token_hash="missing", revoked_at=NOW
        )
        is None
    )
    assert len(missing.statements) == 2


@pytest.mark.anyio
async def test_audit_insert_and_normalized_identity_lookups() -> None:
    connection = FakeConnection(
        [
            FakeResult(rowcount=1),
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(SimpleNamespace(userId="user-2")),
        ]
    )
    store = AuditStore()
    await store.create(
        cast(AsyncConnection, connection),
        event=AuditEventInsert(
            id="audit-1",
            event_type="login",
            outcome="success",
            created_at=NOW,
            user_id="user-1",
            details_json={"source": "phase4"},
        ),
    )
    assert (
        await store.find_user_id_by_email(
            cast(AsyncConnection, connection), email=" User@Example.com "
        )
        == "user-1"
    )
    assert (
        await store.find_user_id_by_password_email(
            cast(AsyncConnection, connection), email=" Password@Example.com "
        )
        == "user-2"
    )
    assert sql(connection.statements[0]).startswith('INSERT INTO "AuditLog"')
    assert "user@example.com" in params(connection.statements[1]).values()
    assert "password@example.com" in params(connection.statements[2]).values()
