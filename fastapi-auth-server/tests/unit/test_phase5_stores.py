from datetime import datetime
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import ClauseElement, Executable

from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.stores import (
    DefaultRole,
    EmailVerificationStore,
    EmailVerificationTokenInsert,
    OAuthIdentityStore,
    OAuthProfileRecord,
    PasswordResetStore,
    PasswordResetTokenInsert,
    VerificationHandoff,
)

NOW = datetime(2026, 8, 31, 3, 4, 5, 678000)
EXPIRES = datetime(2026, 8, 31, 4, 4, 5, 678000)


class FakeResult:
    def __init__(self, row: object | None = None, *, rowcount: int = 0) -> None:
        self._row = row
        self.rowcount = rowcount

    def one_or_none(self) -> object | None:
        return self._row


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
async def test_email_verification_request_and_token_handoff_mapping() -> None:
    store = EmailVerificationStore()
    eligible = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="user-1",
                    email="user@example.com",
                    status=UserStatus.ACTIVE,
                    pendingExpiresAt=EXPIRES,
                )
            )
        ]
    )
    user = await store.find_eligible_user(
        cast(AsyncConnection, eligible), email="user@example.com", now=NOW
    )
    assert user is not None and user.has_pending_password_credential
    assert 'LEFT OUTER JOIN "PendingPasswordCredential"' in sql(eligible.statements[0])

    handoff = VerificationHandoff(
        client_id="temis",
        audience="temis",
        redirect_uri="https://temis.example/callback",
        state="state-1",
        code_challenge="challenge-1",
    )
    created = FakeConnection([FakeResult(rowcount=1)])
    await store.create_token(
        cast(AsyncConnection, created),
        token=EmailVerificationTokenInsert(
            "verification-1", "user-1", "hash-1", EXPIRES, NOW, handoff
        ),
    )
    assert sql(created.statements[0]).startswith('INSERT INTO "EmailVerificationToken"')
    assert "challenge-1" in params(created.statements[0]).values()

    found = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="verification-1",
                    userId="user-1",
                    expiresAt=EXPIRES,
                    usedAt=None,
                    handoffClientId="temis",
                    handoffAudience="temis",
                    handoffRedirectUri="https://temis.example/callback",
                    handoffState="state-1",
                    handoffCodeChallenge="challenge-1",
                    handoffCodeChallengeMethod="S256",
                )
            )
        ]
    )
    record = await store.find_token(cast(AsyncConnection, found), token_hash="hash-1")
    assert record is not None and record.handoff == handoff


@pytest.mark.anyio
async def test_email_verification_confirm_consumes_then_activates_and_assigns_default_role() -> (
    None
):
    connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="temporary-user",
                    email="user@example.com",
                    status=UserStatus.PENDING_EMAIL_VERIFICATION,
                )
            ),
            FakeResult(None),
            FakeResult(rowcount=1),
            FakeResult(SimpleNamespace(subjectId="stable-user")),
            FakeResult(None),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=0),
            FakeResult(rowcount=0),
            FakeResult(rowcount=0),
            FakeResult(SimpleNamespace(id="role-user")),
            FakeResult(rowcount=1),
        ]
    )
    result = await EmailVerificationStore().confirm(
        cast(AsyncConnection, connection),
        token_id="verification-1",
        user_id="temporary-user",
        used_at=NOW,
    )
    assert result == "stable-user"
    rendered = [sql(statement) for statement in connection.statements]
    assert rendered[0].startswith('SELECT "User".id')
    assert rendered[1].startswith('SELECT "PendingPasswordCredential"')
    assert rendered[2].startswith('UPDATE "EmailVerificationToken"')
    assert rendered[3].startswith('SELECT "SubjectReservation"."subjectId"')
    assert rendered[4].startswith('SELECT "User".id')
    assert rendered[5].startswith('UPDATE "User"')
    assert params(connection.statements[5])["id"] == "stable-user"
    assert params(connection.statements[5])["updatedAt"] == NOW
    assert [params(statement)["name"] for statement in connection.statements[6:10]] == [
        "pending",
        "user",
        "admin",
        "user",
    ]
    assert rendered[11].startswith('INSERT INTO "UserRole"')


@pytest.mark.anyio
async def test_email_verification_rejects_ineligible_user_before_burning_token() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(id="user-1", email="x", status=UserStatus.ACTIVE)),
            FakeResult(None),
        ]
    )
    result = await EmailVerificationStore().confirm(
        cast(AsyncConnection, connection), token_id="token-1", user_id="user-1", used_at=NOW
    )
    assert result is None
    assert len(connection.statements) == 2


@pytest.mark.anyio
async def test_email_verification_attaches_and_deletes_live_pending_password() -> None:
    pending = SimpleNamespace(
        userId="oauth-user",
        email="oauth@example.com",
        passwordHash="pending-hash",
        expiresAt=EXPIRES,
    )
    connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="oauth-user", email="oauth@example.com", status=UserStatus.ACTIVE
                )
            ),
            FakeResult(pending),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
        ]
    )
    result = await EmailVerificationStore().confirm(
        cast(AsyncConnection, connection),
        token_id="verification-1",
        user_id="oauth-user",
        used_at=NOW,
    )
    assert result == "oauth-user"
    rendered = [sql(statement) for statement in connection.statements]
    assert rendered[2].startswith('UPDATE "EmailVerificationToken"')
    assert rendered[3].startswith('INSERT INTO "PasswordCredential"')
    assert "pending-hash" in params(connection.statements[3]).values()
    assert rendered[4].startswith('DELETE FROM "PendingPasswordCredential"')


@pytest.mark.anyio
async def test_password_reset_request_and_confirm_preserve_lock_and_revoke_order() -> None:
    store = PasswordResetStore()
    lookup = FakeConnection(
        [FakeResult(SimpleNamespace(userId="user-1", email="user@example.com"))]
    )
    user = await store.find_active_user(cast(AsyncConnection, lookup), email="user@example.com")
    assert user is not None and user.id == "user-1"
    assert 'JOIN "User"' in sql(lookup.statements[0])
    assert '"User".status =' in sql(lookup.statements[0])

    create = FakeConnection([FakeResult(rowcount=1)])
    await store.create_token(
        cast(AsyncConnection, create),
        token=PasswordResetTokenInsert("reset-1", "user-1", "hash-1", EXPIRES, NOW),
    )
    assert sql(create.statements[0]).startswith('INSERT INTO "PasswordResetToken"')

    confirm = FakeConnection(
        [
            FakeResult(SimpleNamespace(id="reset-1", userId="user-1")),
            FakeResult(rowcount=1),
            FakeResult(SimpleNamespace(id="user-1")),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=3),
        ]
    )
    result = await store.confirm(
        cast(AsyncConnection, confirm), token_hash="hash-1", password_hash="new-hash", now=NOW
    )
    assert result == "user-1"
    rendered = [sql(statement) for statement in confirm.statements]
    assert rendered[0].startswith('SELECT "PasswordResetToken".id')
    assert rendered[1].startswith('UPDATE "PasswordResetToken"')
    assert rendered[2].endswith("FOR UPDATE")
    assert rendered[3].startswith('UPDATE "PasswordCredential"')
    assert params(confirm.statements[3])["failedLoginCount"] == 0
    assert params(confirm.statements[3])["passwordUpdatedAt"] == NOW
    assert params(confirm.statements[3])["updatedAt"] == NOW
    assert rendered[4].startswith('UPDATE "User"')
    assert '"ssoSessionVersion"' in rendered[4]
    assert rendered[5].startswith('UPDATE "RefreshToken"')


@pytest.mark.anyio
@pytest.mark.parametrize("status", [UserStatus.ACTIVE, UserStatus.PENDING_EMAIL_VERIFICATION])
async def test_verified_social_email_never_attaches_or_deletes_existing_identity(
    status: UserStatus,
) -> None:
    existing = SimpleNamespace(id="employee-or-password-user", status=status)
    created = SimpleNamespace(
        id="new-customer",
        email=None,
        emailVerified=True,
        name="OAuth User",
        profileUrl=None,
        status=UserStatus.ACTIVE,
        accountExpiresAt=None,
    )
    connection = FakeConnection(
        [
            FakeResult(existing),
            FakeResult(created),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(SimpleNamespace(id="role-pending")),
            FakeResult(rowcount=1),
        ]
    )
    result = await OAuthIdentityStore().resolve_or_create(
        cast(AsyncConnection, connection),
        profile=OAuthProfileRecord(
            "google", "google-1", "OAuth@Example.com", True, "OAuth User", None
        ),
        default_role=DefaultRole(),
        now=NOW,
    )
    assert result.id == "new-customer"
    rendered = [sql(statement) for statement in connection.statements]
    assert not any(statement.startswith("DELETE") for statement in rendered)
    assert rendered[1].startswith('INSERT INTO "User"')
    assert params(connection.statements[1])["email"] is None
    assert params(connection.statements[1])["userType"] == "CUSTOMER"
    social = params(connection.statements[2])
    assert social["userId"] != existing.id
    assert social["userId"] == params(connection.statements[1])["id"]


@pytest.mark.anyio
async def test_oauth_new_user_reuses_reservation_and_seeds_then_assigns_default_role() -> None:
    created = SimpleNamespace(
        id="stable-user",
        email="oauth@example.com",
        emailVerified=False,
        name="OAuth User",
        profileUrl=None,
        status=UserStatus.ACTIVE,
        accountExpiresAt=None,
    )
    connection = FakeConnection(
        [
            FakeResult(None),
            FakeResult(SimpleNamespace(subjectId="stable-user")),
            FakeResult(created, rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=0),
            FakeResult(rowcount=0),
            FakeResult(rowcount=0),
            FakeResult(SimpleNamespace(id="role-payroll-pending")),
            FakeResult(rowcount=1),
        ]
    )
    result = await OAuthIdentityStore().resolve_or_create(
        cast(AsyncConnection, connection),
        profile=OAuthProfileRecord(
            "naver", "naver-1", "OAuth@Example.com", False, "OAuth User", None
        ),
        default_role=DefaultRole("payroll", "pending"),
        now=NOW,
    )
    assert result.id == "stable-user"
    rendered = [sql(statement) for statement in connection.statements]
    assert rendered[0].startswith('SELECT "User".id')
    assert rendered[1].startswith('SELECT "SubjectReservation"."subjectId"')
    assert rendered[2].startswith('INSERT INTO "User"')
    assert rendered[3].startswith('INSERT INTO "SocialAccount"')
    assert [params(statement)["name"] for statement in connection.statements[4:8]] == [
        "pending",
        "user",
        "admin",
        "pending",
    ]
    assert rendered[9].startswith('INSERT INTO "UserRole"')


@pytest.mark.anyio
async def test_oauth_provider_lookup_returns_owning_user() -> None:
    connection = FakeConnection(
        [
            FakeResult(
                SimpleNamespace(
                    id="user-1",
                    email=None,
                    emailVerified=False,
                    name=None,
                    profileUrl=None,
                    status=UserStatus.ACTIVE,
                    accountExpiresAt=None,
                )
            )
        ]
    )
    result = await OAuthIdentityStore().find_by_provider_id(
        cast(AsyncConnection, connection), provider="kakao", provider_user_id="kakao-1"
    )
    assert result is not None and result.id == "user-1"
    rendered = sql(connection.statements[0])
    assert 'FROM "SocialAccount" JOIN "User"' in rendered
    assert '"SocialAccount".provider =' in rendered
