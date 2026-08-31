from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from wiseacct_sso.application.auth import LoginInput, Phase4AuthService, RequestAuditContext
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.tokens import (
    AccessTokenIdentity,
    IssuedRefreshToken,
    RefreshTokenClaims,
)
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.redis import RedisStateStore
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher, JwtTokenCodec
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.stores import (
    AuditEventInsert,
    AuditStore,
    CurrentUserRecord,
    PasswordAuthStore,
    PasswordCredentialRecord,
    RefreshReplacementFactory,
    RefreshTokenRecord,
    RoleAssignment,
    TokenIssueStore,
    UserReadStore,
)


class AccessSigningFailure(RuntimeError):
    pass


class FailingAccessCodec:
    def issue_refresh_token(
        self, *, user_id: str, audience: str | None = None
    ) -> IssuedRefreshToken:
        now = datetime.now(UTC)
        return IssuedRefreshToken(
            token=f"refresh-{user_id}",
            token_id="a" * 64,
            token_hash="b" * 64,
            expires_at=now + timedelta(days=30),
        )

    def issue_access_token(
        self, identity: AccessTokenIdentity, *, audience: str | None = None
    ) -> str:
        raise AccessSigningFailure(identity.user_id)

    def verify_refresh_token(
        self, token: str, *, audience: str | None = None
    ) -> RefreshTokenClaims:
        now = datetime.now(UTC)
        return RefreshTokenClaims(
            user_id="user-1",
            token_id="c" * 64,
            audience="temis",
            issued_at=now,
            expires_at=now + timedelta(days=30),
        )


class SuccessfulCodec(FailingAccessCodec):
    def __init__(self) -> None:
        self.issued_refresh_tokens: list[str] = []

    def issue_refresh_token(
        self, *, user_id: str, audience: str | None = None
    ) -> IssuedRefreshToken:
        sequence = len(self.issued_refresh_tokens) + 1
        token = f"refresh-{sequence}"
        self.issued_refresh_tokens.append(token)
        now = datetime.now(UTC)
        return IssuedRefreshToken(
            token=token,
            token_id=f"{sequence:064x}",
            token_hash=f"{sequence + 100:064x}",
            expires_at=now + timedelta(days=30),
        )

    def issue_access_token(
        self, identity: AccessTokenIdentity, *, audience: str | None = None
    ) -> str:
        return f"access-{len(self.issued_refresh_tokens)}"


class TransactionTrackingDatabase:
    def __init__(self) -> None:
        self.rolled_back = False
        self.committed_transactions = 0

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        try:
            result = await work.callback(cast(AsyncConnection, object()))
            self.committed_transactions += 1
            return result
        except Exception:
            self.rolled_back = True
            raise

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())


def _user() -> CurrentUserRecord:
    return CurrentUserRecord(
        id="user-1",
        email="person@example.com",
        email_verified=True,
        name="Person",
        status=UserStatus.ACTIVE,
        roles=(RoleAssignment(service_key="temis", name="user"),),
    )


def _service(
    database: object,
    *,
    passwords: AsyncPasswordHasher | None = None,
    tokens: JwtTokenCodec | None = None,
) -> Phase4AuthService:
    codec = tokens or cast(JwtTokenCodec, FailingAccessCodec())
    return Phase4AuthService(
        database=lambda: cast(Database, database),
        redis=lambda: cast(RedisStateStore, object()),
        passwords=passwords or cast(AsyncPasswordHasher, object()),
        tokens=codec,
        password_policy=PasswordPolicy(min_length=8, allowed_email_domain=None),
        default_audience="temis",
        rate_limit_window_seconds=60,
        rate_limit_max_requests=20,
    )


@pytest.mark.anyio
async def test_access_signing_failure_rolls_back_initial_refresh_insert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = TransactionTrackingDatabase()
    mutation_applied = False

    async def issue(
        _store: TokenIssueStore,
        _connection: AsyncConnection,
        *,
        user_id: str,
        refresh: object,
    ) -> CurrentUserRecord:
        nonlocal mutation_applied
        mutation_applied = True
        return _user()

    monkeypatch.setattr(TokenIssueStore, "issue_for_active_user", issue)
    service = _service(database)

    with pytest.raises(AccessSigningFailure):
        await service._issue_pair("user-1", "temis")

    assert mutation_applied is True
    assert database.rolled_back is True


@pytest.mark.anyio
async def test_access_signing_failure_rolls_back_refresh_revoke_and_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = TransactionTrackingDatabase()
    mutation_applied = False

    async def rotate(
        _store: object,
        _connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: object = None,
        replacement_factory: RefreshReplacementFactory | None = None,
    ) -> RefreshTokenRecord:
        nonlocal mutation_applied
        assert replacement_factory is not None
        replacement_factory(RefreshTokenRecord(user_id="user-1", audience="temis"))
        mutation_applied = True
        return RefreshTokenRecord(user_id="user-1", audience="temis")

    async def find_active(
        _store: UserReadStore, _connection: AsyncConnection, *, user_id: str
    ) -> CurrentUserRecord:
        return _user()

    async def skip_failure_audit(_context: RequestAuditContext) -> None:
        return None

    monkeypatch.setattr("wiseacct_sso.persistence.stores.RefreshRotationStore.rotate", rotate)
    monkeypatch.setattr(UserReadStore, "find_current_active", find_active)
    service = _service(database)
    monkeypatch.setattr(service, "_audit_refresh_failure", skip_failure_audit)

    with pytest.raises(AccessSigningFailure):
        await service.refresh(
            "old-refresh-token", RequestAuditContext(ip_address=None, user_agent=None)
        )

    assert mutation_applied is True
    assert database.rolled_back is True


@pytest.mark.anyio
async def test_login_status_race_audits_success_before_active_issue_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = TransactionTrackingDatabase()
    reset_applied = False
    issue_attempted = False
    audit_events: list[AuditEventInsert] = []

    class VerifyingPasswords:
        async def verify_password(self, password_hash: str, password: str) -> bool:
            return True

    async def find_credential(
        _store: PasswordAuthStore,
        _connection: AsyncConnection,
        *,
        email: str,
    ) -> PasswordCredentialRecord:
        return PasswordCredentialRecord(
            user_id="user-1",
            email=email,
            password_hash="hash",
            failed_login_count=0,
            locked_until=None,
            user_status=UserStatus.ACTIVE,
        )

    async def mark_success(
        _store: PasswordAuthStore,
        _connection: AsyncConnection,
        *,
        user_id: str,
        updated_at: datetime,
    ) -> None:
        nonlocal reset_applied
        reset_applied = True

    async def find_suspended(
        _store: UserReadStore,
        _connection: AsyncConnection,
        *,
        user_id: str,
    ) -> CurrentUserRecord:
        user = _user()
        return CurrentUserRecord(
            id=user.id,
            email=user.email,
            email_verified=user.email_verified,
            name=user.name,
            status=UserStatus.SUSPENDED,
            roles=user.roles,
        )

    async def audit(
        _store: AuditStore,
        _connection: AsyncConnection,
        *,
        event: AuditEventInsert,
    ) -> None:
        audit_events.append(event)

    async def reject_issue(
        _store: TokenIssueStore,
        _connection: AsyncConnection,
        *,
        user_id: str,
        refresh: object,
    ) -> None:
        nonlocal issue_attempted
        issue_attempted = True
        return None

    monkeypatch.setattr(PasswordAuthStore, "find_credential_by_email", find_credential)
    monkeypatch.setattr(PasswordAuthStore, "mark_login_success", mark_success)
    monkeypatch.setattr(UserReadStore, "find_current", find_suspended)
    monkeypatch.setattr(AuditStore, "create", audit)
    monkeypatch.setattr(TokenIssueStore, "issue_for_active_user", reject_issue)
    service = _service(
        database,
        passwords=cast(AsyncPasswordHasher, VerifyingPasswords()),
    )

    with pytest.raises(DomainError) as captured:
        await service.login(
            LoginInput(email="person@example.com", password="password"),
            RequestAuditContext(ip_address=None, user_agent=None),
        )

    assert captured.value.status_code == 401
    assert captured.value.code == "UNAUTHORIZED"
    assert reset_applied is True
    assert issue_attempted is True
    assert [event.event_type for event in audit_events] == ["login_success"]


class PgError(Exception):
    def __init__(self, sqlstate: str) -> None:
        self.sqlstate = sqlstate


def _db_error(sqlstate: str) -> DBAPIError:
    return DBAPIError("statement", {}, PgError(sqlstate), False)


class RetryingEngine:
    def __init__(self) -> None:
        self.begin_calls = 0

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncConnection]:
        self.begin_calls += 1
        yield cast(AsyncConnection, object())

    async def dispose(self) -> None:
        return None


@pytest.mark.anyio
async def test_refresh_discards_attempt_tokens_and_commits_only_retry_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = RetryingEngine()

    async def no_backoff(_attempt: int) -> None:
        return None

    database = Database(engine=cast(AsyncEngine, engine), backoff=no_backoff)
    codec = SuccessfulCodec()
    retry_errors = iter((_db_error("40001"), _db_error("40P01")))
    audit_outcomes: list[str] = []

    async def rotate(
        _store: object,
        _connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: object = None,
        replacement_factory: RefreshReplacementFactory | None = None,
    ) -> RefreshTokenRecord:
        assert replacement_factory is not None
        replacement_factory(RefreshTokenRecord(user_id="user-1", audience="temis"))
        if engine.begin_calls < 3:
            raise next(retry_errors)
        return RefreshTokenRecord(user_id="user-1", audience="temis")

    async def find_active(
        _store: UserReadStore, _connection: AsyncConnection, *, user_id: str
    ) -> CurrentUserRecord:
        return _user()

    async def record_audit(**values: object) -> None:
        audit_outcomes.append(cast(str, values["outcome"]))

    monkeypatch.setattr("wiseacct_sso.persistence.stores.RefreshRotationStore.rotate", rotate)
    monkeypatch.setattr(UserReadStore, "find_current_active", find_active)
    service = _service(database, tokens=cast(JwtTokenCodec, codec))
    monkeypatch.setattr(service, "_write_audit", record_audit)

    pair = await service.refresh(
        "old-refresh-token", RequestAuditContext(ip_address=None, user_agent=None)
    )

    assert engine.begin_calls == 3
    assert codec.issued_refresh_tokens == ["refresh-1", "refresh-2", "refresh-3"]
    assert pair.refresh_token == "refresh-3"
    assert pair.access_token == "access-3"
    assert audit_outcomes == ["success"]


@pytest.mark.anyio
async def test_refresh_retry_exhaustion_audits_failure_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = RetryingEngine()

    async def no_backoff(_attempt: int) -> None:
        return None

    database = Database(engine=cast(AsyncEngine, engine), backoff=no_backoff)
    codec = SuccessfulCodec()
    failure_audits: list[RequestAuditContext] = []

    async def rotate(
        _store: object,
        _connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: object = None,
        replacement_factory: RefreshReplacementFactory | None = None,
    ) -> RefreshTokenRecord:
        assert replacement_factory is not None
        replacement_factory(RefreshTokenRecord(user_id="user-1", audience="temis"))
        raise _db_error("40001")

    async def record_failure(context: RequestAuditContext) -> None:
        failure_audits.append(context)

    monkeypatch.setattr("wiseacct_sso.persistence.stores.RefreshRotationStore.rotate", rotate)
    service = _service(database, tokens=cast(JwtTokenCodec, codec))
    monkeypatch.setattr(service, "_audit_refresh_failure", record_failure)
    context = RequestAuditContext(ip_address=None, user_agent=None)

    with pytest.raises(DBAPIError):
        await service.refresh("old-refresh-token", context)

    assert engine.begin_calls == 3
    assert codec.issued_refresh_tokens == ["refresh-1", "refresh-2", "refresh-3"]
    assert failure_audits == [context]


@pytest.mark.anyio
async def test_refresh_success_audit_failure_attempts_failure_audit_after_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SuccessAuditFailure(RuntimeError):
        pass

    database = TransactionTrackingDatabase()
    codec = SuccessfulCodec()
    audit_outcomes: list[str] = []

    async def rotate(
        _store: object,
        _connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: object = None,
        replacement_factory: RefreshReplacementFactory | None = None,
    ) -> RefreshTokenRecord:
        assert replacement_factory is not None
        replacement_factory(RefreshTokenRecord(user_id="user-1", audience="temis"))
        return RefreshTokenRecord(user_id="user-1", audience="temis")

    async def find_active(
        _store: UserReadStore, _connection: AsyncConnection, *, user_id: str
    ) -> CurrentUserRecord:
        return _user()

    async def audit(**values: object) -> None:
        outcome = cast(str, values["outcome"])
        audit_outcomes.append(outcome)
        if outcome == "success":
            raise SuccessAuditFailure()

    monkeypatch.setattr("wiseacct_sso.persistence.stores.RefreshRotationStore.rotate", rotate)
    monkeypatch.setattr(UserReadStore, "find_current_active", find_active)
    service = _service(database, tokens=cast(JwtTokenCodec, codec))
    monkeypatch.setattr(service, "_write_audit", audit)

    with pytest.raises(SuccessAuditFailure):
        await service.refresh(
            "old-refresh-token", RequestAuditContext(ip_address=None, user_agent=None)
        )

    assert database.committed_transactions == 1
    assert audit_outcomes == ["success", "failure"]
