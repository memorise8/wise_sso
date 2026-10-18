from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import cast

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.auth import (
    AuthHandoffExchangeInput,
    LoginInput,
    OAuthStartInput,
    Phase4AuthService,
    Phase5AuthService,
    RequestAuditContext,
    TokenPair,
    _redirect_with_code,
)
from wiseacct_sso.config import RelyingClientPolicy
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.oauth import ClientHandoff, OAuthProfile
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.domain.verification import VerificationTokenRecord
from wiseacct_sso.infrastructure.auth_state import (
    AuthHandoffStore,
    OAuthStateMetadata,
    OAuthStateStore,
    StoredAuthHandoffMetadata,
)
from wiseacct_sso.infrastructure.mail import FakeMailService
from wiseacct_sso.infrastructure.oauth_providers import (
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderInfrastructureError,
    OAuthProviderInvalidResponseError,
)
from wiseacct_sso.infrastructure.redis import RedisStateStore
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher, JwtTokenCodec
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.models import UserStatus, utc_now_ms
from wiseacct_sso.persistence.stores import (
    EmailVerificationStore,
    EmailVerificationTokenRecord,
    OAuthIdentityStore,
    OAuthUserRecord,
    PasswordCredentialRecord,
    PasswordResetStore,
    PasswordResetUser,
)

CONTEXT = RequestAuditContext("127.0.0.1", "tests")
CHALLENGE = "a" * 43
REDIRECT = "https://financenow.kr/auth/callback"


class TrackingDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        self.events.append("transaction")
        return await work.callback(cast(AsyncConnection, object()))

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())


class TrackingPasswords:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def hash_password(self, password: str) -> str:
        self.events.append("argon2")
        return f"hash:{password}"


class PgUniqueViolation(Exception):
    sqlstate = "23505"


class UniqueRaceDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        self.events.append("transaction-conflict")
        raise IntegrityError("insert", {}, PgUniqueViolation())

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        self.events.append("fresh-connection")
        yield cast(AsyncConnection, object())


class ResultDatabase:
    def __init__(self, result: object) -> None:
        self.result = result

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        return cast(Result, self.result)

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())


class CommitBoundaryDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        self.events.append("begin")
        try:
            result = await work.callback(cast(AsyncConnection, object()))
        except Exception:
            self.events.append("rollback")
            raise
        self.events.append("commit")
        return result

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())


def client() -> RelyingClientPolicy:
    return RelyingClientPolicy.model_validate(
        {
            "clientId": "temis",
            "audience": "temis",
            "allowedRedirectUris": [REDIRECT],
            "allowedOrigins": ["https://financenow.kr"],
            "defaultRole": {"serviceKey": "temis", "name": "user"},
        }
    )


def service(
    events: list[str],
    *,
    database: object | None = None,
    auth_clients: tuple[RelyingClientPolicy, ...] | None = None,
    mail: FakeMailService | None = None,
    passwords: object | None = None,
    oauth_client: object | None = None,
) -> Phase5AuthService:
    return Phase5AuthService(
        database=lambda: cast(Database, database or TrackingDatabase(events)),
        redis=lambda: cast(RedisStateStore, object()),
        passwords=cast(AsyncPasswordHasher, passwords or object()),
        tokens=cast(JwtTokenCodec, object()),
        password_policy=PasswordPolicy(8, None),
        default_audience="temis",
        rate_limit_window_seconds=60,
        rate_limit_max_requests=20,
        mail=mail,
        verification_url_base="https://auth.example/verify-email",
        password_reset_url_base="https://auth.example/password-reset",
        auth_clients=(client(),) if auth_clients is None else auth_clients,
        provider_config=lambda _provider: OAuthProviderConfig(
            "https://provider.example/authorize",
            "https://provider.example/token",
            "https://provider.example/user",
            "provider-client",
            "provider-secret",
            "https://auth.example/oauth/callback",
            "openid email",
        ),
        oauth_client=cast(OAuthProviderClient | None, oauth_client),
    )


def test_phase4_name_is_a_compatibility_alias() -> None:
    assert Phase4AuthService is Phase5AuthService


@pytest.mark.parametrize(
    ("url", "code", "state", "expected"),
    [
        (
            "https://e.test/cb?x=1&x=2&code=old#frag",
            "new",
            "s",
            "https://e.test/cb?x=1&x=2&code=new&state=s#frag",
        ),
        (
            "https://e.test/cb?state=old&x=1&state=again&code=old&x=2#frag",
            "new",
            "s",
            "https://e.test/cb?state=s&x=1&code=new&x=2#frag",
        ),
        (
            "https://e.test/cb?x=1#frag",
            "new",
            None,
            "https://e.test/cb?x=1&code=new#frag",
        ),
        (
            "https://e.test/cb?x=1&state=old&state=again#frag",
            "new",
            None,
            "https://e.test/cb?x=1&state=old&state=again&code=new#frag",
        ),
        (
            "https://e.test/cb?x=~#frag",
            "new",
            "a~ b",
            "https://e.test/cb?x=%7E&code=new&state=a%7E+b#frag",
        ),
        (
            "https://e.test/cb#",
            "new",
            None,
            "https://e.test/cb?code=new#",
        ),
    ],
)
def test_redirect_query_matches_node_url_search_params_set(
    url: str, code: str, state: str | None, expected: str
) -> None:
    assert _redirect_with_code(url, code, state) == expected


@pytest.mark.anyio
async def test_invalid_login_handoff_is_rejected_before_authentication_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events)

    async def audit(**_kwargs: object) -> None:
        events.append("audit")

    monkeypatch.setattr(auth, "_write_audit", audit)
    invalid_handoff = ClientHandoff(
        client_id="temis",
        audience="temis",
        redirect_uri="https://attacker.example/callback",
        state=None,
        code_challenge=CHALLENGE,
    )

    with pytest.raises(DomainError) as raised:
        await auth.login(
            LoginInput("person@example.com", "password"),
            CONTEXT,
            invalid_handoff,
        )

    assert raised.value.code == "INVALID_CLIENT_REDIRECT_URI"
    assert events == []


@pytest.mark.anyio
async def test_password_reset_hashes_before_transaction_then_audits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events, passwords=TrackingPasswords(events))

    async def confirm(
        _store: PasswordResetStore,
        _connection: AsyncConnection,
        *,
        token_hash: str,
        password_hash: str,
        now: object,
    ) -> str:
        events.append("reset")
        assert password_hash == "hash:a-strong-password"
        return "user-1"

    async def audit(**_kwargs: object) -> None:
        events.append("audit")

    monkeypatch.setattr(PasswordResetStore, "confirm", confirm)
    monkeypatch.setattr(auth, "_write_audit", audit)

    result = await auth.confirm_password_reset("raw-token", "a-strong-password", CONTEXT)

    assert result.user_id == "user-1"
    assert events == ["argon2", "transaction", "reset", "audit"]


@pytest.mark.anyio
async def test_password_reset_consumption_commits_before_invalid_result_conversion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(
        events,
        database=CommitBoundaryDatabase(events),
        passwords=TrackingPasswords(events),
    )

    async def confirm(
        _store: PasswordResetStore,
        _connection: AsyncConnection,
        *,
        token_hash: str,
        password_hash: str,
        now: object,
    ) -> None:
        events.append("token-consumed-user-missing")

    async def audit(**kwargs: object) -> None:
        events.append(f"audit:{kwargs['reason_code']}")

    monkeypatch.setattr(PasswordResetStore, "confirm", confirm)
    monkeypatch.setattr(auth, "_write_audit", audit)

    with pytest.raises(DomainError) as raised:
        await auth.confirm_password_reset("token", "a-strong-password", CONTEXT)

    assert raised.value.code == "INVALID_RESET_TOKEN"
    assert events == [
        "argon2",
        "begin",
        "token-consumed-user-missing",
        "commit",
        "audit:INVALID_RESET_TOKEN",
    ]


@pytest.mark.anyio
async def test_verification_consumption_commits_before_activation_race_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events, database=CommitBoundaryDatabase(events))
    now = utc_now_ms()

    async def find_token(
        _store: EmailVerificationStore,
        _connection: AsyncConnection,
        *,
        token_hash: str,
    ) -> EmailVerificationTokenRecord:
        return EmailVerificationTokenRecord(
            "verification-1",
            "user-1",
            now + timedelta(hours=1),
            None,
            None,
        )

    async def confirm(
        _store: EmailVerificationStore,
        _connection: AsyncConnection,
        *,
        token_id: str,
        user_id: str,
        used_at: object,
    ) -> None:
        events.append("token-consumed-activation-race")

    async def audit(**kwargs: object) -> None:
        events.append(f"audit:{kwargs['reason_code']}")

    monkeypatch.setattr(EmailVerificationStore, "find_token", find_token)
    monkeypatch.setattr(EmailVerificationStore, "confirm", confirm)
    monkeypatch.setattr(auth, "_write_audit", audit)

    with pytest.raises(DomainError) as raised:
        await auth.confirm_email_verification("token", CONTEXT)

    assert raised.value.code == "INVALID_VERIFICATION_TOKEN"
    assert events == [
        "begin",
        "token-consumed-activation-race",
        "commit",
        "audit:INVALID_VERIFICATION_TOKEN",
    ]


@pytest.mark.anyio
async def test_password_reset_request_is_generic_and_orders_token_mail_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    mail = FakeMailService()
    auth = service(events, mail=mail)

    async def find_user(
        _store: PasswordResetStore, _connection: AsyncConnection, *, email: str
    ) -> PasswordResetUser:
        assert email == "person@example.com"
        return PasswordResetUser("user-1", email)

    async def create_token(
        _store: PasswordResetStore,
        _connection: AsyncConnection,
        *,
        token: object,
    ) -> None:
        events.append("token")

    async def find_credential(
        _store: object, _connection: AsyncConnection, *, email: str
    ) -> PasswordCredentialRecord:
        return PasswordCredentialRecord("user-1", email, "hash", 0, None, UserStatus.ACTIVE)

    async def send_reset(*, to: str, reset_url: str) -> None:
        events.append("mail")
        assert to == "person@example.com" and "token=" in reset_url

    async def audit(**_kwargs: object) -> None:
        events.append("audit")

    monkeypatch.setattr(PasswordResetStore, "find_active_user", find_user)
    monkeypatch.setattr(PasswordResetStore, "create_token", create_token)
    monkeypatch.setattr(
        "wiseacct_sso.persistence.stores.PasswordAuthStore.find_credential_by_email",
        find_credential,
    )
    monkeypatch.setattr(mail, "send_password_reset", send_reset)
    monkeypatch.setattr(auth, "_write_audit", audit)

    result = await auth.request_password_reset(" Person@Example.com ", CONTEXT)

    assert result.status == "accepted"
    assert events == ["transaction", "token", "mail", "audit"]


@pytest.mark.anyio
async def test_handoff_is_consumed_before_issue_and_success_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events)

    async def consume(_store: AuthHandoffStore, _input: object) -> StoredAuthHandoffMetadata:
        events.append("consume")
        return StoredAuthHandoffMetadata(
            "temis",
            "payroll",
            REDIRECT,
            "user-1",
            "password",
            CHALLENGE,
            "S256",
            None,
            9_999_999_999_999,
        )

    async def issue(user_id: str, audience: str) -> TokenPair:
        events.append(f"issue:{user_id}:{audience}")
        return TokenPair("access", "refresh")

    async def audit(**kwargs: object) -> None:
        events.append(f"audit:{kwargs['outcome']}")

    monkeypatch.setattr(AuthHandoffStore, "consume", consume)
    monkeypatch.setattr(auth, "_issue_pair", issue)
    monkeypatch.setattr(auth, "_write_audit", audit)

    pair = await auth.exchange_auth_handoff(
        AuthHandoffExchangeInput("temis", REDIRECT, "code", "verifier"), CONTEXT
    )

    assert pair.access_token == "access"
    assert events == ["consume", "issue:user-1:payroll", "audit:success"]


@pytest.mark.anyio
async def test_invalid_handoff_is_generic_and_never_issues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events)

    async def consume(_store: AuthHandoffStore, _input: object) -> None:
        events.append("consume")

    async def audit(**kwargs: object) -> None:
        events.append(f"audit:{kwargs['reason_code']}")

    monkeypatch.setattr(AuthHandoffStore, "consume", consume)
    monkeypatch.setattr(auth, "_write_audit", audit)

    with pytest.raises(DomainError) as raised:
        await auth.exchange_auth_handoff(
            AuthHandoffExchangeInput("temis", REDIRECT, "bad", "verifier"), CONTEXT
        )

    assert raised.value.code == "INVALID_AUTH_HANDOFF_CODE"
    assert events == ["consume", "audit:INVALID_AUTH_HANDOFF_CODE"]


@pytest.mark.anyio
async def test_malformed_handoff_body_audits_without_client_before_generic_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[dict[str, object]] = []
    auth = service([])

    async def audit(**kwargs: object) -> None:
        events.append(kwargs)

    monkeypatch.setattr(auth, "_write_audit", audit)

    with pytest.raises(DomainError) as raised:
        await auth.invalid_auth_handoff_exchange(CONTEXT)

    assert raised.value.code == "INVALID_AUTH_HANDOFF_CODE"
    assert events == [
        {
            "event_type": "auth_handoff_exchange_failure",
            "outcome": "failure",
            "user_id": None,
            "context": CONTEXT,
            "reason_code": "INVALID_AUTH_HANDOFF_CODE",
            "details_json": {"route": "/auth/exchange"},
        }
    ]


@pytest.mark.anyio
async def test_oauth_start_validates_client_before_creating_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events)

    async def create(_store: OAuthStateStore, provider: str, metadata: OAuthStateMetadata) -> str:
        events.append(f"state:{provider}:{metadata.client_id}")
        return "opaque-state"

    monkeypatch.setattr(OAuthStateStore, "create", create)

    url = await auth.oauth_start(
        "google", OAuthStartInput("temis", REDIRECT, "caller", CHALLENGE, "S256")
    )

    assert url.startswith("https://provider.example/authorize?")
    assert "state=opaque-state" in url
    assert events == ["state:google:temis"]

    with pytest.raises(DomainError) as raised:
        await auth.oauth_start(
            "google", OAuthStartInput("temis", REDIRECT, "caller", "too-short", "S256")
        )
    assert raised.value.code == "INVALID_OAUTH_REQUEST"
    assert events == ["state:google:temis"]

    await auth.oauth_start(
        "google", OAuthStartInput("temis", REDIRECT, "😀" * 256, CHALLENGE, None)
    )
    with pytest.raises(DomainError) as utf16_raised:
        await auth.oauth_start(
            "google", OAuthStartInput("temis", REDIRECT, "😀" * 257, CHALLENGE, None)
        )
    assert utf16_raised.value.code == "INVALID_OAUTH_REQUEST"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("provider_error", "status", "code", "message"),
    [
        (
            OAuthProviderInfrastructureError("transport"),
            500,
            "INTERNAL_SERVER_ERROR",
            "Internal server error",
        ),
        (
            OAuthProviderInvalidResponseError("shape"),
            400,
            "INVALID_REQUEST",
            "Invalid request",
        ),
    ],
)
async def test_oauth_provider_typed_failures_map_without_aggregation(
    monkeypatch: pytest.MonkeyPatch,
    provider_error: Exception,
    status: int,
    code: str,
    message: str,
) -> None:
    class OAuthClient:
        async def fetch_profile(
            self, provider: str, config: OAuthProviderConfig, provider_code: str
        ) -> OAuthProfile:
            raise provider_error

    auth = service([], oauth_client=OAuthClient())

    async def consume(_store: OAuthStateStore, provider: str, state: str) -> OAuthStateMetadata:
        return OAuthStateMetadata("temis", REDIRECT, None, CHALLENGE, "S256")

    monkeypatch.setattr(OAuthStateStore, "consume", consume)

    with pytest.raises(DomainError) as raised:
        await auth.oauth_callback("google", "code", "state", CONTEXT)

    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        status,
        code,
        message,
    )


@pytest.mark.anyio
async def test_oauth_callback_consumes_state_before_http_then_db_audit_and_handoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class OAuthClient:
        async def fetch_profile(
            self, provider: str, config: OAuthProviderConfig, code: str
        ) -> OAuthProfile:
            events.append("http")
            return OAuthProfile("google", "google-1", "person@example.com", True, "P", None)

    auth = service(events, oauth_client=OAuthClient())

    async def consume(_store: OAuthStateStore, provider: str, state: str) -> OAuthStateMetadata:
        events.append("consume")
        return OAuthStateMetadata("temis", REDIRECT, "caller", CHALLENGE, "S256")

    async def find(
        _store: OAuthIdentityStore,
        _connection: AsyncConnection,
        *,
        provider: str,
        provider_user_id: str,
    ) -> OAuthUserRecord:
        events.append("resolve")
        return OAuthUserRecord("user-1", "person@example.com", True, "P", None, UserStatus.ACTIVE)

    async def audit(**_kwargs: object) -> None:
        events.append("audit")

    async def create_handoff(_store: AuthHandoffStore, metadata: object) -> str:
        events.append("handoff")
        return "handoff-code"

    monkeypatch.setattr(OAuthStateStore, "consume", consume)
    monkeypatch.setattr(OAuthIdentityStore, "find_by_provider_id", find)
    monkeypatch.setattr(auth, "_write_audit", audit)
    monkeypatch.setattr(AuthHandoffStore, "create", create_handoff)

    result = await auth.oauth_callback("google", "provider-code", "state", CONTEXT)

    assert result.redirect_url.endswith("?code=handoff-code&state=caller")
    assert events == ["consume", "http", "transaction", "resolve", "audit", "handoff"]


@pytest.mark.anyio
async def test_oauth_unique_race_rereads_same_provider_identity_on_fresh_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class OAuthClient:
        async def fetch_profile(
            self, provider: str, config: OAuthProviderConfig, code: str
        ) -> OAuthProfile:
            events.append("http")
            return OAuthProfile("google", "google-race", None, False, None, None)

    auth = service(
        events,
        database=UniqueRaceDatabase(events),
        oauth_client=OAuthClient(),
    )

    async def consume(_store: OAuthStateStore, provider: str, state: str) -> OAuthStateMetadata:
        events.append("consume")
        return OAuthStateMetadata("temis", REDIRECT, None, CHALLENGE, "S256")

    async def find(
        _store: OAuthIdentityStore,
        _connection: AsyncConnection,
        *,
        provider: str,
        provider_user_id: str,
    ) -> OAuthUserRecord:
        events.append("canonical-read")
        assert provider_user_id == "google-race"
        return OAuthUserRecord("canonical", None, False, None, None, UserStatus.ACTIVE)

    async def audit(**_kwargs: object) -> None:
        events.append("audit")

    async def create_handoff(_store: AuthHandoffStore, metadata: object) -> str:
        events.append("handoff")
        return "race-code"

    monkeypatch.setattr(OAuthStateStore, "consume", consume)
    monkeypatch.setattr(OAuthIdentityStore, "find_by_provider_id", find)
    monkeypatch.setattr(auth, "_write_audit", audit)
    monkeypatch.setattr(AuthHandoffStore, "create", create_handoff)

    result = await auth.oauth_callback("google", "provider-code", "state", CONTEXT)

    assert "code=race-code" in result.redirect_url
    assert events == [
        "consume",
        "http",
        "transaction-conflict",
        "fresh-connection",
        "canonical-read",
        "audit",
        "handoff",
    ]


@pytest.mark.anyio
async def test_oauth_unique_conflict_without_canonical_identity_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class OAuthClient:
        async def fetch_profile(
            self, provider: str, config: OAuthProviderConfig, code: str
        ) -> OAuthProfile:
            return OAuthProfile("google", "google-conflict", None, False, None, None)

    auth = service(
        events,
        database=UniqueRaceDatabase(events),
        oauth_client=OAuthClient(),
    )

    async def consume(_store: OAuthStateStore, provider: str, state: str) -> OAuthStateMetadata:
        return OAuthStateMetadata("temis", REDIRECT, None, CHALLENGE, "S256")

    async def find(
        _store: OAuthIdentityStore,
        _connection: AsyncConnection,
        *,
        provider: str,
        provider_user_id: str,
    ) -> None:
        events.append("canonical-missing")

    monkeypatch.setattr(OAuthStateStore, "consume", consume)
    monkeypatch.setattr(OAuthIdentityStore, "find_by_provider_id", find)

    with pytest.raises(DomainError) as raised:
        await auth.oauth_callback("google", "provider-code", "state", CONTEXT)

    assert raised.value.code == "OAUTH_PROVIDER_ERROR"
    assert raised.value.status_code == 400
    assert events == [
        "transaction-conflict",
        "fresh-connection",
        "canonical-missing",
    ]


@pytest.mark.anyio
async def test_stored_verification_handoff_survives_current_policy_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handoff = ClientHandoff("removed-client", "removed-aud", REDIRECT, "old", CHALLENGE)
    now = utc_now_ms()
    record = VerificationTokenRecord(
        "verification-1",
        "user-1",
        now + timedelta(hours=1),
        None,
        handoff,
    )
    auth = service(
        [],
        database=ResultDatabase((record, "user-1")),
        auth_clients=(),
    )

    async def audit(**_kwargs: object) -> None:
        return None

    async def create_handoff(_store: AuthHandoffStore, metadata: object) -> str:
        return "persisted-code"

    monkeypatch.setattr(auth, "_write_audit", audit)
    monkeypatch.setattr(AuthHandoffStore, "create", create_handoff)

    result = await auth.confirm_email_verification("token", CONTEXT)

    assert result.redirect_url == f"{REDIRECT}?code=persisted-code&state=old"


def test_oauth_client_binding_is_lifespan_scoped_and_stale_unbind_is_safe() -> None:
    events: list[str] = []
    first = cast(OAuthProviderClient, object())
    second = cast(OAuthProviderClient, object())
    third = cast(OAuthProviderClient, object())
    auth = service(events, oauth_client=first)

    auth.bind_oauth_client(first)
    with pytest.raises(RuntimeError, match="already bound"):
        auth.bind_oauth_client(second)
    auth.unbind_oauth_client(first)
    auth.bind_oauth_client(second)
    auth.unbind_oauth_client(first)
    with pytest.raises(RuntimeError, match="already bound"):
        auth.bind_oauth_client(third)
    auth.unbind_oauth_client(second)
    auth.bind_oauth_client(third)


@pytest.mark.anyio
async def test_oauth_callback_while_client_unbound_is_controlled_and_preserves_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events, oauth_client=None)

    async def consume(_store: OAuthStateStore, provider: str, state: str) -> OAuthStateMetadata:
        events.append("consumed")
        return OAuthStateMetadata("temis", REDIRECT, None, CHALLENGE, "S256")

    monkeypatch.setattr(OAuthStateStore, "consume", consume)

    with pytest.raises(DomainError) as raised:
        await auth.oauth_callback("google", "code", "state", CONTEXT)

    assert raised.value.status_code == 503
    assert raised.value.code == "OAUTH_PROVIDER_UNAVAILABLE"
    assert events == []


@pytest.mark.anyio
async def test_oauth_provider_error_audits_before_generic_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    auth = service(events)

    async def audit(**kwargs: object) -> None:
        events.append(f"audit:{kwargs['provider']}:{kwargs['reason_code']}:{kwargs['outcome']}")

    monkeypatch.setattr(auth, "_write_audit", audit)

    with pytest.raises(DomainError) as raised:
        await auth.oauth_provider_error("google", CONTEXT)

    assert raised.value.code == "OAUTH_PROVIDER_ERROR"
    assert events == ["audit:google:OAUTH_PROVIDER_ERROR:failure"]
