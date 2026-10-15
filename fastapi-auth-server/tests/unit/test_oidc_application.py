from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.oidc import (
    AuthorizationRequest,
    OidcRequestContext,
    OidcService,
    OidcServiceError,
    TokenExchangeInput,
    _url_with_query,
)
from wiseacct_sso.infrastructure.oidc_state import (
    OidcAuthorizationCodeStore,
    OidcAuthorizationTransaction,
    OidcAuthorizationTransactionCreateInput,
    OidcAuthorizationTransactionStore,
    OidcProviderStateStore,
    StoredOidcAuthorizationCode,
)
from wiseacct_sso.infrastructure.oidc_tokens import OidcAccessTokenStore, OidcIdTokenSigner
from wiseacct_sso.infrastructure.redis import RedisStateStore
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH, AsyncPasswordHasher
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.oidc import OidcIdentityStore, OidcUserRecord
from wiseacct_sso.persistence.stores import AuditEventInsert, AuditStore, RoleAssignment


class FakeEngine:
    @asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())


class FakeDatabase:
    engine = FakeEngine()

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        del max_attempts
        return await work.callback(cast(AsyncConnection, object()))


class FakeHasher:
    def __init__(self, *, secret_valid: bool = True) -> None:
        self.secret_valid = secret_valid
        self.calls: list[tuple[str, str]] = []

    async def verify_password(self, password_hash: str, password: str) -> bool:
        self.calls.append((password_hash, password))
        return self.secret_valid


class FakeTransactions:
    def __init__(self) -> None:
        self.created: OidcAuthorizationTransactionCreateInput | None = None

    async def create(self, input: OidcAuthorizationTransactionCreateInput) -> str:
        self.created = input
        return "transaction-1"

    async def get(
        self, transaction_id: str, *, browser_binding: str
    ) -> OidcAuthorizationTransaction | None:
        if (
            transaction_id != "transaction-1"
            or self.created is None
            or browser_binding != self.created.browser_binding
        ):
            return None
        return OidcAuthorizationTransaction(
            client_id=self.created.client_id,
            redirect_uri=self.created.redirect_uri,
            scopes=self.created.scopes,
            state=self.created.state,
            nonce=self.created.nonce,
            code_challenge=self.created.code_challenge,
            code_challenge_method=self.created.code_challenge_method,
            browser_binding_hash="stored-by-real-store",
            csrf_hash="stored-by-real-store",
            expires_at_epoch_ms=2_000_000_000_000,
        )


class FakeCodes:
    def __init__(
        self, record: StoredOidcAuthorizationCode | None, *, fail_discard: bool = False
    ) -> None:
        self.record = record
        self.fail_discard = fail_discard
        self.consumed: list[tuple[str, str]] = []
        self.discarded: list[str] = []

    async def consume_for_client(
        self, code: str, client_id: str
    ) -> StoredOidcAuthorizationCode | None:
        self.consumed.append((code, client_id))
        record, self.record = self.record, None
        return record

    async def discard(self, code: str) -> None:
        self.discarded.append(code)
        if self.fail_discard:
            raise CleanupFailure("raw-code-sensitive")


class FakeProviderStates:
    def __init__(self) -> None:
        self.created: object | None = None

    async def create(self, input: object) -> str:
        self.created = input
        return "provider-state"

    async def consume_for_provider(self, state: str, provider: str, browser_binding: str) -> None:
        del state, provider, browser_binding
        return None


class FakeAccessTokens:
    def __init__(self, *, fail_revoke: bool = False) -> None:
        self.created = 0
        self.revoked: list[str] = []
        self.fail_revoke = fail_revoke

    async def create(self, input: object) -> str:
        del input
        self.created += 1
        return "oidc-access-token"

    async def revoke(self, token: str) -> bool:
        self.revoked.append(token)
        if self.fail_revoke:
            raise CleanupFailure("raw-token-sensitive")
        return True


class CleanupFailure(RuntimeError):
    pass


class FakeLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def warning(self, event: str, **metadata: object) -> None:
        self.events.append((event, metadata))


class FakeSigner:
    def issue(self, identity: object, *, client_id: str, nonce: str | None = None) -> str:
        del identity, client_id, nonce
        return "signed-id-token"


class FakeIdentities:
    def __init__(self, user: OidcUserRecord | None) -> None:
        self.user = user
        self.locked: list[str] = []

    async def lock_user(
        self, connection: AsyncConnection, *, user_id: str
    ) -> OidcUserRecord | None:
        del connection
        self.locked.append(user_id)
        return self.user


class FakeAudit:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.events: list[AuditEventInsert] = []

    async def create(self, connection: AsyncConnection, *, event: AuditEventInsert) -> None:
        del connection
        self.events.append(event)
        if self.fail:
            raise RuntimeError("audit unavailable")


class FakeRedisLimiter:
    def __init__(self, count: int) -> None:
        self.count = count
        self.keys: list[str | bytes] = []

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        del ttl_seconds
        self.keys.append(key)
        return self.count


def _client() -> OidcClientPolicy:
    return OidcClientPolicy.model_validate(
        {
            "clientId": "cloudflare-access-dash",
            "redirectUris": ["https://access.example.test/callback"],
            "clientSecretHash": DUMMY_PASSWORD_HASH,
            "requiredRoles": [{"serviceKey": "agent-hub", "name": "user"}],
            "groupsServiceKeys": ["agent-hub"],
            "requirePkce": False,
        }
    )


def _user(*, authorized: bool = True) -> OidcUserRecord:
    roles = (
        (RoleAssignment(service_key="agent-hub", name="user"),)
        if authorized
        else (RoleAssignment(service_key="temis", name="user"),)
    )
    return OidcUserRecord(
        id="user-1",
        email="person@example.test",
        email_verified=True,
        name="Person",
        status=UserStatus.ACTIVE,
        roles=roles,
    )


def _code() -> StoredOidcAuthorizationCode:
    return StoredOidcAuthorizationCode(
        client_id="cloudflare-access-dash",
        redirect_uri="https://access.example.test/callback",
        user_id="user-1",
        scopes=("openid", "email", "profile"),
        nonce="nonce-1",
        code_challenge=None,
        code_challenge_method=None,
        expires_at_epoch_ms=2_000_000_000_000,
    )


def build_fake_oidc_service(
    *,
    codes: FakeCodes | None = None,
    access: FakeAccessTokens | None = None,
    hasher: FakeHasher | None = None,
    limiter: FakeRedisLimiter | None = None,
    logger: FakeLogger | None = None,
) -> tuple[OidcService, FakeCodes, FakeAccessTokens, FakeHasher]:
    selected_codes = codes or FakeCodes(_code())
    selected_access = access or FakeAccessTokens()
    selected_hasher = hasher or FakeHasher()
    service = OidcService(
        database=lambda: cast(Database, FakeDatabase()),
        passwords=cast(AsyncPasswordHasher, selected_hasher),
        clients=OidcClientRegistry((_client(),)),
        transactions=cast(OidcAuthorizationTransactionStore, FakeTransactions()),
        provider_states=cast(OidcProviderStateStore, FakeProviderStates()),
        codes=cast(OidcAuthorizationCodeStore, selected_codes),
        access_tokens=cast(OidcAccessTokenStore, selected_access),
        id_tokens=cast(OidcIdTokenSigner, FakeSigner()),
        redis=(None if limiter is None else lambda: cast(RedisStateStore, limiter)),
        logger=logger,
    )
    return service, selected_codes, selected_access, selected_hasher


@pytest.mark.anyio
async def test_begin_authorization_creates_independent_browser_and_csrf_secrets() -> None:
    service, _, _, _ = build_fake_oidc_service()
    transactions = cast(FakeTransactions, service._transactions)
    start = await service.begin_authorization(
        AuthorizationRequest(
            client_id="cloudflare-access-dash",
            redirect_uri="https://access.example.test/callback",
            response_type="code",
            scopes=("openid", "email"),
            state="caller-state",
            nonce="caller-nonce",
            code_challenge=None,
            code_challenge_method=None,
        ),
        OidcRequestContext(None, None),
    )
    assert start.transaction_id == "transaction-1"
    assert start.browser_binding != start.csrf_token
    assert transactions.created is not None
    assert transactions.created.browser_binding == start.browser_binding
    assert transactions.created.csrf_token == start.csrf_token


@pytest.mark.anyio
async def test_token_exchange_rechecks_current_role_and_audits_denial() -> None:
    service, _, access, _ = build_fake_oidc_service()
    identities = FakeIdentities(_user(authorized=False))
    audit = FakeAudit()
    service._identities = cast(OidcIdentityStore, identities)
    service._audit = cast(AuditStore, audit)

    with pytest.raises(OidcServiceError) as caught:
        await service.exchange_code(
            TokenExchangeInput(
                client_id="cloudflare-access-dash",
                client_secret="secret",
                grant_type="authorization_code",
                code="code-1",
                redirect_uri="https://access.example.test/callback",
                code_verifier=None,
            ),
            OidcRequestContext("127.0.0.1", "test"),
        )

    assert caught.value.error == "invalid_grant"
    assert caught.value.status_code == 400
    assert access.created == 0
    assert audit.events[0].reason_code == "OIDC_REQUIRED_ROLE_MISSING"
    assert audit.events[0].details_json == {"clientId": "cloudflare-access-dash"}


@pytest.mark.anyio
async def test_token_audit_failure_revokes_prepared_bearer_and_burns_code() -> None:
    service, codes, access, _ = build_fake_oidc_service()
    service._identities = cast(OidcIdentityStore, FakeIdentities(_user()))
    service._audit = cast(AuditStore, FakeAudit(fail=True))

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await service.exchange_code(
            TokenExchangeInput(
                client_id="cloudflare-access-dash",
                client_secret="secret",
                grant_type="authorization_code",
                code="code-1",
                redirect_uri="https://access.example.test/callback",
                code_verifier=None,
            ),
            OidcRequestContext(None, None),
        )

    assert codes.record is None
    assert access.created == 1
    assert access.revoked == ["oidc-access-token"]


@pytest.mark.anyio
async def test_client_rate_limit_happens_before_secret_hashing() -> None:
    limiter = FakeRedisLimiter(21)
    hasher = FakeHasher()
    service, codes, _, _ = build_fake_oidc_service(hasher=hasher, limiter=limiter)

    with pytest.raises(OidcServiceError) as caught:
        await service.exchange_code(
            TokenExchangeInput(
                client_id="cloudflare-access-dash",
                client_secret="secret",
                grant_type="authorization_code",
                code="code-1",
                redirect_uri="https://access.example.test/callback",
                code_verifier=None,
            ),
            OidcRequestContext(None, None),
        )

    assert caught.value.status_code == 429
    assert hasher.calls == []
    assert codes.record is not None
    assert len(limiter.keys) == 1
    assert "cloudflare-access-dash" not in str(limiter.keys[0])


@pytest.mark.anyio
async def test_non_pkce_code_rejects_injected_verifier_after_single_use_consume() -> None:
    service, codes, access, _ = build_fake_oidc_service()
    audit = FakeAudit()
    service._audit = cast(AuditStore, audit)

    with pytest.raises(OidcServiceError) as caught:
        await service.exchange_code(
            TokenExchangeInput(
                client_id="cloudflare-access-dash",
                client_secret="secret",
                grant_type="authorization_code",
                code="code-1",
                redirect_uri="https://access.example.test/callback",
                code_verifier="a" * 43,
            ),
            OidcRequestContext(None, None),
        )

    assert caught.value.error == "invalid_grant"
    assert codes.record is None
    assert access.created == 0
    assert audit.events[0].reason_code == "OIDC_INVALID_GRANT"


@pytest.mark.anyio
async def test_provider_callback_consumes_bound_provider_state_before_network() -> None:
    service, _, _, _ = build_fake_oidc_service()
    oauth_getter_called = False

    def oauth_client() -> object:
        nonlocal oauth_getter_called
        oauth_getter_called = True
        return object()

    service._oauth_client = cast(object, oauth_client)  # type: ignore[assignment]

    with pytest.raises(OidcServiceError, match="Invalid provider state"):
        await service.provider_callback(
            provider="google",
            code="provider-code",
            state="wrong-provider-state",
            browser_binding="browser-binding",
            context=OidcRequestContext(None, None),
        )

    assert oauth_getter_called is False


@pytest.mark.anyio
async def test_cleanup_failure_logs_only_operation_and_type_and_preserves_original_error() -> None:
    logger = FakeLogger()
    access = FakeAccessTokens(fail_revoke=True)
    service, _, _, _ = build_fake_oidc_service(access=access, logger=logger)
    service._identities = cast(OidcIdentityStore, FakeIdentities(_user()))
    service._audit = cast(AuditStore, FakeAudit(fail=True))

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await service.exchange_code(
            TokenExchangeInput(
                client_id="cloudflare-access-dash",
                client_secret="secret",
                grant_type="authorization_code",
                code="raw-code-sensitive",
                redirect_uri="https://access.example.test/callback",
                code_verifier=None,
            ),
            OidcRequestContext(None, None),
        )

    assert logger.events == [
        (
            "oidc_cleanup_failure",
            {"operation": "revoke_access_token", "error_type": "CleanupFailure"},
        )
    ]
    assert "raw-token-sensitive" not in repr(logger.events)


@pytest.mark.anyio
async def test_code_cleanup_failure_is_observable_without_code_or_error_text() -> None:
    logger = FakeLogger()
    codes = FakeCodes(_code(), fail_discard=True)
    service, _, _, _ = build_fake_oidc_service(codes=codes, logger=logger)

    await service._best_effort_consume_code("raw-code-sensitive", "client-sensitive")

    assert logger.events == [
        (
            "oidc_cleanup_failure",
            {"operation": "discard_authorization_code", "error_type": "CleanupFailure"},
        )
    ]
    assert "raw-code-sensitive" not in repr(logger.events)
    assert "client-sensitive" not in repr(logger.events)


def test_redirect_append_preserves_registered_uri_bytes_and_duplicate_query_order() -> None:
    redirect_uri = "https://access.example.test/callback?encoded=%41&item=1&item=2&space=%20"

    result = _url_with_query(redirect_uri, code="code/value", state="state value")

    assert result == (f"{redirect_uri}&code=code%2Fvalue&state=state+value")
