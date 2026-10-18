from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import jwt
import pytest

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.oidc import (
    OidcIdentity,
    has_required_role,
    parse_requested_scopes,
    project_groups,
    validate_pkce_request,
    verify_pkce,
)
from wiseacct_sso.domain.users import Role
from wiseacct_sso.infrastructure.auth_state import sha256_base64url
from wiseacct_sso.infrastructure.oidc_state import (
    OIDC_AUTHORIZATION_CODE_TTL_SECONDS,
    OIDC_PROVIDER_STATE_TTL_SECONDS,
    OIDC_TRANSACTION_TTL_SECONDS,
    OidcAuthorizationCodeCreateInput,
    OidcAuthorizationCodeStore,
    OidcAuthorizationTransactionCreateInput,
    OidcAuthorizationTransactionStore,
    OidcProviderStateCreateInput,
    OidcProviderStateStore,
    oidc_authorization_code_key,
    oidc_provider_state_key,
    oidc_transaction_key,
    provider_state_transaction_id,
)
from wiseacct_sso.infrastructure.oidc_tokens import (
    OIDC_ACCESS_TOKEN_TTL_SECONDS,
    OidcAccessTokenCreateInput,
    OidcAccessTokenStore,
    OidcIdTokenIdentity,
    OidcIdTokenSigner,
    oidc_access_token_key,
)
from wiseacct_sso.oidc_config import (
    OidcClientPolicy,
    parse_oidc_clients_json,
)

_ARGON2ID = (
    "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$"
    "U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM"
)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[bytes, bytes] = {}
        self.ttls: dict[bytes, int] = {}
        self.cas_calls = 0

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        assert isinstance(key, bytes)
        if key in self.values:
            return False
        self.values[key] = value
        self.ttls[key] = ttl_seconds
        return True

    async def get_raw(self, key: str | bytes) -> bytes | None:
        assert isinstance(key, bytes)
        return self.values.get(key)

    async def consume(self, key: str | bytes) -> bytes | None:
        assert isinstance(key, bytes)
        return self.values.pop(key, None)

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None:
        assert isinstance(key, bytes)
        self.cas_calls += 1
        if self.values.get(key) != expected:
            return None
        return self.values.pop(key)


def byte_sources(*values: bytes) -> Iterator[bytes]:
    yield from values


def next_bytes(values: Iterator[bytes]) -> Callable[[int], bytes]:
    def generate(length: int) -> bytes:
        assert length == 32
        return next(values)

    return generate


def client_json(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "clientId": "cloudflare-access-dash",
        "redirectUris": ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
        "clientSecretHash": _ARGON2ID,
        "requiredRoles": [{"serviceKey": "agent-hub", "name": "user"}],
        "groupsServiceKeys": ["agent-hub"],
        "requirePkce": True,
        "allowedScopes": ["openid", "email", "profile"],
    }
    result.update(overrides)
    return result


def policy() -> OidcClientPolicy:
    return OidcClientPolicy.model_validate(client_json())


def test_oidc_groups_limit_counts_serialized_unicode_bytes() -> None:
    identity = OidcIdentity(
        user_id="test-user",
        email="test@example.invalid",
        name=None,
        email_verified=True,
        roles=tuple(Role("agent-hub", f"{index}" + "가" * 60) for index in range(20)),
    )
    with pytest.raises(ValueError, match="release limit"):
        project_groups(identity, policy())


@pytest.mark.parametrize("query", ["code=preset", "%73tate=preset", "error=preset"])
def test_oidc_redirect_cannot_predefine_response_fields(query: str) -> None:
    with pytest.raises(ValueError, match="response parameters"):
        OidcClientPolicy.model_validate(
            client_json(redirectUris=[f"https://team.cloudflareaccess.com/callback?{query}"])
        )


def test_oidc_client_registry_is_strict_and_preserves_exact_redirects() -> None:
    registry = parse_oidc_clients_json(json.dumps([client_json()]))
    client = registry.require("cloudflare-access-dash")

    assert client.accepts_redirect_uri("https://team.cloudflareaccess.com/cdn-cgi/access/callback")
    assert not client.accepts_redirect_uri(
        "https://team.cloudflareaccess.com/cdn-cgi/access/callback/"
    )
    assert registry.get("missing") is None

    with pytest.raises(ValueError, match="invalid client policy") as error:
        parse_oidc_clients_json(json.dumps([client_json(clientSecretHash="plain-secret")]))
    assert "plain-secret" not in str(error.value)


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "https://user@team.cloudflareaccess.com/callback",
        "https://team.cloudflareaccess.com/callback#",
        "https://*.cloudflareaccess.com/callback",
        "https://team.cloudflareaccess.com/\ncallback",
        "http://example.com/callback",
    ],
)
def test_oidc_client_rejects_ambiguous_or_insecure_redirects(redirect_uri: str) -> None:
    with pytest.raises(ValueError):
        OidcClientPolicy.model_validate(client_json(redirectUris=[redirect_uri]))


def test_loopback_redirect_requires_explicit_test_parse_mode() -> None:
    raw = json.dumps([client_json(redirectUris=["http://127.0.0.1:9876/callback"])])
    with pytest.raises(ValueError, match="test mode"):
        parse_oidc_clients_json(raw)
    assert parse_oidc_clients_json(raw, allow_loopback=True).clients


def test_client_roles_groups_scopes_and_pkce_rules() -> None:
    client = policy()
    identity = OidcIdentity(
        user_id="user-1",
        email="user@example.com",
        name=None,
        email_verified=True,
        roles=(
            Role(service_key="other", name="admin"),
            Role(service_key="agent-hub", name="viewer"),
            Role(service_key="agent-hub", name="user"),
            Role(service_key="agent-hub", name="user"),
        ),
    )
    assert has_required_role(identity, client)
    assert project_groups(identity, client) == ("agent-hub:user", "agent-hub:viewer")
    assert parse_requested_scopes("openid profile openid", client.allowed_scopes) == (
        "openid",
        "profile",
    )
    with pytest.raises(ValueError):
        parse_requested_scopes("email", client.allowed_scopes)

    verifier = "v" * 43
    challenge = sha256_base64url(verifier)
    validate_pkce_request(challenge, "S256", required=True)
    assert verify_pkce(verifier, challenge)
    assert not verify_pkce("wrong" * 10, challenge)
    with pytest.raises(ValueError):
        validate_pkce_request(None, None, required=True)


def transaction_input() -> OidcAuthorizationTransactionCreateInput:
    return OidcAuthorizationTransactionCreateInput(
        client_id="cloudflare-access-dash",
        redirect_uri="https://team.cloudflareaccess.com/cdn-cgi/access/callback",
        scopes=("openid", "email", "profile"),
        state="caller-state",
        nonce="caller-nonce",
        code_challenge=sha256_base64url("v" * 43),
        code_challenge_method="S256",
        browser_binding="browser-secret",
        csrf_token="csrf-secret",
    )


@pytest.mark.anyio
async def test_oidc_transaction_is_digest_keyed_browser_bound_and_single_use() -> None:
    redis = FakeRedis()
    store = OidcAuthorizationTransactionStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"T" * 32
    )
    transaction_id = await store.create(transaction_input())
    key = oidc_transaction_key(transaction_id)

    assert transaction_id.encode() not in key
    assert redis.ttls[key] == OIDC_TRANSACTION_TTL_SECONDS == 600
    assert b"browser-secret" not in redis.values[key]
    assert b"csrf-secret" not in redis.values[key]
    assert await store.get(transaction_id, browser_binding="wrong") is None
    assert key in redis.values

    record = await store.consume(transaction_id, browser_binding="browser-secret")
    assert record is not None and record.csrf_matches("csrf-secret")
    assert record.nonce == "caller-nonce"
    assert await store.consume(transaction_id, browser_binding="browser-secret") is None


@pytest.mark.anyio
async def test_provider_state_is_independent_bound_and_consumed_before_provider_use() -> None:
    redis = FakeRedis()
    transaction_id = base64.urlsafe_b64encode(b"T" * 32).rstrip(b"=").decode()
    store = OidcProviderStateStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"P" * 32
    )
    state = await store.create(
        OidcProviderStateCreateInput(
            provider="google",
            transaction_id=transaction_id,
            browser_binding="browser-secret",
        )
    )
    key = oidc_provider_state_key(state)

    assert state != transaction_id
    assert state.startswith(f"{transaction_id}.")
    assert provider_state_transaction_id(state) == transaction_id
    assert provider_state_transaction_id(transaction_id) is None
    assert state.encode() not in key
    assert redis.ttls[key] == OIDC_PROVIDER_STATE_TTL_SECONDS == 600
    assert b"browser-secret" not in redis.values[key]

    assert await store.consume_for_provider(state, "naver", "browser-secret") is None
    assert await store.consume_for_provider(state, "google", "wrong-browser") is None
    assert key in redis.values
    assert redis.cas_calls == 0

    record = await store.consume_for_provider(state, "google", "browser-secret")
    assert record is not None
    assert record.provider == "google"
    assert record.transaction_id == transaction_id
    assert key not in redis.values
    assert await store.consume_for_provider(state, "google", "browser-secret") is None


@pytest.mark.anyio
async def test_provider_state_expiry_and_record_prefix_mismatch_fail_closed() -> None:
    redis = FakeRedis()
    transaction_id = base64.urlsafe_b64encode(b"T" * 32).rstrip(b"=").decode()
    store = OidcProviderStateStore(
        redis,
        now_epoch_ms=lambda: 1_000_000,
        random_bytes=next_bytes(byte_sources(b"A" * 32, b"B" * 32)),
    )
    first = await store.create(
        OidcProviderStateCreateInput("google", transaction_id, "browser-secret")
    )
    first_key = oidc_provider_state_key(first)
    first_raw = json.loads(redis.values[first_key])
    first_raw["expiresAtEpochMs"] = 999_999
    redis.values[first_key] = json.dumps(first_raw).encode()
    assert await store.consume_for_provider(first, "google", "browser-secret") is None
    assert first_key not in redis.values

    second = await store.create(
        OidcProviderStateCreateInput("google", transaction_id, "browser-secret")
    )
    second_key = oidc_provider_state_key(second)
    second_raw = json.loads(redis.values[second_key])
    second_raw["transactionId"] = base64.urlsafe_b64encode(b"X" * 32).rstrip(b"=").decode()
    redis.values[second_key] = json.dumps(second_raw).encode()
    assert await store.consume_for_provider(second, "google", "browser-secret") is None
    assert second_key not in redis.values


def code_input() -> OidcAuthorizationCodeCreateInput:
    return OidcAuthorizationCodeCreateInput(
        client_id="cloudflare-access-dash",
        redirect_uri="https://team.cloudflareaccess.com/cdn-cgi/access/callback",
        user_id="user-1",
        scopes=("openid", "email"),
        nonce="nonce",
        code_challenge=sha256_base64url("v" * 43),
        code_challenge_method="S256",
    )


@pytest.mark.anyio
async def test_oidc_code_wrong_client_does_not_consume_but_owner_consumes_atomically() -> None:
    redis = FakeRedis()
    store = OidcAuthorizationCodeStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"C" * 32
    )
    code = await store.create(code_input())
    key = oidc_authorization_code_key(code)

    assert code.encode() not in key
    assert redis.ttls[key] == OIDC_AUTHORIZATION_CODE_TTL_SECONDS == 60
    assert await store.consume_for_client(code, "other-client") is None
    assert key in redis.values
    assert redis.cas_calls == 0

    record = await store.consume_for_client(code, "cloudflare-access-dash")
    assert record is not None and record.user_id == "user-1"
    assert key not in redis.values
    assert await store.consume_for_client(code, "cloudflare-access-dash") is None


@pytest.mark.anyio
async def test_expired_or_malformed_oidc_state_is_removed_fail_closed() -> None:
    redis = FakeRedis()
    codes = OidcAuthorizationCodeStore(redis, now_epoch_ms=lambda: 1_000_000)
    key = oidc_authorization_code_key("expired")
    redis.values[key] = b"not-json"
    assert await codes.consume_for_client("expired", "client") is None
    assert key not in redis.values

    transaction = OidcAuthorizationTransactionStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"E" * 32
    )
    transaction_id = await transaction.create(transaction_input())
    raw = json.loads(redis.values[oidc_transaction_key(transaction_id)])
    raw["expiresAtEpochMs"] = 999_999
    redis.values[oidc_transaction_key(transaction_id)] = json.dumps(raw).encode()
    assert await transaction.get(transaction_id, browser_binding="browser-secret") is None
    assert oidc_transaction_key(transaction_id) not in redis.values


def test_oidc_id_token_has_separate_claim_contract_and_optional_values(
    synthetic_settings: Settings,
) -> None:
    settings = synthetic_settings
    now = datetime(2026, 10, 15, 1, 2, 3, tzinfo=UTC)
    signer = OidcIdTokenSigner(
        private_key=settings.jwt_access_private_key,
        key_id=settings.jwt_access_key_id,
        issuer=settings.jwt_issuer,
        now=lambda: now,
    )
    token = signer.issue(
        OidcIdTokenIdentity(
            user_id="user-1",
            email="user@example.com",
            email_verified=True,
            name=None,
            groups=("agent-hub:user",),
        ),
        client_id="cloudflare-access-dash",
        nonce="caller-nonce",
    )
    payload = jwt.decode(
        token,
        jwt.PyJWK.from_dict(settings.jwt_access_public_jwk.model_dump()).key,
        algorithms=["RS256"],
        issuer=settings.jwt_issuer,
        audience="cloudflare-access-dash",
        options={"verify_exp": False},
    )
    assert jwt.get_unverified_header(token)["kid"] == settings.jwt_access_key_id
    assert payload == {
        "sub": "user-1",
        "email": "user@example.com",
        "email_verified": True,
        "groups": ["agent-hub:user"],
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + 300,
        "iss": settings.jwt_issuer,
        "aud": "cloudflare-access-dash",
        "nonce": "caller-nonce",
    }


@pytest.mark.anyio
async def test_oidc_opaque_access_token_is_digest_keyed_persistent_and_revocable() -> None:
    redis = FakeRedis()
    values = byte_sources(b"A" * 32)
    store = OidcAccessTokenStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=next_bytes(values)
    )
    token = await store.create(
        OidcAccessTokenCreateInput(
            client_id="cloudflare-access-dash",
            user_id="user-1",
            scopes=("openid", "email"),
        )
    )
    expected = base64.urlsafe_b64encode(b"A" * 32).rstrip(b"=").decode()
    key = oidc_access_token_key(token)
    assert token == expected
    assert token.encode() not in key
    assert redis.ttls[key] == OIDC_ACCESS_TOKEN_TTL_SECONDS == 300

    first = await store.get(token)
    second = await store.get(token)
    assert first == second
    assert first is not None and first.user_id == "user-1"
    assert await store.revoke(token)
    assert await store.get(token) is None
