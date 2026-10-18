import base64
import hashlib
import json
from collections.abc import Callable, Iterator

import pytest

from wiseacct_sso.infrastructure.auth_state import (
    AuthHandoffConsumeInput,
    AuthHandoffCreateInput,
    AuthHandoffCreationError,
    AuthHandoffStore,
    OAuthStateCreationError,
    OAuthStateMetadata,
    OAuthStateStore,
    sha256_base64url,
)
from wiseacct_sso.infrastructure.redis import (
    AUTH_HANDOFF_TTL_SECONDS,
    OAUTH_STATE_TTL_SECONDS,
    auth_handoff_key,
    node_utf8_bytes,
    oauth_state_key,
    sha256_hex,
)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[bytes, bytes] = {}
        self.ttls: dict[bytes, int] = {}
        self.set_attempts = 0
        self.cas_values: list[bytes] = []

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        assert isinstance(key, bytes)
        self.set_attempts += 1
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
        self.cas_values.append(expected)
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


def oauth_metadata() -> OAuthStateMetadata:
    return OAuthStateMetadata(
        client_id="temis",
        redirect_uri="https://financenow.kr/auth/callback",
        caller_state="caller-state",
        code_challenge="challenge",
        code_challenge_method="S256",
    )


def handoff_input(challenge: str) -> AuthHandoffCreateInput:
    return AuthHandoffCreateInput(
        client_id="temis",
        audience="ledger-api",
        redirect_uri="https://financenow.kr/auth/callback",
        user_id="user-1",
        provider="google",
        login_method="oauth",
        code_challenge=challenge,
        code_challenge_method="S256",
        state="caller-state",
    )


@pytest.mark.anyio
async def test_oauth_state_uses_raw_key_32_bytes_nx_ttl_and_consumes_wrong_provider() -> None:
    redis = FakeRedis()
    random_values = byte_sources(b"A" * 32, b"B" * 32)
    store = OAuthStateStore(redis, random_bytes=next_bytes(random_values))

    first = await store.create("google", oauth_metadata())
    assert first == base64.urlsafe_b64encode(b"A" * 32).rstrip(b"=").decode()
    assert len(first) == 43
    assert redis.ttls[oauth_state_key(first)] == OAUTH_STATE_TTL_SECONDS == 600
    assert await store.create("google", oauth_metadata()) != first

    assert await store.consume("naver", first) is None
    assert await store.consume("google", first) is None


@pytest.mark.anyio
async def test_oauth_state_strict_semantic_json_and_provider_binding() -> None:
    redis = FakeRedis()
    store = OAuthStateStore(redis)
    key = oauth_state_key("state")
    valid = {
        "provider": "google",
        "clientId": "temis",
        "redirectUri": "https://financenow.kr/callback",
        "callerState": None,
        "codeChallenge": None,
        "codeChallengeMethod": None,
    }

    for invalid in (
        {**valid, "extra": True},
        {**valid, "provider": "github"},
        {**valid, "redirectUri": "/relative"},
        {**valid, "callerState": ""},
    ):
        redis.values[key] = json.dumps(invalid).encode()
        assert await store.consume("google", "state") is None
        assert key not in redis.values

    redis.values[key] = b"not-json"
    assert await store.consume("google", "state") is None
    assert key not in redis.values


@pytest.mark.anyio
async def test_three_oauth_and_handoff_nx_collisions_raise_specific_errors() -> None:
    collision = b"C" * 32
    state_redis = FakeRedis()
    state = base64.urlsafe_b64encode(collision).rstrip(b"=").decode()
    state_redis.values[oauth_state_key(state)] = b"occupied"
    state_store = OAuthStateStore(state_redis, random_bytes=lambda _: collision)
    with pytest.raises(OAuthStateCreationError):
        await state_store.create("google", oauth_metadata())
    assert state_redis.set_attempts == 3

    handoff_redis = FakeRedis()
    code = state
    handoff_redis.values[auth_handoff_key(code)] = b"occupied"
    handoff_store = AuthHandoffStore(
        handoff_redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: collision
    )
    with pytest.raises(AuthHandoffCreationError):
        await handoff_store.create(handoff_input(sha256_base64url("verifier")))
    assert handoff_redis.set_attempts == 3


@pytest.mark.anyio
async def test_handoff_uses_hashed_key_ttl_and_returns_matching_metadata_once() -> None:
    redis = FakeRedis()
    verifier = "verifier-123456789012345678901234567890123"
    challenge = sha256_base64url(verifier)
    store = AuthHandoffStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"D" * 32
    )
    code = await store.create(handoff_input(challenge))
    key = auth_handoff_key(code)

    assert code.encode() not in key
    assert redis.ttls[key] == AUTH_HANDOFF_TTL_SECONDS == 120
    assert b"accessToken" not in redis.values[key]
    assert b"refreshToken" not in redis.values[key]
    result = await store.consume(
        AuthHandoffConsumeInput(
            client_id="temis",
            redirect_uri="https://financenow.kr/auth/callback",
            code=code,
            code_verifier=verifier,
        )
    )
    assert result is not None
    assert result.user_id == "user-1"
    assert result.audience == "ledger-api"
    assert (
        await store.consume(
            AuthHandoffConsumeInput("temis", "https://financenow.kr/auth/callback", code, verifier)
        )
        is None
    )


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("client_id", "redirect_uri", "verifier"),
    [
        ("other", "https://financenow.kr/auth/callback", "correct"),
        ("temis", "https://evil.example/callback", "correct"),
        ("temis", "https://financenow.kr/auth/callback", "wrong"),
    ],
)
async def test_wrong_handoff_binding_does_not_consume(
    client_id: str, redirect_uri: str, verifier: str
) -> None:
    redis = FakeRedis()
    store = AuthHandoffStore(
        redis, now_epoch_ms=lambda: 1_000_000, random_bytes=lambda _: b"E" * 32
    )
    code = await store.create(handoff_input(sha256_base64url("correct")))
    key = auth_handoff_key(code)

    assert (
        await store.consume(AuthHandoffConsumeInput(client_id, redirect_uri, code, verifier))
        is None
    )
    assert key in redis.values
    assert redis.cas_values == []


@pytest.mark.anyio
async def test_malformed_and_expired_handoff_consume_exact_original_raw_value() -> None:
    redis = FakeRedis()
    store = AuthHandoffStore(redis, now_epoch_ms=lambda: 1_000_000)
    key = auth_handoff_key("code")
    malformed = b'{ "clientId": "temis", "unexpected": true }'
    redis.values[key] = malformed
    attempt = AuthHandoffConsumeInput("temis", "https://financenow.kr/callback", "code", "x")

    assert await store.consume(attempt) is None
    assert redis.cas_values[-1] is malformed
    assert key not in redis.values

    expired = {
        "clientId": "temis",
        "audience": "ledger-api",
        "redirectUri": "https://financenow.kr/callback",
        "userId": "user-1",
        "loginMethod": "password",
        "codeChallenge": sha256_base64url("x"),
        "codeChallengeMethod": "S256",
        "state": None,
        "expiresAtEpochMs": 999_999,
    }
    raw = json.dumps(expired, indent=2).encode()
    redis.values[key] = raw
    assert await store.consume(attempt) is None
    assert redis.cas_values[-1] is raw
    assert key not in redis.values


@pytest.mark.anyio
async def test_handoff_strict_schema_rejects_null_provider_but_accepts_integer_float_expiry() -> (
    None
):
    redis = FakeRedis()
    store = AuthHandoffStore(redis, now_epoch_ms=lambda: 999_000)
    key = auth_handoff_key("code")
    verifier = "x"
    record = {
        "clientId": "temis",
        "audience": "ledger-api",
        "redirectUri": "https://financenow.kr/callback",
        "userId": "user-1",
        "loginMethod": "password",
        "codeChallenge": sha256_base64url(verifier),
        "codeChallengeMethod": "S256",
        "state": None,
        "expiresAtEpochMs": 1_000_000.0,
    }
    attempt = AuthHandoffConsumeInput("temis", "https://financenow.kr/callback", "code", verifier)

    redis.values[key] = json.dumps({**record, "provider": None}).encode()
    assert await store.consume(attempt) is None
    assert key not in redis.values

    redis.values[key] = json.dumps(record).encode()
    assert await store.consume(attempt) is not None
    assert key not in redis.values


def test_node_string_normalization_matches_node_hash_and_base64url_contract() -> None:
    replacement = "\ufffd".encode()
    assert node_utf8_bytes("\ud800") == replacement
    assert node_utf8_bytes("\udc00") == replacement
    assert node_utf8_bytes("\ud83d\ude00") == "😀".encode()
    assert sha256_hex("\ud800") == hashlib.sha256(replacement).hexdigest()
    assert sha256_base64url("\ud800") == (
        base64.urlsafe_b64encode(hashlib.sha256(replacement).digest()).rstrip(b"=").decode()
    )
