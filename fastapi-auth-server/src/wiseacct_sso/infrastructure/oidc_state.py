"""Independent Redis records for OIDC browser transactions and authorization codes."""

from __future__ import annotations

import base64
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Literal, Protocol, cast

from wiseacct_sso.domain.oauth import OAUTH_PROVIDERS, OAuthProvider
from wiseacct_sso.infrastructure.redis import node_utf8_bytes

OIDC_TRANSACTION_TTL_SECONDS: Final = 10 * 60
OIDC_PROVIDER_STATE_TTL_SECONDS: Final = 10 * 60
OIDC_AUTHORIZATION_CODE_TTL_SECONDS: Final = 60
OIDC_TRANSACTION_KEY_PREFIX: Final = b"wiseacct:oidc:transaction:"
OIDC_PROVIDER_STATE_KEY_PREFIX: Final = b"wiseacct:oidc:provider-state:"
OIDC_AUTHORIZATION_CODE_KEY_PREFIX: Final = b"wiseacct:oidc:code:"

_RANDOM_BYTES: Final = 32
_MAX_GENERATION_ATTEMPTS: Final = 3
_OPAQUE_VALUE_RE = r"[A-Za-z0-9_-]{43}"
_TRANSACTION_ID = re.compile(rf"^{_OPAQUE_VALUE_RE}$")
_PROVIDER_STATE = re.compile(
    rf"^(?P<transaction>{_OPAQUE_VALUE_RE})\.(?P<random>{_OPAQUE_VALUE_RE})$"
)


class _RedisState(Protocol):
    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool: ...

    async def get_raw(self, key: str | bytes) -> bytes | None: ...

    async def consume(self, key: str | bytes) -> bytes | None: ...

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class OidcAuthorizationTransactionCreateInput:
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str | None
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: Literal["S256"] | None
    browser_binding: str
    csrf_token: str


@dataclass(frozen=True, slots=True)
class OidcAuthorizationTransaction:
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str | None
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: Literal["S256"] | None
    browser_binding_hash: str
    csrf_hash: str
    expires_at_epoch_ms: int

    def csrf_matches(self, csrf_token: str) -> bool:
        return hmac.compare_digest(self.csrf_hash, oidc_secret_digest(csrf_token))


@dataclass(frozen=True, slots=True)
class OidcProviderStateCreateInput:
    provider: OAuthProvider
    transaction_id: str
    browser_binding: str


@dataclass(frozen=True, slots=True)
class OidcProviderState:
    provider: OAuthProvider
    transaction_id: str
    browser_binding_hash: str
    expires_at_epoch_ms: int


@dataclass(frozen=True, slots=True)
class OidcAuthorizationCodeCreateInput:
    client_id: str
    redirect_uri: str
    user_id: str
    scopes: tuple[str, ...]
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: Literal["S256"] | None


@dataclass(frozen=True, slots=True)
class StoredOidcAuthorizationCode:
    client_id: str
    redirect_uri: str
    user_id: str
    scopes: tuple[str, ...]
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: Literal["S256"] | None
    expires_at_epoch_ms: int


class OidcStateCreationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Unable to generate unique OIDC state")


def oidc_secret_digest(value: str) -> str:
    return sha256(node_utf8_bytes(value)).hexdigest()


def oidc_transaction_key(transaction_id: str) -> bytes:
    return OIDC_TRANSACTION_KEY_PREFIX + oidc_secret_digest(transaction_id).encode("ascii")


def oidc_provider_state_key(state: str) -> bytes:
    return OIDC_PROVIDER_STATE_KEY_PREFIX + oidc_secret_digest(state).encode("ascii")


def oidc_authorization_code_key(code: str) -> bytes:
    return OIDC_AUTHORIZATION_CODE_KEY_PREFIX + oidc_secret_digest(code).encode("ascii")


def _random_token(random_bytes: Callable[[int], bytes]) -> str:
    raw = random_bytes(_RANDOM_BYTES)
    if len(raw) != _RANDOM_BYTES:
        raise ValueError("random byte source must return exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _serialize(record: dict[str, object]) -> bytes:
    return json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _object(raw: bytes) -> dict[str, object] | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _nonempty(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _optional_nonempty(value: object) -> str | bool | None:
    if value is None:
        return None
    return value if isinstance(value, str) and value else False


def _scopes(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or not value or len(value) > 16:
        return None
    if any(not isinstance(scope, str) or not scope for scope in value):
        return None
    parsed = tuple(cast(list[str], value))
    return parsed if len(set(parsed)) == len(parsed) else None


def _positive_integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _pkce(challenge: object, method: object) -> tuple[str | None, Literal["S256"] | None] | None:
    parsed_challenge = _optional_nonempty(challenge)
    if parsed_challenge is False:
        return None
    if parsed_challenge is None and method is None:
        return None, None
    if isinstance(parsed_challenge, str) and method == "S256":
        return parsed_challenge, "S256"
    return None


def _transaction_record(raw: bytes) -> OidcAuthorizationTransaction | None:
    record = _object(raw)
    required = {
        "purpose",
        "clientId",
        "redirectUri",
        "scopes",
        "state",
        "nonce",
        "codeChallenge",
        "codeChallengeMethod",
        "browserBindingHash",
        "csrfHash",
        "expiresAtEpochMs",
    }
    if record is None or set(record) != required or record["purpose"] != "oidc-transaction":
        return None
    client_id = _nonempty(record["clientId"])
    redirect_uri = _nonempty(record["redirectUri"])
    scopes = _scopes(record["scopes"])
    state = _optional_nonempty(record["state"])
    nonce = _optional_nonempty(record["nonce"])
    pkce = _pkce(record["codeChallenge"], record["codeChallengeMethod"])
    binding_hash = _nonempty(record["browserBindingHash"])
    csrf_hash = _nonempty(record["csrfHash"])
    expires = _positive_integer(record["expiresAtEpochMs"])
    if (
        client_id is None
        or redirect_uri is None
        or scopes is None
        or state is False
        or nonce is False
        or pkce is None
        or binding_hash is None
        or csrf_hash is None
        or expires is None
    ):
        return None
    return OidcAuthorizationTransaction(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
        state=cast(str | None, state),
        nonce=cast(str | None, nonce),
        code_challenge=pkce[0],
        code_challenge_method=pkce[1],
        browser_binding_hash=binding_hash,
        csrf_hash=csrf_hash,
        expires_at_epoch_ms=expires,
    )


def _provider_state_record(raw: bytes) -> OidcProviderState | None:
    record = _object(raw)
    required = {
        "purpose",
        "provider",
        "transactionId",
        "browserBindingHash",
        "expiresAtEpochMs",
    }
    if record is None or set(record) != required or record["purpose"] != "oidc-provider-state":
        return None
    provider = record["provider"]
    transaction_id = _nonempty(record["transactionId"])
    binding_hash = _nonempty(record["browserBindingHash"])
    expires = _positive_integer(record["expiresAtEpochMs"])
    if (
        provider not in OAUTH_PROVIDERS
        or transaction_id is None
        or _TRANSACTION_ID.fullmatch(transaction_id) is None
        or binding_hash is None
        or expires is None
    ):
        return None
    return OidcProviderState(
        provider=provider,
        transaction_id=transaction_id,
        browser_binding_hash=binding_hash,
        expires_at_epoch_ms=expires,
    )


def _code_record(raw: bytes) -> StoredOidcAuthorizationCode | None:
    record = _object(raw)
    required = {
        "purpose",
        "clientId",
        "redirectUri",
        "userId",
        "scopes",
        "nonce",
        "codeChallenge",
        "codeChallengeMethod",
        "expiresAtEpochMs",
    }
    if record is None or set(record) != required or record["purpose"] != "oidc-code":
        return None
    client_id = _nonempty(record["clientId"])
    redirect_uri = _nonempty(record["redirectUri"])
    user_id = _nonempty(record["userId"])
    scopes = _scopes(record["scopes"])
    nonce = _optional_nonempty(record["nonce"])
    pkce = _pkce(record["codeChallenge"], record["codeChallengeMethod"])
    expires = _positive_integer(record["expiresAtEpochMs"])
    if (
        client_id is None
        or redirect_uri is None
        or user_id is None
        or scopes is None
        or nonce is False
        or pkce is None
        or expires is None
    ):
        return None
    return StoredOidcAuthorizationCode(
        client_id=client_id,
        redirect_uri=redirect_uri,
        user_id=user_id,
        scopes=scopes,
        nonce=cast(str | None, nonce),
        code_challenge=pkce[0],
        code_challenge_method=pkce[1],
        expires_at_epoch_ms=expires,
    )


class OidcAuthorizationTransactionStore:
    def __init__(
        self,
        redis: _RedisState,
        *,
        now_epoch_ms: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._redis = redis
        self._now_epoch_ms = now_epoch_ms or (lambda: int(time.time() * 1000))
        self._random_bytes = random_bytes

    async def create(self, input: OidcAuthorizationTransactionCreateInput) -> str:
        expires = self._now_epoch_ms() + OIDC_TRANSACTION_TTL_SECONDS * 1000
        raw = _serialize(
            {
                "purpose": "oidc-transaction",
                "clientId": input.client_id,
                "redirectUri": input.redirect_uri,
                "scopes": list(input.scopes),
                "state": input.state,
                "nonce": input.nonce,
                "codeChallenge": input.code_challenge,
                "codeChallengeMethod": input.code_challenge_method,
                "browserBindingHash": oidc_secret_digest(input.browser_binding),
                "csrfHash": oidc_secret_digest(input.csrf_token),
                "expiresAtEpochMs": expires,
            }
        )
        if _transaction_record(raw) is None:
            raise ValueError("invalid OIDC authorization transaction")
        return await self._store_unique(raw, OIDC_TRANSACTION_TTL_SECONDS)

    async def get(
        self, transaction_id: str, *, browser_binding: str
    ) -> OidcAuthorizationTransaction | None:
        key = oidc_transaction_key(transaction_id)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        record = _transaction_record(raw)
        if record is None or record.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        if not hmac.compare_digest(
            record.browser_binding_hash, oidc_secret_digest(browser_binding)
        ):
            return None
        return record

    async def consume(
        self, transaction_id: str, *, browser_binding: str
    ) -> OidcAuthorizationTransaction | None:
        key = oidc_transaction_key(transaction_id)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        record = _transaction_record(raw)
        if record is None or record.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        if not hmac.compare_digest(
            record.browser_binding_hash, oidc_secret_digest(browser_binding)
        ):
            return None
        consumed = await self._redis.consume_if_exact(key, raw)
        return record if consumed is not None else None

    async def discard(self, transaction_id: str) -> None:
        await self._redis.consume(oidc_transaction_key(transaction_id))

    async def _store_unique(self, raw: bytes, ttl_seconds: int) -> str:
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            token = _random_token(self._random_bytes)
            if await self._redis.set_if_absent(oidc_transaction_key(token), raw, ttl_seconds):
                return token
        raise OidcStateCreationError()


def provider_state_transaction_id(state: str) -> str | None:
    """Recover the cookie-selector transaction id; the Redis record remains authoritative."""

    match = _PROVIDER_STATE.fullmatch(state)
    return match.group("transaction") if match is not None else None


class OidcProviderStateStore:
    def __init__(
        self,
        redis: _RedisState,
        *,
        now_epoch_ms: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._redis = redis
        self._now_epoch_ms = now_epoch_ms or (lambda: int(time.time() * 1000))
        self._random_bytes = random_bytes

    async def create(self, input: OidcProviderStateCreateInput) -> str:
        if (
            input.provider not in OAUTH_PROVIDERS
            or _TRANSACTION_ID.fullmatch(input.transaction_id) is None
            or not input.browser_binding
        ):
            raise ValueError("invalid OIDC provider state metadata")
        raw = _serialize(
            {
                "purpose": "oidc-provider-state",
                "provider": input.provider,
                "transactionId": input.transaction_id,
                "browserBindingHash": oidc_secret_digest(input.browser_binding),
                "expiresAtEpochMs": self._now_epoch_ms() + OIDC_PROVIDER_STATE_TTL_SECONDS * 1000,
            }
        )
        if _provider_state_record(raw) is None:
            raise ValueError("invalid OIDC provider state metadata")
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            state = f"{input.transaction_id}.{_random_token(self._random_bytes)}"
            if await self._redis.set_if_absent(
                oidc_provider_state_key(state), raw, OIDC_PROVIDER_STATE_TTL_SECONDS
            ):
                return state
        raise OidcStateCreationError()

    async def consume_for_provider(
        self,
        state: str,
        provider: OAuthProvider,
        browser_binding: str,
    ) -> OidcProviderState | None:
        transaction_id = provider_state_transaction_id(state)
        if transaction_id is None:
            return None
        key = oidc_provider_state_key(state)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        record = _provider_state_record(raw)
        if record is None or record.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        if record.transaction_id != transaction_id:
            await self._redis.consume_if_exact(key, raw)
            return None
        binding_hash = oidc_secret_digest(browser_binding)
        if record.provider != provider or not hmac.compare_digest(
            record.browser_binding_hash, binding_hash
        ):
            return None
        consumed = await self._redis.consume_if_exact(key, raw)
        return record if consumed is not None else None

    async def discard(self, state: str) -> None:
        await self._redis.consume(oidc_provider_state_key(state))


class OidcAuthorizationCodeStore:
    def __init__(
        self,
        redis: _RedisState,
        *,
        now_epoch_ms: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._redis = redis
        self._now_epoch_ms = now_epoch_ms or (lambda: int(time.time() * 1000))
        self._random_bytes = random_bytes

    async def create(self, input: OidcAuthorizationCodeCreateInput) -> str:
        raw = _serialize(
            {
                "purpose": "oidc-code",
                "clientId": input.client_id,
                "redirectUri": input.redirect_uri,
                "userId": input.user_id,
                "scopes": list(input.scopes),
                "nonce": input.nonce,
                "codeChallenge": input.code_challenge,
                "codeChallengeMethod": input.code_challenge_method,
                "expiresAtEpochMs": (
                    self._now_epoch_ms() + OIDC_AUTHORIZATION_CODE_TTL_SECONDS * 1000
                ),
            }
        )
        if _code_record(raw) is None:
            raise ValueError("invalid OIDC authorization code metadata")
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            code = _random_token(self._random_bytes)
            if await self._redis.set_if_absent(
                oidc_authorization_code_key(code), raw, OIDC_AUTHORIZATION_CODE_TTL_SECONDS
            ):
                return code
        raise OidcStateCreationError()

    async def consume_for_client(
        self, code: str, client_id: str
    ) -> StoredOidcAuthorizationCode | None:
        key = oidc_authorization_code_key(code)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        record = _code_record(raw)
        if record is None or record.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        if not hmac.compare_digest(record.client_id, client_id):
            return None
        consumed = await self._redis.consume_if_exact(key, raw)
        return record if consumed is not None else None

    async def discard(self, code: str) -> None:
        await self._redis.consume(oidc_authorization_code_key(code))
