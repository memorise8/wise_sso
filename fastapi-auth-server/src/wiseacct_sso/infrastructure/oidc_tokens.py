"""OIDC-specific ID-token signing and opaque UserInfo bearer storage."""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Final, Protocol, cast

import jwt

from wiseacct_sso.infrastructure.redis import node_utf8_bytes

OIDC_ACCESS_TOKEN_TTL_SECONDS: Final = 5 * 60
OIDC_ACCESS_TOKEN_KEY_PREFIX: Final = b"wiseacct:oidc:access-token:"
_RANDOM_BYTES: Final = 32
_MAX_GENERATION_ATTEMPTS: Final = 3


class _RedisState(Protocol):
    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool: ...

    async def get_raw(self, key: str | bytes) -> bytes | None: ...

    async def consume(self, key: str | bytes) -> bytes | None: ...

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None: ...


class OidcSigningSettings(Protocol):
    jwt_access_private_key: str
    jwt_access_key_id: str
    jwt_issuer: str


@dataclass(frozen=True, slots=True)
class OidcIdTokenIdentity:
    user_id: str
    email: str
    email_verified: bool
    name: str | None
    groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OidcAccessTokenCreateInput:
    client_id: str
    user_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StoredOidcAccessToken:
    client_id: str
    user_id: str
    scopes: tuple[str, ...]
    expires_at_epoch_ms: int


class OidcTokenCreationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Unable to generate unique OIDC token")


class OidcIdTokenSigner:
    """Sign OIDC ID tokens with the same published RS256 key, but separate claims."""

    def __init__(
        self,
        *,
        private_key: str,
        key_id: str,
        issuer: str,
        expires_in_seconds: int = OIDC_ACCESS_TOKEN_TTL_SECONDS,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not private_key or not key_id or not issuer:
            raise ValueError("OIDC signing settings must not be empty")
        if expires_in_seconds <= 0:
            raise ValueError("OIDC ID token expiry must be positive")
        self._private_key = private_key
        self._key_id = key_id
        self._issuer = issuer
        self._expires_in_seconds = expires_in_seconds
        self._now = now or (lambda: datetime.now(UTC))

    @classmethod
    def from_settings(cls, settings: OidcSigningSettings) -> OidcIdTokenSigner:
        return cls(
            private_key=settings.jwt_access_private_key,
            key_id=settings.jwt_access_key_id,
            issuer=settings.jwt_issuer,
        )

    def issue(
        self,
        identity: OidcIdTokenIdentity,
        *,
        client_id: str,
        nonce: str | None = None,
    ) -> str:
        if (
            not identity.user_id
            or not identity.email
            or not identity.email_verified
            or not client_id
            or (identity.name is not None and not identity.name)
            or (nonce is not None and not nonce)
            or any(not group for group in identity.groups)
        ):
            raise ValueError("invalid OIDC ID token identity or audience")
        issued_at = self._now().astimezone(UTC).replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=self._expires_in_seconds)
        payload: dict[str, object] = {
            "sub": identity.user_id,
            "email": identity.email,
            "email_verified": identity.email_verified,
            "groups": list(identity.groups),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self._issuer,
            "aud": client_id,
        }
        if identity.name is not None:
            payload["name"] = identity.name
        if nonce is not None:
            payload["nonce"] = nonce
        return jwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._key_id},
        )


def oidc_access_token_key(token: str) -> bytes:
    digest = sha256(node_utf8_bytes(token)).hexdigest()
    return OIDC_ACCESS_TOKEN_KEY_PREFIX + digest.encode("ascii")


def _random_token(random_bytes: Callable[[int], bytes]) -> str:
    raw = random_bytes(_RANDOM_BYTES)
    if len(raw) != _RANDOM_BYTES:
        raise ValueError("random byte source must return exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _serialize(input: OidcAccessTokenCreateInput, expires: int) -> bytes:
    return json.dumps(
        {
            "purpose": "oidc-userinfo",
            "clientId": input.client_id,
            "userId": input.user_id,
            "scopes": list(input.scopes),
            "expiresAtEpochMs": expires,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _record(raw: bytes) -> StoredOidcAccessToken | None:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "purpose",
        "clientId",
        "userId",
        "scopes",
        "expiresAtEpochMs",
    }:
        return None
    scopes = value["scopes"]
    expires = value["expiresAtEpochMs"]
    if (
        value["purpose"] != "oidc-userinfo"
        or not isinstance(value["clientId"], str)
        or not value["clientId"]
        or not isinstance(value["userId"], str)
        or not value["userId"]
        or not isinstance(scopes, list)
        or not scopes
        or len(scopes) > 16
        or any(not isinstance(scope, str) or not scope for scope in scopes)
        or len(set(cast(list[str], scopes))) != len(scopes)
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or expires <= 0
    ):
        return None
    return StoredOidcAccessToken(
        client_id=value["clientId"],
        user_id=value["userId"],
        scopes=tuple(cast(list[str], scopes)),
        expires_at_epoch_ms=expires,
    )


class OidcAccessTokenStore:
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

    async def create(self, input: OidcAccessTokenCreateInput) -> str:
        expires = self._now_epoch_ms() + OIDC_ACCESS_TOKEN_TTL_SECONDS * 1000
        raw = _serialize(input, expires)
        if _record(raw) is None:
            raise ValueError("invalid OIDC access token metadata")
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            token = _random_token(self._random_bytes)
            if await self._redis.set_if_absent(
                oidc_access_token_key(token), raw, OIDC_ACCESS_TOKEN_TTL_SECONDS
            ):
                return token
        raise OidcTokenCreationError()

    async def get(self, token: str) -> StoredOidcAccessToken | None:
        key = oidc_access_token_key(token)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        record = _record(raw)
        if record is None or record.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        return record

    async def revoke(self, token: str) -> bool:
        return await self._redis.consume(oidc_access_token_key(token)) is not None
