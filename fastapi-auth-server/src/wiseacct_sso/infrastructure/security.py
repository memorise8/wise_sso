"""Password and token primitives compatible with the Express security policy."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol, cast

import anyio
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.tokens import (
    AccessTokenClaims,
    AccessTokenIdentity,
    IssuedRefreshToken,
    RefreshTokenClaims,
    RoleClaim,
    TokenValidationError,
)

ARGON2_MEMORY_COST_KIB: Final = 19_456
ARGON2_TIME_COST: Final = 2
ARGON2_PARALLELISM: Final = 1
ARGON2_HASH_LENGTH: Final = 32
ARGON2_SALT_LENGTH: Final = 16
DEFAULT_PASSWORD_HASH_THREADS: Final = 4
_REFRESH_TOKEN_ID: Final = re.compile(r"^[0-9a-f]{64}$")
_HIGH_SURROGATE_START: Final = 0xD800
_HIGH_SURROGATE_END: Final = 0xDBFF
_LOW_SURROGATE_START: Final = 0xDC00
_LOW_SURROGATE_END: Final = 0xDFFF

# Existing Express dummy credential. Keeping it fixed prevents user-enumeration shortcuts.
DUMMY_PASSWORD_HASH: Final = (
    "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$"  # noqa: S105
    "U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM"
)


class _SyncPasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, hash: str, password: str) -> bool: ...


def build_password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        salt_len=ARGON2_SALT_LENGTH,
        type=Type.ID,
    )


def _normalize_node_string(value: str) -> str:
    """Mirror Node's UTF-16 to UTF-8 replacement behavior for string inputs."""

    normalized: list[str] = []
    index = 0
    while index < len(value):
        code_point = ord(value[index])
        if _HIGH_SURROGATE_START <= code_point <= _HIGH_SURROGATE_END:
            if index + 1 < len(value):
                low_surrogate = ord(value[index + 1])
                if _LOW_SURROGATE_START <= low_surrogate <= _LOW_SURROGATE_END:
                    astral_code_point = (
                        0x10000
                        + ((code_point - _HIGH_SURROGATE_START) << 10)
                        + (low_surrogate - _LOW_SURROGATE_START)
                    )
                    normalized.append(chr(astral_code_point))
                    index += 2
                    continue
            normalized.append("\ufffd")
        elif _LOW_SURROGATE_START <= code_point <= _LOW_SURROGATE_END:
            normalized.append("\ufffd")
        else:
            normalized.append(value[index])
        index += 1
    return "".join(normalized)


class AsyncPasswordHasher:
    """Run memory-hard password work outside the event loop with bounded concurrency."""

    def __init__(
        self,
        *,
        max_threads: int = DEFAULT_PASSWORD_HASH_THREADS,
        hasher: _SyncPasswordHasher | None = None,
    ) -> None:
        if max_threads <= 0:
            raise ValueError("max_threads must be positive")
        self._hasher = hasher or build_password_hasher()
        self._limiter = anyio.CapacityLimiter(max_threads)

    async def hash_password(self, password: str) -> str:
        if not password:
            raise ValueError("password must not be empty")
        return await anyio.to_thread.run_sync(
            self._hasher.hash,
            _normalize_node_string(password),
            limiter=self._limiter,
        )

    async def verify_password(self, password_hash: str, password: str) -> bool:
        if not password_hash:
            return False

        def verify() -> bool:
            try:
                return self._hasher.verify(password_hash, _normalize_node_string(password))
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False

        return await anyio.to_thread.run_sync(verify, limiter=self._limiter)


def sha256_token(token: str) -> str:
    """Match Node's createHash('sha256').update(token).digest('hex') contract."""

    return hashlib.sha256(_normalize_node_string(token).encode()).hexdigest()


def _integer_claim(payload: Mapping[str, object], name: str) -> int:
    value = payload.get(name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _string_claim(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_string_claim(payload: Mapping[str, object], name: str) -> str | None:
    if name not in payload:
        raise ValueError(f"{name} is required")
    value = payload.get(name)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{name} must be a string or null")
    return value


def _roles_claim(payload: Mapping[str, object]) -> tuple[RoleClaim, ...]:
    roles = payload.get("roles")
    if not isinstance(roles, list):
        raise ValueError("roles must be a list")
    parsed: list[RoleClaim] = []
    for role in roles:
        if not isinstance(role, dict) or set(role) != {"serviceKey", "name"}:
            raise ValueError("role entries must use the Express claim shape")
        service_key = role.get("serviceKey")
        name = role.get("name")
        if not isinstance(service_key, str) or not isinstance(name, str):
            raise ValueError("role values must be strings")
        parsed.append(RoleClaim(service_key=service_key, name=name))
    return tuple(parsed)


class JwtTokenCodec:
    """Issue and validate the cryptographically separated access and refresh JWTs."""

    def __init__(
        self,
        *,
        access_private_key: str,
        access_public_jwk: Mapping[str, object],
        access_key_id: str,
        issuer: str,
        default_audience: str,
        access_expires_in_seconds: int,
        refresh_secret: str,
        refresh_expires_in_days: int,
    ) -> None:
        self._access_private_key = access_private_key
        self._access_public_key = cast(
            RSAPublicKey,
            jwt.PyJWK.from_dict(dict(access_public_jwk), algorithm="RS256").key,
        )
        self._access_key_id = access_key_id
        self._issuer = issuer
        self._default_audience = default_audience
        self._access_expires_in_seconds = access_expires_in_seconds
        self._refresh_secret = refresh_secret
        self._refresh_expires_in_days = refresh_expires_in_days

    @classmethod
    def from_settings(cls, settings: Settings) -> JwtTokenCodec:
        return cls(
            access_private_key=settings.jwt_access_private_key,
            access_public_jwk=settings.jwt_access_public_jwk.model_dump(),
            access_key_id=settings.jwt_access_key_id,
            issuer=settings.jwt_issuer,
            default_audience=settings.jwt_audience,
            access_expires_in_seconds=settings.access_token_expires_in,
            refresh_secret=settings.jwt_refresh_secret,
            refresh_expires_in_days=settings.refresh_token_expires_in_days,
        )

    def issue_access_token(
        self,
        identity: AccessTokenIdentity,
        *,
        audience: str | None = None,
    ) -> str:
        issued_at = datetime.now(UTC).replace(microsecond=0)
        expires_at = issued_at + timedelta(seconds=self._access_expires_in_seconds)
        payload: dict[str, object] = {
            "sub": identity.user_id,
            "email": identity.email,
            "name": identity.name,
            "email_verified": identity.email_verified,
            "type": "access",
            "roles": [
                {"serviceKey": role.service_key, "name": role.name} for role in identity.roles
            ],
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self._issuer,
            "aud": audience or self._default_audience,
        }
        return jwt.encode(
            payload,
            self._access_private_key,
            algorithm="RS256",
            headers={"kid": self._access_key_id},
        )

    def verify_access_token(
        self,
        token: str,
        *,
        audience: str | None = None,
    ) -> AccessTokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._access_public_key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=audience or self._default_audience,
                options={
                    "require": [
                        "sub",
                        "email_verified",
                        "type",
                        "roles",
                        "iat",
                        "exp",
                        "iss",
                        "aud",
                    ]
                },
            )
            if payload.get("type") != "access":
                raise ValueError("not an access token")
            email_verified = payload.get("email_verified")
            if not isinstance(email_verified, bool):
                raise ValueError("email_verified must be a boolean")
            token_audience = _string_claim(payload, "aud")
            identity = AccessTokenIdentity(
                user_id=_string_claim(payload, "sub"),
                email=_optional_string_claim(payload, "email"),
                name=_optional_string_claim(payload, "name"),
                email_verified=email_verified,
                roles=_roles_claim(payload),
            )
            issued_at = datetime.fromtimestamp(_integer_claim(payload, "iat"), UTC)
            expires_at = datetime.fromtimestamp(_integer_claim(payload, "exp"), UTC)
        except (jwt.PyJWTError, KeyError, OSError, OverflowError, TypeError, ValueError):
            raise TokenValidationError() from None
        return AccessTokenClaims(
            identity=identity,
            audience=token_audience,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def verify_admin_access_subject(self, token: str) -> str:
        """Mirror Express admin authentication without imposing Phase 4 claim shape.

        ``jsonwebtoken.verify`` errors are deliberately allowed to propagate so the
        admin route's generic error middleware returns the same 500 response as
        Express.  Only the post-verification ``readJwtPayload`` checks become the
        public 401 ``INVALID_TOKEN`` response.
        """

        payload = jwt.decode(
            token,
            self._access_public_key,
            algorithms=["RS256"],
            issuer=self._issuer,
            audience=self._default_audience,
            options={
                # jsonwebtoken ignores iat unless maxAge is configured and does
                # not validate these claim types as part of verify().
                "verify_iat": False,
                "verify_jti": False,
                "verify_sub": False,
            },
        )
        subject = payload.get("sub")
        if not isinstance(subject, str) or payload.get("type") != "access":
            raise TokenValidationError()
        return subject

    def issue_refresh_token(
        self,
        *,
        user_id: str,
        audience: str | None = None,
    ) -> IssuedRefreshToken:
        issued_at = datetime.now(UTC).replace(microsecond=0)
        expires_at = issued_at + timedelta(days=self._refresh_expires_in_days)
        token_id = secrets.token_hex(32)
        token = jwt.encode(
            {
                "sub": user_id,
                "type": "refresh",
                "tokenId": token_id,
                "audience": audience or self._default_audience,
                "iat": int(issued_at.timestamp()),
                "exp": int(expires_at.timestamp()),
            },
            self._refresh_secret,
            algorithm="HS256",
        )
        return IssuedRefreshToken(
            token=token,
            token_id=token_id,
            token_hash=sha256_token(token),
            expires_at=expires_at,
        )

    def verify_refresh_token(
        self,
        token: str,
        *,
        audience: str | None = None,
    ) -> RefreshTokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._refresh_secret,
                algorithms=["HS256"],
                options={
                    "verify_aud": False,
                    "require": ["sub", "type", "tokenId", "iat", "exp"],
                },
            )
            if payload.get("type") != "refresh":
                raise ValueError("not a refresh token")
            token_id = _string_claim(payload, "tokenId")
            if _REFRESH_TOKEN_ID.fullmatch(token_id) is None:
                raise ValueError("invalid refresh token id")
            token_audience = (
                _string_claim(payload, "audience")
                if "audience" in payload
                else self._default_audience
            )
            if audience is not None and token_audience != audience:
                raise ValueError("refresh token audience mismatch")
            user_id = _string_claim(payload, "sub")
            issued_at = datetime.fromtimestamp(_integer_claim(payload, "iat"), UTC)
            expires_at = datetime.fromtimestamp(_integer_claim(payload, "exp"), UTC)
        except (jwt.PyJWTError, KeyError, OSError, OverflowError, TypeError, ValueError):
            raise TokenValidationError() from None
        return RefreshTokenClaims(
            user_id=user_id,
            token_id=token_id,
            audience=token_audience,
            issued_at=issued_at,
            expires_at=expires_at,
        )
