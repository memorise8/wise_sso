"""Redis-backed one-time OAuth state and authorization handoff records."""

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
from urllib.parse import urlsplit

from wiseacct_sso.infrastructure.redis import (
    AUTH_HANDOFF_TTL_SECONDS,
    OAUTH_STATE_TTL_SECONDS,
    auth_handoff_key,
    node_utf8_bytes,
    oauth_state_key,
)

Provider = Literal["google", "naver", "kakao"]
LoginMethod = Literal["oauth", "password"]

_CODE_BYTES: Final = 32
_MAX_GENERATION_ATTEMPTS: Final = 3
_ABSOLUTE_URL_SCHEME: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_HOST_REQUIRED_SCHEMES: Final = frozenset({"ftp", "http", "https", "ws", "wss"})
_WHATWG_EDGE_WHITESPACE: Final = "".join(chr(value) for value in range(0x21))


class _RedisState(Protocol):
    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool: ...

    async def get_raw(self, key: str | bytes) -> bytes | None: ...

    async def consume(self, key: str | bytes) -> bytes | None: ...

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class OAuthStateMetadata:
    client_id: str
    redirect_uri: str
    caller_state: str | None
    code_challenge: str | None
    code_challenge_method: Literal["S256"] | None


@dataclass(frozen=True, slots=True)
class AuthHandoffCreateInput:
    client_id: str
    audience: str
    redirect_uri: str
    user_id: str
    login_method: LoginMethod
    code_challenge: str
    code_challenge_method: Literal["S256"]
    state: str | None
    provider: Provider | None = None


@dataclass(frozen=True, slots=True)
class AuthHandoffConsumeInput:
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str


@dataclass(frozen=True, slots=True)
class StoredAuthHandoffMetadata:
    client_id: str
    audience: str
    redirect_uri: str
    user_id: str
    login_method: LoginMethod
    code_challenge: str
    code_challenge_method: Literal["S256"]
    state: str | None
    expires_at_epoch_ms: int
    provider: Provider | None = None


class OAuthStateCreationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Unable to generate a unique OAuth state")


class AuthHandoffCreationError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Unable to generate a unique authorization handoff code")


def _valid_url_hostname(hostname: str | None) -> bool:
    return (
        hostname is not None
        and bool(hostname)
        and not any(
            character.isspace() or ord(character) <= 0x20 or 0xD800 <= ord(character) <= 0xDFFF
            for character in hostname
        )
    )


def _contains_invalid_url_character(value: str) -> bool:
    return any(
        character.isspace() or ord(character) <= 0x20 or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


def _is_absolute_zod_url(value: str) -> bool:
    normalized = value.strip(_WHATWG_EDGE_WHITESPACE)
    match = _ABSOLUTE_URL_SCHEME.match(normalized)
    if match is None:
        return False
    scheme = normalized[: match.end() - 1].lower()
    try:
        parsed = urlsplit(normalized)
        _ = parsed.port
    except ValueError:
        return False
    remainder = normalized[match.end() :]
    if scheme == "file":
        if not remainder.startswith("//") or remainder == "///":
            return not _contains_invalid_url_character(remainder)
        authority = remainder[2:].split("/", 1)[0]
        return not authority or _valid_url_hostname(authority)
    if scheme not in _HOST_REQUIRED_SCHEMES:
        if _contains_invalid_url_character(remainder):
            return False
        if not remainder.startswith("//") or remainder == "//":
            return True
        return _valid_url_hostname(parsed.hostname)
    if parsed.hostname is None:
        repaired_remainder = remainder.lstrip("/")
        if not repaired_remainder:
            return False
        try:
            repaired = urlsplit(f"{scheme}://{repaired_remainder}")
            _ = repaired.port
        except ValueError:
            return False
        hostname = repaired.hostname
    else:
        hostname = parsed.hostname
    return _valid_url_hostname(hostname)


def _nonempty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


class _Invalid:
    pass


_INVALID: Final = _Invalid()


def _nullable_nonempty_string(value: object) -> str | _Invalid | None:
    if value is None:
        return None
    return _nonempty_string(value) or _INVALID


def _random_base64url(random_bytes: Callable[[int], bytes]) -> str:
    raw = random_bytes(_CODE_BYTES)
    if len(raw) != _CODE_BYTES:
        raise ValueError("random byte source must return exactly 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha256_base64url(value: str) -> str:
    return base64.urlsafe_b64encode(sha256(node_utf8_bytes(value)).digest()).rstrip(b"=").decode()


def _serialize(value: dict[str, object]) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _parse_json_object(raw: bytes) -> dict[str, object] | None:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return cast(dict[str, object], parsed) if isinstance(parsed, dict) else None


def _oauth_record(raw: bytes) -> tuple[Provider, OAuthStateMetadata] | None:
    record = _parse_json_object(raw)
    required = {
        "provider",
        "clientId",
        "redirectUri",
        "callerState",
        "codeChallenge",
        "codeChallengeMethod",
    }
    if record is None or set(record) != required:
        return None
    provider = record["provider"]
    client_id = _nonempty_string(record["clientId"])
    redirect_uri = _nonempty_string(record["redirectUri"])
    caller_state = _nullable_nonempty_string(record["callerState"])
    code_challenge = _nullable_nonempty_string(record["codeChallenge"])
    method = record["codeChallengeMethod"]
    if (
        provider not in ("google", "naver", "kakao")
        or client_id is None
        or redirect_uri is None
        or not _is_absolute_zod_url(redirect_uri)
        or caller_state is _INVALID
        or code_challenge is _INVALID
        or method not in ("S256", None)
    ):
        return None
    return provider, OAuthStateMetadata(
        client_id=client_id,
        redirect_uri=redirect_uri,
        caller_state=cast(str | None, caller_state),
        code_challenge=cast(str | None, code_challenge),
        code_challenge_method=method,
    )


def _handoff_record(raw: bytes) -> StoredAuthHandoffMetadata | None:
    record = _parse_json_object(raw)
    required = {
        "clientId",
        "audience",
        "redirectUri",
        "userId",
        "loginMethod",
        "codeChallenge",
        "codeChallengeMethod",
        "state",
        "expiresAtEpochMs",
    }
    if record is None or set(record) not in (required, required | {"provider"}):
        return None
    client_id = _nonempty_string(record["clientId"])
    audience = _nonempty_string(record["audience"])
    redirect_uri = _nonempty_string(record["redirectUri"])
    user_id = _nonempty_string(record["userId"])
    code_challenge = _nonempty_string(record["codeChallenge"])
    state = _nullable_nonempty_string(record["state"])
    provider = record.get("provider")
    expires = record["expiresAtEpochMs"]
    expires_is_integer = (
        isinstance(expires, (int, float))
        and not isinstance(expires, bool)
        and float(expires).is_integer()
        and expires > 0
    )
    if (
        client_id is None
        or audience is None
        or redirect_uri is None
        or not _is_absolute_zod_url(redirect_uri)
        or user_id is None
        or record["loginMethod"] not in ("oauth", "password")
        or code_challenge is None
        or record["codeChallengeMethod"] != "S256"
        or state is _INVALID
        or ("provider" in record and provider not in ("google", "naver", "kakao"))
        or not expires_is_integer
    ):
        return None
    return StoredAuthHandoffMetadata(
        client_id=client_id,
        audience=audience,
        redirect_uri=redirect_uri,
        user_id=user_id,
        provider=cast(Provider | None, provider),
        login_method=record["loginMethod"],
        code_challenge=code_challenge,
        code_challenge_method="S256",
        state=cast(str | None, state),
        expires_at_epoch_ms=int(cast(int | float, expires)),
    )


class OAuthStateStore:
    def __init__(
        self,
        redis: _RedisState,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._redis = redis
        self._random_bytes = random_bytes

    async def create(self, provider: Provider, metadata: OAuthStateMetadata) -> str:
        parsed = _oauth_record(
            _serialize(
                {
                    "provider": provider,
                    "clientId": metadata.client_id,
                    "redirectUri": metadata.redirect_uri,
                    "callerState": metadata.caller_state,
                    "codeChallenge": metadata.code_challenge,
                    "codeChallengeMethod": metadata.code_challenge_method,
                }
            )
        )
        if parsed is None:
            raise ValueError("invalid OAuth state metadata")
        serialized = _serialize(
            {
                "provider": parsed[0],
                "clientId": parsed[1].client_id,
                "redirectUri": parsed[1].redirect_uri,
                "callerState": parsed[1].caller_state,
                "codeChallenge": parsed[1].code_challenge,
                "codeChallengeMethod": parsed[1].code_challenge_method,
            }
        )
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            state = _random_base64url(self._random_bytes)
            if await self._redis.set_if_absent(
                oauth_state_key(state), serialized, OAUTH_STATE_TTL_SECONDS
            ):
                return state
        raise OAuthStateCreationError()

    async def consume(self, provider: Provider, state: str) -> OAuthStateMetadata | None:
        raw = await self._redis.consume(oauth_state_key(state))
        if raw is None:
            return None
        parsed = _oauth_record(raw)
        if parsed is None or parsed[0] != provider:
            return None
        return parsed[1]


class AuthHandoffStore:
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

    async def create(self, metadata: AuthHandoffCreateInput) -> str:
        record: dict[str, object] = {
            "clientId": metadata.client_id,
            "audience": metadata.audience,
            "redirectUri": metadata.redirect_uri,
            "userId": metadata.user_id,
        }
        if metadata.provider is not None:
            record["provider"] = metadata.provider
        record.update(
            {
                "loginMethod": metadata.login_method,
                "codeChallenge": metadata.code_challenge,
                "codeChallengeMethod": metadata.code_challenge_method,
                "state": metadata.state,
                "expiresAtEpochMs": self._now_epoch_ms() + AUTH_HANDOFF_TTL_SECONDS * 1000,
            }
        )
        serialized = _serialize(record)
        if _handoff_record(serialized) is None:
            raise ValueError("invalid auth handoff metadata")
        for _ in range(_MAX_GENERATION_ATTEMPTS):
            code = _random_base64url(self._random_bytes)
            if await self._redis.set_if_absent(
                auth_handoff_key(code), serialized, AUTH_HANDOFF_TTL_SECONDS
            ):
                return code
        raise AuthHandoffCreationError()

    async def consume(self, input: AuthHandoffConsumeInput) -> StoredAuthHandoffMetadata | None:
        key = auth_handoff_key(input.code)
        raw = await self._redis.get_raw(key)
        if raw is None:
            return None
        metadata = _handoff_record(raw)
        if metadata is None or metadata.expires_at_epoch_ms <= self._now_epoch_ms():
            await self._redis.consume_if_exact(key, raw)
            return None
        challenge = sha256_base64url(input.code_verifier)
        binding_matches = (
            metadata.client_id == input.client_id
            and metadata.redirect_uri == input.redirect_uri
            and hmac.compare_digest(metadata.code_challenge.encode(), challenge.encode())
        )
        if not binding_matches:
            return None
        consumed = await self._redis.consume_if_exact(key, raw)
        return metadata if consumed is not None else None
