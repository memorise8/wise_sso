"""Absolute-lived central SSO sessions; no bearer credentials stored in cookies/URLs."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Protocol

SSO_SESSION_TTL_SECONDS = 8 * 60 * 60
SSO_COOKIE_NAME = "__Host-wise_sso"
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_PREFIX = b"wiseacct:sso:session:"


class SessionRedis(Protocol):
    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool: ...
    async def get_raw(self, key: str | bytes) -> bytes | None: ...
    async def consume(self, key: str | bytes) -> bytes | None: ...


@dataclass(frozen=True, slots=True)
class SsoSession:
    user_id: str
    version: int
    auth_time: int
    expires_at: int
    csrf: str = field(repr=False)


def session_key(token: str) -> bytes:
    return _PREFIX + sha256(token.encode("ascii")).hexdigest().encode("ascii")


class SsoSessionStore:
    def __init__(self, redis: SessionRedis, *, clock: Callable[[], int] | None = None) -> None:
        self._redis = redis
        self._clock = clock or (lambda: int(time.time()))

    async def create(self, user_id: str, version: int, auth_time: int) -> str:
        if (
            not user_id
            or type(version) is not int
            or version < 0
            or type(auth_time) is not int
            or auth_time < 0
            or auth_time > self._clock()
        ):
            raise ValueError("Invalid central session metadata")
        for _ in range(3):
            token = secrets.token_urlsafe(32)
            data = json.dumps(
                {
                    "userId": user_id,
                    "version": version,
                    "authTime": auth_time,
                    "expiresAt": self._clock() + SSO_SESSION_TTL_SECONDS,
                    "csrf": secrets.token_urlsafe(32),
                },
                separators=(",", ":"),
            ).encode()
            if await self._redis.set_if_absent(session_key(token), data, SSO_SESSION_TTL_SECONDS):
                return token
        raise RuntimeError("Unable to create central session")

    async def get(self, token: str | None) -> SsoSession | None:
        if token is None or _OPAQUE.fullmatch(token) is None:
            return None
        raw = await self._redis.get_raw(session_key(token))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or set(data) != {
                "userId",
                "version",
                "authTime",
                "expiresAt",
                "csrf",
            }:
                return None
            if any(
                type(data[k]) is not int or data[k] < 0
                for k in ("version", "authTime", "expiresAt")
            ):
                return None
            if not isinstance(data["userId"], str) or not data["userId"]:
                return None
            if not isinstance(data["csrf"], str) or _OPAQUE.fullmatch(data["csrf"]) is None:
                return None
            if data["expiresAt"] <= self._clock() or data["authTime"] > self._clock():
                return None
            return SsoSession(
                data["userId"], data["version"], data["authTime"], data["expiresAt"], data["csrf"]
            )
        except (ValueError, TypeError, UnicodeDecodeError):
            return None

    async def revoke(self, token: str | None) -> None:
        if token is not None and _OPAQUE.fullmatch(token) is not None:
            await self._redis.consume(session_key(token))
