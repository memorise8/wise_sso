"""client_credentials tokens for machine clients that call SSO service APIs."""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol

from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH, AsyncPasswordHasher
from wiseacct_sso.oidc_config import ServiceClientPolicy

SERVICE_TOKEN_TTL_SECONDS = 300
SERVICE_RATE_LIMIT_PER_MINUTE = 30
_TOKEN_PREFIX = b"wise:svc:token:"
_RATE_PREFIX = "wise:svc:rate:"


class ServiceRedis(Protocol):
    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool: ...

    async def get_raw(self, key: str | bytes) -> bytes | None: ...

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int: ...


class ServiceAuthError(Exception):
    """Raised with an OAuth error code; messages never include client input."""

    def __init__(self, code: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class IssuedServiceToken:
    access_token: str
    scope: str
    expires_in: int = SERVICE_TOKEN_TTL_SECONDS


@dataclass(frozen=True, slots=True)
class ServiceCaller:
    client_id: str
    scopes: tuple[str, ...]


def _key(token: str) -> bytes:
    return _TOKEN_PREFIX + sha256(token.encode("utf-8")).hexdigest().encode("ascii")


class ServiceClientAuth:
    def __init__(
        self,
        clients: tuple[ServiceClientPolicy, ...],
        redis: ServiceRedis,
        passwords: AsyncPasswordHasher | None = None,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self._clients = {client.client_id: client for client in clients}
        self._redis = redis
        self._passwords = passwords or AsyncPasswordHasher()
        self._clock = clock
        self._random_bytes = random_bytes

    @property
    def enabled(self) -> bool:
        return bool(self._clients)

    async def issue(
        self, client_id: str, client_secret: str, scope: str | None
    ) -> IssuedServiceToken:
        client = self._clients.get(client_id)
        # Always pay for one hash check so unknown client IDs are not distinguishable by timing.
        expected = DUMMY_PASSWORD_HASH if client is None else client.client_secret_hash
        valid = await self._passwords.verify_password(expected, client_secret)
        if client is None or not valid:
            raise ServiceAuthError("invalid_client", 401)
        requested = tuple(scope.split()) if scope else client.scopes
        if not requested or any(item not in client.scopes for item in requested):
            raise ServiceAuthError("invalid_scope", 400)
        await self.enforce_rate_limit(client.client_id)
        record = json.dumps(
            {
                "clientId": client.client_id,
                "scopes": list(dict.fromkeys(requested)),
                "expiresAt": self._clock() + SERVICE_TOKEN_TTL_SECONDS,
            }
        ).encode("utf-8")
        for _ in range(3):
            token = base64.urlsafe_b64encode(self._random_bytes(32)).rstrip(b"=").decode("ascii")
            if await self._redis.set_if_absent(_key(token), record, SERVICE_TOKEN_TTL_SECONDS):
                return IssuedServiceToken(token, " ".join(dict.fromkeys(requested)))
        raise RuntimeError("could not allocate a service token")

    async def authenticate(self, authorization: str | None, scope: str) -> ServiceCaller:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not token or len(token) > 256 or " " in token:
            raise ServiceAuthError("invalid_token", 401)
        raw = await self._redis.get_raw(_key(token))
        if raw is None:
            raise ServiceAuthError("invalid_token", 401)
        record = json.loads(raw)
        client = self._clients.get(record.get("clientId", ""))
        if client is None or float(record.get("expiresAt", 0)) <= self._clock():
            raise ServiceAuthError("invalid_token", 401)
        scopes = tuple(str(item) for item in record.get("scopes", ()))
        # A scope removed from the client's configuration stops working at once.
        if scope not in scopes or scope not in client.scopes:
            raise ServiceAuthError("insufficient_scope", 403)
        await self.enforce_rate_limit(client.client_id)
        return ServiceCaller(client.client_id, scopes)

    async def enforce_rate_limit(self, client_id: str) -> None:
        window = int(self._clock() // 60)
        count = await self._redis.increment_with_ttl(f"{_RATE_PREFIX}{client_id}:{window}", 60)
        if count > SERVICE_RATE_LIMIT_PER_MINUTE:
            raise ServiceAuthError("RATE_LIMITED", 429)
