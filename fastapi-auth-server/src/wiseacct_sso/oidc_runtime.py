"""Lazy runtime resources for OIDC, owned by the existing application lifespan."""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import replace
from hashlib import sha256
from urllib.parse import urlsplit

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.oauth import OAuthProvider
from wiseacct_sso.infrastructure.oauth_providers import (
    OAuthProviderConfig,
    OAuthProviderDisabledError,
    provider_config_for,
)
from wiseacct_sso.infrastructure.redis import RedisStateStore


class RuntimeOidcRedis:
    """Resolve the lifespan-owned store at call time, without opening another connection."""

    def __init__(self, provider: Callable[[], RedisStateStore]) -> None:
        self._provider = provider

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        return await self._provider().set_if_absent(key, value, ttl_seconds)

    async def get_raw(self, key: str | bytes) -> bytes | None:
        return await self._provider().get_raw(key)

    async def consume(self, key: str | bytes) -> bytes | None:
        return await self._provider().consume(key)

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None:
        return await self._provider().consume_if_exact(key, expected)

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        return await self._provider().increment_with_ttl(key, ttl_seconds)

    async def rate_check(self, path: str, address: str) -> bool:
        # Bounded route vocabulary: arbitrary attacker-controlled paths do not create
        # distinct buckets. The peer is already resolved by trusted-proxy middleware.
        category = (
            path
            if path in {"/oauth2/authorize", "/oauth2/token", "/oauth2/userinfo", "/oauth2/login"}
            else "/oauth2/other"
        )
        digest = sha256(f"{category}\0{address}".encode()).hexdigest()
        count = await self.increment_with_ttl(f"wiseacct:oidc:rate:ip:{digest}", 60)
        return count <= 60


def oidc_provider_config_for(settings: Settings, provider: OAuthProvider) -> OAuthProviderConfig:
    callback: str | None = getattr(settings, f"oidc_{provider}_redirect_uri")
    if callback is None:
        raise OAuthProviderDisabledError(provider)
    return replace(provider_config_for(settings, provider), redirect_uri=callback)


def oidc_form_action_sources(settings: Settings) -> tuple[str, ...]:
    """Only registered callback origins may receive a browser form's 303 navigation."""
    origins: set[str] = set()
    for client in settings.oidc_clients:
        for uri in client.redirect_uris:
            parsed = urlsplit(uri)
            if parsed.hostname is None:
                raise ValueError("OIDC redirect has no hostname")
            hostname = parsed.hostname.encode("idna").decode("ascii")
            try:
                address = ipaddress.ip_address(hostname)
                host = f"[{address}]" if address.version == 6 else str(address)
            except ValueError:
                if re.fullmatch(r"[A-Za-z0-9.-]+", hostname) is None:
                    raise ValueError(
                        "OIDC redirect hostname is invalid for browser policy"
                    ) from None
                host = hostname.lower()
            default_port = 443 if parsed.scheme == "https" else 80
            port = f":{parsed.port}" if parsed.port not in (None, default_port) else ""
            origins.add(f"{parsed.scheme}://{host}{port}")
    return tuple(sorted(origins))
