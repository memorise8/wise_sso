from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_sso_sessions import ORIGIN, admin_rig

from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc.app import build_oidc_app
from wiseacct_sso.application.service_clients import (
    SERVICE_RATE_LIMIT_PER_MINUTE,
    ServiceAuthError,
    ServiceClientAuth,
)
from wiseacct_sso.infrastructure.security import build_password_hasher
from wiseacct_sso.oidc_config import ServiceClientPolicy

SECRET = "synthetic-service-secret"
HASH = build_password_hasher().hash(SECRET)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[Any, bytes] = {}
        self.counters: dict[Any, int] = {}

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        if key in self.values:
            return False
        self.values[key] = value
        return True

    async def get_raw(self, key: str | bytes) -> bytes | None:
        return self.values.get(key)

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]


def policy(scopes: tuple[str, ...] = ("external-invite",)) -> ServiceClientPolicy:
    return ServiceClientPolicy.model_validate(
        {"clientId": "agent-hub-service", "clientSecretHash": HASH, "scopes": list(scopes)}
    )


def auth(clock: list[float] | None = None) -> tuple[ServiceClientAuth, FakeRedis]:
    redis = FakeRedis()
    now = clock or [1_000.0]
    return ServiceClientAuth((policy(),), redis, clock=lambda: now[0]), redis


def test_service_client_policy_rejects_plain_secrets_and_unknown_scopes() -> None:
    with pytest.raises(ValueError):
        ServiceClientPolicy.model_validate(
            {"clientId": "svc", "clientSecretHash": "plain", "scopes": ["external-invite"]}
        )
    with pytest.raises(ValueError):
        ServiceClientPolicy.model_validate(
            {"clientId": "svc", "clientSecretHash": HASH, "scopes": ["admin"]}
        )


@pytest.mark.anyio
async def test_issued_token_is_opaque_short_lived_and_scope_checked() -> None:
    clock = [1_000.0]
    service, redis = auth(clock)
    issued = await service.issue("agent-hub-service", SECRET, "external-invite")
    assert issued.expires_in == 300 and issued.scope == "external-invite"
    assert all(issued.access_token.encode() not in key for key in redis.values)
    caller = await service.authenticate(f"Bearer {issued.access_token}", "external-invite")
    assert caller.client_id == "agent-hub-service"
    with pytest.raises(ServiceAuthError) as wrong_scope:
        await service.authenticate(f"Bearer {issued.access_token}", "other")
    assert wrong_scope.value.status_code == 403
    clock[0] += 301
    with pytest.raises(ServiceAuthError) as expired:
        await service.authenticate(f"Bearer {issued.access_token}", "external-invite")
    assert expired.value.code == "invalid_token"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("client_id", "secret", "scope", "code"),
    [
        ("agent-hub-service", "wrong", None, "invalid_client"),
        ("unknown", SECRET, None, "invalid_client"),
        ("agent-hub-service", SECRET, "openid", "invalid_scope"),
    ],
)
async def test_issue_rejects_bad_clients_and_scopes(
    client_id: str, secret: str, scope: str | None, code: str
) -> None:
    service, _ = auth()
    with pytest.raises(ServiceAuthError) as caught:
        await service.issue(client_id, secret, scope)
    assert caught.value.code == code


@pytest.mark.anyio
async def test_calls_are_rate_limited_per_client() -> None:
    service, _ = auth()
    issued = await service.issue("agent-hub-service", SECRET, None)
    for _ in range(SERVICE_RATE_LIMIT_PER_MINUTE - 1):
        await service.authenticate(f"Bearer {issued.access_token}", "external-invite")
    with pytest.raises(ServiceAuthError) as caught:
        await service.authenticate(f"Bearer {issued.access_token}", "external-invite")
    assert caught.value.status_code == 429


def test_token_endpoint_issues_client_credentials_tokens() -> None:
    rig = admin_rig()
    service, _ = auth()
    app = build_oidc_app(service=rig.service, public_origin=ORIGIN, service_auth=service)
    client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN)
    form = {
        "grant_type": "client_credentials",
        "scope": "external-invite",
        "client_id": "agent-hub-service",
        "client_secret": SECRET,
    }
    response = client.post("/oauth2/token", data=form)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    assert "id_token" not in body and "refresh_token" not in body
    assert response.headers["cache-control"] == "no-store"
    denied = client.post("/oauth2/token", data={**form, "client_secret": "wrong"})
    assert denied.status_code == 401 and denied.json()["error"] == "invalid_client"
    extra = client.post("/oauth2/token", data={**form, "code": "x"})
    assert extra.status_code == 400

    plain = build_oidc_app(service=rig.service, public_origin=ORIGIN)
    unsupported = TestClient(SecurityHeadersMiddleware(plain), base_url=ORIGIN).post(
        "/oauth2/token", data=form
    )
    assert unsupported.json()["error"] == "unsupported_grant_type"
