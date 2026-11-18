from __future__ import annotations

import asyncio
from typing import cast

import pytest
from fastapi.testclient import TestClient
from test_service_clients import SECRET, FakeRedis, policy
from test_sso_sessions import ORIGIN, admin_rig

from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc.app import build_oidc_app
from wiseacct_sso.application.service_clients import ServiceAuthError, ServiceClientAuth
from wiseacct_sso.application.service_password_change import (
    ServicePasswordChangeRequest,
    ServicePasswordChangeService,
)
from wiseacct_sso.domain.users import DomainError

PATH = "/oauth2/service/password-change"
BODY = {
    "email": "member@wise.test",
    "current_password": "current-password-1",
    "new_password": "brand-new-password-2",
}


class StubPasswordChange:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, ServicePasswordChangeRequest]] = []
        self.error = error

    async def change(self, client_id: str, request: ServicePasswordChangeRequest) -> None:
        self.calls.append((client_id, request))
        if self.error is not None:
            raise self.error


def client_for(
    stub: StubPasswordChange, scopes: tuple[str, ...] = ("external-invite", "password-change")
) -> tuple[TestClient, ServiceClientAuth]:
    rig = admin_rig()
    auth = ServiceClientAuth((policy(scopes),), FakeRedis(), clock=lambda: 1_000.0)
    app = build_oidc_app(
        service=rig.service,
        public_origin=ORIGIN,
        service_auth=auth,
        service_password_change=cast(ServicePasswordChangeService, stub),
    )
    return TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN), auth


def bearer(auth: ServiceClientAuth, scope: str | None = None) -> dict[str, str]:
    token = asyncio.run(auth.issue("agent-hub-service", SECRET, scope)).access_token
    return {"authorization": f"Bearer {token}"}


def test_password_change_scope_is_a_known_service_scope() -> None:
    assert policy(("password-change",)).scopes == ("password-change",)


@pytest.mark.anyio
async def test_external_invite_token_cannot_change_passwords() -> None:
    auth = ServiceClientAuth(
        (policy(("external-invite", "password-change")),), FakeRedis(), clock=lambda: 1.0
    )
    issued = await auth.issue("agent-hub-service", SECRET, "external-invite")
    with pytest.raises(ServiceAuthError) as caught:
        await auth.authenticate(f"Bearer {issued.access_token}", "password-change")
    assert caught.value.status_code == 403


def test_success_is_204_and_passes_the_request_through() -> None:
    stub = StubPasswordChange()
    client, auth = client_for(stub)
    response = client.post(PATH, json=BODY, headers=bearer(auth))
    assert response.status_code == 204, response.text
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    client_id, request = stub.calls[0]
    assert client_id == "agent-hub-service"
    assert request == ServicePasswordChangeRequest(
        email=BODY["email"],
        current_password=BODY["current_password"],
        new_password=BODY["new_password"],
    )


def test_service_auth_is_required() -> None:
    stub = StubPasswordChange()
    client, auth = client_for(stub)
    missing = client.post(PATH, json=BODY)
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "invalid_token"
    assert 'scope="password-change"' in missing.headers["www-authenticate"]
    wrong_scope = client.post(PATH, json=BODY, headers=bearer(auth, "external-invite"))
    assert wrong_scope.status_code == 403
    assert wrong_scope.json()["error"]["code"] == "insufficient_scope"
    assert not stub.calls


def test_route_needs_the_scope_on_the_client_configuration() -> None:
    stub = StubPasswordChange()
    client, auth = client_for(stub, scopes=("external-invite",))
    response = client.post(PATH, json=BODY, headers=bearer(auth))
    assert response.status_code == 403 and not stub.calls


def test_malformed_bodies_are_invalid_requests() -> None:
    stub = StubPasswordChange()
    client, auth = client_for(stub)
    headers = bearer(auth)
    for invalid in (
        {**BODY, "extra": 1},
        {k: v for k, v in BODY.items() if k != "new_password"},
        {**BODY, "current_password": 123},
        {**BODY, "new_password": ""},
        {**BODY, "new_password": "x" * 1025},
    ):
        response = client.post(PATH, json=invalid, headers=headers)
        assert response.status_code == 400, invalid
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert client.post(PATH, data={"email": "x"}, headers=headers).status_code == 400
    assert client.post(PATH + "?x=1", json=BODY, headers=headers).status_code == 400
    assert not stub.calls


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "invalid_current_password"),
        (409, "no_password"),
        (400, "weak_password"),
        (400, "same_password"),
        (429, "rate_limited"),
    ],
)
def test_domain_errors_use_the_error_envelope(status: int, code: str) -> None:
    client, auth = client_for(StubPasswordChange(DomainError(status, code, "message")))
    response = client.post(PATH, json=BODY, headers=bearer(auth))
    assert response.status_code == status
    assert response.json() == {"error": {"code": code, "message": "message"}}
    assert response.headers["cache-control"] == "no-store"
    for secret in BODY.values():
        if "password" in secret:
            assert secret not in response.text


def test_route_is_absent_without_a_password_change_service() -> None:
    rig = admin_rig()
    auth = ServiceClientAuth((policy(),), FakeRedis(), clock=lambda: 1_000.0)
    app = build_oidc_app(service=rig.service, public_origin=ORIGIN, service_auth=auth)
    client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN)
    assert client.post(PATH, json=BODY, headers=bearer(auth)).status_code == 404
