from typing import Any, cast

from fastapi.testclient import TestClient
from test_employee_invitations import fixture, mail_token
from test_sso_sessions import ORIGIN, admin_login, admin_rig

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc.app import build_oidc_app


def test_cookie_admin_invitation_and_public_password_setup() -> None:
    rig = admin_rig()
    invitations, db, mail, _ = fixture()
    app = build_oidc_app(
        service=rig.service,
        public_origin=ORIGIN,
        portal_service=rig.service,
        admin_services=cast(Phase6Services, rig.portal),
        invitation_service=invitations,
    )
    rig.client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN, follow_redirects=False)
    body = {
        "email": "employee@example.test",
        "name": "Employee",
        "roles": [{"serviceKey": "gitlab", "name": "user"}],
    }
    assert rig.client.post("/oauth2/admin/api/invitations", json=body).status_code == 401
    admin_login(rig)
    dashboard = rig.client.get("/oauth2/admin/dashboard")
    assert "data-employee-invite" in dashboard.text
    import re

    match = re.search(r'name="admin-session-csrf" content="([^"]+)"', dashboard.text)
    assert match is not None
    assert (
        rig.client.post(
            "/oauth2/admin/api/invitations", json=body, headers={"origin": ORIGIN}
        ).status_code
        == 403
    )
    headers = {"origin": ORIGIN, "x-admin-csrf": match[1]}
    response = rig.client.post("/oauth2/admin/api/invitations", json=body, headers=headers)
    assert response.status_code == 201
    assert response.json()["invitationUrl"] is None  # mail delivery never returns the link
    token = mail_token(mail)
    page = rig.client.get("/oauth2/invitations/accept")
    assert token not in page.text
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert csrf is not None
    data = {"token": token, "password": "private-new-password", "csrf_token": csrf[1]}
    assert rig.client.post("/oauth2/invitations/accept", data=data).status_code == 400
    assert (
        rig.client.post(
            "/oauth2/invitations/accept", data=data, headers={"origin": "https://evil.test"}
        ).status_code
        == 400
    )
    result = rig.client.post("/oauth2/invitations/accept", data=data, headers={"origin": ORIGIN})
    assert result.status_code == 200, result.text
    assert db.tables["User"][0]["userType"] == "EMPLOYEE"
    assert not any(secret in result.text for secret in (token, data["password"]))


def test_admin_creates_external_account_link_with_day_term() -> None:
    import re

    rig = admin_rig()
    invitations, db, mail, _ = fixture()
    app = build_oidc_app(
        service=rig.service,
        public_origin=ORIGIN,
        portal_service=rig.service,
        admin_services=cast(Phase6Services, rig.portal),
        invitation_service=invitations,
    )
    rig.client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN, follow_redirects=False)
    admin_login(rig)
    dashboard = rig.client.get("/oauth2/admin/dashboard")
    assert "data-external-create" in dashboard.text
    assert "/assets/admin-external.js" in dashboard.text
    match = re.search(r'name="admin-session-csrf" content="([^"]+)"', dashboard.text)
    assert match is not None
    headers = {"origin": ORIGIN, "x-admin-csrf": match[1]}
    path = "/oauth2/admin/api/external-accounts"
    body = {"email": "guest@example.test", "name": "Guest", "days": 45}

    for invalid in ({**body, "days": 0}, {**body, "days": 366}, {**body, "days": "45"}):
        assert rig.client.post(path, json=invalid, headers=headers).status_code in {400, 422}
    denied = {**body, "roles": [{"serviceKey": "agent-hub", "name": "user"}]}
    assert rig.client.post(path, json=denied, headers=headers).status_code == 403
    assert not db.tables["EmployeeInvitation"]

    created = rig.client.post(
        path, json={**body, "roles": [{"serviceKey": "gitlab", "name": "user"}]}, headers=headers
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["invitationUrl"].startswith(ORIGIN + "/oauth2/invitations/accept#token=")
    assert payload["accountExpiresAt"].endswith("Z")
    assert not mail.messages
    assert db.tables["EmployeeInvitation"][0]["kind"] == "EXTERNAL"


def test_accepting_a_service_invitation_sends_people_to_the_allowed_return_to() -> None:
    import re

    rig = admin_rig()
    invitations, _, _, _ = fixture()
    invitations.return_to_prefixes = ("https://dash.example.test/invite/",)
    destination = ["https://dash.example.test/invite/abc"]

    async def accept(token: str, password: str) -> str | None:
        return destination[0]

    invitations.accept = accept  # type: ignore[method-assign]
    app = build_oidc_app(
        service=rig.service,
        public_origin=ORIGIN,
        portal_service=rig.service,
        admin_services=cast(Phase6Services, rig.portal),
        invitation_service=invitations,
    )
    client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN, follow_redirects=False)

    def post(accept_header: str | None) -> Any:
        page = client.get("/oauth2/invitations/accept")
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        data = {"token": "t" * 43, "password": "private-new-password", "csrf_token": csrf[1]}
        headers = {"origin": ORIGIN, **({"accept": accept_header} if accept_header else {})}
        return client.post("/oauth2/invitations/accept", data=data, headers=headers)

    assert post("application/json").json() == {"returnTo": destination[0]}
    redirect = post(None)
    assert redirect.status_code == 303 and redirect.headers["location"] == destination[0]
    destination[0] = "https://elsewhere.example.test/invite/abc"  # prefix no longer configured
    plain = post("application/json")
    assert plain.status_code == 200 and "location" not in plain.headers
    assert "returnTo" not in plain.text
