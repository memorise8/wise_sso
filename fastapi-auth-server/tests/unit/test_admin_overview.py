from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncConnection
from test_employee_invitations import fixture
from test_sso_sessions import ORIGIN, admin_login, admin_rig

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc.app import build_oidc_app
from wiseacct_sso.domain.admin import AdminUserListInput
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH
from wiseacct_sso.persistence.oidc import OidcUserRecord, RoleAssignment

NOW = datetime(2026, 11, 11, 0, 0)


def test_user_list_filter_accepts_external_accounts() -> None:
    assert AdminUserListInput(user_type="EXTERNAL").user_type == "EXTERNAL"


def test_overview_routes_need_an_admin_session() -> None:
    rig = admin_rig()
    invitations, _, _, _ = fixture()
    app = build_oidc_app(
        service=rig.service,
        public_origin=ORIGIN,
        portal_service=rig.service,
        admin_services=cast(Phase6Services, rig.portal),
        invitation_service=invitations,
    )
    client = TestClient(SecurityHeadersMiddleware(app), base_url=ORIGIN, follow_redirects=False)
    for path in ("/oauth2/admin/api/summary", "/oauth2/admin/api/roles"):
        assert client.get(path).status_code == 401
    dashboard = client.get("/oauth2/admin/dashboard")
    assert dashboard.status_code in {302, 303}


def test_user_filters_are_read_before_controls_are_disabled() -> None:
    # Disabled form controls are dropped from FormData, so reading the filters
    # after setBusy(true) silently sent an unfiltered user query.
    from pathlib import Path

    import wiseacct_sso

    source = (
        Path(wiseacct_sso.__file__).parent / "static" / "assets" / "admin-dashboard.js"
    ).read_text()
    body = source.split("const loadUsers = async () => {", 1)[1].split("\n};", 1)[0]
    assert body.index("userQueryString()") < body.index("setBusy(true)")


def test_user_actions_refresh_the_list_after_releasing_the_controls() -> None:
    # loadUsers returns early while busy, so a refresh inside the try block never ran.
    from pathlib import Path

    import wiseacct_sso

    source = (
        Path(wiseacct_sso.__file__).parent / "static" / "assets" / "admin-dashboard.js"
    ).read_text()
    body = source.split("const runUserAction = async", 1)[1].split("\n};", 1)[0]
    assert body.index("setBusy(false)") < body.index("await loadUsers()")


def _client(**policy: object) -> Any:
    from wiseacct_sso.oidc_config import OidcClientPolicy

    base: dict[str, object] = {
        "clientId": "gitlab-temis",
        "clientSecretHash": DUMMY_PASSWORD_HASH,
        "redirectUris": ["https://gitlab.example.test/callback"],
        "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
        "groupsServiceKeys": ["gitlab"],
    }
    return OidcClientPolicy.model_validate({**base, **policy})


def _users(rig: Any) -> list[OidcUserRecord]:
    user = replace(rig.identities.user, roles=(RoleAssignment("staff", "user"),))
    return [
        user,
        replace(user, id="no-role", roles=()),
        replace(user, id="wrong-type", user_type="CUSTOMER"),
    ]


def _serve(monkeypatch: pytest.MonkeyPatch, users: list[OidcUserRecord]) -> None:
    async def candidates(
        _connection: AsyncConnection,
    ) -> AsyncIterator[tuple[OidcUserRecord, list[dict[str, str]]]]:
        for user in users:
            yield user, []

    monkeypatch.setattr("wiseacct_sso.application.oidc.iter_admin_access_users", candidates)


def test_service_access_uses_the_login_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    rig = admin_rig()
    users = _users(rig)
    _serve(monkeypatch, users)
    url = "/oauth2/admin/api/service-access"
    assert rig.client.get(url).status_code == 401
    assert admin_login(rig).status_code == 303

    ids = [user.id for user in users] + ["gone"]
    response = rig.client.get(url, params=[("id", value) for value in ids])
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    staff = {
        user_id: next(entry for entry in entries if entry["clientId"] == "staff")
        for user_id, entries in response.json()["users"].items()
    }
    assert staff[users[0].id] == {"clientId": "staff", "allowed": True, "reason": None}
    assert staff["no-role"]["reason"] == "OIDC_REQUIRED_ROLE_MISSING"
    assert staff["wrong-type"]["reason"] == "OIDC_USER_TYPE_DENIED"
    assert staff["gone"] == {"clientId": "staff", "allowed": False, "reason": "OIDC_USER_INACTIVE"}


def test_role_free_services_count_only_role_holders(monkeypatch: pytest.MonkeyPatch) -> None:
    # The hub lets every signed-in user through SSO and gates by its own invitations,
    # so the dashboard must not list it as usable for people without agent-hub:user.
    from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry

    rig = admin_rig()
    member = replace(rig.identities.user, roles=(RoleAssignment("agent-hub", "user"),))
    guest = replace(member, id="guest", roles=())
    _serve(monkeypatch, [member, guest])
    hub = OidcClientPolicy.model_validate(
        {
            "clientId": "agent-hub-dash",
            "clientSecretHash": DUMMY_PASSWORD_HASH,
            "redirectUris": ["https://hub.example.test/callback"],
            "requiredRoles": [{"serviceKey": "agent-hub", "name": "user"}],
            "groupsServiceKeys": ["agent-hub"],
            "allowWithoutRequiredRole": True,
        }
    )
    assert admin_login(rig).status_code == 303
    rig.service._clients = OidcClientRegistry((hub,))
    users = rig.client.get(
        "/oauth2/admin/api/service-access", params=[("id", member.id), ("id", "guest")]
    ).json()["users"]
    assert users[member.id] == [{"clientId": "agent-hub-dash", "allowed": True, "reason": None}]
    assert users["guest"] == [
        {"clientId": "agent-hub-dash", "allowed": False, "reason": "OIDC_INVITATION_REQUIRED"}
    ]


def test_role_errors_are_explained_in_korean_on_both_admin_screens() -> None:
    from pathlib import Path

    import wiseacct_sso

    assets = Path(wiseacct_sso.__file__).parent / "static" / "assets"
    for name in ("admin-dashboard.js", "admin-service.js"):
        source = (assets / name).read_text()
        for code in ("EMPLOYEE_REQUIRED", "EXTERNAL_ROLE_NOT_ALLOWED", "LAST_SSO_ADMIN"):
            assert f"{code}: " in source, (name, code)
    assert "직원으로 분류된 사용자만" in (assets / "admin-dashboard.js").read_text()


@pytest.mark.anyio
async def test_role_list_marks_roles_external_accounts_may_hold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import asynccontextmanager

    from wiseacct_sso.application.admin import Phase6AdminService

    async def page(_connection: object, *, page: int, page_size: int) -> dict[str, object]:
        items = [
            {"id": "r1", "serviceKey": "agent-hub", "name": "user"},
            {"id": "r2", "serviceKey": "gitlab", "name": "user"},
        ]
        return {"items": items, "total": 2, "page": page, "pageSize": page_size}

    class Database:
        @asynccontextmanager
        async def connection(self) -> AsyncIterator[object]:
            yield object()

    monkeypatch.setattr("wiseacct_sso.application.admin.read_role_page", page)
    service = Phase6AdminService(database=Database, tokens=cast(Any, None))  # type: ignore[arg-type]
    result = await service.list_roles(page=1, page_size=100)
    assert [(r["serviceKey"], r["externalAllowed"]) for r in result["items"]] == [  # type: ignore[union-attr]
        ("agent-hub", False),
        ("gitlab", True),
    ]
