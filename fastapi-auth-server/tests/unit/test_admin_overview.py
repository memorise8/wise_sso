from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from test_employee_invitations import fixture
from test_sso_sessions import ORIGIN, admin_rig

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc.admin_overview import role_catalogue, summary_numbers
from wiseacct_sso.api.oidc.app import build_oidc_app
from wiseacct_sso.domain.admin import AdminUserListInput
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH

NOW = datetime(2026, 11, 11, 0, 0)


class Result:
    def __init__(self, scalar: object = None, rows: list[Any] | None = None) -> None:
        self.scalar, self.rows = scalar, rows or []

    def scalar_one(self) -> object:
        return self.scalar

    def all(self) -> list[Any]:
        return self.rows


class Connection:
    def __init__(self, results: list[Result]) -> None:
        self.results = results
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> Result:
        self.statements.append(statement)
        return self.results.pop(0)

    def sql(self, index: int) -> str:
        dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
        return str(self.statements[index].compile(dialect=dialect))


def test_user_list_filter_accepts_external_accounts() -> None:
    assert AdminUserListInput(user_type="EXTERNAL").user_type == "EXTERNAL"


@pytest.mark.anyio
async def test_summary_counts_active_users_by_type_and_upcoming_expiries() -> None:
    connection = Connection(
        [
            Result(rows=[("EMPLOYEE", 3), (None, 5), ("EXTERNAL", 2)]),
            Result(rows=[("ACTIVE", 10), ("SUSPENDED", 1)]),
            Result(1),
            Result(2),
            Result(4),
            Result(1),
            Result(7),
            Result(0),
        ]
    )
    data = await summary_numbers(cast(AsyncConnection, connection), NOW)
    assert data["activeUsersByType"] == {
        "EMPLOYEE": 3,
        "CUSTOMER": 0,
        "EXTERNAL": 2,
        "UNCLASSIFIED": 5,
    }
    assert data["usersByStatus"] == {"ACTIVE": 10, "SUSPENDED": 1}
    assert data["external"] == {"expiringIn7Days": 1, "expiringIn30Days": 2}
    assert data["invitations"] == {"pending": 4, "expiredUnaccepted": 1}
    assert data["last24Hours"] == {"loginFailures": 7}
    assert data["lockedAccounts"] == 0
    assert '"User".status = ' in connection.sql(0)
    assert '"User"."accountExpiresAt" IS NULL OR' in connection.sql(0)
    expiring = connection.sql(2)
    assert '"User"."userType" = ' in expiring and '"User"."accountExpiresAt" >' in expiring
    assert '"AuditLog".outcome = ' in connection.sql(6)


@pytest.mark.anyio
async def test_role_catalogue_marks_roles_external_accounts_may_hold() -> None:
    connection = Connection(
        [
            Result(
                rows=[
                    SimpleNamespace(id="r1", serviceKey="agent-hub", name="user"),
                    SimpleNamespace(id="r2", serviceKey="gitlab", name="user"),
                ]
            )
        ]
    )
    roles = await role_catalogue(cast(AsyncConnection, connection))
    assert [(r["serviceKey"], r["externalAllowed"]) for r in roles] == [
        ("agent-hub", False),
        ("gitlab", True),
    ]


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


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, (True, "역할 있음")),
        ({"status": "SUSPENDED"}, (False, "계정 정지·비활성")),
        ({"expires_at": datetime(2026, 11, 10)}, (False, "기한 만료")),
        ({"email_verified": False}, (False, "이메일 미인증")),
        ({"roles": set()}, (False, "gitlab:user 필요")),
    ],
)
def test_client_access_follows_the_login_gate_order(
    overrides: dict[str, object], expected: tuple[bool, str]
) -> None:
    from wiseacct_sso.api.oidc.admin_overview import client_access

    values: dict[str, Any] = {
        "status": "ACTIVE",
        "email_verified": True,
        "user_type": "EXTERNAL",
        "expires_at": datetime(2027, 1, 1),
        "roles": {("gitlab", "user")},
        "now": NOW,
    }
    values.update(overrides)
    assert client_access(_client(), **values) == expected


def test_client_access_respects_user_types_and_role_free_clients() -> None:
    from wiseacct_sso.api.oidc.admin_overview import client_access

    values: dict[str, Any] = {
        "status": "ACTIVE",
        "email_verified": True,
        "user_type": None,
        "expires_at": None,
        "roles": set(),
        "now": NOW,
    }
    typed = _client(allowedUserTypes=["EMPLOYEE"])
    assert client_access(typed, **values) == (False, "허용되지 않은 유형")
    hub = _client(
        clientId="agent-hub-dash",
        requiredRoles=[{"serviceKey": "agent-hub", "name": "user"}],
        groupsServiceKeys=["agent-hub"],
        allowWithoutRequiredRole=True,
    )
    assert client_access(hub, **values) == (
        False,
        "agent-hub:user 없음 (서비스 초대로만 입장)",
    )
    guest = {**values, "user_type": "EXTERNAL"}
    assert client_access(hub, **guest) == (False, "초대받은 손님만 입장 (서비스에서 초대)")
    assert client_access(hub, **{**values, "roles": {("agent-hub", "user")}}) == (
        True,
        "역할 있음",
    )


def test_managed_services_leave_open_sign_up_services_out() -> None:
    from wiseacct_sso.api.oidc.admin_overview import managed_services
    from wiseacct_sso.oidc_config import OidcClientRegistry

    hub = _client(
        clientId="agent-hub-dash",
        requiredRoles=[{"serviceKey": "agent-hub", "name": "user"}],
        groupsServiceKeys=["agent-hub"],
        allowWithoutRequiredRole=True,
    )
    fantra = _client(
        clientId="fantra-oidc",
        requiredRoles=[{"serviceKey": "temis", "name": "user"}],
        groupsServiceKeys=["temis"],
    )
    items = managed_services(OidcClientRegistry((_client(), hub, fantra)))
    assert [(i["label"], i["roles"]) for i in items] == [
        ("GitLab", ["gitlab:user"]),
        ("에이전트 허브", ["agent-hub:user"]),
    ]
