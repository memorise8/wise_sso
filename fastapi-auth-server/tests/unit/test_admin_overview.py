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
