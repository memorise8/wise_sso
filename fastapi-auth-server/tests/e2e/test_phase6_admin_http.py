from __future__ import annotations

import base64
import codecs
import json
import os
import shutil
import subprocess
import time
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from dotenv import dotenv_values
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.errors import ExpressJsonResponse, PublicHttpError, install_error_handlers
from wiseacct_sso.api.middleware import KnownPathCompatibilityMiddleware, normalized_route
from wiseacct_sso.api.routes.admin import _coerce_js_integer as coerce_js_integer
from wiseacct_sso.api.routes.admin import _iso as admin_iso
from wiseacct_sso.api.routes.admin import _parse_date as parse_admin_date
from wiseacct_sso.api.routes.admin import build_admin_router
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.admin import (
    AdminAuditLogListItem,
    AdminAuditLogPage,
    AdminRoleProfile,
    AdminUserListInput,
    AdminUserPage,
    AdminUserProfile,
    AuditLogListInput,
)
from wiseacct_sso.domain.users import DomainError, UserStatus
from wiseacct_sso.main import create_app

DATE_CORPUS = Path(__file__).parents[1] / "fixtures" / "admin-date-corpus.json"
DATE_ORACLE = Path(__file__).parents[1] / "helpers" / "admin_date_oracle.mjs"
NUMBER_CORPUS = Path(__file__).parents[1] / "fixtures" / "admin-number-corpus.json"
NUMBER_ORACLE = Path(__file__).parents[1] / "helpers" / "admin_number_oracle.mjs"
EXPRESS_DIR = Path(__file__).parents[3] / "auth-server"
EXPRESS_BODY_ORACLE = Path(__file__).parents[1] / "helpers" / "phase6_express_body_oracle.ts"
NODE = shutil.which("node")


@dataclass(frozen=True)
class _StatusResult:
    status_changed: bool
    revoked_refresh_token_count: int


@dataclass(frozen=True)
class _AssignResult:
    role_assigned: bool
    role_id: str


@dataclass(frozen=True)
class _RemoveResult:
    role_removed: bool
    role_id: str | None
    revoked_refresh_token_count: int


@dataclass(frozen=True)
class _RevokeResult:
    revoked_count: int


class FakePhase6Services:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.authorization_error: DomainError | None = None
        role = AdminRoleProfile("role-user", "temis", "user")
        self.role: AdminRoleProfile | None = role
        self.users = AdminUserPage(
            items=(
                AdminUserProfile(
                    id="target-user",
                    email="target@example.test",
                    name="Target",
                    status=UserStatus.ACTIVE,
                    created_at=datetime(2026, 7, 22, 3, tzinfo=UTC),
                    roles=(role,),
                ),
            ),
            total=1,
            page=2,
            page_size=5,
        )
        self.audit_logs = AdminAuditLogPage(
            items=(
                AdminAuditLogListItem(
                    id="audit-new",
                    event_type="login_failure",
                    outcome="failure",
                    user_id="target-user",
                    actor_user_id="admin-user",
                    target_user_id="target-user",
                    reason_code="INVALID_CREDENTIALS",
                    details_json={"accessToken": "[REDACTED]", "empty": None},
                    created_at=datetime(2026, 7, 22, 4, tzinfo=UTC),
                ),
            ),
            total=1,
            page=2,
            page_size=5,
        )

    async def authenticate_admin(self, access_token: str, *, route: str, method: str) -> str:
        self.calls.append(("authenticate", (access_token, route, method)))
        if self.authorization_error is not None:
            raise self.authorization_error
        return "admin-user"

    async def list_users(self, input: AdminUserListInput) -> AdminUserPage:
        self.calls.append(("list_users", input))
        return self.users

    async def list_audit_logs(self, input: AuditLogListInput) -> AdminAuditLogPage:
        self.calls.append(("list_audit_logs", input))
        return self.audit_logs

    async def find_role_by_id(self, role_id: str) -> AdminRoleProfile | None:
        self.calls.append(("find_role", role_id))
        return self.role

    async def set_user_status(self, **values: object) -> _StatusResult:
        self.calls.append(("set_status", values))
        return _StatusResult(True, 2)

    async def assign_role(self, **values: object) -> _AssignResult:
        self.calls.append(("assign_role", values))
        return _AssignResult(True, "role-admin")

    async def remove_role(self, **values: object) -> _RemoveResult:
        self.calls.append(("remove_role", values))
        return _RemoveResult(True, "role-user", 2)

    async def revoke_sessions(self, **values: object) -> _RevokeResult:
        self.calls.append(("revoke_sessions", values))
        return _RevokeResult(2)


@pytest.fixture
def services() -> FakePhase6Services:
    return FakePhase6Services()


@pytest.fixture
def client(services: FakePhase6Services) -> Iterator[TestClient]:
    application = FastAPI(default_response_class=ExpressJsonResponse, redirect_slashes=False)
    application.state.phase6_services = services
    install_error_handlers(application)
    application.include_router(build_admin_router(prefix="/admin"))
    application.include_router(build_admin_router(prefix="/manage-api"))
    application.add_middleware(KnownPathCompatibilityMiddleware)
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def test_admin_responses_are_no_store_in_the_composed_application(
    synthetic_settings: Settings, services: FakePhase6Services
) -> None:
    application = create_app(
        settings=synthetic_settings,
        readiness_check=lambda: True,
        phase6_services=cast(Phase6Services, services),
    )

    with TestClient(application, raise_server_exceptions=False) as test_client:
        authorized = test_client.get(
            "/admin/users", headers={"authorization": "Bearer access-token"}
        )
        unauthorized = test_client.get("/manage-api/audit-logs")

    assert authorized.status_code == 200
    assert unauthorized.status_code == 401
    assert authorized.headers["cache-control"] == "no-store"
    assert unauthorized.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("prefix", ["/admin", "/manage-api"])
def test_admin_aliases_authorize_and_list_users(
    client: TestClient, services: FakePhase6Services, prefix: str
) -> None:
    response = client.get(
        f"{prefix}/users",
        params={
            "page": "2",
            "pageSize": "5",
            "status": "ACTIVE",
            "email": " target@example.test ",
            "role": " temis:user ",
            "ignored": "zod-strips-this",
        },
        headers={"authorization": "Bearer access-token ignored"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "id": "target-user",
                "email": "target@example.test",
                "name": "Target",
                "status": "ACTIVE",
                "createdAt": "2026-07-22T03:00:00.000Z",
                "roles": [{"id": "role-user", "serviceKey": "temis", "name": "user"}],
            }
        ],
        "total": 1,
        "page": 2,
        "pageSize": 5,
    }
    assert services.calls[-2:] == [
        ("authenticate", ("access-token", f"{prefix}/users", "GET")),
        (
            "list_users",
            AdminUserListInput(
                page=2,
                page_size=5,
                status=UserStatus.ACTIVE,
                email="target@example.test",
                role="temis:user",
            ),
        ),
    ]


def test_audit_log_filters_and_response_shape(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/audit-logs",
        params={
            "page": "2",
            "pageSize": "5",
            "createdAtFrom": "2026-07-01T00:00:00.000Z",
            "createdAtTo": "2026-07-23T09:00:00+09:00",
            "eventType": "login_failure",
            "outcome": "failure",
            "userId": "target-user",
            "actorUserId": "admin-user",
            "targetUserId": "target-user",
            "reasonCode": "INVALID_CREDENTIALS",
        },
        headers={"authorization": "Bearer access-token"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [
            {
                "id": "audit-new",
                "eventType": "login_failure",
                "outcome": "failure",
                "userId": "target-user",
                "actorUserId": "admin-user",
                "targetUserId": "target-user",
                "reasonCode": "INVALID_CREDENTIALS",
                "detailsJson": {"accessToken": "[REDACTED]", "empty": None},
                "createdAt": "2026-07-22T04:00:00.000Z",
            }
        ],
        "total": 1,
        "page": 2,
        "pageSize": 5,
    }
    call = services.calls[-1]
    assert call[0] == "list_audit_logs"
    assert call[1] == AuditLogListInput(
        page=2,
        page_size=5,
        created_at_from=datetime(2026, 7, 1, tzinfo=UTC),
        created_at_to=datetime.fromisoformat("2026-07-23T09:00:00+09:00"),
        event_type="login_failure",
        outcome="failure",
        user_id="target-user",
        actor_user_id="admin-user",
        target_user_id="target-user",
        reason_code="INVALID_CREDENTIALS",
    )


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_admin_date_parser_matches_checked_in_node_oracle_corpus() -> None:
    corpus = json.loads(DATE_CORPUS.read_text())
    process_timezone = corpus["processTimezone"]
    node_expected = {case["input"]: case["iso"] for case in corpus["cases"]}
    python_expected = {
        case["input"]: case.get("pythonIso", case["iso"]) for case in corpus["cases"]
    }
    environment = {**os.environ, "TZ": process_timezone}
    assert NODE is not None
    completed = subprocess.run(  # noqa: S603 - fixed local Node binary and checked-in helper
        [NODE, str(DATE_ORACLE), str(DATE_CORPUS)],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    node_result = json.loads(completed.stdout)
    assert node_result["processTimezone"] == process_timezone
    assert {case["input"]: case["iso"] for case in node_result["cases"]} == node_expected

    previous_timezone = os.environ.get("TZ")
    try:
        os.environ["TZ"] = process_timezone
        time.tzset()
        python_result: dict[str, str | None] = {}
        for raw in node_expected:
            try:
                parsed = parse_admin_date(raw)
            except PublicHttpError:
                python_result[raw] = None
            else:
                assert parsed is not None
                python_result[raw] = admin_iso(parsed)
    finally:
        if previous_timezone is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_timezone
        time.tzset()
    assert python_result == python_expected


@pytest.mark.skipif(NODE is None, reason="Node.js is not installed")
def test_admin_number_coercion_matches_checked_in_node_ieee754_corpus() -> None:
    corpus = json.loads(NUMBER_CORPUS.read_text())
    expected = {case["input"]: (case["accepted"], case["integer"]) for case in corpus["cases"]}
    assert NODE is not None
    completed = subprocess.run(  # noqa: S603 - fixed local Node binary and checked-in helper
        [NODE, str(NUMBER_ORACLE), str(NUMBER_CORPUS)],
        check=True,
        capture_output=True,
        text=True,
    )
    oracle = json.loads(completed.stdout)
    assert {
        case["input"]: (case["accepted"], case["integer"]) for case in oracle["cases"]
    } == expected

    python_result: dict[str, tuple[bool, str | None]] = {}
    for raw in expected:
        try:
            parsed = coerce_js_integer(raw)
        except ValueError:
            python_result[raw] = (False, None)
        else:
            python_result[raw] = (True, str(parsed))
    assert python_result == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Wed, 01 Jul 2026 00:00:00 GMT", datetime(2026, 7, 1, tzinfo=UTC)),
        ("2026-07-01T24:00:00Z", datetime(2026, 7, 2, tzinfo=UTC)),
    ],
)
def test_audit_http_accepts_node_date_parse_formats(
    client: TestClient,
    services: FakePhase6Services,
    raw: str,
    expected: datetime,
) -> None:
    response = client.get(
        "/admin/audit-logs",
        params={"createdAtFrom": raw},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert services.calls[-1] == (
        "list_audit_logs",
        AuditLogListInput(created_at_from=expected),
    )


@pytest.mark.parametrize("path", ["/admin/users", "/manage-api/audit-logs"])
def test_get_routes_support_express_head_semantics(
    client: TestClient, services: FakePhase6Services, path: str
) -> None:
    response = client.head(path, headers={"authorization": "Bearer access-token"})
    assert response.status_code == 200
    assert response.content == b""
    assert services.calls[0] == ("authenticate", ("access-token", path, "HEAD"))
    assert services.calls[1][0] in {"list_users", "list_audit_logs"}


@pytest.mark.parametrize("path", ["/ADMIN/USERS/", "/Manage-Api/Audit-Logs/"])
def test_admin_static_routes_are_case_insensitive_and_non_strict(
    client: TestClient,
    services: FakePhase6Services,
    path: str,
) -> None:
    response = client.get(path, headers={"authorization": "Bearer access-token"})
    assert response.status_code == 200
    assert services.calls[0] == ("authenticate", ("access-token", path, "GET"))


def test_case_insensitive_trailing_slash_admin_head_uses_get_handler(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.head(
        "/MANAGE-API/USERS/",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert response.content == b""
    assert services.calls[:2] == [
        ("authenticate", ("access-token", "/MANAGE-API/USERS/", "HEAD")),
        ("list_users", AdminUserListInput()),
    ]


def test_admin_dynamic_route_is_case_insensitive_non_strict_and_preserves_parameters(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.patch(
        "/MANAGE-API/USERS/Target-User/STATUS/",
        json={"status": "SUSPENDED"},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert services.calls[0] == (
        "authenticate",
        ("access-token", "/MANAGE-API/USERS/Target-User/STATUS/", "PATCH"),
    )
    mutation = cast(dict[str, object], services.calls[1][1])
    assert mutation["target_user_id"] == "Target-User"


def test_percent_encoded_slash_user_id_is_restored_at_route_boundary(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.patch(
        "/admin/users/Target%2FNested/status",
        json={"status": "SUSPENDED"},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert services.calls[0] == (
        "authenticate",
        ("access-token", "/admin/users/Target/Nested/status", "PATCH"),
    )
    mutation = cast(dict[str, object], services.calls[1][1])
    assert mutation["target_user_id"] == "Target/Nested"


def test_percent_encoded_slash_role_id_is_restored_at_route_boundary(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.request(
        "DELETE",
        "/manage-api/users/Target%2FNested/roles/Role%2FNested",
        json={"reasonCode": "ADMIN_ROLE_REMOVE"},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert services.calls[:2] == [
        (
            "authenticate",
            (
                "access-token",
                "/manage-api/users/Target/Nested/roles/Role/Nested",
                "DELETE",
            ),
        ),
        ("find_role", "Role/Nested"),
    ]
    mutation = cast(dict[str, object], services.calls[2][1])
    assert mutation["target_user_id"] == "Target/Nested"
    assert mutation["details"] == {
        "roleId": "Role/Nested",
        "route": "DELETE /admin/users/:id/roles/:roleId",
    }


def test_percent_encoded_admin_static_segment_does_not_expand_route_surface(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/%61dmin/users",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 404
    assert services.calls == []


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("/ADMIN/USERS/", "/admin/users"),
        ("/manage-api/AUDIT-LOGS/", "/manage-api/audit-logs"),
        ("/ADMIN/USERS/secret-user/STATUS/", "/admin/users/:id/status"),
        ("/manage-api/users/a/ROLES/", "/manage-api/users/:id/roles"),
        (
            "/ADMIN/users/private/roles/private-role/",
            "/admin/users/:id/roles/:roleId",
        ),
        (
            "/manage-api/users/private/revoke-sessions",
            "/manage-api/users/:id/revoke-sessions",
        ),
    ],
)
def test_admin_instrumentation_labels_are_canonical_and_bounded(path: str, label: str) -> None:
    assert normalized_route(path) == label


@pytest.mark.parametrize(
    "authorization",
    [None, "bearer token", "Bearer", "Bearer ", " Bearer token"],
)
def test_missing_or_malformed_bearer_is_401_before_service(
    client: TestClient, services: FakePhase6Services, authorization: str | None
) -> None:
    headers = {} if authorization is None else {"authorization": authorization}
    response = client.get("/admin/users", headers=headers)
    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "UNAUTHORIZED", "message": "Bearer access token is required"}
    }
    assert services.calls == []


def test_signature_valid_empty_subject_is_unauthorized_before_database_or_audit(
    client: TestClient, services: FakePhase6Services
) -> None:
    services.authorization_error = DomainError(401, "UNAUTHORIZED", "Authentication is required")

    response = client.get(
        "/admin/users",
        headers={"authorization": "Bearer node-signed-empty-subject"},
    )

    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "UNAUTHORIZED", "message": "Authentication is required"}
    }
    assert services.calls == [
        (
            "authenticate",
            ("node-signed-empty-subject", "/admin/users", "GET"),
        )
    ]


def test_db_backed_admin_denial_uses_actual_alias_and_stops_handler(
    client: TestClient, services: FakePhase6Services
) -> None:
    services.authorization_error = DomainError(403, "FORBIDDEN", "Admin role is required")
    response = client.patch(
        "/manage-api/users/target-user/status",
        json={"status": "SUSPENDED", "reasonCode": "ADMIN_SUSPEND"},
        headers={"authorization": "Bearer stale-admin-token"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "FORBIDDEN", "message": "Admin role is required"}}
    assert services.calls == [
        (
            "authenticate",
            ("stale-admin-token", "/manage-api/users/target-user/status", "PATCH"),
        )
    ]


@pytest.mark.parametrize(
    ("path", "method", "payload"),
    [
        ("/admin/users/target-user/status", "PATCH", {"status": "disabled"}),
        ("/admin/users/target-user/status", "PATCH", {"status": " ACTIVE "}),
        ("/admin/users/target-user/roles", "POST", {"serviceKey": " ", "name": "admin"}),
        ("/admin/users/target-user/revoke-sessions", "POST", {"reasonCode": " "}),
    ],
)
def test_invalid_body_is_400_after_authorization_before_mutation(
    client: TestClient,
    services: FakePhase6Services,
    path: str,
    method: str,
    payload: dict[str, str],
) -> None:
    response = client.request(
        method,
        path,
        json=payload,
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert services.calls == [("authenticate", ("access-token", path, method))]


@pytest.mark.parametrize("body", [b"null", b'"value"', b"1", b"true"])
def test_express_json_strict_mode_scalar_admin_error_matches_generic_mapper(
    client: TestClient, services: FakePhase6Services, body: bytes
) -> None:
    response = client.patch(
        "/admin/users/target-user/status",
        content=body,
        headers={
            "authorization": "Bearer access-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}
    }
    assert services.calls == []


def test_malformed_admin_json_matches_express_generic_error_before_authorization(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.post(
        "/manage-api/users/target-user/roles",
        content=b'{"serviceKey":',
        headers={
            "authorization": "Bearer access-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}
    }
    assert services.calls == []


def test_oversize_admin_json_matches_express_global_parser_failure(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.post(
        "/admin/users/target-user/roles",
        content=b'{"serviceKey":"' + (b"a" * (100 * 1024)) + b'"}',
        headers={
            "authorization": "Bearer access-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}
    }
    assert services.calls == []


@pytest.mark.parametrize(
    ("body", "content_type", "expected_status"),
    [
        (
            codecs.BOM_UTF16_LE + '{"status":"SUSPENDED","reasonCode":"UTF16"}'.encode("utf-16-le"),
            "application/json; charset=utf-16le",
            200,
        ),
        (
            b'{"status":"SUSPENDED"}',
            "application/json; charset=iso-8859-1",
            500,
        ),
        (b'{"status":"SUSPENDED"}', "application/problem+json", 400),
    ],
)
def test_admin_json_content_type_and_charset_match_express_parser(
    client: TestClient,
    services: FakePhase6Services,
    body: bytes,
    content_type: str,
    expected_status: int,
) -> None:
    response = client.patch(
        "/admin/users/target-user/status",
        content=body,
        headers={"authorization": "Bearer access-token", "content-type": content_type},
    )
    assert response.status_code == expected_status
    if expected_status == 500:
        assert services.calls == []
    else:
        assert [name for name, _value in services.calls] == ["authenticate"] + (
            ["set_status"] if expected_status == 200 else []
        )


def test_duplicate_admin_json_fields_keep_the_last_value(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.patch(
        "/admin/users/target-user/status",
        content=b'{"status":"DELETED","status":"SUSPENDED"}',
        headers={
            "authorization": "Bearer access-token",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200
    mutation = cast(dict[str, object], services.calls[-1][1])
    assert mutation["status"] == "SUSPENDED"


def _express_body_parser_results(probes: list[dict[str, object]]) -> list[dict[str, object]]:
    npx = shutil.which("npx")
    assert npx is not None
    environment = dict(os.environ)
    environment.update(
        {
            key: value
            for key, value in dotenv_values(Path(__file__).parents[2] / ".env.example").items()
            if value is not None
        }
    )
    completed = subprocess.run(  # noqa: S603 - fixed npx and checked-in local oracle
        [npx, "tsx", str(EXPRESS_BODY_ORACLE)],
        cwd=EXPRESS_DIR,
        env=environment,
        input=json.dumps(probes, separators=(",", ":")),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return cast(list[dict[str, object]], json.loads(completed.stdout))


def test_admin_body_parser_matches_actual_express_create_app(
    client: TestClient, services: FakePhase6Services
) -> None:
    valid = b'{"status":"SUSPENDED"}'
    exact_limit = b'{"x":"' + (b"a" * ((100 * 1024) - 8)) + b'"}'
    utf7 = '{"status":"SUSPENDED","ignored":"한글"}'.encode("utf-7")
    utf16_text = '{"status":"SUSPENDED","ignored":"한글"}'
    probes = [
        (b'{"status":', {"content-type": "application/json"}),
        (b"null", {"content-type": "application/json"}),
        (b"\xff{}", {"content-type": "application/json; charset=utf-8"}),
        (zlib.compress(valid), {"content-type": "application/json", "content-encoding": "deflate"}),
        (
            zlib.compress(valid, wbits=zlib.MAX_WBITS | 16),
            {"content-type": "application/json", "content-encoding": "gzip"},
        ),
        (
            zlib.compress(exact_limit, wbits=zlib.MAX_WBITS | 16),
            {"content-type": "application/json", "content-encoding": "gzip"},
        ),
        (
            zlib.compress(b'{"ignored":"' + (b"a" * (100 * 1024)) + b'"}', wbits=31),
            {"content-type": "application/json", "content-encoding": "gzip"},
        ),
        (b"not-gzip", {"content-type": "application/json", "content-encoding": "gzip"}),
        (valid, {"content-type": "application/json", "content-encoding": "br"}),
        (utf7, {"content-type": "application/json; charset=utf-7"}),
        (valid, {"content-type": "application/json; charset=utf-7-imap"}),
        (
            utf16_text.encode("utf-16-le"),
            {"content-type": "application/json; charset=utf-16le"},
        ),
        (
            utf16_text.encode("utf-16-be"),
            {"content-type": "application/json; charset=utf-16be"},
        ),
        (
            utf16_text.encode("utf-16-le"),
            {"content-type": "application/json; charset=utf-16"},
        ),
        (valid, {"content-type": "application/json; charset=utf-32"}),
        (valid, {"content-type": "application/json; charset=utf8"}),
        (valid, {"content-type": "application/problem+json"}),
    ]
    request_probes = [
        (body, headers, "PATCH", "/admin/users/target/status") for body, headers in probes
    ] + [
        (b'{"broken":', {"content-type": "application/json"}, "GET", "/admin/users"),
        (b"null", {"content-type": "application/json"}, "GET", "/admin/users"),
        (b'{"broken":', {"content-type": "application/json"}, "PUT", "/unmatched"),
        (b"true", {"content-type": "application/json"}, "PUT", "/unmatched"),
        (b'{"broken":', {"content-type": "application/json"}, "POST", "/auth/login"),
        (b"1", {"content-type": "application/json"}, "POST", "/auth/login"),
        (b"null", {}, "PUT", "/unmatched"),
        (b"null", {"content-type": "application/problem+json"}, "PUT", "/unmatched"),
    ]
    oracle_input: list[dict[str, object]] = [
        {
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "headers": headers,
            "method": method,
            "path": path,
        }
        for body, headers, method, path in request_probes
    ]
    express_results = _express_body_parser_results(oracle_input)
    fastapi_results: list[dict[str, object]] = []
    for body, headers, method, path in request_probes:
        response = client.request(method, path, content=body, headers=headers)
        fastapi_results.append({"body": response.text, "status": response.status_code})

    assert fastapi_results == express_results
    assert services.calls == []


def test_invalid_query_is_400_after_authorization_before_query(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/audit-logs",
        params={"page": "0", "createdAtFrom": "not-a-date", "outcome": "maybe"},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 400
    assert services.calls == [("authenticate", ("access-token", "/admin/audit-logs", "GET"))]


def test_enum_query_is_not_trimmed_like_express_zod_enum(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/audit-logs",
        params={"outcome": " failure "},
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 400
    assert [name for name, _ in services.calls] == ["authenticate"]


def test_repeated_known_query_is_rejected_like_express_query_array(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/users?page=1&page=2",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 400
    assert [name for name, _ in services.calls] == ["authenticate"]


def test_pagination_uses_javascript_number_coercion(
    client: TestClient, services: FakePhase6Services
) -> None:
    services.users = AdminUserPage(items=(), total=0, page=2, page_size=16)
    response = client.get(
        "/admin/users?page=2e0&pageSize=0x10",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "page": 2, "pageSize": 16}
    assert services.calls[-1] == (
        "list_users",
        AdminUserListInput(page=2, page_size=16),
    )


def test_pagination_applies_ieee754_rounding_before_domain_input(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/users?page=0x20000000000001",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 200
    assert services.calls[-1] == (
        "list_users",
        AdminUserListInput(page=9_007_199_254_740_992),
    )


def test_pagination_rejects_javascript_number_overflow_after_authorization(
    client: TestClient, services: FakePhase6Services
) -> None:
    response = client.get(
        "/admin/users?page=1e309",
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 400
    assert [name for name, _ in services.calls] == ["authenticate"]


def test_admin_denial_precedes_invalid_body(
    client: TestClient, services: FakePhase6Services
) -> None:
    services.authorization_error = DomainError(403, "FORBIDDEN", "Admin role is required")
    response = client.patch(
        "/admin/users/target-user/status",
        json={"status": "disabled"},
        headers={"authorization": "Bearer stale-admin-token"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "FORBIDDEN", "message": "Admin role is required"}}
    assert services.calls == [
        (
            "authenticate",
            ("stale-admin-token", "/admin/users/target-user/status", "PATCH"),
        )
    ]


def test_mutations_map_defaults_details_and_results(
    client: TestClient, services: FakePhase6Services
) -> None:
    headers = {"authorization": "Bearer access-token"}
    status = client.patch(
        "/admin/users/target-user/status", json={"status": "SUSPENDED"}, headers=headers
    )
    assign = client.post(
        "/admin/users/target-user/roles",
        json={"serviceKey": "temis", "name": "admin"},
        headers=headers,
    )
    remove = client.request(
        "DELETE",
        "/admin/users/target-user/roles/role-user",
        json={"reasonCode": "ADMIN_ROLE_REMOVE"},
        headers=headers,
    )
    revoke = client.post(
        "/admin/users/target-user/revoke-sessions",
        json={"reasonCode": "ADMIN_REVOKE_TARGET"},
        headers=headers,
    )

    assert status.json() == {"statusChanged": True, "revokedRefreshTokenCount": 2}
    assert assign.json() == {"roleAssigned": True, "roleId": "role-admin"}
    assert remove.json() == {
        "roleRemoved": True,
        "roleId": "role-user",
        "revokedRefreshTokenCount": 2,
    }
    assert revoke.json() == {"revokedCount": 2}
    assert (
        "set_status",
        {
            "actor_user_id": "admin-user",
            "target_user_id": "target-user",
            "status": "SUSPENDED",
            "reason_code": "ADMIN_STATUS_CHANGE",
            "details": {"route": "PATCH /admin/users/:id/status"},
        },
    ) in services.calls
    assert (
        "assign_role",
        {
            "actor_user_id": "admin-user",
            "target_user_id": "target-user",
            "service_key": "temis",
            "name": "admin",
            "reason_code": "ADMIN_ROLE_ASSIGN",
            "details": {"route": "POST /admin/users/:id/roles"},
        },
    ) in services.calls


@pytest.mark.parametrize(
    ("path", "method", "payload", "message"),
    [
        (
            "/admin/users/admin-user/status",
            "PATCH",
            {"status": "DELETED"},
            "Admins cannot suspend or delete their own account",
        ),
        (
            "/admin/users/admin-user/revoke-sessions",
            "POST",
            {"reasonCode": "ADMIN_REVOKE_SELF"},
            "Admins cannot revoke their own sessions",
        ),
    ],
)
def test_self_protection_stops_mutation(
    client: TestClient,
    services: FakePhase6Services,
    path: str,
    method: str,
    payload: dict[str, str],
    message: str,
) -> None:
    response = client.request(
        method,
        path,
        json=payload,
        headers={"authorization": "Bearer access-token"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": {"code": "FORBIDDEN", "message": message}}
    assert all(name not in {"set_status", "revoke_sessions"} for name, _ in services.calls)


def test_self_admin_role_removal_and_missing_role_are_rejected(
    client: TestClient, services: FakePhase6Services
) -> None:
    headers = {"authorization": "Bearer access-token"}
    services.role = AdminRoleProfile("role-admin", "temis", "admin")
    self_remove = client.request(
        "DELETE",
        "/admin/users/admin-user/roles/role-admin",
        json={"reasonCode": "ADMIN_ROLE_REMOVE_SELF"},
        headers=headers,
    )
    assert self_remove.status_code == 403
    assert self_remove.json() == {
        "error": {
            "code": "FORBIDDEN",
            "message": "Admins cannot remove their own admin role",
        }
    }
    assert all(name != "remove_role" for name, _ in services.calls)

    services.calls.clear()
    services.role = None
    missing = client.request(
        "DELETE",
        "/admin/users/target-user/roles/missing",
        json={"reasonCode": "ADMIN_ROLE_REMOVE"},
        headers=headers,
    )
    assert missing.status_code == 404
    assert missing.json() == {"error": {"code": "ROLE_NOT_FOUND", "message": "Role not found"}}
    assert [name for name, _ in services.calls] == ["authenticate", "find_role"]

    services.calls.clear()
    whitespace = client.request(
        "DELETE",
        "/admin/users/target-user/roles/%20",
        json={"reasonCode": "ADMIN_ROLE_REMOVE"},
        headers=headers,
    )
    assert whitespace.status_code == 404
    assert whitespace.json() == {"error": {"code": "ROLE_NOT_FOUND", "message": "Role not found"}}
    assert [name for name, _ in services.calls] == ["authenticate"]
