import codecs
import json
from collections.abc import Iterator
from typing import cast

import pytest
from fastapi.testclient import TestClient

from wiseacct_sso.application.auth import (
    LoginInput,
    RegisterInput,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.users import CurrentUser, DomainError, Role
from wiseacct_sso.main import create_app


class FakePhase4Services:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.error: DomainError | None = None
        self.retry_after: int | None = None

    async def enforce_rate_limit(
        self,
        *,
        client_key: str,
        route: str,
        method: str,
        context: RequestAuditContext,
    ) -> int | None:
        self.calls.append(("rate", (client_key, route, method, context)))
        return self.retry_after

    async def register(self, input: RegisterInput, context: RequestAuditContext) -> None:
        self.calls.append(("register", (input, context)))
        self._raise()

    async def login(self, input: LoginInput, context: RequestAuditContext) -> TokenPair:
        self.calls.append(("login", (input, context)))
        self._raise()
        return TokenPair(access_token="access-token", refresh_token="refresh-token")

    async def refresh(self, refresh_token: str, context: RequestAuditContext) -> TokenPair:
        self.calls.append(("refresh", (refresh_token, context)))
        self._raise()
        return TokenPair(access_token="new-access-token", refresh_token="new-refresh-token")

    async def logout(self, refresh_token: str, context: RequestAuditContext) -> None:
        self.calls.append(("logout", (refresh_token, context)))
        self._raise()

    async def current_user(self, access_token: str) -> CurrentUser:
        self.calls.append(("me", access_token))
        self._raise()
        return CurrentUser(
            id="user-1",
            email="person@example.com",
            email_verified=True,
            name="Person",
            roles=(Role(service_key="temis", name="user"),),
        )

    def _raise(self) -> None:
        if self.error is not None:
            raise self.error


@pytest.fixture
def services() -> FakePhase4Services:
    return FakePhase4Services()


@pytest.fixture
def client(synthetic_settings: Settings, services: FakePhase4Services) -> Iterator[TestClient]:
    application = create_app(
        settings=synthetic_settings,
        readiness_check=lambda: True,
        phase4_services=services,
    )
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def test_direct_password_auth_contract(client: TestClient, services: FakePhase4Services) -> None:
    register = client.post(
        "/auth/register",
        json={
            "email": "person@example.com",
            "password": "correct-password-123",
            "name": "Person",
            "ignored": "express-zod-strips-this",
        },
        headers={"x-forwarded-for": "203.0.113.9, 10.0.0.1", "user-agent": "phase4-test"},
    )
    login = client.post(
        "/auth/login",
        json={"email": "person@example.com", "password": "correct-password-123"},
    )
    refresh = client.post("/auth/refresh", json={"refreshToken": "refresh-token"})
    logout = client.post("/auth/logout", json={"refreshToken": "unknown-token"})
    me = client.get("/users/me", headers={"authorization": "Bearer access-token ignored"})

    assert register.status_code == 202
    assert register.json() == {"status": "accepted"}
    assert login.status_code == 200
    assert login.json() == {"accessToken": "access-token", "refreshToken": "refresh-token"}
    assert refresh.status_code == 200
    assert refresh.json() == {
        "accessToken": "new-access-token",
        "refreshToken": "new-refresh-token",
    }
    assert logout.status_code == 204
    assert logout.content == b""
    assert me.status_code == 200
    assert me.json() == {
        "id": "user-1",
        "email": "person@example.com",
        "email_verified": True,
        "name": "Person",
        "roles": [{"serviceKey": "temis", "name": "user"}],
    }
    register_call = next(value for name, value in services.calls if name == "register")
    register_input, register_context = cast(
        tuple[RegisterInput, RequestAuditContext], register_call
    )
    assert register_input == RegisterInput(
        email="person@example.com", password="correct-password-123", name="Person"
    )
    assert register_context == RequestAuditContext(
        ip_address="203.0.113.9", user_agent="phase4-test"
    )
    assert services.calls[-1] == ("me", "access-token")


def test_auth_rate_limit_runs_before_body_validation(
    client: TestClient, services: FakePhase4Services
) -> None:
    services.retry_after = 60
    response = client.post("/auth/login", json={"invalid": "body"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert response.json() == {
        "error": {
            "code": "RATE_LIMITED",
            "message": "Too many authentication requests",
        }
    }
    assert [name for name, _value in services.calls] == ["rate"]


def test_malformed_json_is_rejected_before_auth_rate_limit(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.post(
        "/auth/login",
        content=b'{"email":"person@example.com",',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert services.calls == []


@pytest.mark.parametrize(
    ("body", "expected_rate_calls"),
    [
        (b"", 1),
        (b"   \t\r\n", 0),
        (b"null", 0),
        (b'"string"', 0),
        (b"42", 0),
        (b"NaN", 0),
        (b"{}", 1),
        (b"[]", 1),
    ],
)
def test_express_json_strict_mode_classifies_before_rate_limit(
    client: TestClient,
    services: FakePhase4Services,
    body: bytes,
    expected_rate_calls: int,
) -> None:
    response = client.post(
        "/auth/login",
        content=body,
        headers={"content-type": "application/json; charset=utf-8"},
    )
    assert response.status_code == 400
    assert sum(name == "rate" for name, _value in services.calls) == expected_rate_calls


def test_malformed_application_plus_json_reaches_limiter_before_validation(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.post(
        "/auth/login",
        content=b'{"email":',
        headers={"content-type": "application/problem+json"},
    )
    assert response.status_code == 400
    assert [name for name, _value in services.calls] == ["rate"]


@pytest.mark.parametrize(
    ("body", "expected_status", "expected_rate_calls", "expected_login_calls"),
    [
        (b'{"email":"person@example.com","password":"password"}', 200, 1, 1),
        (b'{"email":"person@example.com"}', 400, 1, 0),
        (b"[]", 400, 1, 0),
        (b"null", 400, 0, 0),
        (b'{"email":', 400, 0, 0),
        (b"   \t\r\n", 400, 0, 0),
    ],
)
def test_utf8_bom_matches_express_json_classification(
    client: TestClient,
    services: FakePhase4Services,
    body: bytes,
    expected_status: int,
    expected_rate_calls: int,
    expected_login_calls: int,
) -> None:
    response = client.post(
        "/auth/login",
        content=b"\xef\xbb\xbf" + body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == expected_status
    assert sum(name == "rate" for name, _value in services.calls) == expected_rate_calls
    assert sum(name == "login" for name, _value in services.calls) == expected_login_calls


def test_rate_exceeded_utf8_bom_valid_json_returns_429_without_login(
    client: TestClient, services: FakePhase4Services
) -> None:
    services.retry_after = 60
    response = client.post(
        "/auth/login",
        content=(b'\xef\xbb\xbf{"email":"person@example.com","password":"password"}'),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 429
    assert [name for name, _value in services.calls] == ["rate"]


_VALID_LOGIN_JSON = '{"email":"person@example.com","password":"password"}'


@pytest.mark.parametrize(
    ("body", "charset", "expected_status", "expected_rate_calls", "expected_login_calls"),
    [
        (_VALID_LOGIN_JSON.encode("utf-8"), "utf-8", 200, 1, 1),
        (codecs.BOM_UTF8 + _VALID_LOGIN_JSON.encode("utf-8"), "utf-8", 200, 1, 1),
        (_VALID_LOGIN_JSON.encode("utf-16"), "utf-16", 200, 1, 1),
        (_VALID_LOGIN_JSON.encode("utf-16-le"), "utf-16le", 200, 1, 1),
        (
            codecs.BOM_UTF16_BE + _VALID_LOGIN_JSON.encode("utf-16-be"),
            "utf-16be",
            200,
            1,
            1,
        ),
        (_VALID_LOGIN_JSON.encode("utf-32"), "utf-32", 500, 0, 0),
        (_VALID_LOGIN_JSON.encode("utf-32-le"), "utf-32le", 500, 0, 0),
        (
            codecs.BOM_UTF32_BE + _VALID_LOGIN_JSON.encode("utf-32-be"),
            "utf-32be",
            500,
            0,
            0,
        ),
        ("[]".encode("utf-16-le"), "utf-16le", 400, 1, 0),
        ("null".encode("utf-32-be"), "utf-32be", 500, 0, 0),
        ('{"email":'.encode("utf-16-le"), "utf-16le", 400, 0, 0),
        (_VALID_LOGIN_JSON.encode("utf-16-le"), None, 400, 0, 0),
        (_VALID_LOGIN_JSON.encode("utf-32-le"), None, 400, 0, 0),
        (_VALID_LOGIN_JSON.encode("utf-16-le"), "utf-16be", 400, 0, 0),
        (_VALID_LOGIN_JSON.encode("utf-8"), "utf8", 500, 0, 0),
    ],
)
def test_application_json_charset_controls_pre_limiter_classification(
    client: TestClient,
    services: FakePhase4Services,
    body: bytes,
    charset: str | None,
    expected_status: int,
    expected_rate_calls: int,
    expected_login_calls: int,
) -> None:
    content_type = "application/json" if charset is None else f"application/json; charset={charset}"
    response = client.post(
        "/auth/login",
        content=body,
        headers={"content-type": content_type},
    )
    assert response.status_code == expected_status
    assert sum(name == "rate" for name, _value in services.calls) == expected_rate_calls
    assert sum(name == "login" for name, _value in services.calls) == expected_login_calls


@pytest.mark.parametrize("charset", ["utf-32be", "iso-8859-1", "utf8"])
def test_unsupported_json_charset_matches_actual_express_app_response(
    client: TestClient, services: FakePhase4Services, charset: str
) -> None:
    response = client.post(
        "/auth/login",
        content=_VALID_LOGIN_JSON.encode(),
        headers={"content-type": f"application/json; charset={charset}"},
    )
    expected = {"error": {"code": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}}
    assert response.status_code == 500
    assert response.headers["content-type"] == "application/json; charset=utf-8"
    assert response.json() == expected
    assert response.text == json.dumps(expected, separators=(",", ":"))
    assert services.calls == []


def test_well_formed_schema_invalid_json_is_limited_before_validation(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.post("/auth/login", json={"email": "person@example.com"})
    assert response.status_code == 400
    assert [name for name, _value in services.calls] == ["rate"]


@pytest.mark.parametrize(
    "body",
    [
        {"email": "person@example.com", "password": "password"},
        {"email": "person@example.com"},
    ],
)
def test_rate_exceeded_wins_for_any_syntactically_valid_json(
    client: TestClient, services: FakePhase4Services, body: dict[str, str]
) -> None:
    services.retry_after = 60
    response = client.post("/auth/login", json=body)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert [name for name, _value in services.calls] == ["rate"]


def test_express_json_size_limit_runs_before_auth_rate_limit(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.post(
        "/auth/login",
        content=b'"' + b"a" * (100 * 1024) + b'"',
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "INTERNAL_SERVER_ERROR", "message": "Internal server error"}
    }
    assert services.calls == []


def test_auth_limiter_uses_original_alias_and_ignores_unsupported_methods(
    client: TestClient, services: FakePhase4Services
) -> None:
    unsupported = client.get("/auth/login")
    aliased = client.post(
        "/AUTH/LOGIN/",
        json={"email": "person@example.com", "password": "password"},
    )
    assert unsupported.status_code == 404
    assert aliased.status_code == 200
    rate_calls = [value for name, value in services.calls if name == "rate"]
    assert len(rate_calls) == 1
    _client_key, route, method, _context = cast(
        tuple[str, str, str, RequestAuditContext], rate_calls[0]
    )
    assert route == "/AUTH/LOGIN/"
    assert method == "POST"


@pytest.mark.parametrize("path", ["/auth/%6cogin", "/auth%2flogin", "/%61uth/login"])
def test_percent_encoded_auth_paths_do_not_consume_limiter(
    client: TestClient, services: FakePhase4Services, path: str
) -> None:
    response = client.post(
        path,
        json={"email": "person@example.com", "password": "password"},
    )
    assert response.status_code == 404
    assert services.calls == []


@pytest.mark.parametrize(
    ("authorization", "expected"),
    [
        (None, {"code": "UNAUTHORIZED", "message": "Bearer access token is required"}),
        ("bearer token", {"code": "UNAUTHORIZED", "message": "Bearer access token is required"}),
        ("Bearer", {"code": "UNAUTHORIZED", "message": "Bearer access token is required"}),
    ],
)
def test_me_requires_express_bearer_shape(
    client: TestClient, authorization: str | None, expected: dict[str, str]
) -> None:
    headers = {} if authorization is None else {"authorization": authorization}
    response = client.get("/users/me", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": expected}


def test_head_me_runs_the_same_authentication_without_a_body(
    client: TestClient, services: FakePhase4Services
) -> None:
    missing_get = client.get("/users/me")
    missing = client.head("/users/me")
    assert missing.status_code == 401
    assert missing.content == b""
    assert missing.headers["content-type"] == missing_get.headers["content-type"]
    assert missing.headers["content-length"] == missing_get.headers["content-length"]
    assert services.calls == []

    valid = client.head("/users/me", headers={"authorization": "Bearer access-token"})
    valid_get = client.get("/users/me", headers={"authorization": "Bearer access-token"})
    assert valid.status_code == 200
    assert valid.content == b""
    assert valid.headers["content-type"] == valid_get.headers["content-type"]
    assert valid.headers["content-length"] == valid_get.headers["content-length"]
    assert services.calls == [("me", "access-token"), ("me", "access-token")]

    services.calls.clear()
    services.error = DomainError(401, "INVALID_TOKEN", "Invalid token")
    invalid = client.head("/users/me", headers={"authorization": "Bearer invalid-token"})
    assert invalid.status_code == 401
    assert invalid.content == b""
    assert services.calls == [("me", "invalid-token")]


@pytest.mark.parametrize(
    ("path", "allow", "etag"),
    [
        ("/auth/register", "POST", 'W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"'),
        ("/auth/login", "POST", 'W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"'),
        ("/AUTH/REFRESH/", "POST", 'W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"'),
        ("/auth/logout", "POST", 'W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"'),
        ("/users/me", "GET,HEAD", 'W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"'),
        ("/USERS/ME/", "GET,HEAD", 'W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"'),
    ],
)
def test_no_origin_options_matches_express_allow_contract_without_side_effects(
    client: TestClient,
    services: FakePhase4Services,
    path: str,
    allow: str,
    etag: str,
) -> None:
    response = client.options(path)
    assert response.status_code == 200
    assert response.headers["allow"] == allow
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["content-length"] == str(len(allow.encode()))
    assert response.headers["etag"] == etag
    assert response.text == allow
    assert services.calls == []


def test_allowed_origin_preflight_remains_cors_204_without_side_effects(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.options(
        "/auth/login",
        headers={
            "origin": "http://localhost:3000",
            "access-control-request-method": "POST",
        },
    )
    assert response.status_code == 204
    assert response.content == b""
    assert services.calls == []


def test_domain_errors_keep_express_envelope(
    client: TestClient, services: FakePhase4Services
) -> None:
    services.error = DomainError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token")
    response = client.post("/auth/refresh", json={"refreshToken": "invalid"})
    assert response.status_code == 401
    assert response.json() == {
        "error": {"code": "INVALID_REFRESH_TOKEN", "message": "Invalid refresh token"}
    }


def test_handoff_login_fails_closed_without_issuing_direct_tokens(
    client: TestClient, services: FakePhase4Services
) -> None:
    response = client.post(
        "/auth/login",
        json={
            "email": "person@example.com",
            "password": "correct-password-123",
            "clientId": "temis",
            "redirectUri": "https://financenow.kr/auth/callback",
            "state": "caller-state",
            "codeChallenge": "A" * 43,
            "codeChallengeMethod": "S256",
        },
    )
    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "AUTH_HANDOFF_UNAVAILABLE",
            "message": "Authentication handoff is not available",
        }
    }
    assert not any(name == "login" for name, _value in services.calls)
    assert "accessToken" not in response.text
    assert "refreshToken" not in response.text


@pytest.mark.parametrize(
    "email",
    [
        ".person@example.com",
        "person.@example.com",
        "per..son@example.com",
        "person@example..com",
        "person@example.com.",
        "person@exa_mple.com",
        "person@example.c",
        "person@localhost",
        "person name@example.com",
    ],
)
def test_email_validation_rejects_zod_oracle_edge_cases(
    client: TestClient, services: FakePhase4Services, email: str
) -> None:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "correct-password-123"},
    )
    assert response.status_code == 400
    assert not any(name == "register" for name, _value in services.calls)


@pytest.mark.parametrize(
    "email",
    [
        "person@example.com",
        "person+tag@sub.example.co.kr",
        "o'connor@example.io",
        "person@example-.com",
    ],
)
def test_email_validation_accepts_zod_oracle_corpus(client: TestClient, email: str) -> None:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "correct-password-123"},
    )
    assert response.status_code == 202


@pytest.mark.parametrize(
    "redirect_uri",
    ["not-a-url", "/relative", "//x", "https://", "foo:// space", "http://\ud800"],
)
def test_handoff_rejects_non_absolute_zod_url_values(
    client: TestClient, services: FakePhase4Services, redirect_uri: str
) -> None:
    payload = {
        "email": "person@example.com",
        "password": "correct-password-123",
        "clientId": "temis",
        "redirectUri": redirect_uri,
        "codeChallenge": "A" * 43,
        "codeChallengeMethod": "S256",
    }
    response = client.post(
        "/auth/login",
        content=json.dumps(payload, ensure_ascii=True).encode(),
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert not any(name == "login" for name, _value in services.calls)


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "mailto:user@example.com",
        "urn:example:sso",
        "foo:",
        "foo:bar",
        " http://x ",
        "http://x\n",
        "http://x\v",
        "HTTP://x",
        "http:x",
        "http:/x",
    ],
)
def test_handoff_accepts_absolute_non_http_urls_like_zod_before_phase5_defer(
    client: TestClient, redirect_uri: str
) -> None:
    response = client.post(
        "/auth/login",
        json={
            "email": "person@example.com",
            "password": "correct-password-123",
            "clientId": "temis",
            "redirectUri": redirect_uri,
            "codeChallenge": "A" * 43,
            "codeChallengeMethod": "S256",
        },
    )
    assert response.status_code == 503


def test_validation_and_known_path_compatibility(
    client: TestClient, services: FakePhase4Services
) -> None:
    incomplete = client.post(
        "/auth/login",
        json={
            "email": "person@example.com",
            "password": "password",
            "state": "caller-state",
        },
    )
    invalid = client.post("/auth/login", json={"email": "not-an-email", "password": "password"})
    compatible = client.post(
        "/AUTH/LOGIN/",
        json={"email": "person@example.com", "password": "password"},
    )
    assert incomplete.status_code == 400
    assert invalid.status_code == 400
    assert compatible.status_code == 200
    assert sum(name == "login" for name, _value in services.calls) == 1
