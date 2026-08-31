from __future__ import annotations

from collections.abc import Iterator
from typing import cast, overload

import pytest
from fastapi.testclient import TestClient

from wiseacct_sso.api.routes.oauth import build_oauth_router
from wiseacct_sso.application.auth import (
    AuthHandoffExchangeInput,
    EmailVerificationResult,
    LoginInput,
    OAuthCallbackResult,
    OAuthStartInput,
    RegisterInput,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.oauth import ClientHandoff, OAuthProvider
from wiseacct_sso.domain.password_reset import PasswordResetAccepted, PasswordResetConfirmed
from wiseacct_sso.domain.users import CurrentUser, DomainError, Role
from wiseacct_sso.domain.verification import VerificationAccepted
from wiseacct_sso.main import create_app

CHALLENGE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
REDIRECT_URI = "https://financenow.kr/auth/callback"


class FakePhase5Services:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
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

    @overload
    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: None = None,
    ) -> TokenPair: ...

    @overload
    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: ClientHandoff,
    ) -> str: ...

    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: ClientHandoff | None = None,
    ) -> TokenPair | str:
        self.calls.append(("login", (input, context, handoff)))
        if handoff is not None:
            return f"{handoff.redirect_uri}?code=password-handoff&state={handoff.state}"
        return TokenPair("access-token", "refresh-token")

    async def refresh(self, refresh_token: str, context: RequestAuditContext) -> TokenPair:
        self.calls.append(("refresh", (refresh_token, context)))
        return TokenPair("new-access-token", "new-refresh-token")

    async def logout(self, refresh_token: str, context: RequestAuditContext) -> None:
        self.calls.append(("logout", (refresh_token, context)))

    async def current_user(self, access_token: str) -> CurrentUser:
        self.calls.append(("me", access_token))
        return CurrentUser(
            "user-1",
            "person@example.com",
            True,
            "Person",
            (Role("temis", "user"),),
        )

    async def request_email_verification(
        self,
        email: str,
        context: RequestAuditContext,
        handoff: ClientHandoff | None = None,
    ) -> VerificationAccepted:
        self.calls.append(("verification_request", (email, context, handoff)))
        return VerificationAccepted()

    async def confirm_email_verification(
        self, token: str, context: RequestAuditContext
    ) -> EmailVerificationResult:
        self.calls.append(("verification_confirm", (token, context)))
        return EmailVerificationResult(
            user_id="user-1",
            redirect_url=(
                f"{REDIRECT_URI}?code=verification-handoff&state=caller-state"
                if token == "handoff-token"
                else None
            ),
        )

    async def request_password_reset(
        self, email: str, context: RequestAuditContext
    ) -> PasswordResetAccepted:
        self.calls.append(("reset_request", (email, context)))
        return PasswordResetAccepted()

    async def confirm_password_reset(
        self, token: str, password: str, context: RequestAuditContext
    ) -> PasswordResetConfirmed:
        self.calls.append(("reset_confirm", (token, password, context)))
        if token == "invalid":
            raise DomainError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token")
        return PasswordResetConfirmed("user-1")

    async def exchange_auth_handoff(
        self, input: AuthHandoffExchangeInput, context: RequestAuditContext
    ) -> TokenPair:
        self.calls.append(("exchange", (input, context)))
        return TokenPair("access-token", "refresh-token")

    async def invalid_auth_handoff_exchange(self, context: RequestAuditContext) -> None:
        self.calls.append(("invalid_exchange", context))
        raise DomainError(400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code")

    async def oauth_start(self, provider: OAuthProvider, input: OAuthStartInput) -> str:
        self.calls.append(("oauth_start", (provider, input)))
        return f"https://provider.example/authorize?provider={provider}&state=opaque"

    async def oauth_provider_error(
        self, provider: OAuthProvider, context: RequestAuditContext
    ) -> None:
        self.calls.append(("oauth_provider_error", (provider, context)))
        raise DomainError(400, "OAUTH_PROVIDER_ERROR", "OAuth provider returned an error")

    async def oauth_callback(
        self,
        provider: OAuthProvider,
        code: str,
        state: str,
        context: RequestAuditContext,
    ) -> OAuthCallbackResult:
        self.calls.append(("oauth_callback", (provider, code, state, context)))
        return OAuthCallbackResult(f"{REDIRECT_URI}?code=handoff&state=caller")


@pytest.fixture
def services() -> FakePhase5Services:
    return FakePhase5Services()


@pytest.fixture
def client(synthetic_settings: Settings, services: FakePhase5Services) -> Iterator[TestClient]:
    application = create_app(
        settings=synthetic_settings,
        readiness_check=lambda: True,
        phase4_services=services,
    )
    if not any(getattr(route, "path", None) == "/auth/google" for route in application.routes):
        application.include_router(build_oauth_router())
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def test_phase5_password_and_verification_contract(
    client: TestClient, services: FakePhase5Services
) -> None:
    reset_request = client.post(
        "/auth/password-reset/request", json={"email": "User@Company.com", "ignored": True}
    )
    reset_confirm = client.post(
        "/auth/password-reset/confirm",
        json={"token": "reset-token", "password": "new-password-123", "ignored": True},
    )
    verification_request = client.post(
        "/auth/email-verification/request",
        json={
            "email": "person@example.com",
            "clientId": "temis",
            "redirectUri": REDIRECT_URI,
            "state": "caller-state",
            "codeChallenge": CHALLENGE,
            "codeChallengeMethod": "S256",
        },
    )
    verification_confirm = client.post(
        "/auth/email-verification/confirm", json={"token": "handoff-token"}
    )

    assert reset_request.status_code == 202
    assert reset_request.json() == {"status": "accepted"}
    assert reset_confirm.status_code == 204
    assert reset_confirm.content == b""
    assert verification_request.status_code == 202
    assert verification_request.json() == {"status": "accepted"}
    assert verification_confirm.status_code == 200
    assert verification_confirm.json() == {
        "status": "verified",
        "redirectUrl": f"{REDIRECT_URI}?code=verification-handoff&state=caller-state",
    }
    verification_call = next(
        value for name, value in services.calls if name == "verification_request"
    )
    handoff = cast(tuple[str, RequestAuditContext, ClientHandoff], verification_call)[2]
    assert handoff == ClientHandoff(
        client_id="temis",
        audience="temis",
        redirect_uri=REDIRECT_URI,
        state="caller-state",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
    )


def test_login_handoff_and_exchange_use_strict_public_contract(
    client: TestClient, services: FakePhase5Services
) -> None:
    login = client.post(
        "/auth/login",
        json={
            "email": "person@example.com",
            "password": "password",
            "clientId": "temis",
            "redirectUri": REDIRECT_URI,
            "state": "caller-state",
            "codeChallenge": CHALLENGE,
            "codeChallengeMethod": "S256",
        },
    )
    exchange = client.post(
        "/auth/exchange",
        json={
            "clientId": "temis",
            "redirectUri": REDIRECT_URI,
            "code": "handoff-code",
            "codeVerifier": "verifier",
        },
    )
    invalid_exchange = client.post(
        "/auth/exchange",
        json={
            "client_id": "temis",
            "redirect_uri": REDIRECT_URI,
            "code": "handoff-code",
            "code_verifier": "verifier",
        },
    )
    empty_exchange = client.post("/auth/exchange")

    assert login.status_code == 200
    assert login.json() == {
        "redirectUrl": f"{REDIRECT_URI}?code=password-handoff&state=caller-state"
    }
    assert exchange.status_code == 200
    assert exchange.json() == {"accessToken": "access-token", "refreshToken": "refresh-token"}
    assert invalid_exchange.status_code == 400
    assert invalid_exchange.json() == {
        "error": {
            "code": "INVALID_AUTH_HANDOFF_CODE",
            "message": "Invalid authorization code",
        }
    }
    assert empty_exchange.status_code == 400
    assert empty_exchange.json() == invalid_exchange.json()
    assert sum(name == "exchange" for name, _value in services.calls) == 1
    assert sum(name == "invalid_exchange" for name, _value in services.calls) == 2


@pytest.mark.parametrize("provider", ["google", "naver", "kakao"])
def test_oauth_start_and_callback_redirect_contract(
    client: TestClient, services: FakePhase5Services, provider: str
) -> None:
    start = client.get(
        f"/auth/{provider}",
        params={
            "client_id": "temis",
            "redirect_uri": REDIRECT_URI,
            "state": "caller-state",
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    callback = client.get(
        f"/auth/{provider}/callback",
        params={"code": "provider-code", "state": "opaque-state"},
        follow_redirects=False,
    )

    assert start.status_code == 302
    assert start.headers["location"].startswith("https://provider.example/authorize")
    assert start.headers["vary"] == "Accept"
    assert start.headers["content-type"] == "text/plain; charset=utf-8"
    assert start.text == f"Found. Redirecting to {start.headers['location']}"
    assert int(start.headers["content-length"]) == len(start.content)
    assert callback.status_code == 302
    assert callback.headers["location"] == f"{REDIRECT_URI}?code=handoff&state=caller"
    start_call = next(value for name, value in services.calls if name == "oauth_start")
    start_input = cast(tuple[OAuthProvider, OAuthStartInput], start_call)[1]
    assert start_input == OAuthStartInput(
        client_id="temis",
        redirect_uri=REDIRECT_URI,
        caller_state="caller-state",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
    )


@pytest.mark.parametrize(
    ("accept", "content_type", "body"),
    [
        (
            "text/plain",
            "text/plain; charset=utf-8",
            "Found. Redirecting to https://provider.example/authorize?provider=google&state=opaque",
        ),
        (
            "text/html",
            "text/html; charset=utf-8",
            "<p>Found. Redirecting to "
            "https://provider.example/authorize?provider=google&amp;state=opaque</p>",
        ),
        ("application/json", None, ""),
    ],
)
def test_oauth_redirect_matches_express_accept_negotiation(
    client: TestClient,
    accept: str,
    content_type: str | None,
    body: str,
) -> None:
    response = client.get(
        "/auth/google",
        params={"code_challenge": CHALLENGE},
        headers={"accept": accept},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://provider.example/authorize?provider=google&state=opaque"
    )
    assert response.headers["vary"] == "Accept"
    assert response.headers.get("content-type") == content_type
    assert response.text == body
    assert int(response.headers["content-length"]) == len(body.encode())


def test_oauth_head_exposes_negotiated_get_headers_without_body(client: TestClient) -> None:
    response = client.head(
        "/auth/google",
        params={"code_challenge": CHALLENGE},
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    expected_body = (
        "<p>Found. Redirecting to "
        "https://provider.example/authorize?provider=google&amp;state=opaque</p>"
    )

    assert response.status_code == 302
    assert response.headers["vary"] == "Accept"
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert int(response.headers["content-length"]) == len(expected_body.encode())
    assert response.content == b""


@pytest.mark.parametrize("path", ["/auth/login", "/auth/email-verification/request"])
def test_auth_handoff_state_uses_javascript_utf16_length(
    client: TestClient, services: FakePhase5Services, path: str
) -> None:
    base = {
        "clientId": "temis",
        "redirectUri": REDIRECT_URI,
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
    }
    accepted_body = {**base, "state": "😀" * 256}
    rejected_body = {**base, "state": "😀" * 257}
    if path == "/auth/login":
        accepted_body.update(email="person@example.com", password="password")
        rejected_body.update(email="person@example.com", password="password")
    else:
        accepted_body["email"] = "person@example.com"
        rejected_body["email"] = "person@example.com"

    accepted = client.post(path, json=accepted_body)
    service_calls_after_accepted = len(services.calls)
    rejected = client.post(path, json=rejected_body)

    assert accepted.status_code in {200, 202}
    assert rejected.status_code == 400
    assert rejected.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert [name for name, _value in services.calls[service_calls_after_accepted:]] == ["rate"]


def test_oauth_start_state_uses_javascript_utf16_length(
    client: TestClient, services: FakePhase5Services
) -> None:
    accepted = client.get(
        "/auth/google",
        params={"code_challenge": CHALLENGE, "state": "😀" * 256},
        follow_redirects=False,
    )
    service_calls_after_accepted = len(services.calls)
    rejected = client.get(
        "/auth/google",
        params={"code_challenge": CHALLENGE, "state": "😀" * 257},
        follow_redirects=False,
    )

    assert accepted.status_code == 302
    assert rejected.status_code == 400
    assert rejected.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert [name for name, _value in services.calls[service_calls_after_accepted:]] == ["rate"]


def test_oauth_callback_state_has_no_express_maximum(client: TestClient) -> None:
    response = client.get(
        "/auth/google/callback",
        params={"code": "provider-code", "state": "😀" * 513},
        follow_redirects=False,
    )

    assert response.status_code == 302


def test_oauth_provider_error_is_audited_and_mapped_by_service(
    client: TestClient, services: FakePhase5Services
) -> None:
    response = client.get(
        "/auth/google/callback", params={"error": "access_denied"}, follow_redirects=False
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "OAUTH_PROVIDER_ERROR",
            "message": "OAuth provider returned an error",
        }
    }
    assert [name for name, _value in services.calls] == ["rate", "oauth_provider_error"]


def test_empty_oauth_provider_error_falls_through_to_request_validation(
    client: TestClient, services: FakePhase5Services
) -> None:
    response = client.get("/auth/google/callback", params={"error": ""}, follow_redirects=False)

    assert response.status_code == 400
    assert response.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert [name for name, _value in services.calls] == ["rate"]


@pytest.mark.parametrize(
    "errors",
    [
        [("error", ""), ("error", "")],
        [("error", "access_denied"), ("error", "")],
    ],
)
def test_duplicate_oauth_provider_errors_are_truthy_express_arrays(
    client: TestClient,
    services: FakePhase5Services,
    errors: list[tuple[str, str]],
) -> None:
    response = client.get(
        "/auth/google/callback",
        params=errors,
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert response.json() == {
        "error": {
            "code": "OAUTH_PROVIDER_ERROR",
            "message": "OAuth provider returned an error",
        }
    }
    assert [name for name, _value in services.calls] == ["rate", "oauth_provider_error"]


@pytest.mark.parametrize(
    "path",
    [
        "/auth/exchange",
        "/auth/password-reset/request",
        "/auth/password-reset/confirm",
        "/auth/email-verification/request",
        "/auth/email-verification/confirm",
    ],
)
def test_new_post_routes_share_express_options_contract(client: TestClient, path: str) -> None:
    response = client.options(path)

    assert response.status_code == 200
    assert response.headers["allow"] == "POST"
    assert response.text == "POST"


def test_oauth_options_validation_and_rate_limit_method_scope(
    client: TestClient, services: FakePhase5Services
) -> None:
    options = client.options("/auth/google")
    invalid = client.get("/auth/google", params={"code_challenge": "short"})
    before = sum(name == "rate" for name, _value in services.calls)
    unsupported = client.post("/auth/google", json={})
    encoded = client.get(
        "/auth/%67oogle",
        params={"code_challenge": CHALLENGE},
        follow_redirects=False,
    )

    assert options.status_code == 200
    assert options.headers["allow"] == "GET,HEAD"
    assert options.text == "GET,HEAD"
    assert invalid.status_code == 400
    assert invalid.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert unsupported.status_code == 404
    assert encoded.status_code == 404
    assert sum(name == "rate" for name, _value in services.calls) == before


def test_strict_handoff_aliases_and_oauth_head_rate_limit(
    client: TestClient, services: FakePhase5Services
) -> None:
    snake_case = client.post(
        "/auth/email-verification/request",
        json={
            "email": "person@example.com",
            "client_id": "temis",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    head = client.head(
        "/auth/google",
        params={"code_challenge": CHALLENGE},
        follow_redirects=False,
    )

    assert snake_case.status_code == 400
    assert snake_case.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert head.status_code == 302
    assert head.content == b""
    rate_call = [value for name, value in services.calls if name == "rate"][-1]
    assert cast(tuple[str, str, str, RequestAuditContext], rate_call)[2] == "HEAD"


def test_phase5_rate_limit_stops_before_route_service(
    client: TestClient, services: FakePhase5Services
) -> None:
    services.retry_after = 45
    response = client.post("/auth/password-reset/request", json={"email": "person@example.com"})

    assert response.status_code == 429
    assert response.headers["retry-after"] == "45"
    assert [name for name, _value in services.calls] == ["rate"]
