from __future__ import annotations

import base64
from pathlib import Path
from typing import NoReturn, cast

from fastapi.testclient import TestClient
from httpx import Response
from pytest import CaptureFixture

from wiseacct_sso.api.oidc import build_oidc_app
from wiseacct_sso.application.oidc import (
    AuthorizationRequest,
    AuthorizationResult,
    AuthorizationStart,
    OidcRequestContext,
    OidcServiceError,
    TokenExchangeInput,
    TokenResponse,
    UserInfo,
)
from wiseacct_sso.domain.oauth import OAuthProvider

PUBLIC_ORIGIN = "https://sso.example.test"
STATIC_ROOT = Path(__file__).parents[2] / "src" / "wiseacct_sso" / "static" / "oidc"
TRANSACTION = "T" * 43
PROVIDER_STATE = f"{TRANSACTION}.{'S' * 43}"


class FakeOidcService:
    def __init__(self) -> None:
        self.authorization_request: AuthorizationRequest | None = None
        self.password_attempts = 0
        self.exchange_input: TokenExchangeInput | None = None
        self.userinfo_token: str | None = None
        self.authorization_error: OidcServiceError | None = None
        self.password_error: Exception | None = None

    async def begin_authorization(
        self, request: AuthorizationRequest, context: OidcRequestContext
    ) -> AuthorizationStart:
        del context
        if self.authorization_error is not None:
            raise self.authorization_error
        self.authorization_request = request
        return AuthorizationStart(TRANSACTION, "csrf-1", "binding-1")

    async def password_login(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        csrf_token: str,
        email: str,
        password: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult:
        del context
        assert (transaction_id, browser_binding, csrf_token) == (
            TRANSACTION,
            "binding-1",
            "csrf-1",
        )
        assert (email, password) == ("user@example.test", "password")
        self.password_attempts += 1
        if self.password_error is not None:
            raise self.password_error
        return AuthorizationResult("https://client.example.test/callback?code=code-1&state=s")

    async def provider_start(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        provider: OAuthProvider,
    ) -> str:
        assert (transaction_id, browser_binding, provider) == (
            TRANSACTION,
            "binding-1",
            "google",
        )
        return f"https://accounts.example.test/authorize?state={PROVIDER_STATE}"

    async def provider_callback(
        self,
        *,
        provider: OAuthProvider,
        code: str,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult:
        del context
        assert (provider, code, state, browser_binding) == (
            "google",
            "provider-code",
            PROVIDER_STATE,
            "binding-1",
        )
        return AuthorizationResult("https://client.example.test/callback?code=oidc-code")

    async def provider_error(
        self,
        *,
        provider: OAuthProvider,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> NoReturn:
        del provider, state, browser_binding, context
        raise OidcServiceError("access_denied", "Provider login was cancelled", status_code=403)

    async def exchange_code(
        self, input: TokenExchangeInput, context: OidcRequestContext
    ) -> TokenResponse:
        del context
        self.exchange_input = input
        return TokenResponse(access_token="access-1", expires_in=300, id_token="id-token-1")

    async def userinfo(self, access_token: str) -> UserInfo:
        self.userinfo_token = access_token
        return UserInfo("user-1", "user@example.test", True, None, ("agent-hub:user",))


def _client(service: FakeOidcService) -> TestClient:
    app = build_oidc_app(
        service=service,
        public_origin=PUBLIC_ORIGIN,
        providers=("google",),
        static_root=STATIC_ROOT,
    )
    return TestClient(app, base_url=PUBLIC_ORIGIN, follow_redirects=False)


def _authorize(client: TestClient) -> Response:
    return cast(
        Response,
        client.get(
            "/oauth2/authorize",
            params={
                "response_type": "code",
                "client_id": "cloudflare-access-dash",
                "redirect_uri": "https://client.example.test/callback",
                "scope": "openid email profile",
                "state": "s",
                "nonce": "n",
                "code_challenge": "A" * 43,
                "code_challenge_method": "S256",
            },
        ),
    )


def test_authorize_starts_bound_browser_transaction_without_caching() -> None:
    service = FakeOidcService()
    client = _client(service)

    response = _authorize(client)

    assert response.status_code == 303
    assert response.headers["location"] == f"/oauth2/login?transaction={TRANSACTION}"
    assert response.headers["cache-control"] == "no-store"
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) == 2
    assert all(
        "Secure" in value and "HttpOnly" in value and "SameSite=lax" in value for value in cookies
    )
    assert all("Path=/oauth2" in value and "Max-Age=600" in value for value in cookies)
    assert service.authorization_request == AuthorizationRequest(
        client_id="cloudflare-access-dash",
        redirect_uri="https://client.example.test/callback",
        response_type="code",
        scopes=("openid", "email", "profile"),
        state="s",
        nonce="n",
        code_challenge="A" * 43,
        code_challenge_method="S256",
        prompt=None,
    )


def test_authorize_rejects_duplicate_parameters_before_service() -> None:
    service = FakeOidcService()
    client = _client(service)

    response = client.get(
        "/oauth2/authorize?response_type=code&response_type=token&client_id=c&redirect_uri="
        "https%3A%2F%2Fclient.example%2Fcb&scope=openid"
    )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert service.authorization_request is None


def test_validated_authorization_error_redirects_with_exact_state() -> None:
    service = FakeOidcService()
    service.authorization_error = OidcServiceError(
        "invalid_scope",
        "Unsupported scope",
        redirect_uri="https://client.example.test/callback?existing=1",
        state="state value",
    )
    client = _client(service)

    response = _authorize(client)

    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://client.example.test/callback?existing=1&error=invalid_scope&"
        "error_description=Unsupported+scope&state=state+value"
    )


def test_password_login_requires_exact_origin_and_bound_cookies() -> None:
    service = FakeOidcService()
    client = _client(service)
    _authorize(client)
    page = client.get(f"/oauth2/login?transaction={TRANSACTION}")
    assert page.status_code == 200
    assert 'name="csrf_token" value="csrf-1"' in page.text
    assert ">Google</a>" in page.text
    assert ">Naver</a>" not in page.text

    rejected = client.post(
        "/oauth2/login",
        data={
            "transaction": TRANSACTION,
            "csrf_token": "csrf-1",
            "email": "user@example.test",
            "password": "password",
        },
    )
    assert rejected.status_code == 400
    assert service.password_attempts == 0

    for headers, csrf_token in (
        ({"origin": "null"}, "csrf-1"),
        ({"origin": "https://evil.example.test"}, "csrf-1"),
        ({"origin": PUBLIC_ORIGIN}, "wrong-csrf"),
    ):
        forged = client.post(
            "/oauth2/login",
            headers=headers,
            data={
                "transaction": TRANSACTION,
                "csrf_token": csrf_token,
                "email": "user@example.test",
                "password": "password",
            },
        )
        assert forged.status_code == 400
    assert service.password_attempts == 0

    accepted = client.post(
        "/oauth2/login",
        headers={"origin": PUBLIC_ORIGIN},
        data={
            "transaction": TRANSACTION,
            "csrf_token": "csrf-1",
            "email": "user@example.test",
            "password": "password",
        },
    )
    assert accepted.status_code == 303
    assert accepted.headers["location"].endswith("?code=code-1&state=s")
    assert service.password_attempts == 1
    assert all("Max-Age=0" in value for value in accepted.headers.get_list("set-cookie"))


def test_provider_flow_requires_browser_binding_and_clears_it_on_callback() -> None:
    service = FakeOidcService()
    client = _client(service)
    _authorize(client)

    started = client.get(f"/oauth2/providers/google/start?transaction={TRANSACTION}")
    assert started.status_code == 302
    assert started.headers["location"].startswith("https://accounts.example.test/")

    completed = client.get(
        f"/oauth2/providers/google/callback?code=provider-code&state={PROVIDER_STATE}"
    )
    assert completed.status_code == 303
    assert completed.headers["location"].endswith("?code=oidc-code")
    assert all("Max-Age=0" in value for value in completed.headers.get_list("set-cookie"))


def test_provider_error_is_consumed_without_reflecting_provider_description() -> None:
    service = FakeOidcService()
    client = _client(service)
    _authorize(client)

    response = client.get(
        f"/oauth2/providers/google/callback?error=access_denied&"
        f"error_description=provider-secret&state={PROVIDER_STATE}"
    )

    assert response.status_code == 403
    assert "Provider login was cancelled" in response.text
    assert "provider-secret" not in response.text
    assert all("Max-Age=0" in value for value in response.headers.get_list("set-cookie"))


def test_role_denial_has_distinct_local_message_and_clears_transaction() -> None:
    service = FakeOidcService()
    service.password_error = OidcServiceError(
        "access_denied", "Account is not eligible", status_code=403
    )
    client = _client(service)
    _authorize(client)

    response = client.post(
        "/oauth2/login",
        headers={"origin": PUBLIC_ORIGIN},
        data={
            "transaction": TRANSACTION,
            "csrf_token": "csrf-1",
            "email": "user@example.test",
            "password": "password",
        },
    )

    assert response.status_code == 403
    assert "이 서비스 사용 권한이 없습니다" in response.text
    assert "Account is not eligible" not in response.text
    assert all("Max-Age=0" in value for value in response.headers.get_list("set-cookie"))


def test_token_supports_post_and_basic_but_rejects_mixed_authentication() -> None:
    service = FakeOidcService()
    client = _client(service)
    form = {
        "grant_type": "authorization_code",
        "code": "code-1",
        "redirect_uri": "https://client.example.test/callback",
        "code_verifier": "V" * 43,
        "client_id": "client-a",
        "client_secret": "secret-a",
    }

    post = client.post("/oauth2/token", data=form)
    assert post.status_code == 200
    assert post.json() == {
        "access_token": "access-1",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": "id-token-1",
    }
    assert service.exchange_input is not None
    assert service.exchange_input.client_id == "client-a"

    encoded = base64.b64encode(b"client-b:secret-b").decode("ascii")
    basic_form = {key: value for key, value in form.items() if not key.startswith("client_")}
    basic = client.post(
        "/oauth2/token",
        data=basic_form,
        headers={"authorization": f"Basic {encoded}"},
    )
    assert basic.status_code == 200
    assert service.exchange_input is not None
    assert service.exchange_input.client_id == "client-b"

    mixed = client.post(
        "/oauth2/token",
        data=form,
        headers={"authorization": f"Basic {encoded}"},
    )
    assert mixed.status_code == 400
    assert mixed.json()["error"] == "invalid_request"

    malformed = client.post(
        "/oauth2/token",
        data=basic_form,
        headers={"authorization": "Basic !!!"},
    )
    assert malformed.status_code == 401
    assert malformed.json()["error"] == "invalid_client"
    assert malformed.headers["www-authenticate"] == 'Basic realm="oauth2/token"'


def test_userinfo_accepts_only_bearer_and_omits_missing_name() -> None:
    service = FakeOidcService()
    client = _client(service)

    missing = client.get("/oauth2/userinfo")
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"

    response = client.get("/oauth2/userinfo", headers={"authorization": "Bearer opaque-token"})
    assert response.status_code == 200
    assert response.json() == {
        "sub": "user-1",
        "email": "user@example.test",
        "email_verified": True,
        "groups": ["agent-hub:user"],
    }
    assert service.userinfo_token == "opaque-token"


def test_unexpected_failure_is_reported_without_exception_text(
    capsys: CaptureFixture[str],
) -> None:
    class FailingService(FakeOidcService):
        async def userinfo(self, access_token: str) -> UserInfo:
            del access_token
            raise RuntimeError("sensitive diagnostic")

    client = _client(FailingService())

    response = client.get("/oauth2/userinfo", headers={"authorization": "Bearer opaque-token"})

    assert response.status_code == 500
    assert response.json()["error"] == "server_error"
    captured = capsys.readouterr()
    assert '"error_type":"RuntimeError"' in captured.err
    assert "sensitive diagnostic" not in captured.err


def test_unknown_oidc_paths_and_methods_keep_isolated_error_contract() -> None:
    client = _client(FakeOidcService())

    missing = client.get("/oauth2/not-found")
    method = client.put("/oauth2/token")

    assert missing.status_code == 404
    assert method.status_code == 405
    assert missing.json()["error"] == method.json()["error"] == "invalid_request"
    assert missing.headers["cache-control"] == method.headers["cache-control"] == "no-store"
