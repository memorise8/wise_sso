from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.oauth_providers import (
    FOLLOW_PROVIDER_REDIRECTS,
    PROVIDER_HTTP_TIMEOUT_SECONDS,
    OAuthProviderCallbackError,
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderDisabledError,
    OAuthProviderInfrastructureError,
    OAuthProviderInvalidResponseError,
    authorization_url,
    normalize_profile,
    provider_config_for,
)


def _oauth_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "oauth_enabled_providers": ("google", "naver", "kakao"),
            "google_client_id": "google-client",
            "google_client_secret": "google-secret",
            "google_redirect_uri": "http://localhost:4000/auth/google/callback",
            "naver_client_id": "naver-client",
            "naver_client_secret": "naver-secret",
            "naver_redirect_uri": "http://localhost:4000/auth/naver/callback",
            "kakao_client_id": "kakao-client",
            "kakao_client_secret": "kakao-secret",
            "kakao_redirect_uri": "http://localhost:4000/auth/kakao/callback",
        }
    )


@pytest.mark.parametrize(
    ("provider", "authorize_host", "scope"),
    [
        ("google", "accounts.google.com", "openid email profile"),
        ("naver", "nid.naver.com", "email profile"),
        ("kakao", "kauth.kakao.com", "profile_nickname profile_image account_email"),
    ],
)
def test_provider_authorization_contract(
    synthetic_settings: Settings, provider: str, authorize_host: str, scope: str
) -> None:
    settings = _oauth_settings(synthetic_settings)
    config = provider_config_for(settings, provider)  # type: ignore[arg-type]
    parsed = urlsplit(authorization_url(config, "opaque-state"))

    assert parsed.hostname == authorize_host
    assert parse_qs(parsed.query) == {
        "response_type": ["code"],
        "client_id": [f"{provider}-client"],
        "redirect_uri": [f"http://localhost:4000/auth/{provider}/callback"],
        "scope": [scope],
        "state": ["opaque-state"],
    }


def test_authorization_url_matches_node_url_search_params_set_edge_encoding() -> None:
    config = OAuthProviderConfig(
        authorize_endpoint=("https://e.test/auth?x=~&client_id=old&x=2&client_id=again#"),
        token_endpoint="https://e.test/token",
        user_info_endpoint="https://e.test/me",
        client_id="a~ b*\ud800",
        client_secret="secret",
        redirect_uri="https://cb.test/x?y=~",
        scope="openid email",
    )

    assert authorization_url(config, "s~ *\ud800") == (
        "https://e.test/auth?x=%7E&client_id=a%7E+b*%EF%BF%BD&x=2&"
        "response_type=code&redirect_uri=https%3A%2F%2Fcb.test%2Fx%3Fy%3D%7E&"
        "scope=openid+email&state=s%7E+*%EF%BF%BD#"
    )


def test_disabled_provider_has_internal_mapping_error(synthetic_settings: Settings) -> None:
    settings = synthetic_settings.model_copy(update={"oauth_enabled_providers": ("google",)})

    with pytest.raises(OAuthProviderDisabledError) as raised:
        provider_config_for(settings, "naver")

    assert raised.value.code == "OAUTH_PROVIDER_DISABLED"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("provider", "raw_user", "expected"),
    [
        (
            "google",
            {
                "sub": "google-1",
                "email": "person@example.com",
                "email_verified": True,
                "name": "Person",
                "picture": "https://images.example/person.png",
            },
            ("google-1", "person@example.com", True, "Person"),
        ),
        (
            "naver",
            {"response": {"id": "naver-1", "email": "person@example.com", "name": "Person"}},
            ("naver-1", "person@example.com", False, "Person"),
        ),
        (
            "kakao",
            {
                "id": 123,
                "kakao_account": {
                    "email": "person@example.com",
                    "profile": {"nickname": "Person"},
                },
            },
            ("123", "person@example.com", False, "Person"),
        ),
    ],
)
async def test_token_and_profile_requests_match_express(
    synthetic_settings: Settings,
    provider: str,
    raw_user: object,
    expected: tuple[object, ...],
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json={"access_token": "provider-token"})
        return httpx.Response(200, json=raw_user)

    settings = _oauth_settings(synthetic_settings)
    config = provider_config_for(settings, provider)  # type: ignore[arg-type]
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthProviderClient(http_client)
    try:
        profile = await client.fetch_profile(provider, config, "authorization-code")  # type: ignore[arg-type]
    finally:
        await http_client.aclose()

    assert (
        profile.provider_user_id,
        profile.email,
        profile.email_verified,
        profile.name,
    ) == expected
    assert requests[0].method == "POST"
    assert requests[0].headers["content-type"] == "application/x-www-form-urlencoded"
    assert parse_qs(requests[0].content.decode()) == {
        "grant_type": ["authorization_code"],
        "client_id": [f"{provider}-client"],
        "client_secret": [f"{provider}-secret"],
        "redirect_uri": [f"http://localhost:4000/auth/{provider}/callback"],
        "code": ["authorization-code"],
    }
    assert requests[1].method == "GET"
    assert requests[1].headers["authorization"] == "Bearer provider-token"
    assert PROVIDER_HTTP_TIMEOUT_SECONDS == 10.0
    assert FOLLOW_PROVIDER_REDIRECTS is False


def test_google_is_only_provider_that_honors_verified_email() -> None:
    naver = normalize_profile("naver", {"response": {"id": "n", "email": "person@example.com"}})
    kakao = normalize_profile(
        "kakao", {"id": "k", "kakao_account": {"email": "person@example.com"}}
    )

    assert naver.email_verified is False
    assert kakao.email_verified is False


@pytest.mark.anyio
async def test_provider_redirect_is_not_followed(synthetic_settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://unexpected.example/token"})

    config = provider_config_for(_oauth_settings(synthetic_settings), "google")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthProviderClient(http_client)
    try:
        with pytest.raises(OAuthProviderInfrastructureError):
            await client.fetch_profile("google", config, "code")
    finally:
        await http_client.aclose()


def test_invalid_provider_shape_is_wrapped() -> None:
    with pytest.raises(OAuthProviderInvalidResponseError):
        normalize_profile("google", {"sub": "", "email": "not-an-email"})

    with pytest.raises(OAuthProviderInvalidResponseError):
        normalize_profile("google", {"sub": "google-1", "email": None})


def test_kakao_number_id_uses_javascript_string_shape() -> None:
    assert normalize_profile("kakao", {"id": 123.0}).provider_user_id == "123"


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["transport", "status", "json"])
@pytest.mark.parametrize("stage", ["token", "profile"])
async def test_transport_status_and_json_failures_are_internal(
    synthetic_settings: Settings, stage: str, failure: str
) -> None:
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        current_stage = "token" if request_count == 1 else "profile"
        if current_stage == stage:
            if failure == "transport":
                raise httpx.ConnectTimeout("provider timeout", request=request)
            if failure == "status":
                return httpx.Response(502, json={"error": "upstream"})
            return httpx.Response(200, content=b"not-json")
        return httpx.Response(200, json={"access_token": "token"})

    config = provider_config_for(_oauth_settings(synthetic_settings), "google")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthProviderClient(http_client)
    try:
        with pytest.raises(OAuthProviderInfrastructureError):
            await client.fetch_profile("google", config, "code")
    finally:
        await http_client.aclose()


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["token", "profile"])
async def test_valid_json_schema_failures_are_invalid_request(
    synthetic_settings: Settings, stage: str
) -> None:
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return httpx.Response(200, json={} if stage == "token" else {"access_token": "token"})
        return httpx.Response(200, json={"email": "missing-sub"})

    config = provider_config_for(_oauth_settings(synthetic_settings), "google")
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = OAuthProviderClient(http_client)
    try:
        with pytest.raises(OAuthProviderInvalidResponseError):
            await client.fetch_profile("google", config, "code")
    finally:
        await http_client.aclose()


def test_explicit_callback_query_error_has_separate_mapping_type() -> None:
    error = OAuthProviderCallbackError("access_denied", "The user denied access")

    assert error.code == "OAUTH_PROVIDER_ERROR"
    assert error.provider_error == "access_denied"
    assert error.description == "The user denied access"
