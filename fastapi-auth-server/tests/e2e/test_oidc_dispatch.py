import httpx
import pytest
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from wiseacct_sso.api.middleware import SecurityHeadersMiddleware, normalized_route
from wiseacct_sso.config import Settings
from wiseacct_sso.main import create_app


async def oidc_probe(scope: Scope, receive: Receive, send: Send) -> None:
    await JSONResponse(
        {"error": "oidc_probe", "path": scope["path"]},
        status_code=400,
        headers={"cache-control": "no-store"},
    )(scope, receive, send)


@pytest.mark.anyio
async def test_disabled_flag_preserves_unknown_route(synthetic_settings: Settings) -> None:
    app = create_app(settings=synthetic_settings, oidc_app=oidc_probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.example.test"
    ) as client:
        response = await client.get("/oauth2/authorize")
    assert response.status_code == 404
    assert response.json()["error"] != "oidc_probe"


@pytest.mark.anyio
async def test_enabled_namespace_bypasses_legacy_json_and_cors(
    synthetic_settings: Settings,
) -> None:
    settings = synthetic_settings.model_copy(update={"oidc_enabled": True})
    app = create_app(settings=settings, oidc_app=oidc_probe)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.example.test"
    ) as client:
        malformed = await client.post(
            "/oauth2/token", content="{", headers={"content-type": "application/json"}
        )
        preflight = await client.options(
            "/oauth2/token", headers={"origin": synthetic_settings.cors_allowed_origins[0]}
        )
    for response in (malformed, preflight):
        assert response.status_code == 400
        assert response.json() == {"error": "oidc_probe", "path": "/oauth2/token"}
        assert "access-control-allow-origin" not in response.headers
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "path",
    [
        "/healthz",
        "/readyz",
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/login",
        "/assets/auth.js",
        "/OAUTH2/authorize",
        "/oauth2evil/token",
        "/unknown",
        "/AUTH/LOGIN/",
    ],
)
async def test_legacy_response_body_unchanged_when_oidc_enabled(
    synthetic_settings: Settings, path: str
) -> None:
    responses: list[httpx.Response] = []
    for enabled in (False, True):
        app = create_app(
            settings=synthetic_settings.model_copy(update={"oidc_enabled": enabled}),
            oidc_app=oidc_probe,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://auth.example.test"
        ) as client:
            responses.append(await client.get(path))
    assert responses[0].status_code == responses[1].status_code
    assert responses[0].content == responses[1].content
    for header in ("content-type", "cache-control", "content-security-policy"):
        assert responses[0].headers.get(header) == responses[1].headers.get(header)


@pytest.mark.anyio
@pytest.mark.parametrize("failure", [False, True])
async def test_oidc_rate_limit_failures_are_isolated(
    synthetic_settings: Settings, failure: bool
) -> None:
    async def rate_check(path: str, address: str) -> bool:
        assert path == "/oauth2/token"
        assert address == "127.0.0.1"
        if failure:
            raise RuntimeError("must never be returned to the client")
        return False

    app = create_app(
        settings=synthetic_settings.model_copy(update={"oidc_enabled": True}),
        oidc_app=oidc_probe,
        oidc_rate_check=rate_check,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.example.test"
    ) as client:
        response = await client.post("/oauth2/token")
        health = await client.get("/healthz")
    assert response.status_code == (503 if failure else 429)
    assert response.json() == {"error": "temporarily_unavailable" if failure else "slow_down"}
    assert response.headers["cache-control"] == "no-store"
    assert health.status_code == 200


def test_enabled_oidc_requires_real_injected_application(synthetic_settings: Settings) -> None:
    with pytest.raises(ValueError, match="initialized OIDC"):
        create_app(settings=synthetic_settings.model_copy(update={"oidc_enabled": True}))


@pytest.mark.anyio
async def test_oidc_form_navigation_policy_does_not_change_legacy_csp() -> None:
    app = SecurityHeadersMiddleware(
        oidc_probe, oidc_form_action_sources=("https://team.cloudflareaccess.com",)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://auth.example.test"
    ) as client:
        login = await client.get("/oauth2/login")
        legacy = await client.get("/login")
    assert (
        "form-action 'self' https://team.cloudflareaccess.com;"
        in login.headers["content-security-policy"]
    )
    assert "form-action 'self';" in legacy.headers["content-security-policy"]
    assert "cloudflareaccess.com" not in legacy.headers["content-security-policy"]


def test_oidc_metric_routes_are_bounded_and_opt_in() -> None:
    assert normalized_route("/oauth2/token") == "unmatched"
    assert normalized_route("/oauth2/token", oidc_enabled=True) == "/oauth2/token"
    assert normalized_route("/oauth2/providers/google/callback", oidc_enabled=True) == (
        "/oauth2/providers/:provider/callback"
    )
    assert normalized_route("/oauth2/providers/attacker/callback", oidc_enabled=True) == "unmatched"
    assert normalized_route("/oauth2/login?secret=hidden", oidc_enabled=True) == "unmatched"
