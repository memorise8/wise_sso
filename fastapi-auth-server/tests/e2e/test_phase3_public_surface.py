import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Body, Request
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from wiseacct_sso.api.errors import PublicHttpError
from wiseacct_sso.config import Settings
from wiseacct_sso.main import create_app

ROOT = Path(__file__).parents[2]
EXPRESS_PUBLIC = ROOT.parent / "auth-server" / "public"
FASTAPI_STATIC = ROOT / "src" / "wiseacct_sso" / "static"
STATIC_FILES = (
    "auth-portal.html",
    "assets/auth.css",
    "assets/auth.js",
    "assets/admin-dashboard.css",
)
ADMIN_DASHBOARD_ASSET = "assets/admin-dashboard.js"
ADMIN_DASHBOARD_XSS_ORACLE = (
    Path(__file__).parents[1] / "helpers" / "admin_dashboard_xss_oracle.mjs"
)
SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self';base-uri 'self';font-src 'self' https: data:;"
        "form-action 'self';frame-ancestors 'self';img-src 'self' data:;"
        "object-src 'none';script-src 'self';script-src-attr 'none';"
        "style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests"
    ),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "origin-agent-cluster": "?1",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=15552000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-dns-prefetch-control": "off",
    "x-download-options": "noopen",
    "x-frame-options": "SAMEORIGIN",
    "x-permitted-cross-domain-policies": "none",
    "x-xss-protection": "0",
}


class RecordingLogger:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, object]]] = []

    def info(self, event: str, **event_kw: object) -> None:
        self.records.append((event, event_kw))

    def warning(self, event: str, **event_kw: object) -> None:
        self.records.append((event, event_kw))


@pytest.fixture
def client(synthetic_settings: Settings) -> Iterator[TestClient]:
    application = create_app(settings=synthetic_settings, readiness_check=lambda: True)

    @application.post("/__phase3_validation_probe__")
    async def validation_probe(value: Annotated[int, Body(embed=True)]) -> dict[str, int]:
        return {"value": value}

    @application.get("/__phase3_public_error__")
    async def public_error() -> None:
        raise PublicHttpError(409, "PHASE3_CONFLICT", "Phase 3 conflict")

    @application.get("/__phase3_unhandled__")
    async def unhandled() -> None:
        raise RuntimeError("must never be public")

    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client


def test_discovery_matches_the_express_public_contract(
    client: TestClient, synthetic_settings: Settings
) -> None:
    jwks = client.get("/.well-known/jwks.json")
    assert jwks.status_code == 200
    assert jwks.headers["cache-control"] == "public, max-age=300"
    assert jwks.json() == {"keys": [synthetic_settings.jwt_access_public_jwk.model_dump()]}
    serialized = jwks.text
    assert "PRIVATE KEY" not in serialized
    assert all(name not in jwks.json()["keys"][0] for name in ("d", "p", "q", "dp", "dq", "qi"))

    discovery = client.get("/.well-known/openid-configuration")
    assert discovery.status_code == 200
    assert discovery.headers["cache-control"] == "public, max-age=300"
    assert discovery.json() == {
        "issuer": synthetic_settings.jwt_issuer,
        "jwks_uri": f"{synthetic_settings.jwt_issuer}/.well-known/jwks.json",
        "subject_types_supported": ["public"],
        "response_types_supported": ["code"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "roles",
            "email",
            "email_verified",
            "name",
            "type",
        ],
    }
    assert "id_token_signing_alg_values_supported" not in discovery.json()


def test_static_copies_are_byte_identical_and_served_with_express_cache_contract(
    client: TestClient,
) -> None:
    for relative in STATIC_FILES:
        assert (FASTAPI_STATIC / relative).read_bytes() == (EXPRESS_PUBLIC / relative).read_bytes()

    portal = client.get("/login")
    assert portal.status_code == 200
    assert portal.content == (EXPRESS_PUBLIC / "auth-portal.html").read_bytes()
    assert portal.headers["cache-control"] == "public, max-age=0"
    assert client.get("/login?filename=../../config.py").content == portal.content

    dashboard = client.get("/manage/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.content == (FASTAPI_STATIC / "admin-dashboard.html").read_bytes()
    assert b"/assets/admin-dashboard.js?v=20260901a" in dashboard.content

    for path, response in (("/login", portal), ("/manage/dashboard", dashboard)):
        assert response.headers["etag"]
        assert response.headers["last-modified"]
        for conditional_headers in (
            {"if-none-match": response.headers["etag"]},
            {"if-none-match": "*"},
            {"if-modified-since": response.headers["last-modified"]},
        ):
            cached_html = client.get(path, headers=conditional_headers)
            assert cached_html.status_code == 304
            assert cached_html.content == b""
            assert cached_html.headers["cache-control"] == "public, max-age=0"

    asset = client.get("/assets/auth.css")
    assert asset.status_code == 200
    assert asset.content == (EXPRESS_PUBLIC / "assets" / "auth.css").read_bytes()
    assert asset.headers["cache-control"] == "public, max-age=3600, immutable"
    assert asset.headers["etag"]
    assert asset.headers["last-modified"]
    cached = client.get("/assets/auth.css", headers={"if-none-match": asset.headers["etag"]})
    assert cached.status_code == 304
    assert cached.content == b""
    assert cached.headers["cache-control"] == "public, max-age=3600, immutable"
    wildcard_cached = client.get("/assets/auth.css", headers={"if-none-match": "*"})
    assert wildcard_cached.status_code == 304
    assert wildcard_cached.content == b""
    assert wildcard_cached.headers["cache-control"] == "public, max-age=3600, immutable"
    assert client.get("/ASSETS/auth.css").content == asset.content
    assert client.get("/assets/AUTH.CSS").status_code == 404
    assert client.get("/assets/%61uth.css").content == asset.content


def test_fastapi_admin_dashboard_renders_api_fields_as_text(client: TestClient) -> None:
    asset_path = FASTAPI_STATIC / ADMIN_DASHBOARD_ASSET
    source = asset_path.read_text()
    assert ".innerHTML" not in source

    response = client.get(f"/{ADMIN_DASHBOARD_ASSET}")
    assert response.status_code == 200
    assert response.content == asset_path.read_bytes()

    completed = subprocess.run(  # noqa: S603 - fixed repository test helper
        ["node", str(ADMIN_DASHBOARD_XSS_ORACLE), str(asset_path)],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
    )
    rendered = json.loads(completed.stdout)

    assert rendered["executedGlobals"] == []
    assert not ({"SCRIPT", "IMG", "SVG", "IFRAME", "MATH"} & set(rendered["users"]["tags"]))
    assert not ({"SCRIPT", "IMG", "SVG", "IFRAME", "MATH"} & set(rendered["audit"]["tags"]))
    assert '<svg onload="globalThis.emailXss=1">' in rendered["users"]["texts"]
    assert "<script>globalThis.nameXss=1</script>" in rendered["users"]["texts"]
    assert '<img src=x onerror="globalThis.userIdXss=1">' in rendered["users"]["texts"]
    assert any(
        "roleServiceXss" in text and "roleNameXss" in text for text in rendered["users"]["texts"]
    )
    assert any(
        "roleIdXss" in value for data in rendered["users"]["datasets"] for value in data.values()
    )
    assert '<img src=x onerror="globalThis.eventXss=1">' in rendered["audit"]["texts"]
    assert any("outcomeXss" in text and "reasonXss" in text for text in rendered["audit"]["texts"])
    assert '<iframe src="javascript:globalThis.auditUserXss=1">' in rendered["audit"]["texts"]
    assert '<img src=x onerror="globalThis.targetXss=1">' in rendered["audit"]["texts"]


@pytest.mark.parametrize("path", ["/assets", "/ASSETS"])
def test_asset_mount_root_matches_express_case_preserving_redirect(
    client: TestClient, path: str
) -> None:
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == f"{path}/"
    assert response.headers["content-type"] == "text/html; charset=UTF-8"
    assert response.headers["content-security-policy"] == "default-src 'none'"
    assert response.text == (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        "<title>Redirecting</title>\n"
        "</head>\n"
        "<body>\n"
        f"<pre>Redirecting to {path}/</pre>\n"
        "</body>\n"
        "</html>\n"
    )
    assert client.head(path, follow_redirects=False).status_code == 301
    assert client.get(f"{path}/").status_code == 404


@pytest.mark.parametrize(
    "path",
    ["/HEALTHZ", "/healthz/", "/.WELL-KNOWN/JWKS.JSON", "/login/", "/MANAGE/DASHBOARD"],
)
def test_known_public_paths_match_express_case_and_trailing_slash_behavior(
    client: TestClient, path: str
) -> None:
    assert client.get(path).status_code == 200


@pytest.mark.parametrize(
    "path",
    [
        "/healthz",
        "/readyz",
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/login",
        "/admin/dashboard",
        "/assets/auth.css",
    ],
)
def test_head_matches_express_get_route_behavior(client: TestClient, path: str) -> None:
    response = client.head(path)
    assert response.status_code == 200
    assert response.content == b""


def test_errors_never_expose_fastapi_or_exception_details(client: TestClient) -> None:
    expected_not_found = {"error": {"code": "NOT_FOUND", "message": "Route not found"}}
    for method, path in (
        ("GET", "/__missing__"),
        ("POST", "/healthz"),
        ("GET", "/docs"),
        ("GET", "/redoc"),
        ("GET", "/openapi.json"),
        ("GET", "/assets/missing.css"),
        ("GET", "/assets/auth.css/"),
        ("GET", "/\u017fignup"),
        ("GET", "/a\u017f\u017fets/auth.css"),
        ("GET", "/%68ealthz"),
        ("GET", "/%2e%77ell-known/jwks.json"),
        ("GET", "/%61ssets/auth.css"),
    ):
        response = client.request(method, path)
        assert response.status_code == 404
        assert response.json() == expected_not_found
        assert response.headers["content-type"] == "application/json; charset=utf-8"

    invalid = client.post("/__phase3_validation_probe__", json={"value": "not-an-int"})
    assert invalid.status_code == 400
    assert invalid.json() == {"error": {"code": "INVALID_REQUEST", "message": "Invalid request"}}
    assert "detail" not in invalid.text

    malformed = client.post(
        "/__phase3_validation_probe__",
        content=b'{"value":',
        headers={"content-type": "application/json"},
    )
    assert malformed.status_code == 500
    assert malformed.json()["error"]["code"] == "INTERNAL_SERVER_ERROR"

    public = client.get("/__phase3_public_error__")
    assert public.status_code == 409
    assert public.json() == {"error": {"code": "PHASE3_CONFLICT", "message": "Phase 3 conflict"}}

    unhandled = client.get("/__phase3_unhandled__")
    assert unhandled.status_code == 500
    assert unhandled.json() == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "Internal server error",
        }
    }
    assert "must never be public" not in unhandled.text


def test_security_headers_cover_success_client_error_and_server_error(
    client: TestClient,
) -> None:
    for path in ("/healthz", "/__missing__", "/__phase3_unhandled__"):
        response = client.get(path)
        for name, value in SECURITY_HEADERS.items():
            assert response.headers[name] == value


def test_cors_allowlist_allows_configured_origin_without_enabling_credentials(
    client: TestClient,
    synthetic_settings: Settings,
) -> None:
    allowed_origin = synthetic_settings.cors_allowed_origins[0]
    allowed = client.get("/healthz", headers={"origin": allowed_origin})
    assert allowed.headers["access-control-allow-origin"] == allowed_origin
    assert "origin" in allowed.headers["vary"].lower()
    assert "access-control-allow-credentials" not in allowed.headers

    denied = client.get("/healthz", headers={"origin": "https://evil.invalid"})
    assert denied.status_code == 200
    assert "access-control-allow-origin" not in denied.headers

    preflight = client.options(
        "/healthz",
        headers={
            "origin": allowed_origin,
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization,content-type",
        },
    )
    assert preflight.status_code == 204
    assert preflight.content == b""
    assert preflight.headers["access-control-allow-origin"] == allowed_origin
    assert preflight.headers["access-control-allow-headers"] == "authorization,content-type"

    origin_only_options = client.options("/healthz", headers={"origin": allowed_origin})
    assert origin_only_options.status_code == 204
    assert origin_only_options.content == b""
    assert origin_only_options.headers["content-length"] == "0"
    assert origin_only_options.headers["access-control-allow-origin"] == allowed_origin
    assert origin_only_options.headers["access-control-allow-methods"] == (
        "GET,HEAD,PUT,PATCH,POST,DELETE"
    )


def test_forwarded_headers_are_not_interpreted_inside_the_application(
    synthetic_settings: Settings,
) -> None:
    application = create_app(settings=synthetic_settings, readiness_check=lambda: True)

    @application.get("/__phase3_client__")
    async def client_address(request: Request) -> dict[str, str | None]:
        return {"client": request.client.host if request.client else None}

    with TestClient(application) as test_client:
        response = test_client.get(
            "/__phase3_client__",
            headers={"x-forwarded-for": "203.0.113.10"},
        )
    assert response.json() == {"client": "testclient"}


def test_runtime_explicitly_disables_proxy_header_interpretation() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--no-proxy-headers"' in dockerfile
    assert '"--no-server-header"' in dockerfile
    assert '"--no-access-log"' in dockerfile


def test_stream_failure_after_response_start_is_observed_as_aborted(
    synthetic_settings: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    logger = RecordingLogger()
    application = create_app(
        settings=synthetic_settings,
        readiness_check=lambda: True,
        request_logger=logger,
    )

    async def broken_stream() -> AsyncIterator[bytes]:
        yield b"partial"
        raise RuntimeError("stream detail must remain private")

    @application.get("/__phase3_broken_stream__")
    async def stream_failure() -> StreamingResponse:
        return StreamingResponse(broken_stream())

    with TestClient(application, raise_server_exceptions=False) as test_client:
        response = test_client.get("/__phase3_broken_stream__")

    assert response.status_code == 200
    assert response.content in {b"", b"partial"}
    observations = [values for event, values in logger.records if event == "http_request_observed"]
    assert len(observations) == 1
    assert observations[0]["outcome"] == "aborted"
    assert set(observations[0]) == {
        "metric",
        "backend",
        "version",
        "method",
        "route",
        "outcome",
        "latencyMs",
    }
    diagnostic = capsys.readouterr().err
    assert '"event":"unhandled_request_error"' in diagnostic
    assert '"error_type":"RuntimeError"' in diagnostic
    assert "stream detail must remain private" not in diagnostic


def test_metric_route_uses_express_original_url_semantics(
    synthetic_settings: Settings,
) -> None:
    logger = RecordingLogger()
    application = create_app(
        settings=synthetic_settings,
        readiness_check=lambda: True,
        request_logger=logger,
    )
    with TestClient(application) as test_client:
        for path in (
            "/healthz",
            "/HEALTHZ",
            "/healthz/",
            "/ASSETS/auth.css",
            "/assets/%61uth.css",
        ):
            assert test_client.get(path).status_code == 200

    observed_routes = [
        values["route"] for event, values in logger.records if event == "http_request_observed"
    ]
    assert observed_routes == [
        "/healthz",
        "unmatched",
        "unmatched",
        "unmatched",
        "/assets/*",
    ]


def test_real_uvicorn_boundary_redacts_query_and_stream_exception(
    tmp_path: Path,
) -> None:
    probe_module = tmp_path / "phase3_uvicorn_probe.py"
    probe_module.write_text(
        """
from collections.abc import AsyncIterator
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from wiseacct_sso.api.middleware import GenericErrorMiddleware, RequestInstrumentationMiddleware
from wiseacct_sso.logging import configure_logging

configure_logging()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@app.get('/healthz')
async def healthz() -> dict[str, str]:
    return {'status': 'ok'}

@app.get('/broken')
async def broken(request: Request) -> StreamingResponse:
    secret = request.query_params.get('token', 'missing')
    async def body() -> AsyncIterator[bytes]:
        yield b'partial'
        raise RuntimeError(secret)
    return StreamingResponse(body())

app.add_middleware(GenericErrorMiddleware)
app.add_middleware(RequestInstrumentationMiddleware, on_delivery_failure=lambda: None)
""".lstrip(),
        encoding="utf-8",
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    environment = os.environ.copy()
    source_path = str(ROOT / "src")
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{source_path}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else source_path
    )
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "phase3_uvicorn_probe:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-access-log",
            "--no-server-header",
            "--no-proxy-headers",
        ],
        cwd=tmp_path,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    logs = ""
    secret = "phase3-query-secret-must-not-appear"
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("Uvicorn probe exited before becoming ready")
            try:
                if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.2).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.05)
        else:
            raise AssertionError("Uvicorn probe did not become ready")

        try:
            httpx.get(
                f"http://127.0.0.1:{port}/broken",
                params={"token": secret},
                timeout=2,
            )
        except httpx.HTTPError:
            pass
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        logs = f"{stdout}\n{stderr}"

    assert secret not in logs
    assert "Response stream aborted" in logs
    assert '"outcome": "aborted"' in logs
