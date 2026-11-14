import inspect
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urljoin

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.datastructures import Headers

from wiseacct_sso.api.staticfiles import conditional_file_response
from wiseacct_sso.config import Settings

ReadinessCheck = Callable[[], bool | Awaitable[bool]]
PUBLIC_METADATA_CACHE_CONTROL = "public, max-age=300"
HTML_CACHE_CONTROL = "public, max-age=0"
ACCESS_TOKEN_CLAIMS = (
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
)
PORTAL_PATHS = ("/", "/login", "/signup", "/auth/callback", "/password-reset", "/verify-email")
PORTAL_ENTRY_PATHS = ("/", "/login", "/signup")
DASHBOARD_PATHS = ("/admin/dashboard", "/manage/dashboard")


def build_system_router(
    *,
    settings: Settings,
    readiness_check: ReadinessCheck,
    static_root: Path,
    on_readiness_error: Callable[[Exception], None],
) -> APIRouter:
    router = APIRouter()

    @router.api_route("/healthz", methods=["GET", "HEAD"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @router.api_route("/readyz", methods=["GET", "HEAD"])
    async def readyz(response: Response) -> dict[str, str]:
        try:
            result = readiness_check()
            is_ready = await result if inspect.isawaitable(result) else result
        except Exception as error:
            is_ready = False
            on_readiness_error(error)
        if not is_ready:
            response.status_code = 503
            return {"status": "unavailable"}
        return {"status": "ok"}

    @router.api_route("/.well-known/jwks.json", methods=["GET", "HEAD"])
    async def jwks(response: Response) -> dict[str, object]:
        response.headers["cache-control"] = PUBLIC_METADATA_CACHE_CONTROL
        return {"keys": [settings.jwt_access_public_jwk.model_dump()]}

    @router.api_route("/.well-known/openid-configuration", methods=["GET", "HEAD"])
    async def openid_configuration(response: Response) -> dict[str, object]:
        response.headers["cache-control"] = PUBLIC_METADATA_CACHE_CONTROL
        return {
            "issuer": settings.jwt_issuer,
            "jwks_uri": urljoin(settings.jwt_issuer, "/.well-known/jwks.json"),
            "subject_types_supported": ["public"],
            "response_types_supported": ["code"],
            "claims_supported": list(ACCESS_TOKEN_CLAIMS),
        }

    def html_response(filename: str, request: Request) -> Response:
        if filename == "auth-portal.html":
            page = (static_root / filename).read_text()
            for provider in ("naver", "kakao"):
                client_key = (
                    settings.naver_client_id if provider == "naver" else settings.kakao_client_id
                )
                secret = getattr(settings, f"{provider}_client_secret")
                if provider not in settings.oauth_enabled_providers or not client_key or not secret:
                    page = re.sub(
                        rf'<a\b[^>]*href="/auth/{provider}"[^>]*>.*?</a>',
                        "",
                        page,
                        flags=re.DOTALL,
                    )
            return HTMLResponse(page, headers={"cache-control": "no-store"})
        return conditional_file_response(
            static_root / filename,
            request_headers=Headers(scope=request.scope),
            media_type="text/html",
            cache_control=HTML_CACHE_CONTROL,
        )

    def html_endpoint(filename: str) -> Callable[[Request], Response]:
        def endpoint(request: Request) -> Response:
            return html_response(filename, request)

        return endpoint

    def portal_entry(request: Request) -> Response:
        # Opened directly, the portal would silently sign people into TEMIS from the
        # SSO domain. Send them to the service instead, which starts a proper handoff.
        if settings.portal_entry_url and "client_id" not in request.query_params:
            return RedirectResponse(
                settings.portal_entry_url, 303, headers={"cache-control": "no-store"}
            )
        return html_response("auth-portal.html", request)

    for path in PORTAL_PATHS:
        router.add_api_route(
            path,
            portal_entry if path in PORTAL_ENTRY_PATHS else html_endpoint("auth-portal.html"),
            methods=["GET", "HEAD"],
            include_in_schema=False,
        )

    def admin_dashboard(request: Request) -> Response:
        if settings.oidc_enabled and settings.oidc_public_origin:
            return RedirectResponse(
                settings.oidc_public_origin + "/oauth2/admin/dashboard",
                303,
                headers={"cache-control": "no-store"},
            )
        return html_response("admin-dashboard.html", request)

    for path in DASHBOARD_PATHS:
        router.add_api_route(
            path,
            admin_dashboard,
            methods=["GET", "HEAD"],
            include_in_schema=False,
        )

    return router
