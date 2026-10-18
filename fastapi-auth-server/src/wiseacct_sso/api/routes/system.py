import inspect
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urljoin

from fastapi import APIRouter, Request, Response
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

    for path in PORTAL_PATHS:
        router.add_api_route(
            path,
            html_endpoint("auth-portal.html"),
            methods=["GET", "HEAD"],
            include_in_schema=False,
        )
    for path in DASHBOARD_PATHS:
        router.add_api_route(
            path,
            html_endpoint("admin-dashboard.html"),
            methods=["GET", "HEAD"],
            include_in_schema=False,
        )

    return router
