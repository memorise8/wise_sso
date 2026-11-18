"""Opt-in OIDC boundary outside the legacy Express compatibility middleware."""

import re
from collections.abc import Awaitable, Callable

import structlog
from starlette.responses import HTMLResponse, JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from wiseacct_sso.api.middleware import safe_log

OidcRateCheck = Callable[[str, str], Awaitable[bool]]


def _admin_page(path: str) -> bool:
    return (
        path == "/oauth2/admin/dashboard"
        or re.fullmatch(r"/oauth2/admin/users/[^/]+", path) is not None
    )


def is_admin_read_request(path: str, method: str) -> bool:
    return method in {"GET", "HEAD"} and (
        _admin_page(path) or path.startswith("/oauth2/admin/api/")
    )


class OidcDispatchMiddleware:
    """Dispatch only the new, case-sensitive namespace; preserve every legacy request."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        oidc_app: ASGIApp,
        rate_check: OidcRateCheck | None = None,
        admin_read_rate_check: OidcRateCheck | None = None,
    ) -> None:
        self.app = app
        self.oidc_app = oidc_app
        self.rate_check = rate_check
        self.admin_read_rate_check = admin_read_rate_check

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and (path == "/oauth2" or path.startswith("/oauth2/")):
            rate_check = self.rate_check
            if self.admin_read_rate_check is not None and is_admin_read_request(
                path, scope.get("method", "")
            ):
                rate_check = self.admin_read_rate_check
            if rate_check is not None:
                peer = scope.get("client")
                address = str(peer[0]) if peer else "unknown"
                try:
                    allowed = await rate_check(path, address)
                except Exception as error:
                    safe_log(
                        structlog.get_logger(),
                        "warning",
                        "oidc_rate_store_failure",
                        lambda: None,
                        error_type=type(error).__name__[:64],
                    )
                    await self._error(scope, receive, send, 503, "temporarily_unavailable")
                    return
                if not allowed:
                    await self._error(scope, receive, send, 429, "slow_down")
                    return
            await self.oidc_app(scope, receive, send)
            return
        await self.app(scope, receive, send)

    @staticmethod
    async def _error(scope: Scope, receive: Receive, send: Send, status: int, error: str) -> None:
        headers = {"cache-control": "no-store", "pragma": "no-cache"}
        if status == 429:
            headers["retry-after"] = "60"
        browser_page = (
            _admin_page(scope.get("path", "")) or scope.get("path") == "/oauth2/admin/login"
        )
        accepts_html = any(
            name.lower() == b"accept" and b"text/html" in value.lower()
            for name, value in scope.get("headers", [])
        )
        if (
            status == 429
            and browser_page
            and accepts_html
            and scope.get("method") in {"GET", "HEAD"}
        ):
            document = (
                '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                "<title>잠시 후 다시 시도해 주세요</title></head><body>"
                "<h1>잠시 후 다시 시도해 주세요</h1>"
                "<p>요청이 잠시 몰렸습니다. 60초 후 다시 접속해 주세요.</p>"
                '<a href="/oauth2/admin/dashboard">대시보드로 돌아가기</a>'
                "</body></html>"
            )
            await HTMLResponse(document, status_code=status, headers=headers)(scope, receive, send)
            return
        await JSONResponse({"error": error}, status_code=status, headers=headers)(
            scope, receive, send
        )
