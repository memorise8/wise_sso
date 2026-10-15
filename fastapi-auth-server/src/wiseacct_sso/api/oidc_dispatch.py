"""Opt-in OIDC boundary outside the legacy Express compatibility middleware."""

from collections.abc import Awaitable, Callable

import structlog
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from wiseacct_sso.api.middleware import safe_log

OidcRateCheck = Callable[[str, str], Awaitable[bool]]


class OidcDispatchMiddleware:
    """Dispatch only the new, case-sensitive namespace; preserve every legacy request."""

    def __init__(
        self, app: ASGIApp, *, oidc_app: ASGIApp, rate_check: OidcRateCheck | None = None
    ) -> None:
        self.app = app
        self.oidc_app = oidc_app
        self.rate_check = rate_check

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and (path == "/oauth2" or path.startswith("/oauth2/")):
            if self.rate_check is not None:
                peer = scope.get("client")
                address = str(peer[0]) if peer else "unknown"
                try:
                    allowed = await self.rate_check(path, address)
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
        await JSONResponse({"error": error}, status_code=status, headers=headers)(
            scope, receive, send
        )
