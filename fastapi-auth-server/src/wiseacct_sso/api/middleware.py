import json
import re
import sys
import time
from collections.abc import Callable, Iterable
from typing import Literal, Protocol
from uuid import uuid4

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from wiseacct_sso import __version__
from wiseacct_sso.api.dependencies import Phase4Services
from wiseacct_sso.api.errors import error_response
from wiseacct_sso.application.auth import RequestAuditContext

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_KNOWN_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
_PUBLIC_ROUTES = {
    "/",
    "/healthz",
    "/readyz",
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/login",
    "/signup",
    "/auth/callback",
    "/password-reset",
    "/verify-email",
    "/admin/dashboard",
    "/manage/dashboard",
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/auth/logout",
    "/users/me",
}
_ASCII_LOWER_TRANSLATION = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _ascii_lower(value: str) -> str:
    return value.translate(_ASCII_LOWER_TRANSLATION)


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _json_charset(content_type: str) -> str:
    for parameter in content_type.split(";")[1:]:
        name, separator, value = parameter.partition("=")
        if separator and name.strip().lower() == "charset":
            return value.strip().strip('"').lower()
    return "utf-8"


class UnsupportedJsonCharset(UnicodeError):
    def __init__(self, charset: str) -> None:
        super().__init__(charset)
        self.charset = charset


def _decode_json_body(body: bytes, charset: str) -> str:
    normalized = charset.replace("_", "-")
    if normalized == "utf-8":
        return body.decode("utf-8")
    if normalized in {"utf-16le", "utf-16-le"}:
        return body.decode("utf-16-le")
    if normalized in {"utf-16be", "utf-16-be"}:
        return body.decode("utf-16-be")
    if normalized == "utf-16":
        if body.startswith((b"\xff\xfe", b"\xfe\xff")):
            return body.decode("utf-16")
        codec = "utf-16-be" if body.startswith(b"\x00") else "utf-16-le"
        return body.decode(codec)
    raise UnsupportedJsonCharset(charset)


_CANONICAL_PUBLIC_ROUTES = {_ascii_lower(path): path for path in _PUBLIC_ROUTES}
_SECURITY_HEADERS = {
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
_ASSET_REDIRECT_MARKER = "x-wiseacct-internal-asset-redirect"
_EXPRESS_JSON_LIMIT_BYTES = 100 * 1024
_PHASE4_AUTH_ROUTES = {
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/auth/logout",
}


class SanitizedResponseAbort(RuntimeError):
    """Fixed-detail exception safe for the outer ASGI server error logger."""


class RequestLogger(Protocol):
    def info(self, event: str, **event_kw: object) -> object: ...

    def warning(self, event: str, **event_kw: object) -> object: ...


def request_id(value: str | None) -> str:
    return value if value is not None and _REQUEST_ID.fullmatch(value) else str(uuid4())


def normalized_route(path: str) -> str:
    if path in _PUBLIC_ROUTES:
        return path
    if path.startswith("/assets/"):
        return "/assets/*"
    return "unmatched"


StatusOutcome = Literal["1xx", "2xx", "3xx", "4xx", "5xx"]
RequestOutcome = Literal["1xx", "2xx", "3xx", "4xx", "5xx", "aborted"]


def outcome(status_code: int) -> StatusOutcome:
    return f"{min(max(status_code // 100, 1), 5)}xx"  # type: ignore[return-value]


def safe_log(
    logger: RequestLogger,
    log_method: Literal["info", "warning"],
    event: str,
    on_failure: Callable[[], None],
    **values: object,
) -> None:
    try:
        getattr(logger, log_method)(event, **values)
    except Exception as error:
        on_failure()
        record = {
            "event": "telemetry_delivery_failed",
            "failed_event": event[:64],
            "error_type": type(error).__name__[:64],
        }
        try:
            sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
        except Exception:
            return


def _write_diagnostic(record: dict[str, str]) -> None:
    try:
        sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        return


class KnownPathCompatibilityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            path = scope.get("path", "")
            raw_path_value = scope.get("raw_path")
            if isinstance(raw_path_value, bytes):
                raw_path = raw_path_value.decode("ascii", errors="surrogateescape")
            else:
                raw_path = path
            scope.setdefault("state", {})["express_original_path"] = raw_path
            if _ascii_lower(raw_path) == "/assets" and scope.get("method") in {"GET", "HEAD"}:
                location = f"{raw_path}/"
                body = (
                    "<!DOCTYPE html>\n"
                    '<html lang="en">\n'
                    "<head>\n"
                    '<meta charset="utf-8">\n'
                    "<title>Redirecting</title>\n"
                    "</head>\n"
                    "<body>\n"
                    f"<pre>Redirecting to {location}</pre>\n"
                    "</body>\n"
                    "</html>\n"
                )
                response = Response(
                    content=body,
                    status_code=301,
                    headers={
                        "content-type": "text/html; charset=UTF-8",
                        "location": location,
                        _ASSET_REDIRECT_MARKER: "1",
                    },
                )
                await response(scope, receive, send)
                return
            raw_candidate = (
                raw_path[:-1] if len(raw_path) > 1 and raw_path.endswith("/") else raw_path
            )
            decoded_candidate = path[:-1] if len(path) > 1 and path.endswith("/") else path
            canonical = _CANONICAL_PUBLIC_ROUTES.get(_ascii_lower(raw_candidate))
            if canonical is not None:
                scope["path"] = canonical
                scope["raw_path"] = canonical.encode("ascii")
            elif _ascii_lower(raw_path).startswith("/assets/"):
                scope["path"] = f"/assets/{path[len('/assets/') :]}"
                scope["raw_path"] = scope["path"].encode("utf-8")
            elif _CANONICAL_PUBLIC_ROUTES.get(
                _ascii_lower(decoded_candidate)
            ) is not None or _ascii_lower(path).startswith("/assets/"):
                scope["path"] = "/__encoded_public_path_not_found__"
                scope["raw_path"] = b"/__encoded_public_path_not_found__"
        await self.app(scope, receive, send)


class RequestInstrumentationMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        logger: RequestLogger | None = None,
        on_delivery_failure: Callable[[], None],
    ) -> None:
        self.app = app
        self.logger = logger or structlog.get_logger()
        self.on_delivery_failure = on_delivery_failure

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started_at = time.perf_counter()
        headers = Headers(scope=scope)
        current_request_id = request_id(headers.get("x-request-id"))
        scope.setdefault("state", {})["request_id"] = current_request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=current_request_id)
        status_code = 500
        response_started = False
        response_completed = False
        request_aborted = False

        async def send_with_observation(message: Message) -> None:
            nonlocal response_completed, response_started, status_code
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                MutableHeaders(scope=message)["x-request-id"] = current_request_id
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                response_completed = True
            await send(message)

        try:
            await self.app(scope, receive, send_with_observation)
        except Exception:
            request_aborted = True
            raise
        finally:
            method = scope.get("method", "").upper()
            observed_outcome: RequestOutcome = (
                "aborted"
                if request_aborted or (response_started and not response_completed)
                else outcome(status_code)
            )
            safe_log(
                self.logger,
                "info",
                "http_request_observed",
                self.on_delivery_failure,
                metric="sso_http_request",
                backend="fastapi",
                version=__version__,
                method=method if method in _KNOWN_METHODS else "OTHER",
                route=normalized_route(
                    scope.get("state", {}).get("express_original_path", scope.get("path", ""))
                ),
                outcome=observed_outcome,
                latencyMs=max(0.0, (time.perf_counter() - started_at) * 1000),
            )
            structlog.contextvars.clear_contextvars()


class AuthRateLimitMiddleware:
    """Run the Redis auth limiter before FastAPI parses or validates request bodies."""

    def __init__(self, app: ASGIApp, *, services: Phase4Services) -> None:
        self.app = app
        self.services = services

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw_path_value = scope.get("raw_path")
        raw_path = (
            raw_path_value.decode("ascii", errors="surrogateescape")
            if isinstance(raw_path_value, bytes)
            else scope.get("path", "")
        )
        candidate = raw_path[:-1] if len(raw_path) > 1 and raw_path.endswith("/") else raw_path
        canonical = _ascii_lower(candidate)
        if scope.get("method") != "POST" or canonical not in _PHASE4_AUTH_ROUTES:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        receive_for_app = receive
        content_type = headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        is_json = media_type == "application/json"
        if is_json:
            content_length = headers.get("content-length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = 0
                if declared_length > _EXPRESS_JSON_LIMIT_BYTES:
                    await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
                        scope, receive, send
                    )
                    return

            messages: list[Message] = []
            body = bytearray()
            disconnected = False
            while True:
                message = await receive()
                messages.append(message)
                if message["type"] == "http.disconnect":
                    disconnected = True
                    break
                if message["type"] != "http.request":
                    continue
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > _EXPRESS_JSON_LIMIT_BYTES:
                    await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
                        scope, receive, send
                    )
                    return
                body.extend(chunk)
                if not message.get("more_body", False):
                    break

            replay_index = 0

            async def replay_receive() -> Message:
                nonlocal replay_index
                if replay_index < len(messages):
                    message = messages[replay_index]
                    replay_index += 1
                    return message
                return await receive()

            receive_for_app = replay_receive
            if disconnected:
                await self.app(scope, receive_for_app, send)
                return
            if body:
                try:
                    classification_text = _decode_json_body(
                        bytes(body), _json_charset(content_type)
                    )
                except UnsupportedJsonCharset:
                    await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
                        scope, receive, send
                    )
                    return
                except UnicodeError:
                    await error_response(400, "INVALID_REQUEST", "Invalid request")(
                        scope, receive, send
                    )
                    return
                if classification_text.startswith("\ufeff"):
                    classification_text = classification_text[1:]
                stripped_text = classification_text.lstrip()
                if not stripped_text or stripped_text[0] not in "{[":
                    await error_response(400, "INVALID_REQUEST", "Invalid request")(
                        scope, receive, send
                    )
                    return
                try:
                    json.loads(classification_text, parse_constant=_reject_json_constant)
                except ValueError:
                    await error_response(400, "INVALID_REQUEST", "Invalid request")(
                        scope, receive, send
                    )
                    return

        forwarded = headers.get("x-forwarded-for")
        forwarded_address = forwarded.split(",", 1)[0].strip() if forwarded else None
        client = scope.get("client")
        client_address = client[0] if client is not None else "unknown"
        retry_after = await self.services.enforce_rate_limit(
            client_key=client_address,
            route=raw_path,
            method=scope.get("method", ""),
            context=RequestAuditContext(
                ip_address=forwarded_address or client_address,
                user_agent=headers.get("user-agent"),
            ),
        )
        if retry_after is not None:
            response = error_response(429, "RATE_LIMITED", "Too many authentication requests")
            response.headers["retry-after"] = str(retry_after)
            await response(scope, receive, send)
            return
        await self.app(scope, receive_for_app, send)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                asset_redirect = headers.get(_ASSET_REDIRECT_MARKER) == "1"
                if asset_redirect:
                    del headers[_ASSET_REDIRECT_MARKER]
                for name, value in _SECURITY_HEADERS.items():
                    headers[name] = (
                        "default-src 'none'"
                        if asset_redirect and name == "content-security-policy"
                        else value
                    )
            await send(message)

        await self.app(scope, receive, send_with_headers)


class ExpressCorsMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_origins: Iterable[str]) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_headers = Headers(scope=scope)
        origin = request_headers.get("origin")
        allowed_origin = origin if origin in self.allowed_origins else None
        if allowed_origin is not None and scope.get("method") == "OPTIONS":
            headers = {
                "access-control-allow-origin": allowed_origin,
                "access-control-allow-methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
                "content-length": "0",
                "vary": "Origin, Access-Control-Request-Headers",
            }
            requested_headers = request_headers.get("access-control-request-headers")
            if requested_headers:
                headers["access-control-allow-headers"] = requested_headers
            response = Response(status_code=204, headers=headers)
            await response(scope, receive, send)
            return

        async def send_with_cors(message: Message) -> None:
            if allowed_origin is not None and message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["access-control-allow-origin"] = allowed_origin
                headers.add_vary_header("Origin")
            await send(message)

        await self.app(scope, receive, send_with_cors)


class GenericErrorMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response_started = False

        async def track_start(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, track_start)
        except Exception as error:
            record = {
                "event": "unhandled_request_error",
                "error_type": type(error).__name__[:64],
            }
            _write_diagnostic(record)
            if scope["type"] != "http":
                raise
            if response_started:
                raise SanitizedResponseAbort("Response stream aborted") from None
            await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
                scope, receive, send
            )
