import base64
import binascii
import json
import re
import sys
import time
import zlib
from collections.abc import Callable, Iterable
from typing import Literal, Protocol
from urllib.parse import unquote
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
    "/auth/exchange",
    "/auth/password-reset/request",
    "/auth/password-reset/confirm",
    "/auth/email-verification/request",
    "/auth/email-verification/confirm",
    "/auth/google",
    "/auth/google/callback",
    "/auth/naver",
    "/auth/naver/callback",
    "/auth/kakao",
    "/auth/kakao/callback",
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


def _decode_imap_utf7(body: bytes) -> str:
    source = body.decode("ascii")
    decoded: list[str] = []
    cursor = 0
    while cursor < len(source):
        marker = source.find("&", cursor)
        if marker < 0:
            decoded.append(source[cursor:])
            break
        decoded.append(source[cursor:marker])
        end = source.find("-", marker)
        if end < 0:
            raise UnicodeError("unterminated modified UTF-7 sequence")
        payload = source[marker + 1 : end]
        if not payload:
            decoded.append("&")
        else:
            padding = "=" * (-len(payload) % 4)
            try:
                raw = base64.b64decode(payload.replace(",", "/") + padding, validate=True)
                decoded.append(raw.decode("utf-16-be", errors="replace"))
            except (binascii.Error, UnicodeError) as error:
                raise UnicodeError("invalid modified UTF-7 sequence") from error
        cursor = end + 1
    return "".join(decoded)


def _decode_json_body(body: bytes, charset: str) -> str:
    normalized = charset.replace("_", "-")
    if not normalized.startswith("utf-"):
        raise UnsupportedJsonCharset(charset)
    if normalized == "utf-7":
        return body.decode("utf-7", errors="replace")
    if normalized == "utf-7-imap":
        return _decode_imap_utf7(body)
    if normalized == "utf-8":
        return body.decode("utf-8", errors="replace")
    if normalized in {"utf-16le", "utf-16-le"}:
        return body.decode("utf-16-le", errors="replace")
    if normalized in {"utf-16be", "utf-16-be"}:
        return body.decode("utf-16-be", errors="replace")
    if normalized == "utf-16":
        if body.startswith((b"\xff\xfe", b"\xfe\xff")):
            return body.decode("utf-16", errors="replace")
        codec = "utf-16-be" if body.startswith(b"\x00") else "utf-16-le"
        return body.decode(codec, errors="replace")
    raise UnsupportedJsonCharset(charset)


_CANONICAL_PUBLIC_ROUTES = {_ascii_lower(path): path for path in _PUBLIC_ROUTES}
_ADMIN_ROUTE_PATTERNS = (
    re.compile(r"^/(?P<prefix>admin|manage-api)/(?P<route>users|audit-logs)/?$", re.IGNORECASE),
    re.compile(
        r"^/(?P<prefix>admin|manage-api)/users/(?P<id>[^/]+)/"
        r"(?P<route>status|roles|revoke-sessions)/?$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^/(?P<prefix>admin|manage-api)/users/(?P<id>[^/]+)/roles/"
        r"(?P<role_id>[^/]+)/?$",
        re.IGNORECASE,
    ),
)
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
_RATE_LIMITED_AUTH_ROUTES = {
    ("POST", "/auth/register"),
    ("POST", "/auth/login"),
    ("POST", "/auth/refresh"),
    ("POST", "/auth/logout"),
    ("POST", "/auth/exchange"),
    ("POST", "/auth/password-reset/request"),
    ("POST", "/auth/password-reset/confirm"),
    ("POST", "/auth/email-verification/request"),
    ("POST", "/auth/email-verification/confirm"),
    ("GET", "/auth/google"),
    ("HEAD", "/auth/google"),
    ("GET", "/auth/google/callback"),
    ("HEAD", "/auth/google/callback"),
    ("GET", "/auth/naver"),
    ("HEAD", "/auth/naver"),
    ("GET", "/auth/naver/callback"),
    ("HEAD", "/auth/naver/callback"),
    ("GET", "/auth/kakao"),
    ("HEAD", "/auth/kakao"),
    ("GET", "/auth/kakao/callback"),
    ("HEAD", "/auth/kakao/callback"),
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
    admin_route = _canonical_admin_path(path, parameter_labels=True)
    if admin_route is not None:
        return admin_route
    return "unmatched"


def _canonical_admin_path(path: str, *, parameter_labels: bool = False) -> str | None:
    for index, pattern in enumerate(_ADMIN_ROUTE_PATTERNS):
        match = pattern.fullmatch(path)
        if match is None:
            continue
        prefix = _ascii_lower(match.group("prefix"))
        if index == 0:
            route = _ascii_lower(match.group("route"))
            return f"/{prefix}/{route}"
        identifier = ":id" if parameter_labels else match.group("id")
        if index == 1:
            route = _ascii_lower(match.group("route"))
            return f"/{prefix}/users/{identifier}/{route}"
        role_id = ":roleId" if parameter_labels else match.group("role_id")
        return f"/{prefix}/users/{identifier}/roles/{role_id}"
    return None


def _decoded_admin_raw_parameters(path: str) -> dict[str, str]:
    for pattern in _ADMIN_ROUTE_PATTERNS[1:]:
        match = pattern.fullmatch(path)
        if match is None:
            continue
        parameters = {"id": unquote(match.group("id"), errors="replace")}
        role_id = match.groupdict().get("role_id")
        if role_id is not None:
            parameters["roleId"] = unquote(role_id, errors="replace")
        return parameters
    return {}


def _is_admin_mutation(path: str, method: str) -> bool:
    canonical = _canonical_admin_path(path)
    if canonical is None:
        return False
    return (
        (method == "PATCH" and canonical.endswith("/status"))
        or (method == "POST" and canonical.endswith(("/roles", "/revoke-sessions")))
        or (method == "DELETE" and "/roles/" in canonical)
    )


async def _empty_body_receive(receive: Receive) -> Receive:
    while True:
        message = await receive()
        if message["type"] != "http.request" or not message.get("more_body", False):
            break
    emitted = False

    async def empty_receive() -> Message:
        nonlocal emitted
        if not emitted:
            emitted = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return await receive()

    return empty_receive


class JsonBodyTooLarge(ValueError):
    pass


def _inflate_json_body(body: bytes, content_encoding: str) -> bytes:
    if content_encoding == "identity":
        return body
    if content_encoding == "gzip":
        window_bits = zlib.MAX_WBITS | 16
    elif content_encoding == "deflate":
        window_bits = zlib.MAX_WBITS
    else:
        raise UnsupportedJsonCharset(content_encoding)

    remaining = body
    chunks: list[bytes] = []
    inflated_size = 0
    while remaining:
        decoder = zlib.decompressobj(window_bits)
        chunk = decoder.decompress(
            remaining,
            (_EXPRESS_JSON_LIMIT_BYTES - inflated_size) + 1,
        )
        if decoder.unconsumed_tail:
            raise JsonBodyTooLarge
        chunk += decoder.flush()
        if not decoder.eof:
            raise zlib.error("incomplete compressed body")
        inflated_size += len(chunk)
        if inflated_size > _EXPRESS_JSON_LIMIT_BYTES:
            raise JsonBodyTooLarge
        chunks.append(chunk)
        if content_encoding != "gzip" or not decoder.unused_data:
            break
        remaining = decoder.unused_data
    return b"".join(chunks)


async def _json_parser_error(
    scope: Scope,
    receive: Receive,
    send: Send,
) -> None:
    await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
        scope, receive, send
    )


async def _express_json_receive(
    scope: Scope,
    receive: Receive,
    send: Send,
) -> tuple[Receive, bool]:
    """Buffer and classify a JSON body like the app-level Express parser."""

    headers = Headers(scope=scope)
    content_type = headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        return receive, True

    content_encoding = headers.get("content-encoding", "identity").lower()
    if content_encoding not in {"identity", "gzip", "deflate"}:
        await _json_parser_error(scope, receive, send)
        return receive, False

    content_length = headers.get("content-length")
    if content_encoding == "identity" and content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError:
            declared_length = 0
        if declared_length > _EXPRESS_JSON_LIMIT_BYTES:
            await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
                scope, receive, send
            )
            return receive, False

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
        if content_encoding == "identity" and len(body) + len(chunk) > _EXPRESS_JSON_LIMIT_BYTES:
            await _json_parser_error(scope, receive, send)
            return receive, False
        body.extend(chunk)
        if not message.get("more_body", False):
            break

    replay_messages = messages
    classified_body = bytes(body)
    if not disconnected and body:
        try:
            classified_body = _inflate_json_body(classified_body, content_encoding)
        except (JsonBodyTooLarge, UnsupportedJsonCharset, zlib.error):
            await _json_parser_error(scope, receive, send)
            return receive, False

    replay_index = 0

    async def replay_receive() -> Message:
        nonlocal replay_index
        if replay_index < len(replay_messages):
            message = replay_messages[replay_index]
            replay_index += 1
            return message
        return await receive()

    if disconnected or not body:
        return replay_receive, True
    try:
        classification_text = _decode_json_body(classified_body, _json_charset(content_type))
    except UnsupportedJsonCharset:
        await error_response(500, "INTERNAL_SERVER_ERROR", "Internal server error")(
            scope, receive, send
        )
        return replay_receive, False
    except UnicodeError:
        await _json_parser_error(scope, receive, send)
        return replay_receive, False
    if classification_text.startswith("\ufeff"):
        classification_text = classification_text[1:]
    stripped_text = classification_text.lstrip()
    if not stripped_text or stripped_text[0] not in "{[":
        await _json_parser_error(scope, receive, send)
        return replay_receive, False
    try:
        json.loads(classification_text, parse_constant=_reject_json_constant)
    except ValueError:
        await _json_parser_error(scope, receive, send)
        return replay_receive, False
    replay_messages = [
        {
            "type": "http.request",
            "body": classification_text.encode("utf-8"),
            "more_body": False,
        }
    ]
    scope["headers"] = [
        (name, value)
        for name, value in scope.get("headers", [])
        if name.lower() not in {b"content-encoding", b"content-length"}
    ]
    scope.setdefault("state", {})["express_json_validated"] = True
    return replay_receive, True


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
            state = scope.setdefault("state", {})
            state["express_original_path"] = raw_path
            state["express_original_decoded_path"] = path
            admin_mutation = _is_admin_mutation(raw_path, scope.get("method", ""))
            headers = Headers(scope=scope)
            media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if admin_mutation and media_type != "application/json":
                receive = await _empty_body_receive(receive)
            if not state.get("express_json_validated", False):
                receive, valid_json = await _express_json_receive(
                    scope,
                    receive,
                    send,
                )
                if not valid_json:
                    return
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
            elif _canonical_admin_path(raw_candidate) is not None and (
                (admin_path := _canonical_admin_path(decoded_candidate)) is not None
                or (admin_path := _canonical_admin_path(raw_candidate)) is not None
            ):
                state["express_admin_path_params"] = _decoded_admin_raw_parameters(raw_candidate)
                scope["path"] = admin_path
                scope["raw_path"] = admin_path.encode("utf-8")
            elif _ascii_lower(raw_path).startswith("/assets/"):
                scope["path"] = f"/assets/{path[len('/assets/') :]}"
                scope["raw_path"] = scope["path"].encode("utf-8")
            elif (
                _CANONICAL_PUBLIC_ROUTES.get(_ascii_lower(decoded_candidate)) is not None
                or _ascii_lower(path).startswith("/assets/")
                or _canonical_admin_path(decoded_candidate) is not None
            ):
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
        method = scope.get("method", "")
        if (method, canonical) not in _RATE_LIMITED_AUTH_ROUTES:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        receive_for_app = receive
        receive_for_app, valid_json = await _express_json_receive(scope, receive, send)
        if not valid_json:
            return

        forwarded = headers.get("x-forwarded-for")
        forwarded_address = forwarded.split(",", 1)[0].strip() if forwarded else None
        client = scope.get("client")
        client_address = client[0] if client is not None else "unknown"
        retry_after = await self.services.enforce_rate_limit(
            client_key=client_address,
            route=raw_path,
            method=method,
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
