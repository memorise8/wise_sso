"""Self-contained OIDC HTTP application dispatched ahead of legacy compatibility middleware."""

from __future__ import annotations

import hashlib
import html
import json
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import NoReturn, Protocol, cast
from urllib.parse import quote, urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHttpException

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
from wiseacct_sso.domain.oauth import OAUTH_PROVIDERS, OAuthProvider
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.oidc_state import provider_state_transaction_id

from .parsing import (
    MAX_FORM_BYTES,
    MAX_QUERY_BYTES,
    ClientAuthenticationError,
    ParseError,
    extract_client_credentials,
    parse_urlencoded,
)

_STATIC_ROOT = Path(__file__).parents[2] / "static" / "oidc"
_COOKIE_MAX_AGE_SECONDS = 600
_COOKIE_PATH = "/oauth2"
_AUTHORIZE_FIELDS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "response_mode",
        "prompt",
    }
)
_TOKEN_FIELDS = frozenset(
    {
        "grant_type",
        "code",
        "redirect_uri",
        "code_verifier",
        "client_id",
        "client_secret",
    }
)


class OidcHttpService(Protocol):
    async def begin_authorization(
        self, request: AuthorizationRequest, context: OidcRequestContext
    ) -> AuthorizationStart: ...

    async def password_login(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        csrf_token: str,
        email: str,
        password: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult: ...

    async def provider_start(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        provider: OAuthProvider,
    ) -> str: ...

    async def provider_callback(
        self,
        *,
        provider: OAuthProvider,
        code: str,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult: ...

    async def provider_error(
        self,
        *,
        provider: OAuthProvider,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> NoReturn: ...

    async def exchange_code(
        self, input: TokenExchangeInput, context: OidcRequestContext
    ) -> TokenResponse: ...

    async def userinfo(self, access_token: str) -> UserInfo: ...


def build_oidc_app(
    *,
    service: OidcHttpService,
    public_origin: str,
    providers: tuple[OAuthProvider, ...] = (),
    static_root: Path | None = None,
) -> FastAPI:
    """Build the full-path OIDC application used by the outer dispatch middleware."""

    origin = _canonical_origin(public_origin)
    if len(set(providers)) != len(providers) or any(
        provider not in OAUTH_PROVIDERS for provider in providers
    ):
        raise ValueError("OIDC providers must be unique supported providers")
    assets = static_root or _STATIC_ROOT
    login_template = (assets / "login.html").read_text(encoding="utf-8")
    login_css = (assets / "login.css").read_bytes()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.middleware("http")
    async def response_policy(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception as error:
            _report_internal_error(error, request)
            response = _oauth_error("server_error", "The request could not be completed", 500)
        response.headers["cache-control"] = "no-store"
        response.headers["pragma"] = "no-cache"
        response.headers["x-content-type-options"] = "nosniff"
        return response

    @app.exception_handler(OidcServiceError)
    async def service_error_handler(request: Request, error: OidcServiceError) -> Response:
        del request
        return _service_error_response(error)

    @app.exception_handler(StarletteHttpException)
    async def http_error_handler(request: Request, error: StarletteHttpException) -> Response:
        del request
        status = error.status_code
        return _oauth_error(
            "invalid_request",
            "The requested OIDC endpoint or method is not available",
            status,
        )

    @app.get("/oauth2/assets/login.css", include_in_schema=False)
    async def login_stylesheet() -> Response:
        return Response(login_css, media_type="text/css; charset=utf-8")

    @app.get("/oauth2/authorize", include_in_schema=False)
    async def authorize(request: Request) -> Response:
        try:
            values = _query(request, allowed=_AUTHORIZE_FIELDS)
            required = _required_fields(
                values, ("response_type", "client_id", "redirect_uri", "scope")
            )
            _bounded(required["response_type"], 32)
            _bounded(required["client_id"], 128)
            _bounded(required["redirect_uri"], 2_048)
            _bounded(required["scope"], 1_024)
            state = _optional_bounded(values, "state", 512)
            nonce = _optional_bounded(values, "nonce", 512)
            challenge = _optional_bounded(values, "code_challenge", 128)
            challenge_method = _optional_bounded(values, "code_challenge_method", 16)
            prompt = _optional_bounded(values, "prompt", 64)
            response_mode = _optional_bounded(values, "response_mode", 16)
            if response_mode not in (None, "query"):
                raise ParseError("unsupported response mode")
            start = await service.begin_authorization(
                AuthorizationRequest(
                    client_id=required["client_id"],
                    redirect_uri=required["redirect_uri"],
                    response_type=required["response_type"],
                    scopes=tuple(required["scope"].split()),
                    state=state,
                    nonce=nonce,
                    code_challenge=challenge,
                    code_challenge_method=challenge_method,
                    prompt=prompt,
                ),
                _context(request),
            )
        except ParseError:
            return _oauth_error("invalid_request", "Invalid authorization request", 400)
        except OidcServiceError as error:
            return _service_error_response(error)
        response = RedirectResponse(
            f"/oauth2/login?{urlencode({'transaction': start.transaction_id})}",
            status_code=303,
        )
        _set_transaction_cookies(response, start)
        return response

    @app.get("/oauth2/login", include_in_schema=False)
    async def login_page(request: Request) -> Response:
        try:
            values = _query(request, allowed=frozenset({"transaction"}))
            transaction = _required_fields(values, ("transaction",))["transaction"]
            _bounded(transaction, 512)
            binding, csrf = _transaction_cookies(request, transaction)
            if not binding or not csrf:
                raise ParseError("missing transaction cookie")
        except ParseError:
            return _login_error_page("로그인 요청이 만료되었거나 올바르지 않습니다.", 400)
        return _render_login(login_template, transaction, csrf, providers=providers)

    @app.post("/oauth2/login", include_in_schema=False)
    async def password_login(request: Request) -> Response:
        transaction: str | None = None
        csrf: str | None = None
        try:
            _require_origin(request, origin)
            values = await _form(
                request,
                allowed=frozenset({"transaction", "csrf_token", "email", "password"}),
            )
            required = _required_fields(values, ("transaction", "csrf_token", "email", "password"))
            transaction = _bounded(required["transaction"], 512)
            csrf = _bounded(required["csrf_token"], 512)
            email = _bounded(required["email"], 320)
            password = _nonempty_sized(required["password"], 1_024)
            binding, cookie_csrf = _transaction_cookies(request, transaction)
            if not binding or not cookie_csrf or cookie_csrf != csrf:
                raise ParseError("invalid browser transaction")
            result = await service.password_login(
                transaction_id=transaction,
                browser_binding=binding,
                csrf_token=csrf,
                email=email,
                password=password,
                context=_context(request),
            )
        except ParseError:
            return _login_error_page("로그인 요청이 만료되었거나 올바르지 않습니다.", 400)
        except DomainError:
            if transaction is not None and csrf is not None:
                return _render_login(
                    login_template,
                    transaction,
                    csrf,
                    providers=providers,
                    error="이메일 또는 비밀번호를 확인해 주세요.",
                    status_code=401,
                )
            return _login_error_page("로그인 요청이 만료되었거나 올바르지 않습니다.", 400)
        except OidcServiceError as error:
            if error.error == "access_denied" and error.status_code == 403:
                message = "이 서비스 사용 권한이 없습니다. 관리자에게 요청하세요."
            elif error.status_code >= 500:
                message = "로그인 서비스를 일시적으로 사용할 수 없습니다."
            else:
                message = "로그인 요청이 만료되었거나 올바르지 않습니다."
            error_response = _login_error_page(message, error.status_code)
            if transaction is not None:
                _clear_transaction_cookies(error_response, transaction)
            return error_response
        if transaction is None:
            raise RuntimeError("OIDC login completed without a transaction")
        response = RedirectResponse(result.redirect_url, status_code=303)
        _clear_transaction_cookies(response, transaction)
        return response

    @app.get("/oauth2/providers/{provider}/start", include_in_schema=False)
    async def provider_start(provider: str, request: Request) -> Response:
        try:
            selected = _provider(provider)
            values = _query(request, allowed=frozenset({"transaction"}))
            transaction = _required_fields(values, ("transaction",))["transaction"]
            _bounded(transaction, 512)
            binding, _ = _transaction_cookies(request, transaction)
            if not binding:
                raise ParseError("missing browser binding")
            destination = await service.provider_start(
                transaction_id=transaction,
                browser_binding=binding,
                provider=selected,
            )
        except ParseError:
            return _login_error_page("소셜 로그인 요청이 올바르지 않습니다.", 400)
        except OidcServiceError as error:
            return _login_error_page(error.description, error.status_code)
        return RedirectResponse(destination, status_code=302)

    @app.get("/oauth2/providers/{provider}/callback", include_in_schema=False)
    async def provider_callback(provider: str, request: Request) -> Response:
        try:
            selected = _provider(provider)
            values = _query(
                request,
                allowed=frozenset({"code", "state", "error", "error_description"}),
            )
            state = _required_fields(values, ("state",))["state"]
            _bounded(state, 512)
            transaction = provider_state_transaction_id(state)
            if transaction is None:
                raise ParseError("invalid provider state")
            binding, _ = _transaction_cookies(request, transaction)
            if not binding:
                raise ParseError("missing browser binding")
            provider_error = values.get("error")
            if provider_error is not None:
                _bounded(provider_error, 128)
                _optional_bounded(values, "error_description", 512)
                if "code" in values:
                    raise ParseError("invalid provider callback")
                await service.provider_error(
                    provider=selected,
                    state=state,
                    browser_binding=binding,
                    context=_context(request),
                )
                raise RuntimeError("provider_error returned")
            if "error_description" in values:
                raise ParseError("invalid provider callback")
            code = _required_fields(values, ("code",))["code"]
            _bounded(code, 4_096)
            result = await service.provider_callback(
                provider=selected,
                code=code,
                state=state,
                browser_binding=binding,
                context=_context(request),
            )
        except ParseError:
            return _login_error_page("소셜 로그인 응답이 올바르지 않습니다.", 400)
        except OidcServiceError as error:
            error_response = _login_error_page(error.description, error.status_code)
            if transaction is not None:
                _clear_transaction_cookies(error_response, transaction)
            return error_response
        if transaction is None:
            raise RuntimeError("OIDC provider callback completed without a transaction")
        response = RedirectResponse(result.redirect_url, status_code=303)
        _clear_transaction_cookies(response, transaction)
        return response

    @app.post("/oauth2/token", include_in_schema=False)
    async def token(request: Request) -> Response:
        if request.scope.get("query_string"):
            return _oauth_error("invalid_request", "Query parameters are not allowed", 400)
        try:
            values = await _form(request, allowed=_TOKEN_FIELDS)
            credentials = extract_client_credentials(request.headers, values)
            required = _required_fields(values, ("grant_type", "code", "redirect_uri"))
            code_verifier = _optional_bounded(values, "code_verifier", 128)
            result = await service.exchange_code(
                TokenExchangeInput(
                    client_id=credentials.client_id,
                    client_secret=credentials.client_secret,
                    grant_type=_bounded(required["grant_type"], 64),
                    code=_bounded(required["code"], 4_096),
                    redirect_uri=_bounded(required["redirect_uri"], 2_048),
                    code_verifier=code_verifier,
                ),
                _context(request),
            )
        except ClientAuthenticationError:
            return _oauth_error(
                "invalid_client",
                "Client authentication failed",
                401,
                authenticate='Basic realm="oauth2/token"',
            )
        except ParseError:
            return _oauth_error("invalid_request", "Invalid token request", 400)
        except OidcServiceError as error:
            return _service_error_response(error)
        return JSONResponse(
            {
                "access_token": result.access_token,
                "token_type": result.token_type,
                "expires_in": result.expires_in,
                "id_token": result.id_token,
            }
        )

    @app.get("/oauth2/userinfo", include_in_schema=False)
    async def userinfo(request: Request) -> Response:
        if request.scope.get("query_string"):
            return _oauth_error("invalid_request", "Query parameters are not allowed", 400)
        try:
            token_value = _bearer_token(request)
            result = await service.userinfo(token_value)
        except ParseError:
            return _oauth_error(
                "invalid_token",
                "A valid bearer token is required",
                401,
                authenticate="Bearer",
            )
        except OidcServiceError as error:
            return _service_error_response(error, bearer=True)
        payload: dict[str, object] = {
            "sub": result.sub,
            "email": result.email,
            "email_verified": result.email_verified,
            "groups": list(result.groups),
        }
        if result.name is not None:
            payload["name"] = result.name
        return JSONResponse(payload)

    return app


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("OIDC public origin must be a canonical HTTPS origin")
    return value.rstrip("/")


def _query(request: Request, *, allowed: frozenset[str]) -> dict[str, str]:
    raw = cast(bytes, request.scope.get("query_string", b""))
    values = parse_urlencoded(raw, max_bytes=MAX_QUERY_BYTES)
    if not set(values).issubset(allowed):
        raise ParseError("unsupported parameter")
    return values


async def _form(request: Request, *, allowed: frozenset[str]) -> dict[str, str]:
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise ParseError("content type is required")
    pieces = [piece.strip() for piece in content_types[0].split(";")]
    if pieces[0].lower() != "application/x-www-form-urlencoded":
        raise ParseError("unsupported content type")
    if len(pieces) > 2 or (len(pieces) == 2 and pieces[1].lower() != "charset=utf-8"):
        raise ParseError("unsupported content type parameter")
    content_lengths = request.headers.getlist("content-length")
    if len(content_lengths) > 1:
        raise ParseError("invalid content length")
    length = content_lengths[0] if content_lengths else None
    if length is not None:
        try:
            if int(length) < 0 or int(length) > MAX_FORM_BYTES:
                raise ParseError("form is too large")
        except ValueError as error:
            raise ParseError("invalid content length") from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_FORM_BYTES:
            raise ParseError("form is too large")
    values = parse_urlencoded(bytes(body), max_bytes=MAX_FORM_BYTES)
    if not set(values).issubset(allowed):
        raise ParseError("unsupported form field")
    return values


def _required_fields(values: dict[str, str], names: tuple[str, ...]) -> dict[str, str]:
    if any(name not in values or not values[name] for name in names):
        raise ParseError("missing required field")
    return values


def _bounded(value: str, limit: int) -> str:
    if (
        not value
        or len(value) > limit
        or any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value)
    ):
        raise ParseError("invalid field value")
    return value


def _nonempty_sized(value: str, limit: int) -> str:
    if not value or len(value) > limit:
        raise ParseError("invalid field value")
    return value


def _optional_bounded(values: dict[str, str], name: str, limit: int) -> str | None:
    value = values.get(name)
    return None if value is None else _bounded(value, limit)


def _provider(value: str) -> OAuthProvider:
    if value not in OAUTH_PROVIDERS:
        raise ParseError("unsupported provider")
    return value


def _context(request: Request) -> OidcRequestContext:
    address = request.client.host if request.client is not None else None
    if address is not None and len(address) > 255:
        address = None
    user_agent = request.headers.get("user-agent")
    if user_agent is not None:
        if any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in user_agent):
            user_agent = None
        else:
            user_agent = user_agent.strip()[:512] or None
    return OidcRequestContext(address, user_agent)


def _require_origin(request: Request, public_origin: str) -> None:
    origins = request.headers.getlist("origin")
    if len(origins) != 1 or origins[0] != public_origin:
        raise ParseError("invalid origin")


def _cookie_suffix(transaction: str) -> str:
    return hashlib.sha256(transaction.encode("utf-8")).hexdigest()[:24]


def _cookie_names(transaction: str) -> tuple[str, str]:
    suffix = _cookie_suffix(transaction)
    return f"wiseacct_oidc_binding_{suffix}", f"wiseacct_oidc_csrf_{suffix}"


def _set_transaction_cookies(response: Response, start: AuthorizationStart) -> None:
    binding_name, csrf_name = _cookie_names(start.transaction_id)
    for name, value in ((binding_name, start.browser_binding), (csrf_name, start.csrf_token)):
        response.set_cookie(
            name,
            value,
            max_age=_COOKIE_MAX_AGE_SECONDS,
            secure=True,
            httponly=True,
            samesite="lax",
            path=_COOKIE_PATH,
        )


def _transaction_cookies(request: Request, transaction: str) -> tuple[str | None, str | None]:
    binding_name, csrf_name = _cookie_names(transaction)
    return request.cookies.get(binding_name), request.cookies.get(csrf_name)


def _clear_transaction_cookies(response: Response, transaction: str) -> None:
    for name in _cookie_names(transaction):
        response.delete_cookie(name, path=_COOKIE_PATH, secure=True, httponly=True, samesite="lax")


def _render_login(
    template: str,
    transaction: str,
    csrf: str,
    *,
    providers: tuple[OAuthProvider, ...],
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    error_block = (
        "" if error is None else f'<p class="oidc-error" role="alert">{html.escape(error)}</p>'
    )
    names = {"google": "Google", "naver": "Naver", "kakao": "Kakao"}
    provider_links = "".join(
        f'<a href="/oauth2/providers/{provider}/start?transaction={quote(transaction, safe="")}">'
        f"{names[provider]}</a>"
        for provider in providers
    )
    provider_block = (
        '<div class="oidc-divider"><span>또는</span></div>'
        f'<nav class="oidc-providers" aria-label="소셜 로그인">{provider_links}</nav>'
        if provider_links
        else ""
    )
    rendered = (
        template.replace("{{TRANSACTION}}", html.escape(transaction, quote=True))
        .replace("{{TRANSACTION_URL}}", quote(transaction, safe=""))
        .replace("{{CSRF_TOKEN}}", html.escape(csrf, quote=True))
        .replace("{{ERROR_BLOCK}}", error_block)
        .replace("{{PROVIDER_BLOCK}}", provider_block)
    )
    return HTMLResponse(rendered, status_code=status_code)


def _login_error_page(message: str, status_code: int) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="ko"><meta charset="utf-8">'
        "<title>로그인 오류</title><main><h1>로그인할 수 없습니다</h1>"
        f"<p>{html.escape(message)}</p>"
        "</main></html>",
        status_code=status_code,
    )


def _bearer_token(request: Request) -> str:
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise ParseError("missing bearer token")
    scheme, separator, value = values[0].partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not value
        or any(character.isspace() or ord(character) < 33 for character in value)
        or len(value) > 4_096
    ):
        raise ParseError("invalid bearer token")
    return value


def _service_error_response(error: OidcServiceError, *, bearer: bool = False) -> Response:
    if error.redirect_uri is not None:
        values = {"error": error.error, "error_description": error.description}
        if error.state is not None:
            values["state"] = error.state
        separator = "&" if "?" in error.redirect_uri else "?"
        return RedirectResponse(
            f"{error.redirect_uri}{separator}{urlencode(values)}", status_code=302
        )
    authenticate: str | None = None
    if error.www_authenticate:
        authenticate = f'Bearer error="{error.error}"' if bearer else 'Basic realm="oauth2/token"'
    return _oauth_error(
        error.error, error.description, error.status_code, authenticate=authenticate
    )


def _oauth_error(
    error: str,
    description: str,
    status_code: int,
    *,
    authenticate: str | None = None,
) -> JSONResponse:
    headers = {} if authenticate is None else {"www-authenticate": authenticate}
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=headers,
    )


def _report_internal_error(error: Exception, request: Request) -> None:
    record: dict[str, str] = {
        "event": "oidc_internal_error",
        "error_type": type(error).__name__[:64],
    }
    request_id = request.scope.get("state", {}).get("request_id")
    if isinstance(request_id, str) and 0 < len(request_id) <= 128:
        record["request_id"] = request_id
    try:
        sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
    except Exception:
        return
