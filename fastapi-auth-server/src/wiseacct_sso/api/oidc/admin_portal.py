"""Cookie-authenticated administrator UI/API; legacy Bearer API stays separate."""

from __future__ import annotations

import hmac
import html
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.errors import error_response, install_error_handlers
from wiseacct_sso.api.routes.admin import build_admin_router
from wiseacct_sso.application.invitations import EmployeeInvitationService
from wiseacct_sso.application.oidc import AdminBrowserIdentity, OidcService, OidcServiceError
from wiseacct_sso.domain.users import DomainError

from .app import (
    _bounded,
    _clear_session_cookie,
    _clear_transaction_cookies,
    _context,
    _form,
    _nonempty_sized,
    _query,
    _render_login,
    _require_origin,
    _required_fields,
    _set_session_cookie,
    _set_transaction_cookies,
    _transaction_cookies,
)
from .parsing import ParseError

ADMIN_ROOT = "/oauth2/admin"
ADMIN_LOGIN = ADMIN_ROOT + "/login"
ADMIN_DASHBOARD = ADMIN_ROOT + "/dashboard"
ADMIN_API = ADMIN_ROOT + "/api"
_AUTH_MARKER = "<!-- ADMIN_AUTH_PANEL_START -->"
_AUTH_END = "<!-- ADMIN_AUTH_PANEL_END -->"


def _page(message: str, status: int) -> HTMLResponse:
    return HTMLResponse(
        '<!doctype html><html lang="ko"><meta charset="utf-8">'
        f'<h1>{html.escape(message)}</h1><p><a href="{ADMIN_LOGIN}?reauth=1">'
        "관리자 계정으로 다시 로그인</a></p></html>",
        status_code=status,
    )


class AdminBrowserMiddleware:
    """Authenticate before JSON parsing and enforce same-origin, bounded mutations."""

    def __init__(self, app: ASGIApp, *, service: OidcService, origin: str) -> None:
        self.app, self.service, self.origin = app, service, origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        try:
            identity = await self.service.admin_browser_identity(_context(request))
        except OidcServiceError as error:
            code = "ADMIN_LOGIN_REQUIRED" if error.status_code == 401 else "FORBIDDEN"
            await error_response(error.status_code, code, error.description)(scope, receive, send)
            return
        if len(scope.get("query_string", b"")) > 8192:
            await error_response(400, "INVALID_REQUEST", "Invalid query")(scope, receive, send)
            return
        if request.method not in {"GET", "HEAD", "POST", "PATCH", "DELETE"}:
            await error_response(405, "METHOD_NOT_ALLOWED", "Method not allowed")(
                scope, receive, send
            )
            return
        body: bytes | None = None
        if request.method not in {"GET", "HEAD"}:
            try:
                _require_origin(request, self.origin)
            except ParseError:
                await error_response(403, "INVALID_ORIGIN", "같은 사이트에서 요청하세요.")(
                    scope, receive, send
                )
                return
            csrf = request.headers.getlist("x-admin-csrf")
            if (
                len(csrf) != 1
                or not csrf[0].isascii()
                or not hmac.compare_digest(csrf[0], identity.csrf_token)
            ):
                await error_response(
                    403, "INVALID_CSRF", "로그인 상태가 변경됐습니다. 화면을 새로고침하세요."
                )(scope, receive, send)
                return
            content_types = request.headers.getlist("content-type")
            if (
                len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower() != "application/json"
            ):
                await error_response(400, "INVALID_REQUEST", "JSON body is required")(
                    scope, receive, send
                )
                return
            chunks: list[bytes] = []
            size = 0
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    return
                chunk = message.get("body", b"")
                size += len(chunk)
                if size > 32 * 1024:
                    await error_response(413, "BODY_TOO_LARGE", "Request body is too large")(
                        scope, receive, send
                    )
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break
            body = b"".join(chunks)
        scope["state"] = dict(scope.get("state", {}))
        scope["state"]["browser_admin_identity"] = identity
        sent = False

        async def replay() -> Message:
            nonlocal sent
            if body is not None and not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay if body is not None else receive, send)


def register_admin_portal(
    app: FastAPI,
    *,
    service: OidcService,
    admin_services: Phase6Services,
    origin: str,
    static_root: Path,
    login_template: str,
    invitation_service: EmployeeInvitationService | None = None,
) -> None:
    template = (static_root / "admin-dashboard.html").read_text()
    if template.count(_AUTH_MARKER) != 1 or template.count(_AUTH_END) != 1:
        raise ValueError("Administrator dashboard authentication markers are required")
    admin_template = (
        login_template.replace('action="/oauth2/login"', f'action="{ADMIN_LOGIN}"')
        .replace("계속하려면 로그인하세요", "관리자 로그인")
        .replace(
            "요청한 내부 서비스로 안전하게 돌아갑니다.", "승인된 직원 관리자 계정으로 로그인하세요."
        )
    )
    destination = origin + ADMIN_DASHBOARD
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    api.state.phase6_services = admin_services

    async def browser_actor(request: Request) -> str:
        identity = getattr(request.state, "browser_admin_identity", None)
        if not isinstance(identity, AdminBrowserIdentity):
            raise DomainError(401, "ADMIN_LOGIN_REQUIRED", "Administrator login is required")
        return identity.user_id

    api.state.admin_browser_actor = browser_actor
    install_error_handlers(api)
    api.include_router(build_admin_router(prefix=""))
    if invitation_service is not None:
        from .invitations import register_invitation_routes

        register_invitation_routes(app, api, invitation_service, origin, static_root)

    @api.get("/users/{user_id}", include_in_schema=False)
    async def user_detail(
        request: Request,
        user_id: str,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 50,
        history_page: Annotated[int, Query(alias="historyPage", ge=1, le=2_147_483_647)] = 1,
        service_page: Annotated[int, Query(alias="servicePage", ge=1, le=2_147_483_647)] = 1,
        role_page: Annotated[int, Query(alias="rolePage", ge=1, le=2_147_483_647)] = 1,
    ) -> Response:
        await browser_actor(request)
        detail = await service.admin_user_detail(
            user_id,
            page=page,
            page_size=page_size,
            history_page=history_page,
            service_page=service_page,
            role_page=role_page,
        )
        if detail is None:
            return error_response(404, "USER_NOT_FOUND", "User not found")
        return JSONResponse(detail, headers={"Cache-Control": "no-store"})

    @api.get("/users/{user_id}/sessions", include_in_schema=False)
    async def user_sessions(
        request: Request,
        user_id: str,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 50,
    ) -> Response:
        await browser_actor(request)
        sessions = await service.admin_user_sessions(user_id, page=page, page_size=page_size)
        if sessions is None:
            return error_response(404, "USER_NOT_FOUND", "User not found")
        return JSONResponse(sessions, headers={"Cache-Control": "no-store"})

    @api.get("/clients", include_in_schema=False)
    async def list_clients(
        request: Request,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 50,
    ) -> Response:
        await browser_actor(request)
        clients = await service.admin_client_page(page=page, page_size=page_size)
        return JSONResponse(clients, headers={"Cache-Control": "no-store"})

    @api.get("/clients/{client_id}/members", include_in_schema=False)
    async def list_client_members(
        request: Request,
        client_id: str,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 50,
    ) -> Response:
        await browser_actor(request)
        members = await service.admin_client_member_page(client_id, page=page, page_size=page_size)
        if members is None:
            return error_response(404, "OIDC_CLIENT_NOT_FOUND", "Service not found")
        return JSONResponse(members, headers={"Cache-Control": "no-store"})

    @api.get("/service-access", include_in_schema=False)
    async def service_access(request: Request) -> Response:
        await browser_actor(request)
        ids = [value for value in request.query_params.getlist("id") if value][:100]
        access = await service.admin_service_access(ids)
        return JSONResponse(access, headers={"Cache-Control": "no-store"})

    @api.get("/roles", include_in_schema=False)
    async def list_roles(
        request: Request,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        page_size: Annotated[int, Query(alias="pageSize", ge=1, le=100)] = 50,
    ) -> Response:
        await browser_actor(request)
        roles = await admin_services.list_roles(page=page, page_size=page_size)
        return JSONResponse(roles, headers={"Cache-Control": "no-store"})

    @api.get("/summary", include_in_schema=False)
    async def summary(request: Request) -> Response:
        await browser_actor(request)
        return JSONResponse(await admin_services.summary(), headers={"Cache-Control": "no-store"})

    app.mount(ADMIN_API, AdminBrowserMiddleware(api, service=service, origin=origin))

    @app.get(ADMIN_LOGIN, include_in_schema=False)
    async def login_page(request: Request) -> Response:
        try:
            query = _query(request, allowed=frozenset({"reauth"}))
            if query.get("reauth") not in (None, "1"):
                raise ParseError("Invalid reauthentication option")
        except ParseError:
            return _page("올바르지 않은 로그인 요청입니다.", 400)
        if "reauth" not in query:
            try:
                await service.admin_browser_identity(_context(request))
            except OidcServiceError as error:
                if error.status_code != 401:
                    return _page("이 계정은 관리자 권한이 없습니다.", error.status_code)
            else:
                return RedirectResponse(ADMIN_DASHBOARD, 303)
        start = await service.admin_login_start(destination)
        response = _render_login(
            admin_template, start.transaction_id, start.csrf_token, providers=()
        )
        _set_transaction_cookies(response, start)
        return response

    @app.post(ADMIN_LOGIN, include_in_schema=False)
    async def password_login(request: Request) -> Response:
        transaction: str | None = None
        csrf: str | None = None
        try:
            _require_origin(request, origin)
            data = await _form(
                request, allowed=frozenset({"transaction", "csrf_token", "email", "password"})
            )
            required = _required_fields(data, ("transaction", "csrf_token", "email", "password"))
            transaction = _bounded(required["transaction"], 512)
            csrf = _bounded(required["csrf_token"], 512)
            binding, cookie_csrf = _transaction_cookies(request, transaction)
            if not binding or not cookie_csrf or cookie_csrf != csrf:
                raise ParseError("Invalid browser binding")
            result = await service.admin_password_login(
                transaction_id=transaction,
                browser_binding=binding,
                csrf_token=csrf,
                email=_bounded(required["email"], 320),
                password=_nonempty_sized(required["password"], 1024),
                redirect_uri=destination,
                context=_context(request),
            )
        except ParseError:
            return _page("로그인 요청이 만료되었거나 올바르지 않습니다.", 400)
        except DomainError:
            if transaction is None or csrf is None:
                return _page("로그인 요청이 올바르지 않습니다.", 400)
            return _render_login(
                admin_template,
                transaction,
                csrf,
                providers=(),
                error="이메일 또는 비밀번호를 확인해 주세요.",
                status_code=401,
            )
        except OidcServiceError as error:
            response = _page(
                "관리자 권한을 확인할 수 없습니다. 다시 로그인하세요.", error.status_code
            )
            if transaction is not None:
                _clear_transaction_cookies(response, transaction)
            return response
        redirect = RedirectResponse(destination, 303)
        _set_session_cookie(redirect, result)
        _clear_transaction_cookies(redirect, transaction)
        return redirect

    @app.get(ADMIN_ROOT + "/users/{user_id}", include_in_schema=False)
    async def user_detail_page(request: Request, user_id: str) -> Response:
        try:
            _query(request, allowed=frozenset())
            identity = await service.admin_browser_identity(_context(request))
        except ParseError:
            return _page("올바르지 않은 요청입니다.", 400)
        except OidcServiceError as error:
            if error.status_code == 401:
                return RedirectResponse(ADMIN_LOGIN, 303)
            return _page("이 계정은 관리자 권한이 없습니다.", error.status_code)

        template = (static_root / "admin-user-detail.html").read_text(encoding="utf-8")
        document = template.replace("__ADMIN_CSRF__", html.escape(identity.csrf_token, quote=True))
        return HTMLResponse(document, headers={"Cache-Control": "no-store"})

    @app.get(ADMIN_DASHBOARD, include_in_schema=False)
    async def dashboard(request: Request) -> Response:
        try:
            _query(request, allowed=frozenset())
            identity = await service.admin_browser_identity(_context(request))
        except ParseError:
            return _page("올바르지 않은 요청입니다.", 400)
        except OidcServiceError as error:
            if error.status_code == 401:
                return RedirectResponse(ADMIN_LOGIN, 303)
            return _page("이 계정은 관리자 권한이 없습니다.", error.status_code)
        escaped_csrf = html.escape(identity.csrf_token, quote=True)
        panel = (
            '<section class="token-panel" data-session-panel><div><h2>관리자 로그인</h2>'
            f"<p>{html.escape(identity.email)}</p>"
            "<p>최근 인증 후 15분 동안 사용할 수 있습니다.</p></div>"
            f'<form method="post" action="{ADMIN_ROOT}/logout">'
            f'<input type="hidden" name="csrf_token" value="{escaped_csrf}">'
            '<button class="secondary-button" type="submit">중앙 세션 종료</button>'
            "</form></section>"
        )
        before, _, rest = template.partition(_AUTH_MARKER)
        _, _, after = rest.partition(_AUTH_END)
        invitations = ""
        if invitation_service is not None:
            invitations = (
                '<section class="panel" data-view="invites"><h2>직원 초대</h2>'
                '<form class="form-grid" data-employee-invite>'
                '<label>이메일 <input name="email" type="email" maxlength="320" required></label>'
                '<label>이름 <input name="name" maxlength="200" required></label>'
                '<fieldset class="role-choices" data-invite-roles>'
                "<legend>줄 서비스 권한 (하나 이상)</legend>"
                '<p class="type-fixed">역할 목록을 불러오는 중…</p></fieldset>'
                '<label>전달 방법 <select name="delivery">'
                '<option value="mail">초대 메일 보내기</option>'
                '<option value="link">링크 복사해서 직접 전달</option></select></label>'
                '<button class="primary-button" type="submit">초대 만들기</button></form>'
                '<button type="button" data-invitation-refresh>초대 목록 조회</button>'
                '<p data-invitation-status role="status"></p>'
                "<div data-invitation-list></div></section>"
                '<script src="/assets/admin-invitations.js?v=20261113-detail" defer></script>'
                '<section class="panel" data-view="external"><h2>외부 계정 (기한 있음)</h2>'
                '<p class="panel-lead">외주 개발자 등 회사 밖 사람용입니다. '
                "기한이 지나면 로그인할 수 없습니다. "
                "직원 서비스 권한은 받을 수 없고, "
                "GitLab이 필요하면 gitlab:user만 줄 수 있습니다.</p>"
                '<form class="form-grid" data-external-create>'
                '<label>이메일 <input name="email" type="email" maxlength="320" required></label>'
                '<label>이름 <input name="name" maxlength="200" required></label>'
                '<label>기한 <select name="preset">'
                '<option value="90">3개월 (90일)</option>'
                '<option value="180">6개월 (180일)</option>'
                '<option value="custom">직접 입력</option></select></label>'
                "<label data-external-days hidden>일수 (1~365) "
                '<input name="days" type="number" min="1" max="365" step="1"></label>'
                '<label><input name="gitlab" type="checkbox"> GitLab 사용 (gitlab:user)</label>'
                '<label>전달 방법 <select name="delivery">'
                '<option value="link">링크 복사해서 직접 전달</option>'
                '<option value="mail">초대 메일 보내기</option></select></label>'
                "<p data-external-preview></p>"
                '<button class="primary-button" type="submit">외부 계정 만들기</button></form>'
                "<div data-external-link hidden><input data-external-link-value readonly "
                'aria-label="초대 링크"><button type="button" data-external-copy>링크 복사</button>'
                "<p>링크는 72시간 동안 한 번만 쓸 수 있습니다. "
                "메신저 등으로 직접 전달하세요.</p></div>"
                '<button type="button" data-external-refresh>외부 계정 목록 조회</button>'
                '<p data-external-status role="status"></p>'
                "<div data-external-list></div></section>"
                '<script src="/assets/admin-external.js?v=20261114-expiry-hashchange"'
                " defer></script>"
            )
        page = (before + panel + invitations + after).replace(
            '<meta name="admin-api-base" content="/manage-api">',
            f'<meta name="admin-api-base" content="{ADMIN_API}">'
            '<meta name="admin-auth-mode" content="session">'
            f'<meta name="admin-session-csrf" content="{escaped_csrf}">',
        )
        return HTMLResponse(page)

    @app.post(ADMIN_ROOT + "/logout", include_in_schema=False)
    async def logout(request: Request) -> Response:
        try:
            _require_origin(request, origin)
            values = await _form(request, allowed=frozenset({"csrf_token"}))
            csrf = _bounded(_required_fields(values, ("csrf_token",))["csrf_token"], 128)
            if not csrf.isascii():
                raise ParseError("Invalid CSRF")
            await service.end_session(_context(request).session_token, csrf, _context(request))
        except ParseError:
            return _page("올바르지 않은 로그아웃 요청입니다.", 400)
        response = RedirectResponse(ADMIN_LOGIN + "?reauth=1", 303)
        _clear_session_cookie(response)
        return response
