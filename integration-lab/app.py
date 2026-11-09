"""Single-worker, local-only confidential OIDC relying party for Wise SSO."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse


@dataclass(frozen=True)
class Config:
    kind: str
    client_id: str
    client_secret: str = field(repr=False)
    public_origin: str = "https://localhost:4445"
    issuer: str = "https://localhost:4444"
    backend: str = "http://app:4001"

    @property
    def cookie(self) -> str:
        return f"wise_lab_{self.kind}"


@dataclass
class Pending:
    state: str
    nonce: str
    verifier: str
    expires: float


@dataclass
class Session:
    subject: str
    expires: float
    access_token: str = field(repr=False)
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)


def verify_id_token(encoded: str, keys: dict, config: Config, nonce: str) -> dict:
    header = jwt.get_unverified_header(encoded)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("Invalid signing header")
    key = next((key for key in keys["keys"] if key.get("kid") == header["kid"]), None)
    if key is None:
        raise ValueError("Unknown signing key")
    claims = jwt.decode(
        encoded,
        jwt.PyJWK.from_dict(key).key,
        algorithms=["RS256"],
        audience=config.client_id,
        issuer=config.issuer,
        options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
    )
    if not isinstance(claims["sub"], str) or not claims["sub"]:
        raise ValueError("Missing subject")
    if not isinstance(claims["nonce"], str) or not hmac.compare_digest(
        claims["nonce"], nonce
    ):
        raise ValueError("Nonce mismatch")
    if isinstance(claims["aud"], list) and claims.get("azp") != config.client_id:
        raise ValueError("Authorized party mismatch")
    return claims


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    response = HTMLResponse(
        f"""<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>body{{font:17px system-ui;max-width:780px;margin:60px auto;padding:24px;background:#f6f8fc;color:#172338}}main{{background:white;border:1px solid #dbe1eb;border-radius:16px;padding:32px}}a,button{{color:#2459bf}}td,th{{padding:10px;text-align:left;border-bottom:1px solid #ddd}}small{{color:#586578}}</style>
<main><small>WISE SSO · 연동 검증용</small><h1>{html.escape(title)}</h1>{body}</main></html>""",
        status_code=status,
    )
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        }
    )
    return response


def create_app(
    config: Config | None = None, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    config = config or Config(
        kind=os.environ["LAB_KIND"],
        client_id=os.environ["LAB_CLIENT_ID"],
        client_secret=os.environ["LAB_CLIENT_SECRET"],
        public_origin=os.environ["LAB_PUBLIC_ORIGIN"],
    )
    if config.kind not in {"customer", "staff"}:
        raise ValueError("Unknown lab service")
    if not config.client_secret or not config.public_origin.startswith(
        "https://localhost:"
    ):
        raise ValueError("Local HTTPS origin and client secret required")
    pending: dict[str, Pending] = {}
    sessions: dict[str, Session] = {}

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, transport=transport
        ) as client:
            app.state.http = client
            yield
        pending.clear()
        sessions.clear()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.pending = pending
    app.state.sessions = sessions
    title = "외부 고객용 더미" if config.kind == "customer" else "직원 전용 더미"
    callback = config.public_origin + "/callback"

    def cookie(response, value: str, age: int):
        response.set_cookie(
            config.cookie,
            value,
            max_age=age,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )

    def cleanup():
        now = time.monotonic()
        for store in (pending, sessions):
            for key in list(store):
                if store[key].expires <= now:
                    del store[key]

    @app.get("/healthz")
    async def health():
        return {"status": "ok"}

    @app.get("/")
    async def home(request: Request):
        cleanup()
        session = sessions.get(request.cookies.get(config.cookie, ""))
        if session is None:
            return page(
                title,
                '<p>업무 기능 없이 로그인과 권한 전달만 확인하는 테스트 서비스입니다.</p><p><a href="/login">wise-sso로 로그인</a> · <a href="https://localhost:4444/oauth2/session">중앙 SSO 세션 관리·종료</a></p>',
            )
        try:
            result = await app.state.http.get(
                config.backend + "/oauth2/userinfo",
                headers={"Authorization": "Bearer " + session.access_token},
            )
            result.raise_for_status()
            identity = result.json()
            if identity.get("sub") != session.subject:
                raise ValueError("Subject mismatch")
        except (httpx.HTTPError, ValueError, KeyError):
            sessions.pop(request.cookies.get(config.cookie, ""), None)
            response = page(
                title,
                '<p>인증이 만료되었거나 접근 권한이 회수됐습니다.</p><a href="/login">다시 로그인</a>',
                401,
            )
            response.delete_cookie(
                config.cookie, path="/", secure=True, httponly=True, samesite="lax"
            )
            return response
        rows = "".join(
            f"<tr><th>{label}</th><td>{html.escape(str(identity.get(key, '미제공')))}</td></tr>"
            for label, key in [
                ("사용자 ID", "sub"),
                ("이메일", "email"),
                ("전달받은 역할", "groups"),
            ]
        )
        body = f'''<p>로그인 성공 · 이 서비스의 서버 세션이 유지되고 있습니다.</p><table>{rows}</table>
<p><a href="https://localhost:4445/">고객용 서비스</a> · <a href="https://localhost:4446/">직원용 서비스</a></p>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{session.csrf}"><button>이 서비스에서 로그아웃</button></form>
<p><small>중앙 SSO 세션이 유효하면 다른 서비스에서 재입력 없이 권한을 검사합니다. 위 로그아웃은 이 더미의 세션만 종료합니다.</small></p>
<p><a href="{config.issuer}/oauth2/session">중앙 SSO 세션 관리·종료</a> · <a href="/login?prompt=login">다른 계정으로 다시 인증</a></p>'''
        return page(title, body)

    @app.get("/login")
    async def login(request: Request):
        cleanup()
        if not set(request.query_params).issubset({"prompt", "max_age"}) or any(
            len(request.query_params.getlist(k)) != 1 for k in request.query_params
        ):
            raise HTTPException(400, "Invalid login options")
        prompt = request.query_params.get("prompt")
        max_age = request.query_params.get("max_age")
        if prompt not in (None, "none", "login", "select_account", "consent"):
            raise HTTPException(400, "Invalid prompt")
        if max_age is not None and (
            len(max_age) > 10
            or not max_age.isascii()
            or not max_age.isdecimal()
            or int(max_age) > 2_147_483_647
        ):
            raise HTTPException(400, "Invalid max_age")
        binding = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        pending[binding] = Pending(state, nonce, verifier, time.monotonic() + 300)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        query = urlencode(
            {
                **({"prompt": prompt} if prompt is not None else {}),
                **({"max_age": max_age} if max_age is not None else {}),
                "client_id": config.client_id,
                "redirect_uri": callback,
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        response = RedirectResponse(config.issuer + "/oauth2/authorize?" + query, 303)
        response.headers["Cache-Control"] = "no-store"
        cookie(response, binding, 300)
        return response

    @app.get("/callback")
    async def finish(request: Request):
        cleanup()
        binding = request.cookies.get(config.cookie, "")
        flow = pending.get(binding)
        states = request.query_params.getlist("state")
        if (
            flow is None
            or len(states) != 1
            or not hmac.compare_digest(flow.state, states[0])
        ):
            return page(
                "요청 확인 실패",
                '<p>만료되었거나 다른 브라우저에서 시작한 로그인입니다.</p><a href="/login">다시 로그인</a>',
                400,
            )
        pending.pop(binding)
        if request.query_params.get("error"):
            return page(
                "접근 거부",
                '<p>이 서비스의 이용 권한이 없거나 인증이 거부됐습니다.</p><a href="/">돌아가기</a>',
                403,
            )
        codes = request.query_params.getlist("code")
        if len(codes) != 1 or not codes[0]:
            return page("인증 실패", '<a href="/login">다시 로그인</a>', 400)
        try:
            result = await app.state.http.post(
                config.backend + "/oauth2/token",
                auth=httpx.BasicAuth(config.client_id, config.client_secret),
                data={
                    "grant_type": "authorization_code",
                    "code": codes[0],
                    "redirect_uri": callback,
                    "code_verifier": flow.verifier,
                },
            )
            result.raise_for_status()
            tokens = result.json()
            keys = await app.state.http.get(config.backend + "/.well-known/jwks.json")
            keys.raise_for_status()
            claims = verify_id_token(
                tokens["id_token"], keys.json(), config, flow.nonce
            )
            access_token = tokens["access_token"]
            if not isinstance(access_token, str) or not access_token:
                raise ValueError("Missing access token")
        except (httpx.HTTPError, ValueError, KeyError, TypeError, jwt.PyJWTError):
            return page(
                "인증 실패",
                '<p>토큰 교환 또는 ID Token 검증에 실패했습니다.</p><a href="/login">다시 로그인</a>',
                401,
            )
        old = request.cookies.get(config.cookie, "")
        sessions.pop(old, None)
        sid = secrets.token_urlsafe(32)
        sessions[sid] = Session(claims["sub"], time.monotonic() + 300, access_token)
        response = RedirectResponse("/", 303)
        response.headers["Cache-Control"] = "no-store"
        cookie(response, sid, 300)
        return response

    @app.post("/logout")
    async def logout(request: Request):
        from urllib.parse import parse_qs

        sid = request.cookies.get(config.cookie, "")
        session = sessions.get(sid)
        if len(await request.body()) > 2048:
            raise HTTPException(400, "Invalid logout")
        values = parse_qs((await request.body()).decode())
        csrf = values.get("csrf", [])
        if (
            session is None
            or len(csrf) != 1
            or not hmac.compare_digest(session.csrf, csrf[0])
        ):
            raise HTTPException(403, "Invalid logout")
        sessions.pop(sid)
        response = RedirectResponse("/", 303)
        response.delete_cookie(
            config.cookie, path="/", secure=True, httponly=True, samesite="lax"
        )
        return response

    return app
