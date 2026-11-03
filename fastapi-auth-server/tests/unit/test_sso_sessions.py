from __future__ import annotations

import json
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import cast
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.api.middleware import SecurityHeadersMiddleware
from wiseacct_sso.api.oidc import build_oidc_app
from wiseacct_sso.application.oidc import OidcService
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.admin import AdminUserListInput, AdminUserPage, AdminUserProfile
from wiseacct_sso.domain.users import UserStatus as DomainUserStatus
from wiseacct_sso.infrastructure.auth_state import sha256_base64url
from wiseacct_sso.infrastructure.oidc_state import (
    OidcAuthorizationCodeStore,
    OidcAuthorizationTransactionStore,
    OidcProviderStateStore,
)
from wiseacct_sso.infrastructure.oidc_tokens import (
    OidcAccessTokenStore,
    OidcIdTokenIdentity,
    OidcIdTokenSigner,
)
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH, AsyncPasswordHasher
from wiseacct_sso.infrastructure.sso_sessions import (
    SSO_COOKIE_NAME,
    SSO_SESSION_TTL_SECONDS,
    SsoSessionStore,
    session_key,
)
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.models import UserStatus
from wiseacct_sso.persistence.oidc import OidcIdentityStore, OidcUserRecord
from wiseacct_sso.persistence.stores import (
    AuditEventInsert,
    AuditStore,
    FailedLoginStore,
    PasswordAuthStore,
    PasswordCredentialRecord,
    RoleAssignment,
)

ORIGIN = "https://sso.example.test"
VERIFIER = "v" * 43


class Redis:
    def __init__(self) -> None:
        self.values: dict[str | bytes, bytes] = {}
        self.ttls: list[int] = []
        self.broken = False

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        if self.broken:
            raise RuntimeError("Redis unavailable")
        if key in self.values:
            return False
        self.values[key] = value
        self.ttls.append(ttl_seconds)
        return True

    async def get_raw(self, key: str | bytes) -> bytes | None:
        if self.broken:
            raise RuntimeError("Redis unavailable")
        return self.values.get(key)

    async def consume(self, key: str | bytes) -> bytes | None:
        return self.values.pop(key, None)

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None:
        return await self.consume(key) if self.values.get(key) == expected else None


class Db:
    @property
    def engine(self) -> Db:
        return self

    @asynccontextmanager
    async def begin(self) -> AsyncIterator[AsyncConnection]:
        yield cast(AsyncConnection, object())

    connection = begin

    async def transaction[T](self, work: DatabaseOnlyTransaction[T], *, max_attempts: int = 3) -> T:
        return await work.callback(cast(AsyncConnection, object()))


class Hasher:
    async def verify_password(self, hashed: str, password: str) -> bool:
        return (hashed, password) in {("hash", "password"), (DUMMY_PASSWORD_HASH, "client-secret")}


class Identities:
    def __init__(self) -> None:
        self.user = OidcUserRecord(
            "user-1",
            "employee@example.test",
            True,
            "Employee",
            UserStatus.ACTIVE,
            (RoleAssignment("customer", "user"), RoleAssignment("staff", "user")),
            user_type="EMPLOYEE",
        )
        self.lookups = 0

    async def lock_user(self, connection: AsyncConnection, *, user_id: str) -> OidcUserRecord:
        self.lookups += 1
        return self.user


class Passwords:
    def __init__(self, identities: Identities) -> None:
        self.identities = identities
        self.hash = "hash"

    async def find_credential_by_email(
        self, connection: AsyncConnection, *, email: str
    ) -> PasswordCredentialRecord:
        return PasswordCredentialRecord(
            "user-1", email, self.hash, 0, None, self.identities.user.status
        )

    async def mark_login_success(self, connection: AsyncConnection, **values: object) -> None:
        pass


class Audit:
    def __init__(self) -> None:
        self.fail = False
        self.events: list[AuditEventInsert] = []

    async def create(self, connection: AsyncConnection, *, event: AuditEventInsert) -> None:
        if self.fail:
            raise RuntimeError("Audit unavailable")
        self.events.append(event)


class Signer:
    def __init__(self) -> None:
        self.auth_time: int | None = None

    def issue(
        self,
        identity: object,
        *,
        client_id: str,
        nonce: str | None = None,
        auth_time: int | None = None,
    ) -> str:
        self.auth_time = auth_time
        return "signed-token"


class Failures:
    def __init__(self) -> None:
        self.count = 0

    async def record_failure(self, connection: AsyncConnection, **values: object) -> None:
        self.count += 1


class PortalApi:
    def __init__(self, identities: Identities) -> None:
        self.identities = identities
        self.calls: list[tuple[str, object]] = []
        self.catalog: dict[str, OidcUserRecord] = {}
        self.noop = False

    async def authenticate_admin(self, *args: object, **kwargs: object) -> str:
        raise AssertionError("Browser endpoint must not accept a Bearer-token shortcut")

    async def list_users(self, input: AdminUserListInput) -> AdminUserPage:
        from datetime import UTC, datetime

        self.calls.append(("list", input))
        user = self.catalog.get(input.email or "", self.identities.user)
        return AdminUserPage(
            (
                AdminUserProfile(
                    user.id,
                    user.email,
                    user.name,
                    DomainUserStatus(user.status),
                    datetime.now(UTC),
                    (),
                    user_type=user.user_type,
                ),
            ),
            1,
            1,
            50,
        )

    async def set_user_types(self, **values: object) -> tuple[int, int]:
        self.calls.append(("types", values))
        return (0, 1) if self.noop else (1, 0)


class Rig:
    def __init__(self, *, portal: bool = False) -> None:
        self.now = 1_800_000_000
        self.redis = Redis()
        self.sessions = SsoSessionStore(self.redis, clock=lambda: self.now)
        self.identities = Identities()
        self.audit = Audit()
        self.passwords = Passwords(self.identities)
        self.signer = Signer()
        self.failures = Failures()
        self.portal = PortalApi(self.identities)
        clients = tuple(
            OidcClientPolicy.model_validate(
                {
                    "clientId": kind,
                    "clientSecretHash": DUMMY_PASSWORD_HASH,
                    "redirectUris": [f"https://{kind}.example.test/callback"],
                    "requiredRoles": [{"serviceKey": kind, "name": "user"}],
                    "groupsServiceKeys": [kind],
                    "allowedUserTypes": ["EMPLOYEE"]
                    if kind == "staff"
                    else ["EMPLOYEE", "CUSTOMER", "UNCLASSIFIED"],
                }
            )
            for kind in ("customer", "staff")
        )
        self.service = OidcService(
            database=lambda: cast(Database, Db()),
            passwords=cast(AsyncPasswordHasher, Hasher()),
            clients=OidcClientRegistry(clients),
            transactions=OidcAuthorizationTransactionStore(
                self.redis, now_epoch_ms=lambda: self.now * 1000
            ),
            provider_states=OidcProviderStateStore(
                self.redis, now_epoch_ms=lambda: self.now * 1000
            ),
            codes=OidcAuthorizationCodeStore(self.redis, now_epoch_ms=lambda: self.now * 1000),
            access_tokens=OidcAccessTokenStore(self.redis, now_epoch_ms=lambda: self.now * 1000),
            id_tokens=cast(OidcIdTokenSigner, self.signer),
            sessions=self.sessions,
            clock_ms=lambda: self.now * 1000,
        )
        self.service._identities = cast(OidcIdentityStore, self.identities)
        self.service._password_store = cast(PasswordAuthStore, self.passwords)
        self.service._audit = cast(AuditStore, self.audit)
        self.service._failed_logins = cast(FailedLoginStore, self.failures)
        self.client = TestClient(
            SecurityHeadersMiddleware(
                build_oidc_app(
                    service=self.service,
                    public_origin=ORIGIN,
                    portal_service=self.service if portal else None,
                    admin_services=cast(Phase6Services, self.portal) if portal else None,
                )
            ),
            base_url=ORIGIN,
            follow_redirects=False,
        )

    def authorize(self, kind: str = "customer", **changes: str) -> Response:
        params = {
            "client_id": kind,
            "redirect_uri": f"https://{kind}.example.test/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "state": "state-1",
            "nonce": "nonce-1",
            "code_challenge": sha256_base64url(VERIFIER),
            "code_challenge_method": "S256",
        }
        params.update(changes)
        return cast(Response, self.client.get("/oauth2/authorize", params=params))

    def login(self) -> Response:
        started = self.authorize(prompt="login")
        assert started.status_code == 303
        page = self.client.get(started.headers["location"])
        transaction = re.search(r'name="transaction" value="([^"]+)"', page.text)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert transaction is not None and csrf is not None
        response = self.client.post(
            "/oauth2/login",
            headers={"origin": ORIGIN},
            data={
                "transaction": transaction[1],
                "csrf_token": csrf[1],
                "email": "employee@example.test",
                "password": "password",
            },
        )
        return cast(Response, response)

    def exchange(self, response: Response, kind: str = "customer") -> Response:
        code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        response = self.client.post(
            "/oauth2/token",
            auth=(kind, "client-secret"),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"https://{kind}.example.test/callback",
                "code_verifier": VERIFIER,
            },
        )
        return response


def test_interactive_cookie_is_secure_opaque_and_sso_does_not_reprompt() -> None:
    rig = Rig()
    response = rig.login()
    assert response.status_code == 303
    token = rig.client.cookies[SSO_COOKIE_NAME]
    cookies = response.headers.get_list("set-cookie")
    central = next(v for v in cookies if v.startswith(SSO_COOKIE_NAME + "="))
    assert all(
        x in central for x in ("HttpOnly", "Secure", "SameSite=lax", "Path=/", "Max-Age=28800")
    )
    assert "Domain=" not in central
    assert token not in response.headers["location"]
    assert token.encode() not in session_key(token)
    assert b'"version":0' in rig.redis.values[session_key(token)]
    assert SSO_SESSION_TTL_SECONDS in rig.redis.ttls
    first_auth = rig.now
    rig.now += 30
    reused = rig.authorize("staff")
    assert reused.status_code == 303
    assert reused.headers["location"].startswith("https://staff.example.test/callback?code=")
    assert rig.identities.lookups >= 2
    assert rig.audit.events[-1].details_json == {"clientId": "staff", "loginMethod": "sso"}
    assert not reused.headers.get_list("set-cookie")  # No sliding expiry.
    assert rig.exchange(reused, "staff").status_code == 200
    assert rig.signer.auth_time == first_auth


@pytest.mark.parametrize(
    "change", [{"prompt": "login"}, {"prompt": "select_account"}, {"max_age": "0"}]
)
def test_force_reauthentication_even_with_central_session(change: dict[str, str]) -> None:
    rig = Rig()
    rig.login()
    response = rig.authorize(**change)
    assert response.headers["location"].startswith("/oauth2/login?")


def test_prompt_none_returns_login_required_without_ui_and_preserves_state() -> None:
    rig = Rig()
    response = rig.authorize(prompt="none")
    values = parse_qs(urlsplit(response.headers["location"]).query)
    assert values["error"] == ["login_required"]
    assert values["state"] == ["state-1"]
    assert not rig.redis.values
    rig.login()
    assert "?code=" in rig.authorize("staff", prompt="none").headers["location"]


def test_max_age_uses_original_authentication_and_absolute_expiry() -> None:
    rig = Rig()
    rig.login()
    rig.now += 61
    assert rig.authorize(max_age="60").headers["location"].startswith("/oauth2/login?")
    assert "error=login_required" in rig.authorize(max_age="60", prompt="none").headers["location"]
    assert "?code=" in rig.authorize().headers["location"]
    rig.now += SSO_SESSION_TTL_SECONDS
    assert "error=login_required" in rig.authorize(prompt="none").headers["location"]


@pytest.mark.parametrize("kind", [None, "CUSTOMER"])
def test_customer_with_mistaken_staff_role_is_denied_by_sso(kind: str | None) -> None:
    rig = Rig()
    rig.identities.user = replace(rig.identities.user, user_type=kind)
    rig.login()
    result = rig.authorize("staff")
    assert "error=access_denied" in result.headers["location"]
    assert "?code=" in rig.authorize("customer").headers["location"]


@pytest.mark.parametrize("change", ["role", "type", "suspend", "version"])
def test_sso_rechecks_live_identity_and_revocation_version(change: str) -> None:
    rig = Rig()
    rig.login()
    user = rig.identities.user
    if change == "role":
        user = replace(user, roles=())
    elif change == "type":
        user = replace(user, user_type="CUSTOMER")
    elif change == "suspend":
        user = replace(user, status=UserStatus.SUSPENDED)
    else:
        user = replace(user, session_version=1)
    rig.identities.user = user
    response = rig.authorize("staff", prompt="none")
    expected = "login_required" if change in {"version", "suspend"} else "access_denied"
    assert "error=" + expected in response.headers["location"]


def test_admin_revocation_blocks_unexchanged_code_and_issued_userinfo_bearer() -> None:
    rig = Rig()
    issued = rig.exchange(rig.login()).json()
    code = rig.authorize()
    rig.identities.user = replace(rig.identities.user, session_version=1)
    assert rig.exchange(code).json()["error"] == "invalid_grant"
    result = rig.client.get(
        "/oauth2/userinfo", headers={"authorization": "Bearer " + issued["access_token"]}
    )
    assert result.status_code == 401


def test_interactive_login_rotates_previous_central_session() -> None:
    rig = Rig()
    rig.login()
    old = rig.client.cookies[SSO_COOKIE_NAME]
    rig.login()
    assert rig.client.cookies[SSO_COOKIE_NAME] != old
    assert session_key(old) not in rig.redis.values


def test_audit_failure_discards_new_session_and_code() -> None:
    rig = Rig()
    rig.audit.fail = True
    response = rig.login()
    assert response.status_code == 500
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert not any(
        key.startswith((b"wiseacct:sso:session:", b"wiseacct:oidc:code:"))
        for key in rig.redis.values
        if isinstance(key, bytes)
    )


def test_logout_requires_same_origin_and_csrf_and_get_does_not_logout() -> None:
    rig = Rig()
    rig.login()
    token = rig.client.cookies[SSO_COOKIE_NAME]
    page = rig.client.get("/oauth2/session")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert page.headers["referrer-policy"] == "same-origin"
    assert page.headers["cache-control"] == "no-store"
    assert csrf is not None
    assert session_key(token) in rig.redis.values
    for headers, value in [
        ({}, csrf[1]),
        ({"origin": "https://evil.example.test"}, csrf[1]),
        ({"origin": ORIGIN}, "wrong"),
    ]:
        response = rig.client.post(
            "/oauth2/session/logout", headers=headers, data={"csrf_token": value}
        )
        assert response.status_code == 400
        assert session_key(token) in rig.redis.values
    response = rig.client.post(
        "/oauth2/session/logout", headers={"origin": ORIGIN}, data={"csrf_token": csrf[1]}
    )
    assert response.status_code == 200
    assert session_key(token) not in rig.redis.values
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert "error=login_required" in rig.authorize(prompt="none").headers["location"]
    assert rig.audit.events[-1].event_type == "oidc_session_logout"


@pytest.mark.parametrize("age", ["-1", "1.5", "abc", "2147483648", "\u0661"])
def test_bad_max_age_does_not_create_transaction(age: str) -> None:
    rig = Rig()
    assert rig.authorize(max_age=age).status_code == 400
    assert not rig.redis.values


def test_invalid_redirect_is_never_used_even_with_valid_session() -> None:
    rig = Rig()
    rig.login()
    response = rig.authorize(redirect_uri="https://evil.example.test/")
    assert response.status_code == 400
    assert "location" not in response.headers


def test_redis_outage_does_not_fall_back_to_authorized_redirect() -> None:
    rig = Rig()
    rig.login()
    rig.redis.broken = True
    response = rig.authorize("staff")
    assert response.status_code == 500
    assert "location" not in response.headers


@pytest.mark.anyio
async def test_session_store_rejects_tampered_records_and_revoked_tokens() -> None:
    redis = Redis()
    store = SsoSessionStore(redis, clock=lambda: 100)
    token = await store.create("user-1", 0, 99)
    assert await store.get(token) is not None
    original = json.loads(redis.values[session_key(token)])
    for changes in (
        {"authTime": 101},
        {"version": True},
        {"expiresAt": 100},
        {"csrf": "bad"},
        {"extra": 1},
    ):
        redis.values[session_key(token)] = json.dumps(original | changes).encode()
        assert await store.get(token) is None
    redis.values[session_key(token)] = json.dumps(original).encode()
    await store.revoke(token)
    assert await store.get(token) is None
    assert await store.get("not-a-session") is None


def test_password_changed_during_authentication_cannot_mint_central_session() -> None:
    rig = Rig()

    class ConcurrentResetHasher:
        async def verify_password(self, hashed: str, password: str) -> bool:
            rig.passwords.hash = "changed-by-password-reset"
            return True

    rig.service._passwords = cast(AsyncPasswordHasher, ConcurrentResetHasher())
    response = rig.login()
    assert response.status_code == 400
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert not any(
        isinstance(key, bytes) and key.startswith(b"wiseacct:sso:session:")
        for key in rig.redis.values
    )


def test_signed_id_token_preserves_original_authentication_time(
    synthetic_settings: Settings,
) -> None:
    signer = OidcIdTokenSigner.from_settings(synthetic_settings)
    auth_time = int(time.time()) - 120
    identity = OidcIdTokenIdentity("user-1", "employee@example.test", True, None, ("staff:user",))
    token = signer.issue(identity, client_id="staff", nonce="nonce-1", auth_time=auth_time)
    claims = jwt.decode(
        token,
        jwt.PyJWK.from_dict(synthetic_settings.jwt_access_public_jwk.model_dump()).key,
        algorithms=["RS256"],
        audience="staff",
        issuer=synthetic_settings.jwt_issuer,
    )
    assert claims["auth_time"] == auth_time < claims["iat"]
    assert claims["nonce"] == "nonce-1"
    with pytest.raises(ValueError, match="authentication time"):
        signer.issue(identity, client_id="staff", auth_time=True)


@pytest.mark.parametrize("change", ["version", "suspended"])
def test_central_session_page_does_not_report_revoked_identity_as_logged_in(change: str) -> None:
    rig = Rig()
    rig.login()
    token = rig.client.cookies[SSO_COOKIE_NAME]
    rig.identities.user = replace(
        rig.identities.user,
        session_version=1 if change == "version" else 0,
        status=UserStatus.SUSPENDED if change == "suspended" else UserStatus.ACTIVE,
    )
    response = rig.client.get("/oauth2/session")
    assert "세션이 없습니다" in response.text
    assert "csrf_token" not in response.text
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert session_key(token) not in rig.redis.values


def admin_rig() -> Rig:
    rig = Rig(portal=True)
    rig.identities.user = replace(
        rig.identities.user, roles=(*rig.identities.user.roles, RoleAssignment("sso", "admin"))
    )
    return rig


def admin_form(rig: Rig) -> dict[str, str]:
    page = rig.client.get("/oauth2/admin/login?reauth=1")
    assert page.status_code == 200
    assert page.headers["referrer-policy"] == "same-origin"
    assert 'action="/oauth2/admin/login"' in page.text
    tx = re.search(r'name="transaction" value="([^"]+)"', page.text)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert tx is not None and csrf is not None
    return {
        "transaction": tx[1],
        "csrf_token": csrf[1],
        "email": "employee@example.test",
        "password": "password",
    }


def admin_login(rig: Rig) -> Response:
    return cast(
        Response,
        rig.client.post("/oauth2/admin/login", headers={"origin": ORIGIN}, data=admin_form(rig)),
    )


def admin_csrf(rig: Rig) -> str:
    page = rig.client.get("/oauth2/admin/dashboard")
    assert page.status_code == 200
    match = re.search(r'name="admin-session-csrf" content="([^"]+)"', page.text)
    assert match is not None
    return match[1]


def test_admin_password_login_enters_dashboard_without_browser_bearer_token() -> None:
    rig = admin_rig()
    assert rig.client.get("/oauth2/admin/dashboard").headers["location"] == "/oauth2/admin/login"
    response = admin_login(rig)
    assert response.status_code == 303
    assert response.headers["location"] == ORIGIN + "/oauth2/admin/dashboard"
    token = rig.client.cookies[SSO_COOKIE_NAME]
    page = rig.client.get(response.headers["location"])
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert 'name="admin-auth-mode" content="session"' in page.text
    assert 'content="/oauth2/admin/api"' in page.text
    assert "Bearer token" not in page.text and "관리자 Access Token" not in page.text
    assert token not in page.text and token not in response.headers["location"]
    assert rig.audit.events[-1].event_type == "admin_browser_login"
    users = rig.client.get("/oauth2/admin/api/users")
    assert users.status_code == 200
    assert users.json()["items"][0]["id"] == "user-1"
    assert users.headers["cache-control"] == "no-store"
    assert (
        "?code=" in rig.authorize("staff").headers["location"]
    )  # Admin login also creates central SSO.


def test_admin_reuses_recent_central_session_without_password_prompt() -> None:
    rig = admin_rig()
    rig.login()
    token = rig.client.cookies[SSO_COOKIE_NAME]
    assert rig.client.get("/oauth2/admin/login").headers["location"] == "/oauth2/admin/dashboard"
    assert rig.client.get("/oauth2/admin/dashboard").status_code == 200
    assert rig.client.cookies[SSO_COOKIE_NAME] == token


@pytest.mark.parametrize("kind,admin_role", [("CUSTOMER", True), (None, True), ("EMPLOYEE", False)])
def test_admin_login_denies_non_employees_and_users_without_admin_role(
    kind: str | None, admin_role: bool
) -> None:
    rig = admin_rig()
    rig.identities.user = replace(
        rig.identities.user,
        user_type=kind,
        roles=rig.identities.user.roles if admin_role else (RoleAssignment("staff", "user"),),
    )
    response = admin_login(rig)
    assert response.status_code == 403
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert not rig.portal.calls
    assert rig.audit.events[-1].event_type == "admin_authorization_failure"


def test_admin_wrong_password_preserves_retry_but_does_not_mint_cookie() -> None:
    rig = admin_rig()
    data = admin_form(rig)
    response = rig.client.post(
        "/oauth2/admin/login", headers={"origin": ORIGIN}, data=data | {"password": "wrong"}
    )
    assert response.status_code == 401
    assert "이메일 또는 비밀번호" in response.text
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert rig.failures.count == 1
    assert (
        rig.client.post("/oauth2/admin/login", headers={"origin": ORIGIN}, data=data).status_code
        == 303
    )


def test_admin_session_needs_fresh_authentication_and_live_permissions() -> None:
    rig = admin_rig()
    admin_login(rig)
    rig.now += 900
    assert rig.client.get("/oauth2/admin/api/users").status_code == 401
    assert rig.client.get("/oauth2/admin/dashboard").status_code == 303
    assert rig.client.get("/oauth2/admin/login").status_code == 200
    admin_login(rig)
    rig.identities.user = replace(rig.identities.user, roles=(RoleAssignment("staff", "user"),))
    assert rig.client.get("/oauth2/admin/api/users").status_code == 403
    assert rig.client.get("/oauth2/admin/dashboard").status_code == 403
    assert not rig.portal.calls


@pytest.mark.parametrize("change", ["suspend", "version", "type", "email"])
def test_admin_cookie_does_not_bypass_updated_database_policy(change: str) -> None:
    rig = admin_rig()
    admin_login(rig)
    original = rig.identities.user
    rig.identities.user = {
        "suspend": replace(original, status=UserStatus.SUSPENDED),
        "version": replace(original, session_version=1),
        "type": replace(original, user_type="CUSTOMER"),
        "email": replace(original, email_verified=False),
    }[change]
    response = rig.client.get("/oauth2/admin/api/users")
    assert response.status_code in (401, 403)
    assert not rig.portal.calls


def test_admin_browser_api_requires_cookie_even_if_bearer_header_is_supplied() -> None:
    rig = admin_rig()
    response = rig.client.get(
        "/oauth2/admin/api/users", headers={"authorization": "Bearer forged-or-valid-legacy-token"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "ADMIN_LOGIN_REQUIRED"


def test_admin_browser_mutations_need_same_origin_csrf_and_bounded_json() -> None:
    rig = admin_rig()
    admin_login(rig)
    csrf = admin_csrf(rig)
    data = {"userIds": ["target"], "userType": "EMPLOYEE"}
    url = "/oauth2/admin/api/users/type"
    for headers in (
        {},
        {"origin": "https://evil.example.test", "x-admin-csrf": csrf},
        {"origin": ORIGIN},
        {"origin": ORIGIN, "x-admin-csrf": "wrong"},
    ):
        assert rig.client.patch(url, headers=headers, json=data).status_code == 403
    headers = {"origin": ORIGIN, "x-admin-csrf": csrf}
    assert (
        rig.client.patch(
            url, headers=headers | {"content-type": "text/plain"}, content="{}"
        ).status_code
        == 400
    )
    assert (
        rig.client.patch(
            url, headers=headers | {"content-type": "application/json"}, content="x" * 32769
        ).status_code
        == 413
    )
    assert not rig.portal.calls
    response = rig.client.patch(url, headers=headers, json=data)
    assert response.status_code == 200
    assert rig.portal.calls[-1][1] == {
        "actor_user_id": "user-1",
        "target_user_ids": ("target",),
        "user_type": "EMPLOYEE",
        "reason_code": "ADMIN_BULK_USER_TYPE_CHANGE",
    }


def test_admin_logout_is_csrf_protected_and_clears_central_authentication() -> None:
    rig = admin_rig()
    admin_login(rig)
    csrf = admin_csrf(rig)
    token = rig.client.cookies[SSO_COOKIE_NAME]
    assert rig.client.get("/oauth2/admin/logout").status_code == 405
    assert rig.client.post("/oauth2/admin/logout", data={"csrf_token": csrf}).status_code == 400
    response = rig.client.post(
        "/oauth2/admin/logout", headers={"origin": ORIGIN}, data={"csrf_token": csrf}
    )
    assert response.status_code == 303
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert session_key(token) not in rig.redis.values
    assert rig.client.get("/oauth2/admin/api/users").status_code == 401


def test_admin_login_and_regular_oidc_transactions_cannot_be_substituted() -> None:
    rig = admin_rig()
    admin = admin_form(rig)
    assert (
        rig.client.post("/oauth2/login", headers={"origin": ORIGIN}, data=admin).status_code == 400
    )
    response = rig.authorize()
    page = rig.client.get(response.headers["location"])
    tx = re.search(r'name="transaction" value="([^"]+)"', page.text)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert tx is not None and csrf is not None
    body = {
        "transaction": tx[1],
        "csrf_token": csrf[1],
        "email": "employee@example.test",
        "password": "password",
    }
    assert (
        rig.client.post("/oauth2/admin/login", headers={"origin": ORIGIN}, data=body).status_code
        == 400
    )
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert admin_login(rig).status_code == 303


def test_admin_audit_failure_cleans_prepared_session() -> None:
    rig = admin_rig()
    rig.audit.fail = True
    response = admin_login(rig)
    assert response.status_code == 500
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert not any(
        isinstance(k, bytes) and k.startswith(b"wiseacct:sso:session:") for k in rig.redis.values
    )


def test_admin_login_has_no_open_redirect_and_escapes_identity(
    synthetic_settings: Settings,
) -> None:
    from wiseacct_sso.main import create_app

    rig = admin_rig()
    assert (
        rig.client.get("/oauth2/admin/login?return_to=https://evil.example.test").status_code == 400
    )
    admin_login(rig)
    rig.identities.user = replace(rig.identities.user, email='<img src=x onerror="bad()">')
    page = rig.client.get("/oauth2/admin/dashboard")
    assert "<img src=x" not in page.text
    assert "&lt;img" in page.text
    app = create_app(
        settings=synthetic_settings.model_copy(
            update={"oidc_enabled": True, "oidc_public_origin": ORIGIN}
        ),
        oidc_app=rig.client.app,
    )
    with TestClient(app, base_url="http://untrusted.example", follow_redirects=False) as client:
        response = client.get("/manage/dashboard")
    assert response.status_code == 303
    assert response.headers["location"] == ORIGIN + "/oauth2/admin/dashboard"
    assert response.headers["cache-control"] == "no-store"


def test_admin_login_origin_csrf_and_single_use_transaction() -> None:
    rig = admin_rig()
    form = admin_form(rig)
    cookies = dict(rig.client.cookies)
    assert rig.client.post("/oauth2/admin/login", data=form).status_code == 400
    assert (
        rig.client.post(
            "/oauth2/admin/login", data=form, headers={"origin": "https://evil.example.test"}
        ).status_code
        == 400
    )
    assert (
        rig.client.post(
            "/oauth2/admin/login", data=form | {"csrf_token": "bad"}, headers={"origin": ORIGIN}
        ).status_code
        == 400
    )
    assert SSO_COOKIE_NAME not in rig.client.cookies
    assert (
        rig.client.post("/oauth2/admin/login", data=form, headers={"origin": ORIGIN}).status_code
        == 303
    )
    rig.client.cookies.update(cookies)
    assert (
        rig.client.post("/oauth2/admin/login", data=form, headers={"origin": ORIGIN}).status_code
        == 400
    )


def test_admin_browser_api_authenticates_before_reading_invalid_json() -> None:
    rig = admin_rig()
    response = rig.client.patch(
        "/oauth2/admin/api/users/type",
        content="invalid-json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "ADMIN_LOGIN_REQUIRED"
    assert not rig.portal.calls


def test_admin_login_transaction_expires_without_creating_a_session() -> None:
    rig = admin_rig()
    form = admin_form(rig)
    rig.now += 601
    assert (
        rig.client.post("/oauth2/admin/login", data=form, headers={"origin": ORIGIN}).status_code
        == 400
    )
    assert SSO_COOKIE_NAME not in rig.client.cookies


@pytest.mark.anyio
async def test_live_admin_login_check_exercises_cookie_flow_without_tokens(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    synthetic_settings: Settings,
) -> None:
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace

    import httpx

    from wiseacct_sso.main import create_app

    rig = admin_rig()
    employee = rig.identities.user
    customer = replace(
        employee,
        id="customer-id",
        email="customer@example.test",
        user_type="CUSTOMER",
        roles=(RoleAssignment("customer", "user"),),
    )
    unapproved = replace(employee, id="unapproved-id", email="unapproved@example.test", roles=())
    catalog = {user.email or "": user for user in (employee, customer, unapproved)}
    rig.portal.catalog = catalog
    rig.portal.noop = True

    class MultiPasswords(Passwords):
        async def find_credential_by_email(
            self, connection: AsyncConnection, *, email: str
        ) -> PasswordCredentialRecord:
            user = catalog[email]
            self.identities.user = user
            return PasswordCredentialRecord(user.id, email, "hash", 0, None, user.status)

    rig.service._password_store = cast(PasswordAuthStore, MultiPasswords(rig.identities))
    app = create_app(
        settings=synthetic_settings.model_copy(
            update={"oidc_enabled": True, "oidc_public_origin": ORIGIN}
        ),
        oidc_app=rig.client.app,
    )
    script = Path(__file__).parents[3] / "integration-lab/admin-login-check.py"
    spec = importlib.util.spec_from_file_location("admin_login_check", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ORIGIN", ORIGIN)
    fixtures = [
        {"name": name, "email": user.email, "password": "password"}
        for name, user in [
            ("employee", employee),
            ("customer", customer),
            ("unapproved", unapproved),
        ]
    ]
    monkeypatch.setattr(
        module, "Path", lambda _: SimpleNamespace(read_text=lambda: json.dumps(fixtures))
    )
    monkeypatch.setattr(
        module.Loopback,
        "__init__",
        lambda self: setattr(self, "transport", httpx.ASGITransport(app=app)),
    )
    for key, value in {
        "DATABASE_URL": "postgresql://synthetic@postgres/fastapi_sso_dev",
        "NODE_ENV": "development",
        "JWT_ISSUER": ORIGIN,
    }.items():
        monkeypatch.setenv(key, value)
    await module.main()
    assert capsys.readouterr().out.count("PASS:") == 7
