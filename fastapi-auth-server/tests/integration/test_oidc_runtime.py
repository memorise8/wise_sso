"""Opt-in black-box OIDC proof against disposable PostgreSQL and Redis targets."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import signal
import sys
from hashlib import sha256
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import httpx
import jwt
import pytest
from dotenv import dotenv_values
from sqlalchemy import delete, func, insert, select

from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    PasswordCredential,
    RefreshToken,
    Role,
    User,
    UserRole,
    UserStatus,
    utc_now_ms,
)

ENABLED = os.getenv("WISEACCT_OIDC_RUNTIME_INTEGRATION") == "1"
DATABASE_URL = os.getenv("WISEACCT_OIDC_RUNTIME_DATABASE_URL", "")
REDIS_URL = os.getenv("WISEACCT_OIDC_RUNTIME_REDIS_URL", "")
HTTP_PORT_TEXT = os.getenv("WISEACCT_OIDC_RUNTIME_HTTP_PORT", "")
RUN_ID = os.getenv("WISEACCT_OIDC_RUNTIME_RUN_ID", "")

ENV_FILE = Path(__file__).parents[2] / ".env.example"
PUBLIC_ORIGIN = "https://auth.oidc-runtime.invalid"
CLIENT_ID = "cloudflare-access-oidc-runtime"
CLIENT_SECRET = "oidc-runtime-client-secret"
CLIENT_SECRET_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$CjHmYITMY8aZFKbiLQO3wA$"
    "iaIIV9u53MAEtTDwvhtNMxVnbW1DSrwukKKjimiv06c"
)
REDIRECT_URI = "https://oidc-runtime.cloudflareaccess.invalid/cdn-cgi/access/callback"
PASSWORD = "express-fixture-password"
PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ABEiM0RVZneImaq7zN3u/w$"
    "zeuaFYFAbBFiUM3IwmEtHtc4d61aWWRsUGaZIOShyuI"
)
VERIFIER = "oidc-runtime-verifier-that-is-long-enough-00000001"
CHALLENGE = (
    base64.urlsafe_b64encode(sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode("ascii")
)
_DISALLOWED_PORTS = {4000, 4001, 5432, 5433, 6379, 6380}


def _guarded_targets() -> int:
    database = urlparse(DATABASE_URL)
    redis = urlparse(REDIS_URL)
    try:
        http_port = int(HTTP_PORT_TEXT)
    except ValueError:
        http_port = 0
    database_name = database.path.removeprefix("/").lower()
    disposable_name = any(marker in database_name for marker in ("test", "contract", "fixture"))
    ports = {database.port, redis.port, http_port}
    if (
        database.scheme != "postgresql+asyncpg"
        or database.hostname != "127.0.0.1"
        or database.port is None
        or not disposable_name
        or not (database.username or "").startswith("oidc_runtime_")
        or redis.scheme != "redis"
        or redis.hostname != "127.0.0.1"
        or redis.port is None
        or redis.path != "/15"
        or redis.username is not None
        or redis.password is not None
        or not 10_000 <= http_port <= 65_535
        or any(port in _DISALLOWED_PORTS for port in ports)
        or len(ports) != 3
        or re.fullmatch(r"[A-Za-z0-9_]+", RUN_ID) is None
    ):
        raise RuntimeError("OIDC integration requires unique guarded loopback-only test targets")
    return http_port


HTTP_PORT = _guarded_targets() if ENABLED else 0
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not ENABLED, reason="OIDC isolated runtime integration only"),
]


def _runtime_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in dotenv_values(ENV_FILE).items() if value is not None
    }
    environment.update(
        {
            "PATH": os.environ.get("PATH", ""),
            "NODE_ENV": "test",
            "DATABASE_URL": DATABASE_URL,
            "REDIS_URL": REDIS_URL,
            "PORT": str(HTTP_PORT),
            "OIDC_ENABLED": "true",
            "OIDC_PUBLIC_ORIGIN": PUBLIC_ORIGIN,
            "OIDC_CLIENTS_JSON": json.dumps(
                [
                    {
                        "clientId": CLIENT_ID,
                        "redirectUris": [REDIRECT_URI],
                        "clientSecretHash": CLIENT_SECRET_HASH,
                        "requiredRoles": [{"serviceKey": "agent-hub", "name": "user"}],
                        "groupsServiceKeys": ["agent-hub"],
                        "requirePkce": True,
                        "allowedScopes": ["openid", "email", "profile"],
                    }
                ],
                separators=(",", ":"),
            ),
            "OAUTH_ENABLED_PROVIDERS": "",
        }
    )
    return environment


async def _wait_until_ready(client: httpx.AsyncClient, process: asyncio.subprocess.Process) -> None:
    for _ in range(150):
        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            pytest.fail(
                "guarded OIDC runtime exited before becoming ready:\n"
                + (stdout + stderr).decode(errors="replace")
            )
        try:
            response = await client.get("/readyz")
            if response.status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.05)
    pytest.fail("guarded OIDC runtime did not become ready")


def _transaction_cookies(response: httpx.Response) -> tuple[str, str]:
    cookies = dict(response.cookies.items())
    assert any("_binding_" in name for name in cookies)
    csrf = next(value for name, value in cookies.items() if "_csrf_" in name)
    return "; ".join(f"{name}={value}" for name, value in cookies.items()), csrf


async def _authorization_code(
    client: httpx.AsyncClient,
    *,
    email: str,
    state: str,
    nonce: str,
) -> str:
    start = await client.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": CHALLENGE,
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert start.status_code == 303
    login_location = start.headers["location"]
    transaction = parse_qs(urlparse(login_location).query)["transaction"][0]
    cookie_header, csrf = _transaction_cookies(start)
    login = await client.post(
        "/oauth2/login",
        data={
            "transaction": transaction,
            "csrf_token": csrf,
            "email": email,
            "password": PASSWORD,
        },
        headers={"origin": PUBLIC_ORIGIN, "cookie": cookie_header},
        follow_redirects=False,
    )
    assert login.status_code == 303, login.text
    callback = urlparse(login.headers["location"])
    values = parse_qs(callback.query)
    assert values["state"] == [state]
    return values["code"][0]


async def _exchange(
    client: httpx.AsyncClient,
    code: str,
    *,
    method: str = "basic",
) -> httpx.Response:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
    }
    if method == "post":
        form.update({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET})
        return await client.post("/oauth2/token", data=form)
    return await client.post(
        "/oauth2/token", data=form, auth=httpx.BasicAuth(CLIENT_ID, CLIENT_SECRET)
    )


async def _set_role(database: Database, *, user_id: str, role_id: str, present: bool) -> None:
    async with database.engine.begin() as connection:
        await connection.execute(
            delete(UserRole).where(UserRole.c.userId == user_id, UserRole.c.roleId == role_id)
        )
        if present:
            await connection.execute(
                insert(UserRole).values(id=f"ur-{uuid4()}", userId=user_id, roleId=role_id)
            )


async def test_oidc_password_code_token_userinfo_and_revocation_runtime() -> None:
    database = Database(DATABASE_URL)
    user_id = f"oidc-runtime-user-{RUN_ID}"
    role_id = f"oidc-runtime-role-{RUN_ID}"
    email = f"oidc-runtime-{RUN_ID}@integration.invalid"
    now = utc_now_ms()
    async with database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=email,
                name="OIDC Runtime User",
                status=UserStatus.ACTIVE,
                emailVerified=True,
                createdAt=now,
                updatedAt=now,
            )
        )
        await connection.execute(
            insert(PasswordCredential).values(
                id=f"oidc-runtime-credential-{RUN_ID}",
                userId=user_id,
                email=email,
                passwordHash=PASSWORD_HASH,
                createdAt=now,
                updatedAt=now,
            )
        )
        await connection.execute(
            insert(Role).values(id=role_id, serviceKey="agent-hub", name="user")
        )
        await connection.execute(
            insert(UserRole).values(
                id=f"oidc-runtime-user-role-{RUN_ID}", userId=user_id, roleId=role_id
            )
        )

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "uvicorn",
        "wiseacct_sso.main:create_runtime_app",
        "--factory",
        "--host",
        "127.0.0.1",
        "--port",
        str(HTTP_PORT),
        "--no-access-log",
        "--no-server-header",
        "--no-proxy-headers",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_runtime_environment(),
    )
    observed_tokens: list[str] = []
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{HTTP_PORT}", timeout=3.0
        ) as client:
            await _wait_until_ready(client, process)

            basic_code = await _authorization_code(
                client, email=email, state="basic-state", nonce="basic-nonce"
            )
            basic = await _exchange(client, basic_code)
            assert basic.status_code == 200, basic.text
            basic_payload = basic.json()
            observed_tokens.extend([basic_payload["access_token"], basic_payload["id_token"]])

            jwks = (await client.get("/.well-known/jwks.json")).json()
            key = jwt.PyJWK.from_dict(jwks["keys"][0], algorithm="RS256").key
            claims = jwt.decode(
                basic_payload["id_token"],
                key,
                algorithms=["RS256"],
                audience=CLIENT_ID,
                issuer="https://fastapi-dev.invalid",
            )
            assert claims["sub"] == user_id
            assert claims["nonce"] == "basic-nonce"
            assert claims["groups"] == ["agent-hub:user"]
            assert claims["email_verified"] is True

            userinfo = await client.get(
                "/oauth2/userinfo",
                headers={"authorization": f"Bearer {basic_payload['access_token']}"},
            )
            assert userinfo.status_code == 200
            assert userinfo.json() == {
                "sub": user_id,
                "email": email,
                "email_verified": True,
                "name": "OIDC Runtime User",
                "groups": ["agent-hub:user"],
            }

            post_code = await _authorization_code(
                client, email=email, state="post-state", nonce="post-nonce"
            )
            post = await _exchange(client, post_code, method="post")
            assert post.status_code == 200, post.text
            observed_tokens.extend([post.json()["access_token"], post.json()["id_token"]])

            race_code = await _authorization_code(
                client, email=email, state="replay-state", nonce="replay-nonce"
            )
            replay_responses = await asyncio.gather(
                *(_exchange(client, race_code) for _ in range(6))
            )
            assert [response.status_code for response in replay_responses].count(200) == 1
            assert [response.status_code for response in replay_responses].count(400) == 5
            assert all(
                response.json().get("error") == "invalid_grant"
                for response in replay_responses
                if response.status_code == 400
            )
            replay_success = next(
                response.json() for response in replay_responses if response.status_code == 200
            )
            observed_tokens.extend([replay_success["access_token"], replay_success["id_token"]])

            revoke_code = await _authorization_code(
                client, email=email, state="lock-state", nonce="lock-nonce"
            )
            async with database.engine.connect() as connection:
                transaction = await connection.begin()
                await connection.execute(
                    select(User.c.id).where(User.c.id == user_id).with_for_update()
                )
                await connection.execute(
                    delete(UserRole).where(
                        UserRole.c.userId == user_id, UserRole.c.roleId == role_id
                    )
                )
                blocked_exchange = asyncio.create_task(_exchange(client, revoke_code))
                await asyncio.sleep(0.15)
                assert not blocked_exchange.done(), "token exchange bypassed the user-row lock"
                await transaction.commit()
            denied = await asyncio.wait_for(blocked_exchange, timeout=3)
            assert denied.status_code == 400
            assert denied.json()["error"] == "invalid_grant"
            replay = await _exchange(client, revoke_code)
            assert replay.status_code == 400
            assert replay.json()["error"] == "invalid_grant"

            await _set_role(database, user_id=user_id, role_id=role_id, present=True)
            revocable_code = await _authorization_code(
                client, email=email, state="userinfo-state", nonce="userinfo-nonce"
            )
            revocable = await _exchange(client, revocable_code)
            assert revocable.status_code == 200
            revocable_access = revocable.json()["access_token"]
            observed_tokens.extend([revocable_access, revocable.json()["id_token"]])
            await _set_role(database, user_id=user_id, role_id=role_id, present=False)
            revoked_userinfo = await client.get(
                "/oauth2/userinfo",
                headers={"authorization": f"Bearer {revocable_access}"},
            )
            assert revoked_userinfo.status_code == 401
            assert revoked_userinfo.json()["error"] == "invalid_token"
            assert (
                await client.get(
                    "/oauth2/userinfo",
                    headers={"authorization": f"Bearer {revocable_access}"},
                )
            ).status_code == 401
    finally:
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()

    runtime_output = stdout + stderr
    assert process.returncode == 0, runtime_output.decode(errors="replace")
    assert PASSWORD.encode() not in runtime_output
    assert CLIENT_SECRET.encode() not in runtime_output
    assert all(token.encode() not in runtime_output for token in observed_tokens)

    async with database.connection() as connection:
        refresh_count = await connection.scalar(select(func.count()).select_from(RefreshToken))
        audit_rows = (
            await connection.execute(
                select(
                    AuditLog.c.eventType,
                    AuditLog.c.outcome,
                    AuditLog.c.reasonCode,
                    AuditLog.c.serviceKey,
                    AuditLog.c.detailsJson,
                )
                .where(AuditLog.c.userId == user_id)
                .order_by(AuditLog.c.createdAt, AuditLog.c.id)
            )
        ).all()
    await database.close()

    assert refresh_count == 0
    assert (
        sum(row.eventType == "oidc_authorize" and row.outcome == "success" for row in audit_rows)
        == 5
    )
    assert (
        sum(row.eventType == "oidc_token" and row.outcome == "success" for row in audit_rows) == 4
    )
    assert any(
        row.eventType == "oidc_token"
        and row.outcome == "failure"
        and row.reasonCode == "OIDC_REQUIRED_ROLE_MISSING"
        for row in audit_rows
    )
    assert all(row.serviceKey is None for row in audit_rows)
    assert all(
        row.detailsJson is not None and row.detailsJson.get("clientId") == CLIENT_ID
        for row in audit_rows
    )
    serialized_audits = json.dumps(
        [dict(row._mapping) for row in audit_rows], default=str, sort_keys=True
    )
    for sensitive in (PASSWORD, CLIENT_SECRET, VERIFIER, *observed_tokens):
        assert sensitive not in serialized_audits
