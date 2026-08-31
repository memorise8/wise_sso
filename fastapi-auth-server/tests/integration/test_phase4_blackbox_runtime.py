"""Black-box TCP smoke for the guarded Phase 4 runtime."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import pytest
from dotenv import dotenv_values
from sqlalchemy import insert, select

from wiseacct_sso.infrastructure.security import sha256_token
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    PasswordCredential,
    RefreshToken,
    User,
    UserStatus,
    utc_now_ms,
)

ENV_FILE = Path(__file__).parents[2] / ".env.example"
PHASE4_ENABLED = os.getenv("WISEACCT_PHASE4_INTEGRATION") == "1"
RUNTIME_URL = os.getenv("WISEACCT_PHASE4_DATABASE_URL", "")
REDIS_URL = os.getenv("WISEACCT_PHASE4_REDIS_URL", "")
HTTP_PORT_TEXT = os.getenv("WISEACCT_PHASE4_HTTP_PORT", "")
NODE_PASSWORD = "express-fixture-password"
NODE_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ABEiM0RVZneImaq7zN3u/w$"
    "zeuaFYFAbBFiUM3IwmEtHtc4d61aWWRsUGaZIOShyuI"
)


def _require_guarded_targets() -> int:
    database = urlparse(RUNTIME_URL)
    redis = urlparse(REDIS_URL)
    try:
        port = int(HTTP_PORT_TEXT)
    except ValueError:
        port = 0
    if (
        database.hostname != "127.0.0.1"
        or database.port != 5433
        or "_test_" not in database.path
        or redis.hostname != "127.0.0.1"
        or redis.port != 6380
        or redis.path != "/15"
        or port != 4011
    ):
        raise RuntimeError("Phase 4 black-box smoke requires exact guarded local targets")
    return port


HTTP_PORT = _require_guarded_targets() if PHASE4_ENABLED else 0
pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not PHASE4_ENABLED, reason="Phase 4 only")]


async def _wait_until_ready(client: httpx.AsyncClient, process: asyncio.subprocess.Process) -> None:
    for _ in range(100):
        if process.returncode is not None:
            pytest.fail("guarded Uvicorn process exited before becoming ready")
        try:
            response = await client.get("/readyz")
            if response.status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.05)
    pytest.fail("guarded Uvicorn process did not become ready")


async def test_black_box_tcp_login_me_refresh_logout_flow() -> None:
    database = Database(RUNTIME_URL)
    suffix = uuid4().hex
    user_id = f"phase4-blackbox-{suffix}"
    email = f"blackbox-{suffix}@phase4.invalid"
    now = utc_now_ms()
    async with database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=email,
                name="Black-box Synthetic",
                status=UserStatus.ACTIVE,
                emailVerified=True,
                createdAt=now,
                updatedAt=now,
            )
        )
        await connection.execute(
            insert(PasswordCredential).values(
                id=f"credential-{uuid4()}",
                userId=user_id,
                email=email,
                passwordHash=NODE_PASSWORD_HASH,
                createdAt=now,
                updatedAt=now,
            )
        )

    environment = {
        key: value for key, value in dotenv_values(ENV_FILE).items() if value is not None
    }
    environment.update(os.environ)
    environment.update(
        {
            "DATABASE_URL": RUNTIME_URL,
            "REDIS_URL": REDIS_URL,
            "PORT": str(HTTP_PORT),
        }
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
        env=environment,
    )
    original_refresh = ""
    replacement_refresh = ""
    try:
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{HTTP_PORT}", timeout=2.0
        ) as client:
            await _wait_until_ready(client, process)
            login = await client.post(
                "/auth/login", json={"email": email, "password": NODE_PASSWORD}
            )
            assert login.status_code == 200
            original_access = login.json()["accessToken"]
            original_refresh = login.json()["refreshToken"]

            current_user = await client.get(
                "/users/me", headers={"authorization": f"Bearer {original_access}"}
            )
            assert current_user.status_code == 200
            assert current_user.json()["id"] == user_id

            refresh = await client.post("/auth/refresh", json={"refreshToken": original_refresh})
            assert refresh.status_code == 200
            replacement_refresh = refresh.json()["refreshToken"]

            logout = await client.post("/auth/logout", json={"refreshToken": replacement_refresh})
            assert logout.status_code == 204
            assert logout.content == b""
    finally:
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
        await database.close()

    runtime_output = stdout + stderr
    assert process.returncode == 0
    for lifecycle_message in (
        b"Shutting down",
        b"Waiting for application shutdown",
        b"Application shutdown complete",
        b"Finished server process",
    ):
        assert lifecycle_message in runtime_output
    assert NODE_PASSWORD.encode() not in runtime_output
    assert not original_refresh or original_refresh.encode() not in runtime_output
    assert not replacement_refresh or replacement_refresh.encode() not in runtime_output

    verification_database = Database(RUNTIME_URL)
    try:
        async with verification_database.connection() as connection:
            rows = (
                await connection.execute(
                    select(RefreshToken.c.tokenHash, RefreshToken.c.revokedAt)
                    .where(RefreshToken.c.userId == user_id)
                    .order_by(RefreshToken.c.createdAt)
                )
            ).all()
    finally:
        await verification_database.close()
    assert len(rows) == 2
    assert rows[0].tokenHash == sha256_token(original_refresh)
    assert rows[1].tokenHash == sha256_token(replacement_refresh)
    assert all(row.revokedAt is not None for row in rows)
    assert rows[1].revokedAt <= now + timedelta(days=1)
