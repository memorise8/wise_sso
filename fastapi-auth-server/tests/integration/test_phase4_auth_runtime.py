"""Live Phase 4 password-auth tests against disposable PostgreSQL and Redis."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import func, insert, select, text, update
from sqlalchemy.exc import ProgrammingError

from wiseacct_sso.application.auth import (
    LoginInput,
    Phase4AuthService,
    RegisterInput,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.auth import PasswordAuthFailure, PasswordPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.redis import RedisOptions, RedisStateStore, rate_limit_key
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher, JwtTokenCodec, sha256_token
from wiseacct_sso.main import create_app
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    PasswordCredential,
    RefreshToken,
    User,
    UserStatus,
    utc_now_ms,
)
from wiseacct_sso.persistence.stores import RefreshRotationStore, RefreshTokenRecord

PHASE4_ENABLED = os.getenv("WISEACCT_PHASE4_INTEGRATION") == "1"
RUNTIME_URL = os.getenv("WISEACCT_PHASE4_DATABASE_URL", "")
REDIS_URL = os.getenv("WISEACCT_PHASE4_REDIS_URL", "")
RUN_ID = os.getenv("WISEACCT_PHASE4_RUN_ID", "")
ENV_FILE = Path(__file__).parents[2] / ".env.example"
NODE_PASSWORD = "express-fixture-password"
NODE_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ABEiM0RVZneImaq7zN3u/w$"
    "zeuaFYFAbBFiUM3IwmEtHtc4d61aWWRsUGaZIOShyuI"
)


def _require_disposable_targets(database_url: str, redis_url: str, run_id: str) -> None:
    database = urlparse(database_url)
    redis = urlparse(redis_url)
    if (
        database.scheme not in {"postgresql", "postgresql+asyncpg"}
        or database.hostname != "127.0.0.1"
        or database.port != 5433
        or database.path == "/"
        or "_test_" not in database.path
    ):
        raise RuntimeError("Phase 4 requires a synthetic _test_ database on 127.0.0.1:5433")
    if (
        redis.scheme != "redis"
        or redis.hostname != "127.0.0.1"
        or redis.port != 6380
        or redis.path != "/15"
        or redis.username is not None
        or redis.password is not None
    ):
        raise RuntimeError("Phase 4 requires credential-free Redis DB 15 on 127.0.0.1:6380")
    if not run_id or not run_id.replace("_", "").isalnum():
        raise RuntimeError("Phase 4 requires a synthetic alphanumeric run identifier")


if PHASE4_ENABLED:
    _require_disposable_targets(RUNTIME_URL, REDIS_URL, RUN_ID)

pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not PHASE4_ENABLED, reason="Phase 4 only")]


@dataclass(slots=True)
class LiveRuntime:
    database: Database
    redis_store: RedisStateStore
    redis_client: Redis
    services: Phase4AuthService
    tokens: JwtTokenCodec


class RotationBarrier(RefreshRotationStore):
    """Test-only transaction barrier immediately before or after live rotation DML."""

    def __init__(self, point: Literal["before", "after"]) -> None:
        self.point = point
        self.reached = asyncio.Event()
        self.release = asyncio.Event()

    async def rotate(self, *args: Any, **kwargs: Any) -> RefreshTokenRecord | None:
        if self.point == "before":
            self.reached.set()
            await self.release.wait()
        result = await super().rotate(*args, **kwargs)
        if self.point == "after":
            self.reached.set()
            await self.release.wait()
        return result


@pytest.fixture
async def runtime() -> AsyncIterator[LiveRuntime]:
    database = Database(RUNTIME_URL)
    redis_store = RedisStateStore.from_options(RedisOptions(REDIS_URL, max_connections=40))
    redis_client = Redis.from_url(REDIS_URL, protocol=2, decode_responses=False)
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    tokens = JwtTokenCodec.from_settings(settings)
    services = Phase4AuthService(
        database=lambda: database,
        redis=lambda: redis_store,
        passwords=AsyncPasswordHasher(),
        tokens=tokens,
        password_policy=PasswordPolicy(min_length=8, allowed_email_domain=None),
        default_audience=settings.jwt_audience,
        rate_limit_window_seconds=60,
        rate_limit_max_requests=2,
    )
    await redis_store.start()
    try:
        yield LiveRuntime(database, redis_store, redis_client, services, tokens)
    finally:
        pattern = f"wiseacct:rate-limit:phase4-{RUN_ID}*"
        keys = [key async for key in redis_client.scan_iter(match=pattern)]
        if keys:
            await redis_client.delete(*keys)
        await redis_client.aclose(close_connection_pool=True)
        await redis_store.close()
        await database.close()


def _context(label: str) -> RequestAuditContext:
    return RequestAuditContext(
        ip_address="192.0.2.44",
        user_agent=f"phase4-{RUN_ID}-{label}",
    )


async def _seed_active_user(runtime: LiveRuntime, label: str) -> tuple[str, str]:
    suffix = uuid4().hex
    user_id = f"phase4-{RUN_ID}-{label}-{suffix}"
    email = f"{label}-{suffix}@phase4.invalid"
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=email,
                name="Phase 4 Synthetic",
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
    return user_id, email


async def _login(runtime: LiveRuntime, label: str) -> tuple[str, str, TokenPair]:
    user_id, email = await _seed_active_user(runtime, label)
    pair = await runtime.services.login(
        LoginInput(email=email, password=NODE_PASSWORD), _context(label)
    )
    return user_id, email, pair


async def test_runtime_role_cannot_create_schema_objects(runtime: LiveRuntime) -> None:
    async with runtime.database.connection() as connection:
        with pytest.raises(ProgrammingError) as captured:
            await connection.execute(text('CREATE TABLE "phase4_forbidden" (id integer)'))
    assert getattr(captured.value.orig, "sqlstate", None) == "42501"


async def test_registration_normalizes_email_and_persists_accepted_side_effects(
    runtime: LiveRuntime,
) -> None:
    suffix = uuid4().hex
    email = f"Register-{suffix}@PHASE4.INVALID"
    context = _context(f"register-{suffix}")

    await runtime.services.register(
        RegisterInput(email=f"  {email}  ", password="synthetic-password-123", name="Registrant"),
        context,
    )

    normalized = email.lower()
    async with runtime.database.connection() as connection:
        row = (
            await connection.execute(
                select(
                    User.c.status,
                    User.c.emailVerified,
                    PasswordCredential.c.passwordHash,
                    AuditLog.c.eventType,
                )
                .select_from(
                    User.join(PasswordCredential, PasswordCredential.c.userId == User.c.id).join(
                        AuditLog, AuditLog.c.userId == User.c.id
                    )
                )
                .where(User.c.email == normalized)
            )
        ).one()
    assert row.status == UserStatus.PENDING_EMAIL_VERIFICATION
    assert row.emailVerified is False
    assert row.passwordHash != "synthetic-password-123"
    assert row.eventType == "register_request"


async def test_login_accepts_node_argon2_and_persists_only_refresh_hash(
    runtime: LiveRuntime,
) -> None:
    user_id, _email, pair = await _login(runtime, "node-login")

    claims = runtime.tokens.verify_access_token(pair.access_token)
    async with runtime.database.connection() as connection:
        stored = (
            await connection.execute(
                select(RefreshToken.c.tokenHash, RefreshToken.c.userId).where(
                    RefreshToken.c.userId == user_id
                )
            )
        ).one()
    assert claims.identity.user_id == user_id
    assert stored.tokenHash == sha256_token(pair.refresh_token)
    assert stored.tokenHash != pair.refresh_token


async def test_access_token_authenticates_users_me_over_asgi(runtime: LiveRuntime) -> None:
    user_id, email, pair = await _login(runtime, "users-me")
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    app = create_app(
        settings=settings,
        readiness_check=lambda: True,
        phase4_services=runtime.services,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://phase4.invalid"
    ) as client:
        response = await client.get(
            "/users/me", headers={"authorization": f"Bearer {pair.access_token}"}
        )

    assert response.status_code == 200
    assert response.json() == {
        "id": user_id,
        "email": email,
        "email_verified": True,
        "name": "Phase 4 Synthetic",
        "roles": [],
    }


async def test_refresh_twenty_way_race_has_one_success_and_one_active_replacement(
    runtime: LiveRuntime,
) -> None:
    user_id, _email, original = await _login(runtime, "refresh-race")

    async def refresh() -> TokenPair | DomainError:
        try:
            return await runtime.services.refresh(original.refresh_token, _context("refresh-race"))
        except DomainError as error:
            return error

    outcomes = await asyncio.gather(*(refresh() for _ in range(20)))
    successes = [outcome for outcome in outcomes if isinstance(outcome, TokenPair)]
    failures = [outcome for outcome in outcomes if isinstance(outcome, DomainError)]
    async with runtime.database.connection() as connection:
        active_count = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None))
        )
        original_revoked = await connection.scalar(
            select(RefreshToken.c.revokedAt).where(
                RefreshToken.c.tokenHash == sha256_token(original.refresh_token)
            )
        )
    assert len(successes) == 1
    assert len(failures) == 19
    assert {failure.code for failure in failures} == {"INVALID_REFRESH_TOKEN"}
    assert active_count == 1
    assert original_revoked is not None


async def test_status_mutation_first_denies_refresh_without_token_writes(
    runtime: LiveRuntime,
) -> None:
    user_id, _email, original = await _login(runtime, "status-first")
    barrier = RotationBarrier("before")
    cast(Any, runtime.services)._rotation = barrier

    async def refresh() -> DomainError:
        try:
            await runtime.services.refresh(original.refresh_token, _context("status-first"))
        except DomainError as error:
            return error
        pytest.fail("inactive-user refresh unexpectedly succeeded")

    async with runtime.database.engine.begin() as mutation_connection:
        await mutation_connection.execute(
            update(User).where(User.c.id == user_id).values(status=UserStatus.SUSPENDED)
        )
        refresh_task = asyncio.create_task(refresh())
        await barrier.reached.wait()
    barrier.release.set()
    failure = await refresh_task

    async with runtime.database.connection() as connection:
        rows = (
            await connection.execute(
                select(RefreshToken.c.tokenHash, RefreshToken.c.revokedAt).where(
                    RefreshToken.c.userId == user_id
                )
            )
        ).all()
    assert failure.code == "INVALID_REFRESH_TOKEN"
    assert [(row.tokenHash, row.revokedAt) for row in rows] == [
        (sha256_token(original.refresh_token), None)
    ]


async def test_refresh_first_commits_once_then_status_mutation_denies_session(
    runtime: LiveRuntime,
) -> None:
    user_id, _email, original = await _login(runtime, "refresh-first")
    barrier = RotationBarrier("after")
    cast(Any, runtime.services)._rotation = barrier
    refresh_task = asyncio.create_task(
        runtime.services.refresh(original.refresh_token, _context("refresh-first"))
    )
    await barrier.reached.wait()
    mutation_started = asyncio.Event()

    async def suspend_user() -> None:
        async with runtime.database.engine.begin() as connection:
            mutation_started.set()
            await connection.execute(
                update(User).where(User.c.id == user_id).values(status=UserStatus.SUSPENDED)
            )

    mutation_task = asyncio.create_task(suspend_user())
    await mutation_started.wait()
    barrier.release.set()
    replacement = await refresh_task
    await mutation_task

    with pytest.raises(DomainError) as refresh_failure:
        await runtime.services.refresh(replacement.refresh_token, _context("refresh-first-denied"))
    with pytest.raises(DomainError) as current_user_failure:
        await runtime.services.current_user(replacement.access_token)
    async with runtime.database.connection() as connection:
        rows = (
            await connection.execute(
                select(RefreshToken.c.tokenHash, RefreshToken.c.revokedAt)
                .where(RefreshToken.c.userId == user_id)
                .order_by(RefreshToken.c.createdAt)
            )
        ).all()
    assert refresh_failure.value.code == "INVALID_REFRESH_TOKEN"
    assert current_user_failure.value.code == "UNAUTHORIZED"
    assert len(rows) == 2
    assert rows[0].tokenHash == sha256_token(original.refresh_token)
    assert rows[0].revokedAt is not None
    assert rows[1].tokenHash == sha256_token(replacement.refresh_token)
    assert rows[1].revokedAt is None
    assert sum(row.revokedAt is None for row in rows) <= 1


async def test_logout_returns_204_and_revokes_the_supplied_refresh_token(
    runtime: LiveRuntime,
) -> None:
    _user_id, _email, pair = await _login(runtime, "logout")
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    app = create_app(
        settings=settings,
        readiness_check=lambda: True,
        phase4_services=runtime.services,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://phase4.invalid"
    ) as client:
        response = await client.post("/auth/logout", json={"refreshToken": pair.refresh_token})

    async with runtime.database.connection() as connection:
        revoked_at = await connection.scalar(
            select(RefreshToken.c.revokedAt).where(
                RefreshToken.c.tokenHash == sha256_token(pair.refresh_token)
            )
        )
    assert response.status_code == 204
    assert response.content == b""
    assert revoked_at is not None


async def test_fifth_failed_login_sets_a_fifteen_minute_lock(runtime: LiveRuntime) -> None:
    user_id, email = await _seed_active_user(runtime, "lockout")
    before = utc_now_ms()

    for _ in range(5):
        with pytest.raises(PasswordAuthFailure) as captured:
            await runtime.services.login(
                LoginInput(email=email, password="wrong-password"), _context("lockout")
            )
        assert captured.value.reason_code == "INVALID_CREDENTIALS"

    with pytest.raises(PasswordAuthFailure) as captured:
        await runtime.services.login(
            LoginInput(email=email, password=NODE_PASSWORD), _context("lockout")
        )
    async with runtime.database.connection() as connection:
        row = (
            await connection.execute(
                select(
                    PasswordCredential.c.failedLoginCount,
                    PasswordCredential.c.lockedUntil,
                ).where(PasswordCredential.c.userId == user_id)
            )
        ).one()
    assert captured.value.reason_code == "ACCOUNT_LOCKED"
    assert row.failedLoginCount == 5
    assert row.lockedUntil is not None
    assert before + timedelta(minutes=14, seconds=59) <= row.lockedUntil
    assert row.lockedUntil <= before + timedelta(minutes=15, seconds=2)


async def test_rate_limit_returns_429_with_exact_count_ttl_and_audit(runtime: LiveRuntime) -> None:
    client_key = f"phase4-{RUN_ID}-rate-{uuid4().hex}"
    context = _context("rate")
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    app = create_app(
        settings=settings,
        readiness_check=lambda: True,
        phase4_services=runtime.services,
    )
    transport = httpx.ASGITransport(app=app, client=(client_key, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://phase4.invalid") as client:
        responses = [
            await client.post(
                "/auth/login",
                json={"invalid": "body"},
                headers={"user-agent": context.user_agent or ""},
            )
            for _ in range(3)
        ]
    ttl = await runtime.redis_client.ttl(rate_limit_key(client_key, "/auth/login"))
    async with runtime.database.connection() as connection:
        audit_count = await connection.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.c.userAgent == context.user_agent,
                AuditLog.c.eventType == "rate_limit_exceeded",
                AuditLog.c.reasonCode == "RATE_LIMITED",
            )
        )
    assert [response.status_code for response in responses] == [400, 400, 429]
    assert responses[2].headers["retry-after"] == "60"
    assert responses[2].json() == {
        "error": {
            "code": "RATE_LIMITED",
            "message": "Too many authentication requests",
        }
    }
    assert 0 < ttl <= 60
    assert audit_count == 1


async def test_audit_sequence_excludes_passwords_and_tokens(runtime: LiveRuntime) -> None:
    _user_id, email = await _seed_active_user(runtime, "audit")
    context = _context(f"audit-{uuid4().hex}")
    secret = "audit-secret-must-not-persist"

    with pytest.raises(PasswordAuthFailure):
        await runtime.services.login(LoginInput(email=email, password=secret), context)
    await asyncio.sleep(0.002)
    pair = await runtime.services.login(LoginInput(email=email, password=NODE_PASSWORD), context)
    await asyncio.sleep(0.002)
    await runtime.services.logout(pair.refresh_token, context)

    async with runtime.database.connection() as connection:
        rows = (
            await connection.execute(
                select(
                    AuditLog.c.eventType,
                    AuditLog.c.outcome,
                    AuditLog.c.reasonCode,
                    AuditLog.c.detailsJson,
                    AuditLog.c.createdAt,
                )
                .where(AuditLog.c.userAgent == context.user_agent)
                .order_by(AuditLog.c.createdAt)
            )
        ).all()
    serialized = repr(rows)
    assert [(row.eventType, row.outcome) for row in rows] == [
        ("login_failure", "failure"),
        ("login_success", "success"),
        ("logout", "success"),
    ]
    assert secret not in serialized
    assert pair.access_token not in serialized
    assert pair.refresh_token not in serialized
