"""Guarded Phase 5 integration proofs against disposable PostgreSQL and Redis."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import smtplib
import socketserver
import ssl
import subprocess
import threading
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values
from redis.asyncio import Redis
from sqlalchemy import func, insert, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.auth import (
    AuthHandoffExchangeInput,
    Phase5AuthService,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.config import RelyingClientPolicy, Settings
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.oauth import OAuthProfile
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.domain.verification import InvalidVerificationTokenError
from wiseacct_sso.infrastructure.auth_state import (
    AuthHandoffConsumeInput,
    AuthHandoffCreateInput,
    AuthHandoffStore,
    OAuthStateMetadata,
    OAuthStateStore,
    sha256_base64url,
)
from wiseacct_sso.infrastructure.mail import (
    MailLinkMessage,
    SmtpMailConfig,
    SmtpMailService,
    resend_mail_config,
)
from wiseacct_sso.infrastructure.oauth_providers import (
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderInfrastructureError,
)
from wiseacct_sso.infrastructure.redis import (
    AUTH_HANDOFF_TTL_SECONDS,
    OAUTH_STATE_TTL_SECONDS,
    RedisOptions,
    RedisStateStore,
    auth_handoff_key,
    oauth_state_key,
)
from wiseacct_sso.infrastructure.security import AsyncPasswordHasher, JwtTokenCodec, sha256_token
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmailVerificationToken,
    PasswordCredential,
    PasswordResetToken,
    PendingPasswordCredential,
    RefreshToken,
    Role,
    SocialAccount,
    SubjectReservation,
    User,
    UserRole,
    UserStatus,
    utc_now_ms,
)
from wiseacct_sso.persistence.stores import (
    DefaultRole,
    OAuthIdentityStore,
    OAuthProfileRecord,
    PasswordResetStore,
)

ENABLED = os.getenv("WISEACCT_PHASE5_INTEGRATION") == "1"
DATABASE_URL = os.getenv("WISEACCT_PHASE5_DATABASE_URL", "")
NODE_DATABASE_URL = os.getenv("WISEACCT_PHASE5_NODE_DATABASE_URL", "")
REDIS_URL = os.getenv("WISEACCT_PHASE5_REDIS_URL", "")
RUN_ID = os.getenv("WISEACCT_PHASE5_RUN_ID", "")
EXPRESS_DIR = Path(__file__).parents[3] / "auth-server"
NODE_BRIDGE = Path(__file__).parents[1] / "helpers" / "phase5_node_redis_bridge.mjs"
NODE_IDENTITY_WRITER = Path(__file__).parents[1] / "helpers" / "phase5_node_identity_writer.ts"
ENV_FILE = Path(__file__).parents[2] / ".env.example"
REDIRECT_URI = "https://financenow.kr/auth/callback"
VERIFIER = "phase5-verifier-that-is-long-enough-for-pkce-0001"
CHALLENGE = sha256_base64url(VERIFIER)


def _require_disposable_targets(database_url: str, redis_url: str, run_id: str) -> None:
    database = urlparse(database_url)
    redis = urlparse(redis_url)
    if (
        database.scheme not in {"postgresql", "postgresql+asyncpg"}
        or database.hostname != "127.0.0.1"
        or database.port != 5433
        or "_test_" not in database.path
    ):
        raise RuntimeError("Phase 5 requires a disposable _test_ database on 127.0.0.1:5433")
    if (
        redis.scheme != "redis"
        or redis.hostname != "127.0.0.1"
        or redis.port != 6380
        or redis.path != "/15"
        or redis.username is not None
        or redis.password is not None
    ):
        raise RuntimeError("Phase 5 requires credential-free Redis DB 15 on 127.0.0.1:6380")
    if not run_id or not run_id.replace("_", "").isalnum():
        raise RuntimeError("Phase 5 requires an alphanumeric synthetic run identifier")


if ENABLED:
    _require_disposable_targets(DATABASE_URL, REDIS_URL, RUN_ID)
    _require_disposable_targets(NODE_DATABASE_URL, REDIS_URL, RUN_ID)

pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not ENABLED, reason="Phase 5 only")]


def _context(label: str) -> RequestAuditContext:
    return RequestAuditContext("192.0.2.55", f"phase5-{RUN_ID}-{label}")


def _client() -> RelyingClientPolicy:
    return RelyingClientPolicy.model_validate(
        {
            "clientId": "temis",
            "audience": "temis",
            "allowedRedirectUris": [REDIRECT_URI],
            "allowedOrigins": ["https://financenow.kr"],
            "defaultRole": {"serviceKey": "temis", "name": "user"},
        }
    )


class TrackingMail:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.messages: list[MailLinkMessage] = []
        self.order: list[str] = []
        self.audit_baselines: dict[str, int] = {}

    async def capture_audit_baseline(self, event_type: str) -> None:
        async with self.database.connection() as connection:
            count = await connection.scalar(
                select(func.count()).select_from(AuditLog).where(AuditLog.c.eventType == event_type)
            )
        self.audit_baselines[event_type] = int(count or 0)

    async def send_email_verification(self, *, to: str, verification_url: str) -> None:
        async with self.database.connection() as connection:
            assert await connection.scalar(select(func.count()).select_from(EmailVerificationToken))
            count = await connection.scalar(
                select(func.count())
                .select_from(AuditLog)
                .where(AuditLog.c.eventType == "email_verification_request")
            )
            assert int(count or 0) == self.audit_baselines["email_verification_request"]
        self.order.append("mail")
        self.messages.append(MailLinkMessage("email-verification", to, verification_url))

    async def send_password_reset(self, *, to: str, reset_url: str) -> None:
        async with self.database.connection() as connection:
            assert await connection.scalar(select(func.count()).select_from(PasswordResetToken))
        self.order.append("mail")
        self.messages.append(MailLinkMessage("password-reset", to, reset_url))


class FakeOAuthClient:
    def __init__(self, profile: OAuthProfile) -> None:
        self.profile = profile
        self.calls: list[tuple[str, str]] = []

    async def fetch_profile(
        self, provider: str, _config: OAuthProviderConfig, code: str
    ) -> OAuthProfile:
        self.calls.append((provider, code))
        return self.profile


@dataclass(slots=True)
class Runtime:
    database: Database
    redis_store: RedisStateStore
    redis_client: Redis
    services: Phase5AuthService
    mail: TrackingMail
    tokens: JwtTokenCodec


@pytest.fixture
async def runtime() -> AsyncIterator[Runtime]:
    database = Database(DATABASE_URL)
    redis_store = RedisStateStore.from_options(RedisOptions(REDIS_URL, max_connections=80))
    redis_client = Redis.from_url(REDIS_URL, protocol=2, decode_responses=False)
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    tokens = JwtTokenCodec.from_settings(settings)
    mail = TrackingMail(database)
    services = Phase5AuthService(
        database=lambda: database,
        redis=lambda: redis_store,
        passwords=AsyncPasswordHasher(),
        tokens=tokens,
        password_policy=PasswordPolicy(8, None),
        default_audience=settings.jwt_audience,
        rate_limit_window_seconds=60,
        rate_limit_max_requests=20,
        mail=mail,
        verification_url_base="https://auth.phase5.invalid/verify-email",
        password_reset_url_base="https://auth.phase5.invalid/password-reset",
        auth_clients=(_client(),),
        provider_config=lambda _provider: OAuthProviderConfig(
            "https://provider.invalid/authorize",
            "https://provider.invalid/token",
            "https://provider.invalid/user",
            "fake-client",
            "fake-secret",
            "https://auth.phase5.invalid/oauth/callback",
            "openid email",
        ),
        oauth_client=cast(
            OAuthProviderClient,
            FakeOAuthClient(
                OAuthProfile("google", "default", "default@phase5.invalid", True, "Default", None)
            ),
        ),
    )
    await redis_store.start()
    try:
        yield Runtime(database, redis_store, redis_client, services, mail, tokens)
    finally:
        keys = [
            key
            async for key in redis_client.scan_iter(match=f"wiseacct:*phase5*{RUN_ID}*", count=500)
        ]
        if keys:
            await redis_client.delete(*keys)
        await redis_client.aclose(close_connection_pool=True)
        await redis_store.close()
        await database.close()


async def _seed_user(
    runtime: Runtime,
    label: str,
    *,
    status: UserStatus,
    verified: bool,
    with_password: bool = True,
) -> tuple[str, str]:
    suffix = uuid4().hex
    user_id = f"phase5-{RUN_ID}-{label}-{suffix}"
    email = f"{label}-{suffix}@phase5.invalid"
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=email,
                name="Phase 5 Synthetic",
                status=status,
                emailVerified=verified,
                createdAt=now,
                updatedAt=now,
            )
        )
        if with_password:
            await connection.execute(
                insert(PasswordCredential).values(
                    id=f"credential-{uuid4()}",
                    userId=user_id,
                    email=email,
                    passwordHash=await AsyncPasswordHasher().hash_password("old-password-123"),
                    failedLoginCount=4,
                    lockedUntil=now + timedelta(minutes=10),
                    createdAt=now,
                    updatedAt=now,
                )
            )
    return user_id, email


def _mail_token(message: MailLinkMessage) -> str:
    values = parse_qs(urlparse(message.link).query)["token"]
    assert len(values) == 1
    return values[0]


async def test_runtime_role_is_dml_only(runtime: Runtime) -> None:
    async with runtime.database.connection() as connection:
        with pytest.raises(ProgrammingError) as captured:
            await connection.execute(text('CREATE TABLE "phase5_forbidden" (id integer)'))
    assert getattr(captured.value.orig, "sqlstate", None) == "42501"


async def test_verification_request_is_hash_only_24h_and_mail_precedes_audit(
    runtime: Runtime,
) -> None:
    user_id, email = await _seed_user(
        runtime, "verify-request", status=UserStatus.PENDING_EMAIL_VERIFICATION, verified=False
    )
    before = utc_now_ms()
    await runtime.mail.capture_audit_baseline("email_verification_request")
    await runtime.services.request_email_verification(email.upper(), _context("verify-request"))
    message = runtime.mail.messages[-1]
    raw = _mail_token(message)
    async with runtime.database.connection() as connection:
        token = (
            await connection.execute(
                select(EmailVerificationToken).where(EmailVerificationToken.c.userId == user_id)
            )
        ).one()
        audit = (
            await connection.execute(
                select(AuditLog.c.eventType).where(
                    AuditLog.c.userId == user_id,
                    AuditLog.c.eventType == "email_verification_request",
                )
            )
        ).one()
    assert token.tokenHash == sha256_token(raw) and token.tokenHash != raw
    assert before + timedelta(hours=24) <= token.expiresAt <= utc_now_ms() + timedelta(hours=24)
    assert message.to == email and audit.eventType == "email_verification_request"
    assert runtime.mail.order[-1] == "mail"


async def test_verification_twenty_way_has_one_activation_and_default_role(
    runtime: Runtime,
) -> None:
    user_id, email = await _seed_user(
        runtime, "verify-race", status=UserStatus.PENDING_EMAIL_VERIFICATION, verified=False
    )
    await runtime.mail.capture_audit_baseline("email_verification_request")
    await runtime.services.request_email_verification(email, _context("verify-race-request"))
    raw = _mail_token(runtime.mail.messages[-1])

    async def confirm() -> object:
        try:
            return await runtime.services.confirm_email_verification(raw, _context("verify-race"))
        except Exception as error:
            return error

    outcomes = await asyncio.gather(*(confirm() for _ in range(20)))
    successes = [value for value in outcomes if not isinstance(value, Exception)]
    failures = [value for value in outcomes if isinstance(value, Exception)]
    async with runtime.database.connection() as connection:
        user = (
            await connection.execute(
                select(User.c.status, User.c.emailVerified).where(User.c.id == user_id)
            )
        ).one()
        roles = (
            await connection.execute(
                select(Role.c.serviceKey, Role.c.name)
                .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
                .where(UserRole.c.userId == user_id)
            )
        ).all()
        used = await connection.scalar(
            select(func.count())
            .select_from(EmailVerificationToken)
            .where(
                EmailVerificationToken.c.userId == user_id,
                EmailVerificationToken.c.usedAt.is_not(None),
            )
        )
    assert len(successes) == 1 and len(failures) == 19
    assert all(isinstance(value, InvalidVerificationTokenError) for value in failures)
    assert user.status == UserStatus.ACTIVE and user.emailVerified is True and used == 1
    assert {(row.serviceKey, row.name) for row in roles} >= {("temis", "user")}


async def test_verification_attaches_pending_password(runtime: Runtime) -> None:
    user_id, email = await _seed_user(
        runtime, "pending-attach", status=UserStatus.ACTIVE, verified=True, with_password=False
    )
    pending_hash = await AsyncPasswordHasher().hash_password("pending-password-123")
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(PendingPasswordCredential).values(
                id=f"pending-{uuid4()}",
                userId=user_id,
                email=email,
                passwordHash=pending_hash,
                expiresAt=now + timedelta(hours=24),
                createdAt=now,
                updatedAt=now,
            )
        )
    await runtime.mail.capture_audit_baseline("email_verification_request")
    await runtime.services.request_email_verification(email, _context("pending-request"))
    await runtime.services.confirm_email_verification(
        _mail_token(runtime.mail.messages[-1]), _context("pending-confirm")
    )
    async with runtime.database.connection() as connection:
        credential = (
            await connection.execute(
                select(PasswordCredential.c.passwordHash).where(
                    PasswordCredential.c.userId == user_id
                )
            )
        ).one()
        pending_count = await connection.scalar(
            select(func.count())
            .select_from(PendingPasswordCredential)
            .where(PendingPasswordCredential.c.userId == user_id)
        )
    assert credential.passwordHash == pending_hash and pending_count == 0


async def test_verification_activation_conflict_commits_token_consumption(
    runtime: Runtime,
) -> None:
    pending_id, pending_email = await _seed_user(
        runtime,
        "verify-conflict",
        status=UserStatus.PENDING_EMAIL_VERIFICATION,
        verified=False,
        with_password=False,
    )
    conflicting_id, _conflicting_email = await _seed_user(
        runtime,
        "verify-conflict-owner",
        status=UserStatus.ACTIVE,
        verified=True,
        with_password=False,
    )
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(SubjectReservation).values(
                id=f"verify-conflict-reservation-{uuid4()}",
                email=pending_email,
                subjectId=conflicting_id,
                reason="phase5-consume-boundary",
                createdAt=now,
                updatedAt=now,
            )
        )
    await runtime.mail.capture_audit_baseline("email_verification_request")
    await runtime.services.request_email_verification(
        pending_email, _context("verify-conflict-request")
    )
    raw = _mail_token(runtime.mail.messages[-1])

    with pytest.raises(InvalidVerificationTokenError):
        await runtime.services.confirm_email_verification(raw, _context("verify-conflict-confirm"))

    async with runtime.database.connection() as connection:
        token = (
            await connection.execute(
                select(EmailVerificationToken.c.usedAt).where(
                    EmailVerificationToken.c.tokenHash == sha256_token(raw)
                )
            )
        ).one()
        pending = (
            await connection.execute(
                select(User.c.status, User.c.emailVerified).where(User.c.id == pending_id)
            )
        ).one()
    assert token.usedAt is not None
    assert pending.status == UserStatus.PENDING_EMAIL_VERIFICATION
    assert pending.emailVerified is False


class _NoRowResult:
    def one_or_none(self) -> None:
        return None


class _MissingUserConnection:
    """Exercise real reset DML while injecting the defensive missing-user lock result."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        rendered = str(statement)
        if statement.is_select and 'FROM "User"' in rendered and "FOR UPDATE" in rendered:
            return _NoRowResult()
        return await self._connection.execute(statement, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _MissingUserAfterConsumeResetStore(PasswordResetStore):
    async def confirm(self, connection: Any, **kwargs: Any) -> str | None:
        simulated = cast(AsyncConnection, _MissingUserConnection(connection))
        return await super().confirm(simulated, **kwargs)


async def test_password_reset_missing_user_result_commits_token_consumption(
    runtime: Runtime,
) -> None:
    _user_id, email = await _seed_user(
        runtime, "reset-missing-user", status=UserStatus.ACTIVE, verified=True
    )
    await runtime.services.request_password_reset(email, _context("reset-missing-request"))
    raw = _mail_token(runtime.mail.messages[-1])
    cast(Any, runtime.services)._password_reset = _MissingUserAfterConsumeResetStore()

    with pytest.raises(DomainError) as captured:
        await runtime.services.confirm_password_reset(
            raw, "replacement-password-789", _context("reset-missing-confirm")
        )
    assert captured.value.code == "INVALID_RESET_TOKEN"

    async with runtime.database.connection() as connection:
        used_at = await connection.scalar(
            select(PasswordResetToken.c.usedAt).where(
                PasswordResetToken.c.tokenHash == sha256_token(raw)
            )
        )
    assert used_at is not None


async def test_password_reset_hash_only_1h_and_twenty_way_single_success(runtime: Runtime) -> None:
    user_id, email = await _seed_user(runtime, "reset", status=UserStatus.ACTIVE, verified=True)
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        for _index in range(3):
            issued = runtime.tokens.issue_refresh_token(user_id=user_id, audience="temis")
            await connection.execute(
                insert(RefreshToken).values(
                    id=f"refresh-{uuid4()}",
                    tokenHash=issued.token_hash,
                    userId=user_id,
                    audience="temis",
                    expiresAt=issued.expires_at.replace(tzinfo=None),
                    createdAt=now,
                )
            )
    before = utc_now_ms()
    await runtime.services.request_password_reset(email, _context("reset-request"))
    raw = _mail_token(runtime.mail.messages[-1])
    async with runtime.database.connection() as connection:
        token = (
            await connection.execute(
                select(PasswordResetToken).where(PasswordResetToken.c.userId == user_id)
            )
        ).one()
    assert token.tokenHash == sha256_token(raw) and token.tokenHash != raw
    assert before + timedelta(hours=1) <= token.expiresAt <= utc_now_ms() + timedelta(hours=1)

    async def confirm() -> object:
        try:
            return await runtime.services.confirm_password_reset(
                raw, "new-password-456", _context("reset-confirm")
            )
        except Exception as error:
            return error

    outcomes = await asyncio.gather(*(confirm() for _ in range(20)))
    successes = [value for value in outcomes if not isinstance(value, Exception)]
    async with runtime.database.connection() as connection:
        credential = (
            await connection.execute(
                select(
                    PasswordCredential.c.passwordHash,
                    PasswordCredential.c.failedLoginCount,
                    PasswordCredential.c.lockedUntil,
                ).where(PasswordCredential.c.userId == user_id)
            )
        ).one()
        active_refreshes = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None))
        )
        used = await connection.scalar(
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.c.userId == user_id, PasswordResetToken.c.usedAt.is_not(None))
        )
    assert len(successes) == 1 and len(outcomes) - len(successes) == 19
    assert await AsyncPasswordHasher().verify_password(credential.passwordHash, "new-password-456")
    assert credential.failedLoginCount == 0 and credential.lockedUntil is None
    assert active_refreshes == 0 and used == 1


async def test_live_oauth_state_ttl_wrong_provider_consumes_and_replay_fails(
    runtime: Runtime,
) -> None:
    store = OAuthStateStore(runtime.redis_store)
    metadata = OAuthStateMetadata("temis", REDIRECT_URI, f"phase5-{RUN_ID}", CHALLENGE, "S256")
    state = await store.create("google", metadata)
    assert 1 <= await runtime.redis_client.ttl(oauth_state_key(state)) <= OAUTH_STATE_TTL_SECONDS
    assert await store.consume("naver", state) is None
    assert await store.consume("google", state) is None


async def test_handoff_hashed_key_ttl_binding_and_twenty_way_raw_cas(runtime: Runtime) -> None:
    store = AuthHandoffStore(runtime.redis_store)
    code = await store.create(
        AuthHandoffCreateInput(
            "temis",
            "temis",
            REDIRECT_URI,
            f"phase5-{RUN_ID}-handoff",
            "password",
            CHALLENGE,
            "S256",
            f"phase5-{RUN_ID}",
        )
    )
    key = auth_handoff_key(code)
    assert code.encode() not in key
    assert 1 <= await runtime.redis_client.ttl(key) <= AUTH_HANDOFF_TTL_SECONDS
    wrong = AuthHandoffConsumeInput("wrong", REDIRECT_URI, code, VERIFIER)
    assert await store.consume(wrong) is None and await runtime.redis_client.exists(key) == 1

    valid = AuthHandoffConsumeInput("temis", REDIRECT_URI, code, VERIFIER)
    outcomes = await asyncio.gather(*(store.consume(valid) for _ in range(20)))
    assert sum(value is not None for value in outcomes) == 1
    assert await runtime.redis_client.exists(key) == 0


async def test_node_python_redis_json_interoperability(runtime: Runtime) -> None:
    state = f"phase5-node-{RUN_ID}-{uuid4().hex}"
    record = {
        "provider": "google",
        "clientId": "temis",
        "redirectUri": REDIRECT_URI,
        "callerState": f"phase5-{RUN_ID}",
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
    }
    produced = await asyncio.to_thread(
        subprocess.run,
        [
            "node",
            str(NODE_BRIDGE),
            "produce-oauth-state",
            REDIS_URL,
            json.dumps({"state": state, "record": record}),
        ],
        cwd=EXPRESS_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(produced.stdout)["key"].endswith(state)
    parsed = await OAuthStateStore(runtime.redis_store).consume("google", state)
    assert parsed == OAuthStateMetadata(
        "temis", REDIRECT_URI, f"phase5-{RUN_ID}", CHALLENGE, "S256"
    )

    handoff = AuthHandoffStore(runtime.redis_store)
    code = await handoff.create(
        AuthHandoffCreateInput(
            "temis",
            "temis",
            REDIRECT_URI,
            f"phase5-{RUN_ID}-node",
            "password",
            CHALLENGE,
            "S256",
            None,
        )
    )
    consumed = await asyncio.to_thread(
        subprocess.run,
        [
            "node",
            str(NODE_BRIDGE),
            "consume-handoff",
            REDIS_URL,
            json.dumps(
                {
                    "clientId": "temis",
                    "redirectUri": REDIRECT_URI,
                    "code": code,
                    "codeVerifier": VERIFIER,
                }
            ),
        ],
        cwd=EXPRESS_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(consumed.stdout)["userId"].endswith("-node")
    assert (
        await handoff.consume(AuthHandoffConsumeInput("temis", REDIRECT_URI, code, VERIFIER))
        is None
    )


async def test_oauth_identity_attach_pending_replacement_and_reserved_subject(
    runtime: Runtime,
) -> None:
    store = OAuthIdentityStore()
    active_id, active_email = await _seed_user(
        runtime, "oauth-attach", status=UserStatus.ACTIVE, verified=True, with_password=False
    )
    pending_id, pending_email = await _seed_user(
        runtime,
        "oauth-pending",
        status=UserStatus.PENDING_EMAIL_VERIFICATION,
        verified=False,
        with_password=False,
    )
    reserved_email = f"reserved-{uuid4().hex}@phase5.invalid"
    reserved_id = f"reserved-subject-{RUN_ID}-{uuid4().hex}"
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(SubjectReservation).values(
                id=f"reservation-{uuid4()}",
                email=reserved_email,
                subjectId=reserved_id,
                reason="phase5-test",
                createdAt=now,
                updatedAt=now,
            )
        )

    async def resolve(profile: OAuthProfileRecord) -> str:
        async def work(connection: Any) -> str:
            return (
                await store.resolve_or_create(
                    connection, profile=profile, default_role=DefaultRole("temis", "user"), now=now
                )
            ).id

        return await runtime.database.transaction(database_only_transaction(work))

    attached = await resolve(
        OAuthProfileRecord("google", f"attach-{uuid4()}", active_email, True, "A", None)
    )
    replaced = await resolve(
        OAuthProfileRecord("google", f"replace-{uuid4()}", pending_email, True, "P", None)
    )
    reserved = await resolve(
        OAuthProfileRecord("google", f"reserved-{uuid4()}", reserved_email, True, "R", None)
    )
    async with runtime.database.connection() as connection:
        pending_exists = await connection.scalar(
            select(func.count()).select_from(User).where(User.c.id == pending_id)
        )
        replacement = (
            await connection.execute(select(User.c.id).where(User.c.email == pending_email))
        ).one()
    assert attached == active_id and pending_exists == 0 and replaced == replacement.id
    assert reserved == reserved_id


async def test_same_provider_identity_race_has_one_committed_owner(runtime: Runtime) -> None:
    store = OAuthIdentityStore()
    provider_id = f"race-{RUN_ID}-{uuid4().hex}"
    profile = OAuthProfileRecord("google", provider_id, None, False, "Race", None)

    async def resolve() -> object:
        try:

            async def work(connection: Any) -> str:
                existing = await store.find_by_provider_id(
                    connection, provider="google", provider_user_id=provider_id
                )
                if existing is not None:
                    return existing.id
                return (
                    await store.resolve_or_create(
                        connection,
                        profile=profile,
                        default_role=DefaultRole("temis", "user"),
                        now=utc_now_ms(),
                    )
                ).id

            return await runtime.database.transaction(database_only_transaction(work))
        except Exception as error:
            return error

    outcomes = await asyncio.gather(*(resolve() for _ in range(20)))
    async with runtime.database.connection() as connection:
        owners = (
            await connection.execute(
                select(SocialAccount.c.userId).where(
                    SocialAccount.c.provider == "google",
                    SocialAccount.c.providerUserId == provider_id,
                )
            )
        ).all()
    assert len(owners) == 1
    assert sum(not isinstance(value, Exception) for value in outcomes) >= 1
    assert {value for value in outcomes if isinstance(value, str)} == {owners[0].userId}


def _node_writer_environment() -> dict[str, str]:
    synthetic = {key: value for key, value in dotenv_values(ENV_FILE).items() if value is not None}
    return {
        **os.environ,
        **synthetic,
        "NODE_ENV": "test",
        "DATABASE_URL": NODE_DATABASE_URL,
        "WISEACCT_PHASE5_NODE_DATABASE_URL": NODE_DATABASE_URL,
        "REDIS_URL": REDIS_URL,
        "DOTENV_CONFIG_PATH": "/dev/null",
    }


async def _run_node_identity_writer(
    profile: OAuthProfileRecord, start_at_epoch_ms: int
) -> dict[str, str]:
    payload = {
        "profile": {
            "provider": profile.provider,
            "providerUserId": profile.provider_user_id,
            "email": profile.email,
            "emailVerified": profile.email_verified,
            "name": profile.name,
            "profileUrl": profile.profile_url,
        },
        "clientId": "temis",
        "startAtEpochMs": start_at_epoch_ms,
    }
    process = await asyncio.create_subprocess_exec(
        str(EXPRESS_DIR / "node_modules" / ".bin" / "tsx"),
        str(NODE_IDENTITY_WRITER),
        json.dumps(payload, separators=(",", ":")),
        cwd=Path(__file__).parents[2],
        env=_node_writer_environment(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    synthetic_password = urlparse(NODE_DATABASE_URL).password or ""
    assert not synthetic_password or (
        synthetic_password.encode() not in stdout and synthetic_password.encode() not in stderr
    )
    assert profile.provider_user_id.encode() not in stdout + stderr
    assert profile.email is None or profile.email.encode() not in stdout + stderr
    assert process.returncode == 0, {
        "stdout": stdout.decode(errors="replace")[:256],
        "stderrType": "node-writer-failed",
    }
    result = json.loads(stdout.decode().splitlines()[-1])
    assert isinstance(result, dict)
    normalized = {str(key): str(value) for key, value in result.items()}
    if normalized.get("status") == "ok":
        assert set(normalized) == {"status", "userIdSha256"}
    else:
        assert set(normalized) == {"status", "code"}
    return normalized


async def _run_fastapi_identity_writer(
    runtime: Runtime, profile: OAuthProfileRecord, start_at_epoch_ms: int
) -> dict[str, str]:
    store = OAuthIdentityStore()
    await asyncio.sleep(max(0.0, start_at_epoch_ms / 1000 - time.time()))
    try:

        async def resolve(connection: Any) -> str:
            existing = await store.find_by_provider_id(
                connection,
                provider=profile.provider,
                provider_user_id=profile.provider_user_id,
            )
            if existing is not None:
                return existing.id
            user = await store.resolve_or_create(
                connection,
                profile=profile,
                default_role=DefaultRole("temis", "user"),
                now=utc_now_ms(),
            )
            return user.id

        user_id = await runtime.database.transaction(database_only_transaction(resolve))
        return {"status": "ok", "userIdSha256": sha256(user_id.encode()).hexdigest()}
    except (IntegrityError, DBAPIError) as error:
        sqlstate = str(getattr(error.orig, "sqlstate", ""))
        assert sqlstate in {"23505", "40001", "40P01"}
        return {"status": "controlled-conflict", "code": sqlstate}


async def test_express_fastapi_mixed_oauth_identity_races(runtime: Runtime) -> None:
    scenarios: list[tuple[str, OAuthProfileRecord, str | None]] = []

    same_provider_id = f"mixed-same-{RUN_ID}-{uuid4().hex}"
    scenarios.append(
        (
            "same-provider",
            OAuthProfileRecord("google", same_provider_id, None, False, "Mixed Same", None),
            None,
        )
    )

    attached_id, attached_email = await _seed_user(
        runtime,
        "mixed-attach",
        status=UserStatus.ACTIVE,
        verified=True,
        with_password=False,
    )
    scenarios.append(
        (
            "verified-attach",
            OAuthProfileRecord(
                "google",
                f"mixed-attach-{RUN_ID}-{uuid4().hex}",
                attached_email,
                True,
                "Mixed Attach",
                None,
            ),
            attached_id,
        )
    )

    reserved_email = f"mixed-reserved-{RUN_ID}-{uuid4().hex}@phase5.invalid"
    reserved_id = f"mixed-reserved-subject-{RUN_ID}-{uuid4().hex}"
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(SubjectReservation).values(
                id=f"mixed-reservation-{uuid4()}",
                email=reserved_email,
                subjectId=reserved_id,
                reason="phase5-mixed-runtime-test",
                createdAt=now,
                updatedAt=now,
            )
        )
    scenarios.append(
        (
            "reserved-subject",
            OAuthProfileRecord(
                "google",
                f"mixed-reserved-{RUN_ID}-{uuid4().hex}",
                reserved_email,
                True,
                "Mixed Reserved",
                None,
            ),
            reserved_id,
        )
    )

    for label, profile, expected_user_id in scenarios:
        start_at = int(time.time() * 1000) + 2_500
        node_outcome, fastapi_outcome = await asyncio.gather(
            _run_node_identity_writer(profile, start_at),
            _run_fastapi_identity_writer(runtime, profile, start_at),
        )
        outcomes = (node_outcome, fastapi_outcome)
        assert {outcome["status"] for outcome in outcomes} <= {
            "ok",
            "controlled-conflict",
        }, label
        assert any(outcome["status"] == "ok" for outcome in outcomes), label

        async with runtime.database.connection() as connection:
            links = (
                await connection.execute(
                    select(SocialAccount.c.userId).where(
                        SocialAccount.c.provider == profile.provider,
                        SocialAccount.c.providerUserId == profile.provider_user_id,
                    )
                )
            ).all()
            email_owners = (
                []
                if profile.email is None
                else (
                    await connection.execute(select(User.c.id).where(User.c.email == profile.email))
                ).all()
            )
        assert len(links) == 1, label
        canonical_user_id = str(links[0].userId)
        assert expected_user_id is None or canonical_user_id == expected_user_id, label
        assert not email_owners or [str(row.id) for row in email_owners] == [canonical_user_id]
        canonical_hash = sha256(canonical_user_id.encode()).hexdigest()
        assert {outcome["userIdSha256"] for outcome in outcomes if outcome["status"] == "ok"} == {
            canonical_hash
        }, label


async def test_exchange_consumes_before_token_issue_failure(runtime: Runtime) -> None:
    user_id, _email = await _seed_user(runtime, "exchange", status=UserStatus.ACTIVE, verified=True)
    store = AuthHandoffStore(runtime.redis_store)
    code = await store.create(
        AuthHandoffCreateInput(
            "temis", "temis", REDIRECT_URI, user_id, "password", CHALLENGE, "S256", None
        )
    )

    async def fail_issue(_user_id: str, _audience: str) -> TokenPair:
        raise RuntimeError("synthetic token issue failure")

    cast(Any, runtime.services)._issue_pair = fail_issue
    with pytest.raises(RuntimeError, match="synthetic token issue failure"):
        await runtime.services.exchange_auth_handoff(
            AuthHandoffExchangeInput("temis", REDIRECT_URI, code, VERIFIER), _context("exchange")
        )
    assert await runtime.redis_client.exists(auth_handoff_key(code)) == 0
    with pytest.raises(DomainError) as replay:
        await runtime.services.exchange_auth_handoff(
            AuthHandoffExchangeInput("temis", REDIRECT_URI, code, VERIFIER),
            _context("exchange-replay"),
        )
    assert replay.value.code == "INVALID_AUTH_HANDOFF_CODE"


class _FakeSmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server = cast(_FakeSmtpServer, self.server)
        if server.implicit_tls:
            self.connection = server.tls_context.wrap_socket(self.connection, server_side=True)
            self.rfile = self.connection.makefile("rb")
            self.wfile = self.connection.makefile("wb")
        self.connection.sendall(b"220 phase5.local ESMTP\r\n")
        tls_active = server.implicit_tls
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("ascii", errors="replace").strip()
            upper = command.upper()
            if upper.startswith("EHLO"):
                if "timeout" in server.mode:
                    time.sleep(0.5)
                    return
                if server.mode == "no-starttls":
                    self.connection.sendall(b"250 phase5.local\r\n")
                elif tls_active:
                    self.connection.sendall(b"250-phase5.local\r\n250 AUTH PLAIN LOGIN\r\n")
                else:
                    self.connection.sendall(b"250-phase5.local\r\n250 STARTTLS\r\n")
            elif upper == "STARTTLS":
                self.connection.sendall(b"220 Ready to start TLS\r\n")
                self.connection = server.tls_context.wrap_socket(self.connection, server_side=True)
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb")
                tls_active = True
            elif upper.startswith("MAIL FROM"):
                self.connection.sendall(b"250 sender ok\r\n")
            elif upper.startswith("AUTH"):
                self.connection.sendall(b"235 authenticated\r\n")
            elif upper.startswith("RCPT TO"):
                response = (
                    b"550 recipient rejected\r\n"
                    if "reject" in server.mode
                    else b"250 recipient ok\r\n"
                )
                self.connection.sendall(response)
            elif upper == "DATA":
                self.connection.sendall(b"354 end with dot\r\n")
                content = bytearray()
                while True:
                    chunk = self.rfile.readline()
                    if chunk in {b".\r\n", b".\n", b""}:
                        break
                    content.extend(chunk)
                server.messages.append(bytes(content))
                self.connection.sendall(b"250 queued\r\n")
            elif upper == "QUIT":
                self.connection.sendall(b"221 bye\r\n")
                return
            else:
                self.connection.sendall(b"250 ok\r\n")


class _FakeSmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self, mode: str, tls_context: ssl.SSLContext, *, implicit_tls: bool = False
    ) -> None:
        super().__init__(("127.0.0.1", 0), _FakeSmtpHandler)
        self.mode = mode
        self.tls_context = tls_context
        self.implicit_tls = implicit_tls
        self.messages: list[bytes] = []


def _smtp_contexts(tmp_path: Path) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "phase5-smtp-cert.pem"
    key_path = tmp_path / "phase5-smtp-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    client_context = ssl.create_default_context(cafile=str(cert_path))
    return server_context, client_context


def _with_fake_smtp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> tuple[_FakeSmtpServer, SmtpMailService]:
    server_context, client_context = _smtp_contexts(tmp_path)
    server = _FakeSmtpServer(mode, server_context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        "wiseacct_sso.infrastructure.mail.ssl.create_default_context",
        lambda: client_context,
    )
    port = cast(tuple[str, int], server.server_address)[1]
    mail = SmtpMailService(
        SmtpMailConfig("Phase 5 <phase5@invalid>", None, "127.0.0.1", port, None, None)
    )
    return server, mail


@pytest.mark.parametrize("mode", ["success", "reject"])
async def test_local_starttls_fake_smtp_success_and_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    server, mail = _with_fake_smtp(tmp_path, monkeypatch, mode)
    try:
        if mode == "success":
            await mail.send_email_verification(
                to="recipient@phase5.invalid",
                verification_url="https://auth.phase5.invalid/verify?token=synthetic",
            )
            assert len(server.messages) == 1
            assert b"Verify your email" in server.messages[0]
        else:
            with pytest.raises(smtplib.SMTPRecipientsRefused):
                await mail.send_password_reset(
                    to="rejected@phase5.invalid",
                    reset_url="https://auth.phase5.invalid/reset?token=synthetic",
                )
            assert server.messages == []
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("mode", ["timeout", "no-starttls"])
async def test_local_fake_smtp_timeout_and_missing_starttls_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    server, mail = _with_fake_smtp(tmp_path, monkeypatch, mode)
    if mode == "timeout":
        monkeypatch.setattr("wiseacct_sso.infrastructure.mail.SMTP_TIMEOUT_SECONDS", 0.1)
    try:
        expected = (
            smtplib.SMTPServerDisconnected if mode == "timeout" else smtplib.SMTPNotSupportedError
        )
        with pytest.raises(expected):
            await mail.send_email_verification(
                to="recipient@phase5.invalid",
                verification_url="https://auth.phase5.invalid/verify?token=synthetic",
            )
        assert server.messages == []
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("mode", ["implicit-success", "implicit-reject", "implicit-timeout"])
async def test_local_implicit_tls_resend_smtp_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    server_context, client_context = _smtp_contexts(tmp_path)
    server = _FakeSmtpServer(mode, server_context, implicit_tls=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(
        "wiseacct_sso.infrastructure.mail.ssl.create_default_context",
        lambda: client_context,
    )
    real_smtp_ssl = smtplib.SMTP_SSL
    local_port = cast(tuple[str, int], server.server_address)[1]

    def local_resend_connector(
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> smtplib.SMTP_SSL:
        assert host == "smtp.resend.com" and port == 465
        return real_smtp_ssl("127.0.0.1", local_port, timeout=timeout, context=context)

    monkeypatch.setattr(
        "wiseacct_sso.infrastructure.mail.smtplib.SMTP_SSL",
        local_resend_connector,
    )
    if mode == "implicit-timeout":
        monkeypatch.setattr("wiseacct_sso.infrastructure.mail.SMTP_TIMEOUT_SECONDS", 0.1)
    settings = Settings(_env_file=ENV_FILE).model_copy(  # type: ignore[call-arg]
        update={"mail_provider": "resend", "resend_api_key": "synthetic-resend-only"}
    )
    mail = SmtpMailService(resend_mail_config(settings))
    try:
        if mode == "implicit-success":
            await mail.send_password_reset(
                to="resend-success@phase5.invalid",
                reset_url="https://auth.phase5.invalid/reset?token=synthetic",
            )
            assert len(server.messages) == 1
        else:
            expected = (
                smtplib.SMTPRecipientsRefused
                if mode == "implicit-reject"
                else smtplib.SMTPServerDisconnected
            )
            with pytest.raises(expected):
                await mail.send_email_verification(
                    to="resend-failure@phase5.invalid",
                    verification_url="https://auth.phase5.invalid/verify?token=synthetic",
                )
            assert server.messages == []
    finally:
        server.shutdown()
        server.server_close()


class _SelfSignedHttpsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = cast(_SelfSignedHttpsServer, self.server)
        try:
            connection = server.tls_context.wrap_socket(self.request, server_side=True)
        except ssl.SSLError:
            server.handshake_failures += 1
            return
        with connection:
            request = connection.recv(16_384)
            server.requests.append(request)
            body = b'{"access_token":"must-not-be-reached"}'
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )


class _SelfSignedHttpsServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, tls_context: ssl.SSLContext) -> None:
        super().__init__(("127.0.0.1", 0), _SelfSignedHttpsHandler)
        self.tls_context = tls_context
        self.handshake_failures = 0
        self.requests: list[bytes] = []


async def test_local_self_signed_oauth_provider_tls_failure_is_fail_closed(
    tmp_path: Path,
) -> None:
    server_context, _trusted_client_context = _smtp_contexts(tmp_path)
    server = _SelfSignedHttpsServer(server_context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = cast(tuple[str, int], server.server_address)[1]
    endpoint = f"https://127.0.0.1:{port}"
    config = OAuthProviderConfig(
        f"{endpoint}/authorize",
        f"{endpoint}/token",
        f"{endpoint}/userinfo",
        "synthetic-client",
        "synthetic-secret",
        "https://auth.phase5.invalid/callback",
        "openid email",
    )
    client = OAuthProviderClient()
    try:
        with pytest.raises(OAuthProviderInfrastructureError):
            await client.fetch_profile("google", config, "synthetic-code")
    finally:
        await client.close()
        server.shutdown()
        server.server_close()
    assert server.handshake_failures == 1
    assert server.requests == []
