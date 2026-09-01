"""Guarded Phase 6 integration proofs against a disposable Prisma schema."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from uuid import uuid4

import httpx
import pytest
from dotenv import dotenv_values
from sqlalchemy import func, insert, select, text
from sqlalchemy.exc import DBAPIError

from wiseacct_sso.api.routes.admin import _parse_date
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.application.auth import Phase5AuthService, RequestAuditContext, TokenPair
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.admin import AdminUserListInput, AuditLogListInput
from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.tokens import AccessTokenIdentity
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import (
    AsyncPasswordHasher,
    JwtTokenCodec,
)
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AuditLog,
    RefreshToken,
    Role,
    User,
    UserRole,
    UserStatus,
    utc_now_ms,
)

ENABLED = os.getenv("WISEACCT_PHASE6_INTEGRATION") == "1"
DATABASE_URL = os.getenv("WISEACCT_PHASE6_DATABASE_URL", "")
NODE_DATABASE_URL = os.getenv("WISEACCT_PHASE6_NODE_DATABASE_URL", "")
REDIS_URL = os.getenv("WISEACCT_PHASE6_REDIS_URL", "")
RUN_ID = os.getenv("WISEACCT_PHASE6_RUN_ID", "")
HTTP_PORT_TEXT = os.getenv("WISEACCT_PHASE6_HTTP_PORT", "")
ENV_FILE = Path(__file__).parents[2] / ".env.example"
EXPRESS_DIR = Path(__file__).parents[3] / "auth-server"
NODE_BRIDGE = Path(__file__).parents[1] / "helpers" / "phase6_node_admin_bridge.ts"


def _require_disposable_targets(
    database_url: str,
    node_database_url: str,
    redis_url: str,
    run_id: str,
    http_port_text: str,
) -> int:
    database = urlparse(database_url)
    node_database = urlparse(node_database_url)
    redis = urlparse(redis_url)
    try:
        port = int(http_port_text)
    except ValueError:
        port = 0
    expected_database = f"fastapi_phase6_test_{run_id}"
    expected_role = f"phase6_runtime_{run_id}"
    database_name = database.path.removeprefix("/")
    node_database_name = node_database.path.removeprefix("/")
    if (
        re.fullmatch(r"[A-Za-z0-9_]+", run_id) is None
        or database.scheme != "postgresql+asyncpg"
        or database.hostname != "127.0.0.1"
        or database.port != 5433
        or database.username != expected_role
        or database.password != "synthetic-phase6-runtime-only"
        or database_name != expected_database
        or database.params
        or database.query
        or database.fragment
        or node_database.scheme != "postgresql"
        or node_database.hostname != "127.0.0.1"
        or node_database.port != 5433
        or node_database.username != expected_role
        or node_database.password != "synthetic-phase6-runtime-only"
        or node_database_name != expected_database
        or node_database_name != database_name
        or node_database.params
        or node_database.query
        or node_database.fragment
        or redis.scheme != "redis"
        or redis.hostname != "127.0.0.1"
        or redis.port != 6380
        or redis.path != "/15"
        or redis.username is not None
        or redis.password is not None
        or redis.params
        or redis.query
        or redis.fragment
        or port != 4012
    ):
        raise RuntimeError("Phase 6 requires exact disposable local targets")
    return port


HTTP_PORT = (
    _require_disposable_targets(
        DATABASE_URL,
        NODE_DATABASE_URL,
        REDIS_URL,
        RUN_ID,
        HTTP_PORT_TEXT,
    )
    if ENABLED
    else 0
)
pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not ENABLED, reason="Phase 6 only")]


@dataclass(slots=True)
class Runtime:
    database: Database
    settings: Settings
    tokens: JwtTokenCodec
    admin: Phase6AdminService
    auth: Phase5AuthService


class _UnusedRedis:
    pass


@pytest.fixture
async def runtime() -> AsyncIterator[Runtime]:
    database = Database(DATABASE_URL)
    settings = Settings(_env_file=ENV_FILE)  # type: ignore[call-arg]
    tokens = JwtTokenCodec.from_settings(settings)
    admin = Phase6AdminService(database=lambda: database, tokens=tokens)
    auth = Phase5AuthService(
        database=lambda: database,
        redis=lambda: cast(Any, _UnusedRedis()),
        passwords=AsyncPasswordHasher(),
        tokens=tokens,
        password_policy=PasswordPolicy(8, None),
        default_audience=settings.jwt_audience,
        rate_limit_window_seconds=60,
        rate_limit_max_requests=20,
    )
    try:
        yield Runtime(database, settings, tokens, admin, auth)
    finally:
        await database.close()


async def _seed_user(
    runtime: Runtime,
    label: str,
    *,
    status: UserStatus = UserStatus.ACTIVE,
    admin: bool = False,
    email: str | None = None,
) -> str:
    suffix = uuid4().hex
    user_id = f"phase6-{RUN_ID}-{label}-{suffix}"
    now = utc_now_ms()
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=email or f"{label}-{suffix}@phase6.invalid",
                name=f"Phase 6 {label}",
                status=status,
                emailVerified=True,
                createdAt=now,
                updatedAt=now,
            )
        )
        if admin:
            role = (
                await connection.execute(
                    select(Role.c.id).where(Role.c.serviceKey == "temis", Role.c.name == "admin")
                )
            ).scalar_one_or_none()
            if role is None:
                role = str(uuid4())
                await connection.execute(
                    insert(Role).values(id=role, serviceKey="temis", name="admin")
                )
            await connection.execute(
                insert(UserRole).values(id=str(uuid4()), userId=user_id, roleId=role)
            )
    return user_id


async def _seed_refresh(runtime: Runtime, user_id: str) -> str:
    issued = runtime.tokens.issue_refresh_token(user_id=user_id)
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(RefreshToken).values(
                id=str(uuid4()),
                tokenHash=issued.token_hash,
                userId=user_id,
                audience=runtime.settings.jwt_audience,
                expiresAt=issued.expires_at.replace(tzinfo=None),
                createdAt=utc_now_ms(),
            )
        )
    return issued.token


def _assert_expected_refresh_race_outcome(value: object) -> None:
    if isinstance(value, TokenPair):
        return
    assert isinstance(value, DomainError)
    assert value.status_code == 401
    assert value.code == "INVALID_REFRESH_TOKEN"


async def _node_bridge(payload: dict[str, object]) -> dict[str, object]:
    environment = dict(os.environ)
    environment["DATABASE_URL"] = NODE_DATABASE_URL
    npx = shutil.which("npx")
    assert npx is not None

    def run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed executable and synthetic guarded input
            [npx, "tsx", str(NODE_BRIDGE), json.dumps(payload, separators=(",", ":"))],
            cwd=EXPRESS_DIR,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    completed = await asyncio.to_thread(run)
    assert completed.returncode == 0, completed.stderr
    return cast(dict[str, object], json.loads(completed.stdout))


async def test_node_bridge_rejects_unguarded_database_before_prisma_import() -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "DATABASE_URL": "postgresql://example.invalid/production",
            "WISEACCT_PHASE6_RUN_ID": RUN_ID,
        }
    )
    npx = shutil.which("npx")
    assert npx is not None

    def run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - fixed executable and synthetic guard probe
            [npx, "tsx", str(NODE_BRIDGE), '{"command":"set-status"}'],
            cwd=EXPRESS_DIR,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    completed = await asyncio.to_thread(run)
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "Error\n"


async def test_python_collection_guard_rejects_mismatched_run_database_before_connect() -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "WISEACCT_PHASE6_INTEGRATION": "1",
            "WISEACCT_PHASE6_DATABASE_URL": (
                "postgresql+asyncpg://phase6_runtime_wrong:synthetic-phase6-runtime-only@"
                "127.0.0.1:5433/fastapi_phase6_test_wrong"
            ),
            "WISEACCT_PHASE6_NODE_DATABASE_URL": NODE_DATABASE_URL,
            "WISEACCT_PHASE6_RUN_ID": RUN_ID,
        }
    )

    def run() -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - current interpreter and fixed guard probe
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                f"{Path(__file__).resolve()}::test_runtime_role_is_dml_only",
            ],
            cwd=Path(__file__).parents[2],
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    completed = await asyncio.to_thread(run)
    combined = completed.stdout + completed.stderr
    assert completed.returncode != 0
    assert "Phase 6 requires exact disposable local targets" in combined
    assert "ConnectionRefused" not in combined


async def test_runtime_role_is_dml_only(runtime: Runtime) -> None:
    with pytest.raises(DBAPIError) as captured:
        async with runtime.database.engine.begin() as connection:
            await connection.execute(text('CREATE TABLE "phase6_forbidden" (id int)'))
    assert getattr(captured.value.orig, "sqlstate", None) == "42501"


async def test_database_backed_admin_authorization_ignores_stale_token_roles(
    runtime: Runtime,
) -> None:
    actor = await _seed_user(runtime, "authorization", admin=True)
    token = runtime.tokens.issue_access_token(AccessTokenIdentity(actor, None, None, True, ()))
    assert (
        await runtime.admin.authenticate_admin(token, route="/admin/users", method="GET") == actor
    )
    async with runtime.database.engine.begin() as connection:
        await connection.execute(UserRole.delete().where(UserRole.c.userId == actor))
    with pytest.raises(DomainError) as captured:
        await runtime.admin.authenticate_admin(token, route="/admin/users", method="GET")
    assert captured.value.code == "FORBIDDEN"
    async with runtime.database.connection() as connection:
        denial = (
            await connection.execute(
                select(AuditLog.c.detailsJson).where(
                    AuditLog.c.actorUserId == actor,
                    AuditLog.c.eventType == "admin_authorization_failure",
                )
            )
        ).scalar_one()
    assert denial == {"route": "/admin/users", "method": "GET"}


async def test_directory_and_audit_filters_are_db_backed_and_redacted(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "filters-actor", admin=True)
    target = await _seed_user(runtime, "filters-target", email="Mixed.Case+target@phase6.invalid")
    await runtime.admin.assign_role(
        actor_user_id=actor,
        target_user_id=target,
        service_key="temis",
        name="auditor",
        reason_code="FILTER_ROLE",
        details={"email": "private@example.test", "route": "filter"},
    )
    users = await runtime.admin.list_users(
        AdminUserListInput(email="CASE+TARGET", role="temis:auditor")
    )
    assert [item.id for item in users.items] == [target]
    logs = await runtime.admin.list_audit_logs(
        AuditLogListInput(
            event_type="admin_user_role_assigned",
            actor_user_id=actor,
            target_user_id=target,
            reason_code="FILTER_ROLE",
        )
    )
    assert logs.total == 1
    assert logs.items[0].details_json == {"email": "[REDACTED]", "route": "filter"}


async def test_aware_http_dates_bind_as_utc_naive_postgres_filters(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "date-filter-actor", admin=True)
    target = await _seed_user(runtime, "date-filter-target")
    await runtime.admin.revoke_sessions(
        actor_user_id=actor,
        target_user_id=target,
        reason_code="DATE_FILTER",
    )
    created_at_from = _parse_date("2000-01-01T00:00:00Z")
    created_at_to = _parse_date("2099-12-31T23:59:59Z")
    assert created_at_from is not None and created_at_to is not None
    logs = await runtime.admin.list_audit_logs(
        AuditLogListInput(
            created_at_from=created_at_from,
            created_at_to=created_at_to,
            target_user_id=target,
            reason_code="DATE_FILTER",
        )
    )
    assert logs.total == 1


async def test_status_mutation_revokes_sessions_and_rolls_back_with_audit_failure(
    runtime: Runtime, monkeypatch: pytest.MonkeyPatch
) -> None:
    actor = await _seed_user(runtime, "rollback-actor", admin=True)
    target = await _seed_user(runtime, "rollback-target")
    await _seed_refresh(runtime, target)

    async def fail_audit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic audit failure")

    monkeypatch.setattr(runtime.admin._mutations, "create_admin_audit_log", fail_audit)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        await runtime.admin.set_user_status(
            actor_user_id=actor,
            target_user_id=target,
            status=UserStatus.SUSPENDED,
            reason_code="ROLLBACK",
        )
    async with runtime.database.connection() as connection:
        status = await connection.scalar(select(User.c.status).where(User.c.id == target))
        live = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.c.userId == target, RefreshToken.c.revokedAt.is_(None))
        )
    assert status == UserStatus.ACTIVE
    assert live == 1


async def test_concurrent_role_assignment_has_one_assignment_and_one_audit(
    runtime: Runtime,
) -> None:
    actor = await _seed_user(runtime, "role-race-actor", admin=True)
    target = await _seed_user(runtime, "role-race-target")
    results = await asyncio.gather(
        *(
            runtime.admin.assign_role(
                actor_user_id=actor,
                target_user_id=target,
                service_key="temis",
                name="race-role",
                reason_code="ROLE_RACE",
            )
            for _ in range(20)
        )
    )
    assert sum(result.role_assigned for result in results) == 1
    async with runtime.database.connection() as connection:
        audits = await connection.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.c.targetUserId == target,
                AuditLog.c.eventType == "admin_user_role_assigned",
                AuditLog.c.reasonCode == "ROLE_RACE",
            )
        )
    assert audits == 1


async def test_concurrent_role_removal_revokes_once_and_audits_once(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "remove-race-actor", admin=True)
    target = await _seed_user(runtime, "remove-race-target")
    await runtime.admin.assign_role(
        actor_user_id=actor,
        target_user_id=target,
        service_key="temis",
        name="removable",
        reason_code="PREPARE_REMOVE_RACE",
    )
    for _ in range(7):
        await _seed_refresh(runtime, target)
    results = await asyncio.gather(
        *(
            runtime.admin.remove_role(
                actor_user_id=actor,
                target_user_id=target,
                service_key="temis",
                name="removable",
                reason_code="REMOVE_RACE",
            )
            for _ in range(20)
        )
    )
    assert sum(result.role_removed for result in results) == 1
    assert sum(result.revoked_refresh_token_count for result in results) == 7
    async with runtime.database.connection() as connection:
        audits = await connection.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.c.targetUserId == target,
                AuditLog.c.reasonCode == "REMOVE_RACE",
            )
        )
    assert audits == 1


async def test_concurrent_explicit_session_revoke_audits_every_call(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "revoke-race-actor", admin=True)
    target = await _seed_user(runtime, "revoke-race-target")
    for _ in range(9):
        await _seed_refresh(runtime, target)
    results = await asyncio.gather(
        *(
            runtime.admin.revoke_sessions(
                actor_user_id=actor,
                target_user_id=target,
                reason_code="SESSION_RACE",
            )
            for _ in range(20)
        )
    )
    assert sum(result.revoked_count for result in results) == 9
    async with runtime.database.connection() as connection:
        audits = await connection.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.c.targetUserId == target,
                AuditLog.c.reasonCode == "SESSION_RACE",
            )
        )
    assert audits == 20


async def test_status_vs_python_refresh_race_never_leaves_live_session(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "python-race-actor", admin=True)
    target = await _seed_user(runtime, "python-race-target")
    raw = await _seed_refresh(runtime, target)
    outcomes = await asyncio.gather(
        runtime.admin.set_user_status(
            actor_user_id=actor,
            target_user_id=target,
            status=UserStatus.SUSPENDED,
            reason_code="PYTHON_REFRESH_RACE",
        ),
        runtime.auth.refresh(raw, RequestAuditContext("192.0.2.66", "phase6-race")),
        return_exceptions=True,
    )
    assert not isinstance(outcomes[0], BaseException)
    _assert_expected_refresh_race_outcome(outcomes[1])
    async with runtime.database.connection() as connection:
        status = await connection.scalar(select(User.c.status).where(User.c.id == target))
        live = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.c.userId == target, RefreshToken.c.revokedAt.is_(None))
        )
    assert status == UserStatus.SUSPENDED
    assert live == 0


async def test_node_admin_vs_python_refresh_mixed_writer_race(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "mixed-race-actor", admin=True)
    target = await _seed_user(runtime, "mixed-race-target")
    raw = await _seed_refresh(runtime, target)
    node, python = await asyncio.gather(
        _node_bridge(
            {
                "command": "set-status",
                "actorUserId": actor,
                "targetUserId": target,
                "status": "SUSPENDED",
                "reasonCode": "NODE_PYTHON_RACE",
            }
        ),
        runtime.auth.refresh(raw, RequestAuditContext("192.0.2.67", "phase6-mixed-race")),
        return_exceptions=True,
    )
    assert not isinstance(node, BaseException)
    assert isinstance(node, dict) and node["statusChanged"] is True
    _assert_expected_refresh_race_outcome(python)
    async with runtime.database.connection() as connection:
        live = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(RefreshToken.c.userId == target, RefreshToken.c.revokedAt.is_(None))
        )
    assert live == 0


async def test_node_and_python_role_writers_converge_to_one_assignment(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "mixed-role-actor", admin=True)
    target = await _seed_user(runtime, "mixed-role-target")
    node, python = await asyncio.gather(
        _node_bridge(
            {
                "command": "assign-role",
                "actorUserId": actor,
                "targetUserId": target,
                "serviceKey": "temis",
                "name": "mixed-writer",
                "reasonCode": "NODE_ROLE_RACE",
            }
        ),
        runtime.admin.assign_role(
            actor_user_id=actor,
            target_user_id=target,
            service_key="temis",
            name="mixed-writer",
            reason_code="PYTHON_ROLE_RACE",
        ),
    )
    assert bool(node["roleAssigned"]) + python.role_assigned == 1
    async with runtime.database.connection() as connection:
        assignments = await connection.scalar(
            select(func.count())
            .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
            .where(
                UserRole.c.userId == target,
                Role.c.serviceKey == "temis",
                Role.c.name == "mixed-writer",
            )
        )
    assert assignments == 1


@pytest.mark.parametrize("node_command", ["remove-role", "revoke-sessions"])
async def test_node_revocation_writers_vs_python_refresh_leave_no_live_session(
    runtime: Runtime,
    node_command: str,
) -> None:
    actor = await _seed_user(runtime, f"{node_command}-actor", admin=True)
    target = await _seed_user(runtime, f"{node_command}-target")
    if node_command == "remove-role":
        await runtime.admin.assign_role(
            actor_user_id=actor,
            target_user_id=target,
            service_key="temis",
            name="mixed-remove",
            reason_code="PREPARE_MIXED_REMOVE",
        )
    raw = await _seed_refresh(runtime, target)
    payload: dict[str, object] = {
        "command": node_command,
        "actorUserId": actor,
        "targetUserId": target,
        "reasonCode": f"NODE_{node_command.upper()}",
    }
    if node_command == "remove-role":
        payload.update({"serviceKey": "temis", "name": "mixed-remove"})
    node, python = await asyncio.gather(
        _node_bridge(payload),
        runtime.auth.refresh(raw, RequestAuditContext("192.0.2.68", "phase6-mixed-revoke")),
        return_exceptions=True,
    )
    assert not isinstance(node, BaseException)
    _assert_expected_refresh_race_outcome(python)
    async with runtime.database.connection() as connection:
        live = await connection.scalar(
            select(func.count())
            .select_from(RefreshToken)
            .where(
                RefreshToken.c.userId == target,
                RefreshToken.c.revokedAt.is_(None),
            )
        )
    assert live == 0


async def test_retention_dry_run_and_strict_cutoff_boundary(runtime: Runtime) -> None:
    now = utc_now_ms()
    old = now - timedelta(days=180, milliseconds=1)
    cutoff = now - timedelta(days=180)
    recent = cutoff + timedelta(milliseconds=1)
    async with runtime.database.engine.begin() as connection:
        await connection.execute(
            insert(AuditLog),
            [
                {
                    "id": f"old-{uuid4()}",
                    "eventType": "retention",
                    "outcome": "success",
                    "createdAt": old,
                },
                {
                    "id": f"cutoff-{uuid4()}",
                    "eventType": "retention",
                    "outcome": "success",
                    "createdAt": cutoff,
                },
                {
                    "id": f"recent-{uuid4()}",
                    "eventType": "retention",
                    "outcome": "success",
                    "createdAt": recent,
                },
            ],
        )
    dry = await runtime.admin.cleanup_audit_logs(now=now)
    assert dry.dry_run is True and dry.deleted_count == 1
    executed = await runtime.admin.cleanup_audit_logs(now=now, execute=True)
    assert executed.deleted_count == 1
    async with runtime.database.connection() as connection:
        remaining = await connection.scalar(
            select(func.count()).select_from(AuditLog).where(AuditLog.c.eventType == "retention")
        )
    assert remaining == 2


async def test_node_zod_date_and_prisma_email_filter_oracle(runtime: Runtime) -> None:
    await _seed_user(runtime, "oracle-one", email="Mixed.Oracle@phase6.invalid")
    await _seed_user(runtime, "oracle-two", email="other@phase6.invalid")
    result = await _node_bridge(
        {
            "command": "query-oracle",
            "query": {
                "page": "0x2",
                "pageSize": "2.0",
                "email": " ORACLE ",
                "createdAt": "2026-08-31 12:34:56+09:00",
            },
        }
    )
    assert result == {
        "accepted": True,
        "page": 2,
        "pageSize": 2,
        "createdAt": "2026-08-31T03:34:56.000Z",
        "emails": ["Mixed.Oracle@phase6.invalid"],
    }


@pytest.mark.parametrize(
    "date_value",
    [
        "2026-08-31T12:34:56",
        "Sun, 31 Aug 2026 12:34:56 GMT",
        "2026-08-31T24:00:00Z",
        "definitely-not-a-date",
    ],
)
async def test_node_date_oracle_matches_fastapi_parser(date_value: str) -> None:
    node = await _node_bridge({"command": "query-oracle", "query": {"createdAt": date_value}})
    try:
        parsed = _parse_date(date_value)
    except Exception:
        python_accepted = False
        python_iso = None
    else:
        python_accepted = True
        assert parsed is not None
        python_iso = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert node["accepted"] is python_accepted
    if python_accepted:
        assert node["createdAt"] == python_iso


@pytest.mark.parametrize(
    "date_value",
    [
        "2026/08/31",
        "08/31/2026",
        "31 Aug 2026",
        "Aug 31 2026",
        "2026-08",
        "2026",
        "2026-8-1",
        "01-02-03",
        "0000-01-01",
    ],
)
async def test_node_legacy_date_parse_matches_fastapi_parser(date_value: str) -> None:
    node = await _node_bridge({"command": "query-oracle", "query": {"createdAt": date_value}})
    try:
        parsed = _parse_date(date_value)
    except Exception:
        python_accepted = False
        python_iso = None
    else:
        python_accepted = True
        assert parsed is not None
        python_iso = parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert node["accepted"] is python_accepted
    if python_accepted:
        if date_value == "0000-01-01":
            # Python/PostgreSQL AD timestamps clamp ECMAScript year zero to their minimum.
            assert node["createdAt"] == "0000-01-01T00:00:00.000Z"
            assert python_iso == "0001-01-01T00:00:00.000Z"
        else:
            assert node["createdAt"] == python_iso


@pytest.mark.parametrize(
    "needle",
    [
        "%literal",
        "_literal",
    ],
)
async def test_node_prisma_email_wildcard_semantics_match_fastapi_store(
    runtime: Runtime,
    needle: str,
) -> None:
    emails = (
        "percent%literal@phase6.invalid",
        "percentXliteral@phase6.invalid",
        "underscore_literal@phase6.invalid",
        "underscoreXliteral@phase6.invalid",
    )
    for email in emails:
        async with runtime.database.connection() as connection:
            exists = await connection.scalar(select(User.c.id).where(User.c.email == email))
        if exists is None:
            await _seed_user(runtime, f"wildcard-{uuid4().hex}", email=email)
    node = await _node_bridge({"command": "query-oracle", "query": {"email": needle}})
    python = await runtime.admin.list_users(AdminUserListInput(email=needle, page_size=100))
    python_emails = {item.email for item in python.items if item.email is not None}
    assert set(cast(list[str], node["emails"])) == python_emails == set(emails)


async def _wait_ready(client: httpx.AsyncClient, process: asyncio.subprocess.Process) -> None:
    for _ in range(120):
        if process.returncode is not None:
            pytest.fail("guarded Phase 6 Uvicorn exited before readiness")
        try:
            if (await client.get("/readyz")).status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.05)
    pytest.fail("guarded Phase 6 Uvicorn did not become ready")


async def test_black_box_admin_and_manage_api_alias(runtime: Runtime) -> None:
    actor = await _seed_user(runtime, "blackbox-actor", admin=True)
    target = await _seed_user(runtime, "blackbox-target")
    identity = AccessTokenIdentity(actor, None, "Blackbox Admin", True, ())
    access = runtime.tokens.issue_access_token(identity)
    environment = {
        key: value for key, value in dotenv_values(ENV_FILE).items() if value is not None
    }
    environment.update(os.environ)
    environment.update(
        {"DATABASE_URL": DATABASE_URL, "REDIS_URL": REDIS_URL, "PORT": str(HTTP_PORT)}
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
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{HTTP_PORT}", timeout=3) as client:
            await _wait_ready(client, process)
            headers = {"authorization": f"Bearer {access}"}
            users = await client.get(
                "/admin/users", headers=headers, params={"email": "blackbox-target"}
            )
            assert users.status_code == 200 and users.json()["items"][0]["id"] == target
            changed = await client.patch(
                f"/manage-api/users/{target}/status",
                headers=headers,
                json={"status": "SUSPENDED", "reasonCode": "BLACKBOX"},
            )
            assert changed.status_code == 200 and changed.json()["statusChanged"] is True
            logs = await client.get(
                "/manage-api/audit-logs",
                headers=headers,
                params={
                    "createdAtFrom": "2000-01-01T00:00:00Z",
                    "createdAtTo": "2099-12-31T23:59:59Z",
                    "targetUserId": target,
                    "reasonCode": "BLACKBOX",
                },
            )
            assert logs.status_code == 200 and logs.json()["total"] == 1
    finally:
        if process.returncode is None:
            process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
    assert process.returncode == 0, (stdout + stderr).decode(errors="replace")
