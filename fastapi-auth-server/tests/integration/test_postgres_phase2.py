"""Live PostgreSQL compatibility probes for the disposable Phase 2 database."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import pytest
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import ProgrammingError

from wiseacct_sso.persistence.catalog import (
    diff_catalog,
    inspect_database_catalog,
    metadata_catalog,
)
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import (
    PasswordCredential,
    RefreshToken,
    SubjectReservation,
    User,
    metadata,
    utc_now_ms,
)
from wiseacct_sso.persistence.stores import (
    FailedLoginStore,
    RefreshReplacement,
    RefreshRotationConflict,
    RefreshRotationStore,
)

PHASE2_ENABLED = os.getenv("WISEACCT_PHASE2_INTEGRATION") == "1"
RUNTIME_URL = os.getenv("WISEACCT_PHASE2_DATABASE_URL", "")
PRISMA_EVIDENCE_FILE = os.getenv("WISEACCT_PHASE2_PRISMA_EVIDENCE_FILE", "")


def _require_disposable_url(raw_url: str) -> None:
    parsed = urlparse(raw_url)
    if (
        parsed.scheme not in {"postgresql", "postgresql+asyncpg"}
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port != 5433
        or parsed.path == "/"
        or "_test_" not in parsed.path
    ):
        raise RuntimeError("Phase 2 requires a synthetic _test_ database on localhost:5433")


if PHASE2_ENABLED:
    _require_disposable_url(RUNTIME_URL)

pytestmark = [pytest.mark.anyio, pytest.mark.skipif(not PHASE2_ENABLED, reason="Phase 2 only")]


@pytest.fixture
async def database() -> AsyncIterator[Database]:
    database = Database(RUNTIME_URL)
    try:
        yield database
    finally:
        await database.close()


async def _delete_user(database: Database, user_id: str) -> None:
    async with database.engine.begin() as connection:
        await connection.execute(delete(User).where(User.c.id == user_id))


async def _create_credential(database: Database, label: str) -> str:
    now = utc_now_ms()
    user_id = f"phase2-user-{label}"
    async with database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=f"{label}@phase2.invalid",
                updatedAt=now,
            )
        )
        await connection.execute(
            insert(PasswordCredential).values(
                id=f"phase2-credential-{label}",
                userId=user_id,
                email=f"{label}@phase2.invalid",
                passwordHash="synthetic-phase2-only",
                updatedAt=now,
            )
        )
    return user_id


async def test_live_catalog_matches_prisma_mirror(database: Database) -> None:
    async with database.connection() as connection:
        actual = await inspect_database_catalog(connection)
    application_catalog = tuple(
        entry
        for entry in actual
        if entry.name != "_prisma_migrations"
        and not entry.name.startswith("_prisma_migrations.")
        and entry.name != "_prisma_migrations_pkey"
    )
    difference = diff_catalog(metadata_catalog(metadata), application_catalog)
    assert difference.matches, (
        f"missing={difference.missing!r}; unexpected={difference.unexpected!r}"
    )


async def test_runtime_role_cannot_create_schema_objects(database: Database) -> None:
    async with database.connection() as connection:
        with pytest.raises(ProgrammingError) as captured:
            await connection.execute(text('CREATE TABLE "phase2_forbidden" (id integer)'))
    assert getattr(captured.value.orig, "sqlstate", None) == "42501"


async def test_prisma_timestamp3_fixture_roundtrips_exactly_in_python(
    database: Database,
) -> None:
    if not PRISMA_EVIDENCE_FILE:
        pytest.fail("runner must provide the Prisma semantic evidence file")
    evidence_text = await asyncio.to_thread(Path(PRISMA_EVIDENCE_FILE).read_text, encoding="utf-8")
    evidence = json.loads(evidence_text)
    fixture_id = evidence["timestamp3FixtureId"]
    async with database.connection() as connection:
        stored = await connection.scalar(
            select(SubjectReservation.c.updatedAt).where(SubjectReservation.c.id == fixture_id)
        )
    assert stored is not None
    assert stored.isoformat(timespec="milliseconds") == "2026-01-02T03:04:05.123"
    assert stored.microsecond == 123_000
    assert evidence["timestamp3Iso"] == "2026-01-02T03:04:05.123Z"
    assert evidence["timestamp3Milliseconds"] == 123


@pytest.mark.parametrize("request_count", [4, 5, 20])
async def test_failed_login_concurrency_is_exact(database: Database, request_count: int) -> None:
    label = f"failure-{request_count}"
    user_id = await _create_credential(database, label)
    store = FailedLoginStore()
    lock_time = utc_now_ms() + timedelta(minutes=15)

    async def record() -> tuple[int, datetime]:
        updated_at = utc_now_ms()
        result = await database.transaction(
            database_only_transaction(
                lambda connection: store.record_failure(
                    connection,
                    user_id=user_id,
                    locked_until=lock_time,
                    updated_at=updated_at,
                )
            )
        )
        assert result.failed_login_count is not None
        return result.failed_login_count, updated_at

    try:
        results = await asyncio.gather(*(record() for _ in range(request_count)))
        counts = [count for count, _updated_at in results]
        assert sorted(counts) == list(range(1, request_count + 1))
        async with database.connection() as connection:
            row = (
                await connection.execute(
                    select(
                        PasswordCredential.c.failedLoginCount,
                        PasswordCredential.c.lockedUntil,
                        PasswordCredential.c.updatedAt,
                    ).where(PasswordCredential.c.userId == user_id)
                )
            ).one()
        assert row.failedLoginCount == request_count
        assert (row.lockedUntil is not None) is (request_count >= 5)
        assert row.updatedAt in {updated_at for _count, updated_at in results}
    finally:
        await _delete_user(database, user_id)


async def test_refresh_rotation_has_one_success_under_twenty_way_race(
    database: Database,
) -> None:
    label = "refresh-race"
    user_id = f"phase2-user-{label}"
    now = utc_now_ms()
    old_hash = "phase2-old-refresh-hash"
    async with database.engine.begin() as connection:
        await connection.execute(
            insert(User).values(
                id=user_id,
                email=f"{label}@phase2.invalid",
                updatedAt=now,
            )
        )
        await connection.execute(
            insert(RefreshToken).values(
                id="phase2-old-refresh",
                tokenHash=old_hash,
                userId=user_id,
                audience="temis",
                expiresAt=now + timedelta(hours=1),
                createdAt=now,
            )
        )

    store = RefreshRotationStore()

    async def rotate(index: int) -> bool:
        try:
            result = await database.transaction(
                database_only_transaction(
                    lambda connection: store.rotate(
                        connection,
                        old_token_hash=old_hash,
                        expected_audience="temis",
                        now=now,
                        replacement=RefreshReplacement(
                            id=f"phase2-new-refresh-{index}",
                            token_hash=f"phase2-new-refresh-hash-{index}",
                            expires_at=now + timedelta(hours=1),
                            created_at=now,
                        ),
                    )
                )
            )
            return result is not None
        except RefreshRotationConflict:
            return False

    try:
        outcomes = await asyncio.gather(*(rotate(index) for index in range(20)))
        assert outcomes.count(True) == 1
        async with database.connection() as connection:
            active_replacements = await connection.scalar(
                select(func.count())
                .select_from(RefreshToken)
                .where(
                    RefreshToken.c.userId == user_id,
                    RefreshToken.c.tokenHash != old_hash,
                    RefreshToken.c.revokedAt.is_(None),
                )
            )
            old_revoked_at = await connection.scalar(
                select(RefreshToken.c.revokedAt).where(RefreshToken.c.tokenHash == old_hash)
            )
        assert active_replacements == 1
        assert old_revoked_at is not None
    finally:
        await _delete_user(database, user_id)
