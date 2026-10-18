"""Dormant, dry-run-first successor for split email identity repair.

Prisma remains the schema owner and this module is never scheduled by the app.
Compared with the retained Express command, apply mode revalidates and locks each
candidate inside its transaction so a stale discovery result cannot be mutated.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from sqlalchemy import Text, bindparam, delete, func, insert, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import Select
from sqlalchemy.sql.elements import ColumnElement

from wiseacct_sso.domain.admin import AuditRetentionCleanupConfigurationError
from wiseacct_sso.ops.audit_cleanup import _async_postgres_url, _database_url
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import (
    AuditLog,
    PasswordCredential,
    SocialAccount,
    User,
    UserStatus,
    application_uuid,
    utc_now_ms,
)

_EMAIL = re.compile(
    r"^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-.]*)[A-Z0-9_+\-]@"
    r"([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$",
    re.IGNORECASE | re.ASCII,
)


class MergeSplitIdentityConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SplitAccountCandidate:
    email: str
    canonical_user_id: str
    password_user_id: str
    provider: str
    provider_user_id: str


@dataclass(frozen=True, slots=True)
class MergeSplitIdentityOptions:
    apply: bool = False
    email: str | None = None


@dataclass(frozen=True, slots=True)
class MergeSplitIdentityResult:
    mode: str
    candidates: tuple[SplitAccountCandidate, ...]
    merged_count: int
    stale_count: int


class MergeSplitIdentityStore(Protocol):
    async def find_candidates(self, email: str | None) -> tuple[SplitAccountCandidate, ...]: ...

    async def merge_candidate(self, candidate: SplitAccountCandidate) -> bool: ...


class _CandidateRow(Protocol):
    email: object
    canonicalUserId: object
    passwordUserId: object
    provider: object
    providerUserId: object


def _candidate_select(email: str | None, *, locked: bool = False) -> Select[tuple[str, ...]]:
    canonical_user = User.alias("canonical_user")
    password_user = User.alias("password_user")
    existing_credential = PasswordCredential.alias("existing_pc")
    # Keep the NULL case typed as text, matching Prisma's explicit ``::text`` cast.
    email_parameter = cast(ColumnElement[str | None], bindparam("email", value=email, type_=Text()))
    statement = (
        select(
            func.lower(PasswordCredential.c.email).label("email"),
            SocialAccount.c.userId.label("canonicalUserId"),
            PasswordCredential.c.userId.label("passwordUserId"),
            SocialAccount.c.provider.label("provider"),
            SocialAccount.c.providerUserId.label("providerUserId"),
        )
        .select_from(
            PasswordCredential.join(
                SocialAccount,
                func.lower(SocialAccount.c.providerEmail) == func.lower(PasswordCredential.c.email),
            )
            .join(canonical_user, canonical_user.c.id == SocialAccount.c.userId)
            .join(password_user, password_user.c.id == PasswordCredential.c.userId)
        )
        .where(
            SocialAccount.c.provider == "google",
            SocialAccount.c.userId != PasswordCredential.c.userId,
            canonical_user.c.status == UserStatus.ACTIVE,
            canonical_user.c.emailVerified.is_(True),
            password_user.c.emailVerified.is_(True),
            ~select(existing_credential.c.id)
            .where(existing_credential.c.userId == SocialAccount.c.userId)
            .exists(),
            or_(
                email_parameter.is_(None),
                func.lower(PasswordCredential.c.email) == func.lower(email_parameter),
            ),
        )
        .order_by(func.lower(PasswordCredential.c.email))
    )
    if locked:
        statement = statement.with_for_update(
            of=(PasswordCredential, SocialAccount, canonical_user, password_user)
        )
    return statement


def candidate_discovery_statement(email: str | None) -> Select[tuple[str, ...]]:
    """Expose the candidate query for exact contract/static verification."""
    return _candidate_select(email)


def _locked_candidate_statement(candidate: SplitAccountCandidate) -> Select[tuple[str, ...]]:
    return _candidate_select(candidate.email, locked=True).where(
        SocialAccount.c.userId == candidate.canonical_user_id,
        PasswordCredential.c.userId == candidate.password_user_id,
        SocialAccount.c.provider == candidate.provider,
        SocialAccount.c.providerUserId == candidate.provider_user_id,
        func.lower(PasswordCredential.c.email) == candidate.email,
    )


def _candidate_from_row(row: _CandidateRow) -> SplitAccountCandidate:
    return SplitAccountCandidate(
        email=str(row.email),
        canonical_user_id=str(row.canonicalUserId),
        password_user_id=str(row.passwordUserId),
        provider=str(row.provider),
        provider_user_id=str(row.providerUserId),
    )


def _require_one(rowcount: int | None, operation: str) -> None:
    if rowcount != 1:
        raise RuntimeError(f"{operation} affected an unexpected row count")


class SqlAlchemyMergeSplitIdentityStore:
    def __init__(self, database: Database) -> None:
        self._database = database

    async def find_candidates(self, email: str | None) -> tuple[SplitAccountCandidate, ...]:
        async with self._database.connection() as connection:
            rows = (await connection.execute(candidate_discovery_statement(email))).all()
        return tuple(_candidate_from_row(cast(_CandidateRow, row)) for row in rows)

    async def merge_candidate(self, candidate: SplitAccountCandidate) -> bool:
        # Generate once outside the retryable callback. Retried transactions use the
        # same audit ID/timestamp and have no non-database effects. SQLAlchemy Core
        # must explicitly preserve Prisma's @updatedAt behavior.
        audit_id = application_uuid()
        updated_at = utc_now_ms()

        async def operation(connection: AsyncConnection) -> bool:
            await connection.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            locked = (
                await connection.execute(_locked_candidate_statement(candidate))
            ).one_or_none()
            if locked is None:
                return False

            _require_one(
                (
                    await connection.execute(
                        update(User)
                        .where(User.c.id == candidate.password_user_id)
                        .values(email=None, updatedAt=updated_at)
                    )
                ).rowcount,
                "password user update",
            )
            _require_one(
                (
                    await connection.execute(
                        update(User)
                        .where(User.c.id == candidate.canonical_user_id)
                        .values(
                            email=candidate.email,
                            emailVerified=True,
                            updatedAt=updated_at,
                        )
                    )
                ).rowcount,
                "canonical user update",
            )
            _require_one(
                (
                    await connection.execute(
                        update(PasswordCredential)
                        .where(PasswordCredential.c.userId == candidate.password_user_id)
                        .values(userId=candidate.canonical_user_id, updatedAt=updated_at)
                    )
                ).rowcount,
                "password credential update",
            )
            _require_one(
                (
                    await connection.execute(
                        insert(AuditLog).values(
                            id=audit_id,
                            eventType="identity_merge",
                            outcome="success",
                            provider=candidate.provider,
                            userId=candidate.canonical_user_id,
                            targetUserId=candidate.password_user_id,
                            reasonCode="OPS_MERGE_SPLIT_EMAIL_IDENTITIES",
                            detailsJson={
                                "email": candidate.email,
                                "providerUserId": candidate.provider_user_id,
                                "canonicalUserId": candidate.canonical_user_id,
                                "mergedPasswordUserId": candidate.password_user_id,
                            },
                        )
                    )
                ).rowcount,
                "audit insert",
            )
            # AuditLog.targetUserId is intentionally created before deletion. The
            # Prisma-owned FK changes it to NULL on delete, while detailsJson retains
            # the retired identifier. Deleting the old User intentionally preserves
            # every other Prisma CASCADE from the retained Express command.
            _require_one(
                (
                    await connection.execute(
                        delete(User).where(User.c.id == candidate.password_user_id)
                    )
                ).rowcount,
                "password user delete",
            )
            return True

        return await self._database.transaction(database_only_transaction(operation))


async def merge_split_identities(
    store: MergeSplitIdentityStore, options: MergeSplitIdentityOptions
) -> MergeSplitIdentityResult:
    candidates = await store.find_candidates(options.email)
    if not options.apply:
        return MergeSplitIdentityResult("dry-run", candidates, 0, 0)

    merged_count = 0
    for candidate in candidates:
        if await store.merge_candidate(candidate):
            merged_count += 1
    # Unlike Express, report actual commits rather than the preflight candidate count.
    return MergeSplitIdentityResult(
        "apply", candidates, merged_count, len(candidates) - merged_count
    )


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if _EMAIL.fullmatch(email) is None:
        raise MergeSplitIdentityConfigurationError("Invalid email")
    return email


def parse_args(argv: Sequence[str] | None = None) -> MergeSplitIdentityOptions:
    apply = False
    email: str | None = None
    arguments = list(argv or ())
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--apply":
            apply = True
        elif argument == "--email":
            index += 1
            if index >= len(arguments) or not arguments[index]:
                raise MergeSplitIdentityConfigurationError("--email requires a value")
            email = _normalize_email(arguments[index])
        elif argument.startswith("--email="):
            email = _normalize_email(argument.partition("=")[2])
        else:
            # Do not echo an unexpected argument because operator input can contain secrets.
            raise MergeSplitIdentityConfigurationError("Unknown option")
        index += 1
    return MergeSplitIdentityOptions(apply=apply, email=email)


async def _run(
    options: MergeSplitIdentityOptions, *, database_url: str
) -> MergeSplitIdentityResult:
    database = Database(_async_postgres_url(database_url))
    try:
        return await merge_split_identities(SqlAlchemyMergeSplitIdentityStore(database), options)
    finally:
        await database.close()


def _candidate_json(candidate: SplitAccountCandidate) -> dict[str, str]:
    return {
        "email": candidate.email,
        "canonicalUserId": candidate.canonical_user_id,
        "passwordUserId": candidate.password_user_id,
        "provider": candidate.provider,
        "providerUserId": candidate.provider_user_id,
    }


def cli(argv: Sequence[str] | None = None) -> None:
    try:
        options = parse_args(sys.argv[1:] if argv is None else argv)
        result = asyncio.run(_run(options, database_url=_database_url(os.environ)))
    except Exception as error:
        detail = (
            str(error)
            if isinstance(
                error,
                (
                    MergeSplitIdentityConfigurationError,
                    AuditRetentionCleanupConfigurationError,
                ),
            )
            else type(error).__name__
        )
        sys.stderr.write(f"merge-split-email-identities failed: {detail}\n")
        raise SystemExit(1) from None

    payload: dict[str, object]
    if result.mode == "dry-run":
        payload = {
            "mode": "dry-run",
            "count": len(result.candidates),
            "candidates": [_candidate_json(candidate) for candidate in result.candidates],
        }
    else:
        payload = {
            "mode": "apply",
            "mergedCount": result.merged_count,
            "staleCount": result.stale_count,
        }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    cli()
