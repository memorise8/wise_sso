"""OIDC 정책 저장소. 변경은 호출자가 소유한 트랜잭션에서 실행합니다."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from pydantic import ValidationError
from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.access_reviews import review_page
from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence.models import (
    OidcAccessPolicy,
    OidcPolicyChange,
    OidcPolicyDecision,
    application_uuid,
)


@dataclass(frozen=True, slots=True)
class NewPolicyChange:
    id: str
    client_id: str
    base_version: int
    before: EditableOidcPolicy
    proposed: EditableOidcPolicy
    requester_id: str
    requester_email: str | None
    reason: str
    now: datetime
    rollback_to_version: int | None = None


def decode_policy(value: object) -> EditableOidcPolicy:
    try:
        return EditableOidcPolicy.model_validate(value)
    except (ValidationError, TypeError, ValueError):
        raise DomainError(
            503, "POLICY_DATA_INVALID", "저장된 접근 정책을 확인할 수 없습니다."
        ) from None


async def register_policy(
    connection: AsyncConnection,
    *,
    client_id: str,
    policy: EditableOidcPolicy,
    now: datetime,
) -> bool:
    result = await connection.execute(
        pg_insert(OidcAccessPolicy)
        .values(
            clientId=client_id,
            version=1,
            policy=policy.public_payload(),
            createdAt=now,
            updatedAt=now,
        )
        .on_conflict_do_nothing(index_elements=[OidcAccessPolicy.c.clientId])
        .returning(OidcAccessPolicy.c.clientId)
    )
    return result.scalar_one_or_none() is not None


async def read_current(
    connection: AsyncConnection, *, client_id: str, lock: bool = False
) -> dict[str, object]:
    statement = select(OidcAccessPolicy).where(OidcAccessPolicy.c.clientId == client_id)
    if lock:
        statement = statement.with_for_update()
    result = await connection.execute(statement)
    row = result.mappings().one_or_none()
    if row is None:
        raise DomainError(
            503, "POLICY_NOT_INITIALIZED", "서비스 접근 정책의 초기 등록이 필요합니다."
        )
    return cast(dict[str, object], dict(row))


async def insert_change(connection: AsyncConnection, change: NewPolicyChange) -> None:
    await connection.execute(
        insert(OidcPolicyChange).values(
            id=change.id,
            clientId=change.client_id,
            baseVersion=change.base_version,
            status="PENDING",
            beforePolicy=change.before.public_payload(),
            proposedPolicy=change.proposed.public_payload(),
            requestedById=change.requester_id,
            requestedByEmail=change.requester_email,
            requestedAt=change.now,
            reasonCode=change.reason,
            rollbackToVersion=change.rollback_to_version,
        )
    )


async def read_change(
    connection: AsyncConnection,
    *,
    client_id: str,
    request_id: str,
    lock: bool = False,
) -> dict[str, object]:
    statement = select(OidcPolicyChange).where(
        OidcPolicyChange.c.id == request_id,
        OidcPolicyChange.c.clientId == client_id,
    )
    if lock:
        statement = statement.with_for_update()
    result = await connection.execute(statement)
    row = result.mappings().one_or_none()
    if row is None:
        raise DomainError(404, "POLICY_REQUEST_NOT_FOUND", "정책 변경 요청이 없습니다.")
    return cast(dict[str, object], dict(row))


async def insert_decision(
    connection: AsyncConnection,
    *,
    request_id: str,
    requester_id: str,
    decider_id: str,
    decider_email: str | None,
    decision: Literal["APPROVE", "REJECT"],
    reason: str,
    now: datetime,
) -> None:
    await connection.execute(
        insert(OidcPolicyDecision).values(
            id=application_uuid(),
            requestId=request_id,
            requestedById=requester_id,
            decidedById=decider_id,
            decidedByEmail=decider_email,
            decision=decision,
            reasonCode=reason,
            decidedAt=now,
        )
    )


async def apply_policy(
    connection: AsyncConnection,
    *,
    client_id: str,
    expected_version: int,
    policy: EditableOidcPolicy,
    actor_id: str,
    actor_email: str | None,
    now: datetime,
) -> int:
    version = expected_version + 1
    result = await connection.execute(
        update(OidcAccessPolicy)
        .where(
            OidcAccessPolicy.c.clientId == client_id,
            OidcAccessPolicy.c.version == expected_version,
        )
        .values(
            version=version,
            policy=policy.public_payload(),
            updatedAt=now,
            updatedById=actor_id,
            updatedByEmail=actor_email,
        )
        .returning(OidcAccessPolicy.c.version)
    )
    value = result.scalar_one_or_none()
    if value is None:
        raise DomainError(409, "POLICY_VERSION_CONFLICT", "현재 정책 버전이 변경됐습니다.")
    return int(value)


async def finish_change(
    connection: AsyncConnection,
    *,
    client_id: str,
    request_id: str,
    status: Literal["APPLIED", "REJECTED"],
    now: datetime,
    applied_version: int | None = None,
) -> None:
    result = await connection.execute(
        update(OidcPolicyChange)
        .where(
            OidcPolicyChange.c.id == request_id,
            OidcPolicyChange.c.clientId == client_id,
            OidcPolicyChange.c.status == "PENDING",
        )
        .values(
            status=status,
            appliedVersion=applied_version,
            resolvedAt=now,
        )
        .returning(OidcPolicyChange.c.id)
    )
    if result.scalar_one_or_none() is None:
        raise DomainError(409, "POLICY_REQUEST_RESOLVED", "이미 처리된 정책 변경 요청입니다.")


async def read_version(
    connection: AsyncConnection, *, client_id: str, version: int
) -> EditableOidcPolicy:
    current = await read_current(connection, client_id=client_id)
    if current["version"] == version:
        return decode_policy(current["policy"])

    result = await connection.execute(
        select(OidcPolicyChange.c.proposedPolicy).where(
            OidcPolicyChange.c.clientId == client_id,
            OidcPolicyChange.c.status == "APPLIED",
            OidcPolicyChange.c.appliedVersion == version,
        )
    )
    value = result.scalar_one_or_none()
    if value is not None:
        return decode_policy(value)

    result = await connection.execute(
        select(OidcPolicyChange.c.beforePolicy).where(
            OidcPolicyChange.c.clientId == client_id,
            OidcPolicyChange.c.status == "APPLIED",
            OidcPolicyChange.c.baseVersion == version,
        )
    )
    value = result.scalar_one_or_none()
    if value is None:
        raise DomainError(404, "POLICY_VERSION_NOT_FOUND", "해당 정책 버전이 없습니다.")
    return decode_policy(value)


async def list_changes(
    connection: AsyncConnection,
    *,
    client_id: str,
    page: int,
    page_size: int,
    status: Literal["PENDING", "APPLIED", "REJECTED"] | None = None,
) -> dict[str, object]:
    review_page(page, page_size)
    statement = select(OidcPolicyChange).where(OidcPolicyChange.c.clientId == client_id)
    if status is not None:
        statement = statement.where(OidcPolicyChange.c.status == status)
    result = await connection.execute(
        statement.order_by(OidcPolicyChange.c.requestedAt.desc(), OidcPolicyChange.c.id.desc())
        .limit(page_size + 1)
        .offset((page - 1) * page_size)
    )
    rows = result.mappings().all()
    return {
        "items": [dict(row) for row in rows[:page_size]],
        "page": page,
        "pageSize": page_size,
        "hasMore": len(rows) > page_size,
    }


async def read_decision(
    connection: AsyncConnection, *, request_id: str
) -> dict[str, object] | None:
    result = await connection.execute(
        select(OidcPolicyDecision).where(OidcPolicyDecision.c.requestId == request_id)
    )
    row = result.mappings().one_or_none()
    return None if row is None else cast(dict[str, object], dict(row))
