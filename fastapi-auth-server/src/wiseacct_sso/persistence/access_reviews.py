"""권한 점검 저장소. 변경은 호출자가 소유한 트랜잭션에서 실행합니다."""

from datetime import datetime
from typing import cast

from sqlalchemy import Text, func, insert, literal, select, update
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.access_reviews import ItemDecision, review_page
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence.models import AccessReview, AccessReviewItem, Role, User, UserRole

_STARTED_BY = User.alias("access_review_started_by")
_COMPLETED_BY = User.alias("access_review_completed_by")
_DECIDED_BY = User.alias("access_review_decided_by")


async def create_review(
    connection: AsyncConnection,
    *,
    review_id: str,
    title: str,
    service_keys: tuple[str, ...] | None,
    actor_id: str,
    reason: str,
    now: datetime,
) -> None:
    await connection.execute(
        insert(AccessReview).values(
            id=review_id,
            title=title,
            status="OPEN",
            serviceKeys=list(service_keys or ()),
            reasonCode=reason,
            startedById=actor_id,
            startedAt=now,
        )
    )
    snapshot = select(
        func.gen_random_uuid().cast(Text),
        literal(review_id),
        UserRole.c.id,
        User.c.id,
        Role.c.id,
        Role.c.serviceKey,
        Role.c.name,
        User.c.email,
        User.c.name,
        User.c.status.cast(Text),
        User.c.userType.cast(Text),
        User.c.accountExpiresAt,
        literal("PENDING"),
        literal(now),
    ).select_from(UserRole.join(User).join(Role))
    if service_keys is not None:
        snapshot = snapshot.where(Role.c.serviceKey.in_(service_keys))

    await connection.execute(
        insert(AccessReviewItem).from_select(
            [
                "id",
                "reviewId",
                "userRoleId",
                "userId",
                "roleId",
                "serviceKey",
                "roleName",
                "userEmail",
                "userName",
                "userStatus",
                "userType",
                "accountExpiresAt",
                "decision",
                "createdAt",
            ],
            snapshot,
            include_defaults=False,
        )
    )
    if service_keys is None:
        result = await connection.execute(
            select(AccessReviewItem.c.serviceKey)
            .where(AccessReviewItem.c.reviewId == review_id)
            .distinct()
            .order_by(AccessReviewItem.c.serviceKey)
        )
        keys = list(result.scalars().all())
        await connection.execute(
            update(AccessReview).where(AccessReview.c.id == review_id).values(serviceKeys=keys)
        )


async def lock_review(connection: AsyncConnection, *, review_id: str) -> dict[str, object]:
    result = await connection.execute(
        select(AccessReview).where(AccessReview.c.id == review_id).with_for_update()
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise DomainError(404, "ACCESS_REVIEW_NOT_FOUND", "점검 회차가 없습니다.")
    return cast(dict[str, object], dict(row))


async def lock_item(
    connection: AsyncConnection, *, review_id: str, item_id: str
) -> dict[str, object]:
    result = await connection.execute(
        select(AccessReviewItem)
        .where(
            AccessReviewItem.c.id == item_id,
            AccessReviewItem.c.reviewId == review_id,
        )
        .with_for_update()
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise DomainError(404, "ACCESS_REVIEW_ITEM_NOT_FOUND", "점검 항목이 없습니다.")
    return cast(dict[str, object], dict(row))


async def original_assignment_exists(
    connection: AsyncConnection,
    *,
    assignment_id: str,
    user_id: str,
    role_id: str,
) -> bool:
    result = await connection.execute(
        select(UserRole.c.id)
        .where(
            UserRole.c.id == assignment_id,
            UserRole.c.userId == user_id,
            UserRole.c.roleId == role_id,
        )
        .with_for_update()
    )
    return result.scalar_one_or_none() is not None


async def record_decision(
    connection: AsyncConnection,
    *,
    review_id: str,
    item_id: str,
    decision: ItemDecision,
    actor_id: str,
    reason: str,
    now: datetime,
) -> None:
    if decision == "PENDING":
        raise DomainError(400, "INVALID_REQUEST", "최종 결정이 필요합니다.")
    result = await connection.execute(
        update(AccessReviewItem)
        .where(
            AccessReviewItem.c.reviewId == review_id,
            AccessReviewItem.c.id == item_id,
            AccessReviewItem.c.decision == "PENDING",
        )
        .values(
            decision=decision,
            decidedById=actor_id,
            decidedAt=now,
            reasonCode=reason,
        )
        .returning(AccessReviewItem.c.id)
    )
    if result.scalar_one_or_none() is None:
        raise DomainError(409, "ACCESS_REVIEW_ITEM_DECIDED", "이미 결정된 항목입니다.")


async def complete_review(
    connection: AsyncConnection, *, review_id: str, actor_id: str, now: datetime
) -> None:
    pending = (
        select(AccessReviewItem.c.id)
        .where(
            AccessReviewItem.c.reviewId == review_id,
            AccessReviewItem.c.decision == "PENDING",
        )
        .exists()
    )
    result = await connection.execute(
        update(AccessReview)
        .where(
            AccessReview.c.id == review_id,
            AccessReview.c.status == "OPEN",
            ~pending,
        )
        .values(status="COMPLETED", completedById=actor_id, completedAt=now)
        .returning(AccessReview.c.id)
    )
    if result.scalar_one_or_none() is None:
        raise DomainError(
            409, "ACCESS_REVIEW_NOT_READY", "미결정 항목이 있거나 이미 완료된 점검입니다."
        )


async def get_review(connection: AsyncConnection, *, review_id: str) -> dict[str, object]:
    result = await connection.execute(
        select(
            AccessReview,
            _STARTED_BY.c.email.label("startedByEmail"),
            _COMPLETED_BY.c.email.label("completedByEmail"),
        )
        .select_from(
            AccessReview.outerjoin(
                _STARTED_BY, AccessReview.c.startedById == _STARTED_BY.c.id
            ).outerjoin(_COMPLETED_BY, AccessReview.c.completedById == _COMPLETED_BY.c.id)
        )
        .where(AccessReview.c.id == review_id)
    )
    row = result.mappings().one_or_none()
    if row is None:
        raise DomainError(404, "ACCESS_REVIEW_NOT_FOUND", "점검 회차가 없습니다.")
    review = cast(dict[str, object], dict(row))
    counts = await connection.execute(
        select(AccessReviewItem.c.decision, func.count().label("count"))
        .where(AccessReviewItem.c.reviewId == review_id)
        .group_by(AccessReviewItem.c.decision)
    )
    summary = {
        "PENDING": 0,
        "KEEP": 0,
        "REVOKE": 0,
        "ALREADY_REMOVED": 0,
    }
    for decision, count in counts:
        summary[str(decision)] = int(count)
    review["counts"] = summary
    review["total"] = sum(summary.values())
    return review


async def list_reviews(
    connection: AsyncConnection, *, page: int, page_size: int
) -> dict[str, object]:
    review_page(page, page_size)
    result = await connection.execute(
        select(
            AccessReview,
            _STARTED_BY.c.email.label("startedByEmail"),
            _COMPLETED_BY.c.email.label("completedByEmail"),
        )
        .select_from(
            AccessReview.outerjoin(
                _STARTED_BY, AccessReview.c.startedById == _STARTED_BY.c.id
            ).outerjoin(_COMPLETED_BY, AccessReview.c.completedById == _COMPLETED_BY.c.id)
        )
        .order_by(AccessReview.c.startedAt.desc(), AccessReview.c.id.desc())
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


async def list_items(
    connection: AsyncConnection,
    *,
    review_id: str,
    page: int,
    page_size: int,
    decision: ItemDecision | None = None,
) -> dict[str, object]:
    review_page(page, page_size)
    query = (
        select(
            AccessReviewItem,
            _DECIDED_BY.c.email.label("decidedByEmail"),
        )
        .select_from(
            AccessReviewItem.outerjoin(
                _DECIDED_BY, AccessReviewItem.c.decidedById == _DECIDED_BY.c.id
            )
        )
        .where(AccessReviewItem.c.reviewId == review_id)
    )
    if decision is not None:
        query = query.where(AccessReviewItem.c.decision == decision)
    result = await connection.execute(
        query.order_by(
            func.lower(AccessReviewItem.c.userEmail).asc().nulls_last(),
            AccessReviewItem.c.userId,
            AccessReviewItem.c.serviceKey,
            AccessReviewItem.c.roleName,
            AccessReviewItem.c.id,
        )
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


async def target_user_exists(connection: AsyncConnection, *, user_id: str) -> bool:
    result = await connection.execute(select(User.c.id).where(User.c.id == user_id))
    return result.scalar_one_or_none() is not None
