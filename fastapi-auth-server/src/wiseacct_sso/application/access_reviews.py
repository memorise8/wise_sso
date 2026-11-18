"""권한 점검과 실제 권한 변경을 하나의 DB 트랜잭션으로 처리합니다."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.access_reviews import (
    ItemDecision,
    ReviewDecision,
    require_open_review,
    require_pending_item,
    review_page,
    review_reason,
    review_title,
)
from wiseacct_sso.domain.admin import AdminAuditEventType, AdminAuditRecord, AuditDetailValue
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence import access_reviews as store
from wiseacct_sso.persistence.database import database_only_transaction
from wiseacct_sso.persistence.models import application_uuid, utc_now_ms

if TYPE_CHECKING:
    from wiseacct_sso.application.admin import Phase6AdminService


def _identifier(value: str) -> str:
    if not value or value != value.strip() or len(value) > 128:
        raise DomainError(400, "INVALID_REQUEST", "잘못된 점검 식별자입니다.")
    return value


def _field(item: dict[str, object], key: str) -> str:
    value = item[key]
    if not isinstance(value, str):
        raise RuntimeError("점검 스냅샷의 필수 정보가 올바르지 않습니다.")
    return value


class AccessReviewService:
    def __init__(self, *, admin: Phase6AdminService) -> None:
        self._admin = admin
        self._database = admin._database

    async def _audit(
        self,
        connection: AsyncConnection,
        *,
        event_type: AdminAuditEventType,
        actor_id: str,
        review_id: str,
        reason: str,
        now: datetime,
        target_id: str | None = None,
        details: dict[str, AuditDetailValue] | None = None,
    ) -> None:
        await self._admin._mutations.create_admin_audit_log(
            connection,
            event=AdminAuditRecord(
                event_type=event_type,
                actor_user_id=actor_id,
                target_user_id=target_id,
                reason_code=reason,
                details_json={"reviewId": review_id, **(details or {})},
            ),
            created_at=now,
        )

    async def start(
        self,
        *,
        actor_id: str,
        title: str,
        reason: str,
        service_keys: tuple[str, ...] | None = None,
    ) -> dict[str, object]:
        title = review_title(title)
        reason = review_reason(reason)
        if service_keys is not None:
            if (
                not 1 <= len(service_keys) <= 100
                or len(set(service_keys)) != len(service_keys)
                or any(not key or key != key.strip() or len(key) > 128 for key in service_keys)
            ):
                raise DomainError(400, "INVALID_REQUEST", "점검 대상 서비스를 확인하세요.")
        review_id = application_uuid()
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            await store.create_review(
                connection,
                review_id=review_id,
                title=title,
                service_keys=service_keys,
                actor_id=actor_id,
                reason=reason,
                now=now,
            )
            result = await store.get_review(connection, review_id=review_id)
            total = result["total"]
            if not isinstance(total, int):
                raise RuntimeError("점검 대상 집계가 올바르지 않습니다.")
            await self._audit(
                connection,
                event_type="admin_access_review_started",
                actor_id=actor_id,
                review_id=review_id,
                reason=reason,
                now=now,
                details={"itemCount": total},
            )
            return result

        return await self._database().transaction(database_only_transaction(work))

    async def decide(
        self,
        *,
        actor_id: str,
        review_id: str,
        item_id: str,
        decision: ReviewDecision,
        reason: str | None = None,
    ) -> dict[str, object]:
        review_id = _identifier(review_id)
        item_id = _identifier(item_id)
        decision_reason = (
            "권한 유지(변경 없음)"
            if decision == "KEEP" and reason is None
            else review_reason(reason or "")
        )
        if decision not in {"KEEP", "REVOKE"}:
            raise DomainError(400, "INVALID_REQUEST", "유지 또는 회수를 선택하세요.")
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            review = await store.lock_review(connection, review_id=review_id)
            require_open_review(_field(review, "status"))
            item = await store.lock_item(connection, review_id=review_id, item_id=item_id)
            require_pending_item(_field(item, "decision"))
            user_id = _field(item, "userId")
            assignment_id = _field(item, "userRoleId")
            exists = await store.original_assignment_exists(
                connection,
                assignment_id=assignment_id,
                user_id=user_id,
                role_id=_field(item, "roleId"),
            )
            final: ItemDecision = decision if exists else "ALREADY_REMOVED"
            revoked = 0
            if exists and decision == "REVOKE":
                removal = await self._admin.remove_role_in_transaction(
                    connection,
                    actor_user_id=actor_id,
                    target_user_id=user_id,
                    service_key=_field(item, "serviceKey"),
                    name=_field(item, "roleName"),
                    reason_code=decision_reason,
                    details={"reviewId": review_id, "itemId": item_id},
                    now=now,
                    expected_user_role_id=assignment_id,
                )
                if not removal.role_removed:
                    final = "ALREADY_REMOVED"
                revoked = removal.revoked_refresh_token_count

            await store.record_decision(
                connection,
                review_id=review_id,
                item_id=item_id,
                decision=final,
                actor_id=actor_id,
                reason=decision_reason,
                now=now,
            )
            target_exists = await store.target_user_exists(connection, user_id=user_id)
            await self._audit(
                connection,
                event_type="admin_access_review_item_decided",
                actor_id=actor_id,
                review_id=review_id,
                target_id=user_id if target_exists else None,
                reason=decision_reason,
                now=now,
                details={
                    "itemId": item_id,
                    "snapshotUserId": user_id,
                    "userRoleId": assignment_id,
                    "decision": final,
                    "revokedRefreshTokenCount": revoked,
                },
            )
            return {
                "itemId": item_id,
                "decision": final,
                "revokedRefreshTokenCount": revoked,
            }

        return await self._database().transaction(database_only_transaction(work))

    async def complete(self, *, actor_id: str, review_id: str, reason: str) -> dict[str, object]:
        review_id = _identifier(review_id)
        reason = review_reason(reason)
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            review = await store.lock_review(connection, review_id=review_id)
            require_open_review(_field(review, "status"))
            await store.complete_review(connection, review_id=review_id, actor_id=actor_id, now=now)
            await self._audit(
                connection,
                event_type="admin_access_review_completed",
                actor_id=actor_id,
                review_id=review_id,
                reason=reason,
                now=now,
            )
            return await store.get_review(connection, review_id=review_id)

        return await self._database().transaction(database_only_transaction(work))

    async def list(self, *, actor_id: str, page: int = 1, page_size: int = 25) -> dict[str, object]:
        review_page(page, page_size)
        await self._admin.authorize_admin(
            actor_id, route="/oauth2/admin/api/access-reviews", method="GET"
        )
        async with self._database().connection() as connection:
            return await store.list_reviews(connection, page=page, page_size=page_size)

    async def get(self, *, actor_id: str, review_id: str) -> dict[str, object]:
        review_id = _identifier(review_id)
        await self._admin.authorize_admin(
            actor_id, route="/oauth2/admin/api/access-reviews", method="GET"
        )
        async with self._database().connection() as connection:
            return await store.get_review(connection, review_id=review_id)

    async def items(
        self,
        *,
        actor_id: str,
        review_id: str,
        page: int = 1,
        page_size: int = 25,
        decision: ItemDecision | None = None,
    ) -> dict[str, object]:
        review_id = _identifier(review_id)
        review_page(page, page_size)
        if decision not in {None, "PENDING", "KEEP", "REVOKE", "ALREADY_REMOVED"}:
            raise DomainError(400, "INVALID_REQUEST", "잘못된 결정 필터입니다.")
        await self._admin.authorize_admin(
            actor_id, route="/oauth2/admin/api/access-reviews", method="GET"
        )
        async with self._database().connection() as connection:
            await store.get_review(connection, review_id=review_id)
            return await store.list_items(
                connection,
                review_id=review_id,
                page=page,
                page_size=page_size,
                decision=decision,
            )
