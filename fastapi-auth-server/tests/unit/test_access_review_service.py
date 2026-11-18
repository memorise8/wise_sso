"""점검 결정과 역할 회수가 같은 트랜잭션을 사용하는지 검증합니다."""

from unittest.mock import AsyncMock

import pytest
from test_admin_viewer_service import service_for_test

from wiseacct_sso.application.access_reviews import AccessReviewService
from wiseacct_sso.application.admin import RemoveRoleResult
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence import access_reviews as store


@pytest.mark.anyio
@pytest.mark.parametrize("exists", [True, False])
async def test_review_revokes_only_original_assignment_in_same_transaction(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch, exists: bool
) -> None:
    admin = service_for_test(synthetic_settings)
    service = AccessReviewService(admin=admin)
    authorize = AsyncMock()
    remove = AsyncMock(return_value=RemoveRoleResult(True, "role-id", 3))
    record = AsyncMock()
    audit = AsyncMock()
    monkeypatch.setattr(admin, "_require_active_admin", authorize)
    monkeypatch.setattr(admin, "remove_role_in_transaction", remove)
    monkeypatch.setattr(admin._mutations, "create_admin_audit_log", audit)
    monkeypatch.setattr(store, "lock_review", AsyncMock(return_value={"status": "OPEN"}))
    monkeypatch.setattr(
        store,
        "lock_item",
        AsyncMock(
            return_value={
                "decision": "PENDING",
                "userId": "target-user",
                "userRoleId": "original-assignment",
                "roleId": "role-id",
                "serviceKey": "sso",
                "roleName": "viewer",
            }
        ),
    )
    monkeypatch.setattr(store, "original_assignment_exists", AsyncMock(return_value=exists))
    monkeypatch.setattr(store, "record_decision", record)
    monkeypatch.setattr(store, "target_user_exists", AsyncMock(return_value=True))

    result = await service.decide(
        actor_id="admin-user",
        review_id="review-id",
        item_id="item-id",
        decision="REVOKE",
        reason="계약 종료",
    )
    expected = "REVOKE" if exists else "ALREADY_REMOVED"
    assert result["decision"] == expected
    authorize.assert_awaited_once()
    record.assert_awaited_once()
    audit.assert_awaited_once()
    assert authorize.await_args is not None
    assert record.await_args is not None
    assert audit.await_args is not None
    connection = authorize.await_args.args[0]
    assert record.await_args.args[0] is connection
    assert audit.await_args.args[0] is connection
    assert record.await_args.kwargs["decision"] == expected
    assert audit.await_args.kwargs["event"].event_type == "admin_access_review_item_decided"

    if exists:
        remove.assert_awaited_once()
        assert remove.await_args is not None
        assert remove.await_args.args[0] is connection
        assert remove.await_args.kwargs["expected_user_role_id"] == "original-assignment"
        assert result["revokedRefreshTokenCount"] == 3
    else:
        remove.assert_not_awaited()
        assert result["revokedRefreshTokenCount"] == 0


@pytest.mark.anyio
async def test_review_rejects_already_decided_item(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = service_for_test(synthetic_settings)
    service = AccessReviewService(admin=admin)
    remove = AsyncMock()
    record = AsyncMock()
    monkeypatch.setattr(admin, "_require_active_admin", AsyncMock())
    monkeypatch.setattr(admin, "remove_role_in_transaction", remove)
    monkeypatch.setattr(store, "lock_review", AsyncMock(return_value={"status": "OPEN"}))
    monkeypatch.setattr(store, "lock_item", AsyncMock(return_value={"decision": "KEEP"}))
    monkeypatch.setattr(store, "record_decision", record)

    with pytest.raises(DomainError) as caught:
        await service.decide(
            actor_id="admin-user",
            review_id="review-id",
            item_id="item-id",
            decision="REVOKE",
            reason="권한 점검",
        )

    assert caught.value.status_code == 409
    remove.assert_not_awaited()
    record.assert_not_awaited()
