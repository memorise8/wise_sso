"""점검의 역할 회수가 기존 보호 규칙과 할당 식별자를 지키는지 검증합니다."""

from typing import cast
from unittest.mock import AsyncMock, Mock

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection
from test_admin_viewer_service import service_for_test

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.admin import AdminRoleProfile
from wiseacct_sso.domain.users import DomainError, UserStatus


@pytest.mark.anyio
async def test_review_cannot_remove_own_admin_role(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = service_for_test(synthetic_settings)
    authorize = AsyncMock()
    monkeypatch.setattr(service, "_authorize_mutation", authorize)

    with pytest.raises(DomainError) as caught:
        await service.remove_role_in_transaction(
            cast(AsyncConnection, object()),
            actor_user_id="admin-user",
            target_user_id="admin-user",
            service_key="sso",
            name="admin",
            reason_code="점검 회수",
            expected_user_role_id="original-assignment",
        )

    assert caught.value.status_code == 403
    authorize.assert_not_awaited()


@pytest.mark.anyio
async def test_review_preserves_last_admin_protection(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = service_for_test(synthetic_settings)
    monkeypatch.setattr(
        service,
        "_authorize_mutation",
        AsyncMock(return_value=("EMPLOYEE", UserStatus.ACTIVE)),
    )
    protect = AsyncMock(side_effect=DomainError(409, "LAST_SSO_ADMIN", "마지막 관리자입니다."))
    find = AsyncMock()
    monkeypatch.setattr(service, "_protect_last_admin", protect)
    monkeypatch.setattr(service._mutations, "find_role", find)

    with pytest.raises(DomainError) as caught:
        await service.remove_role_in_transaction(
            cast(AsyncConnection, object()),
            actor_user_id="review-admin",
            target_user_id="target-admin",
            service_key="sso",
            name="admin",
            reason_code="점검 회수",
            expected_user_role_id="original-assignment",
        )

    assert caught.value.code == "LAST_SSO_ADMIN"
    protect.assert_awaited_once()
    find.assert_not_awaited()


@pytest.mark.anyio
async def test_missing_original_assignment_does_not_revoke_or_audit_removal(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = service_for_test(synthetic_settings)
    monkeypatch.setattr(
        service,
        "_authorize_mutation",
        AsyncMock(return_value=("EMPLOYEE", UserStatus.ACTIVE)),
    )
    monkeypatch.setattr(
        service._mutations,
        "find_role",
        AsyncMock(return_value=AdminRoleProfile("role-id", "gitlab", "user")),
    )
    revoke = AsyncMock()
    audit = AsyncMock()
    monkeypatch.setattr(service._mutations, "revoke_all_refresh_tokens_for_user", revoke)
    monkeypatch.setattr(service, "_record_mutation_audit", audit)

    result = Mock()
    result.scalar_one_or_none.return_value = None
    execute = AsyncMock(return_value=result)
    connection = Mock()
    connection.execute = execute

    outcome = await service.remove_role_in_transaction(
        cast(AsyncConnection, connection),
        actor_user_id="review-admin",
        target_user_id="target-user",
        service_key="gitlab",
        name="user",
        reason_code="점검 회수",
        expected_user_role_id="original-assignment",
    )

    assert outcome.role_removed is False
    assert outcome.revoked_refresh_token_count == 0
    execute.assert_awaited_once()
    statement = execute.call_args.args[0]
    assert "original-assignment" in statement.compile().params.values()
    revoke.assert_not_awaited()
    audit.assert_not_awaited()
