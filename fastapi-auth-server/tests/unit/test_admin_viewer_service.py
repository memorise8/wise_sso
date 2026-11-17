"""서비스 내부의 admin 재검사와 viewer 역할 부여 제한을 검증합니다."""

from typing import cast
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.config import Settings
from wiseacct_sso.domain.admin import AuditLogListInput
from wiseacct_sso.domain.users import DomainError, UserStatus, UserType
from wiseacct_sso.infrastructure.security import JwtTokenCodec
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction


class TransactionDatabase:
    async def transaction[T](self, work: DatabaseOnlyTransaction[T], *, max_attempts: int = 3) -> T:
        return await work.callback(cast(AsyncConnection, object()))


def service_for_test(settings: Settings) -> Phase6AdminService:
    database = TransactionDatabase()
    return Phase6AdminService(
        database=lambda: cast(Database, database),
        tokens=JwtTokenCodec.from_settings(settings),
    )


@pytest.mark.anyio
async def test_export_denies_non_admin_before_read_or_success_audit(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = service_for_test(synthetic_settings)
    lock = AsyncMock()
    permission = AsyncMock(return_value=False)
    query = AsyncMock()
    audit = AsyncMock()
    monkeypatch.setattr(service._mutations, "lock_policy", lock)
    monkeypatch.setattr(service._directory, "is_active_sso_admin", permission)
    monkeypatch.setattr(service._audit_query, "export_rows", query)
    monkeypatch.setattr(service._mutations, "create_admin_audit_log", audit)

    with pytest.raises(DomainError) as caught:
        await service.export_audit_csv(
            actor_user_id="viewer-user",
            input=AuditLogListInput(),
            reason_code="권한 검증",
        )

    assert caught.value.status_code == 403
    lock.assert_awaited_once()
    permission.assert_awaited_once()
    query.assert_not_awaited()
    audit.assert_not_awaited()


@pytest.mark.anyio
async def test_mutation_denies_non_admin_before_loading_target(
    synthetic_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = service_for_test(synthetic_settings)
    permission = AsyncMock(return_value=False)
    target = AsyncMock()
    monkeypatch.setattr(service._mutations, "lock_policy", AsyncMock())
    monkeypatch.setattr(service._directory, "is_active_sso_admin", permission)
    monkeypatch.setattr(service._mutations, "user_policy", target)

    with pytest.raises(DomainError) as caught:
        await service._authorize_mutation(
            cast(AsyncConnection, object()), "viewer-user", "target-user"
        )

    assert caught.value.status_code == 403
    target.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("user_type", [UserType.CUSTOMER, UserType.EXTERNAL, None])
async def test_viewer_role_requires_employee(
    synthetic_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    user_type: UserType | None,
) -> None:
    service = service_for_test(synthetic_settings)
    upsert = AsyncMock()
    grant = AsyncMock()
    monkeypatch.setattr(
        service,
        "_authorize_mutation",
        AsyncMock(return_value=(user_type, UserStatus.ACTIVE)),
    )
    monkeypatch.setattr(service._mutations, "upsert_role", upsert)
    monkeypatch.setattr(service._mutations, "assign_role_to_user", grant)

    with pytest.raises(DomainError) as caught:
        await service.assign_role(
            actor_user_id="admin-user",
            target_user_id="target-user",
            service_key="sso",
            name="viewer",
            reason_code="읽기 전용 역할 부여 검증",
        )

    assert caught.value.status_code == 403
    upsert.assert_not_awaited()
    grant.assert_not_awaited()
