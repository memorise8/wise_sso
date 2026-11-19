"""최초 정책 등록의 관리자 검사와 재실행 동작을 검증합니다."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy
from wiseacct_sso.persistence import oidc_policy_changes as store

pytest_plugins = ("test_oidc_policy_change_service",)


def client_for(rig: SimpleNamespace) -> OidcClientPolicy:
    return OidcClientPolicy.model_construct(client_id="gitlab", **rig.before.model_dump())


@pytest.mark.anyio
@pytest.mark.parametrize("created", [True, False])
async def test_initialization_registers_only_missing_policies(
    monkeypatch: pytest.MonkeyPatch, rig: SimpleNamespace, created: bool
) -> None:
    register = AsyncMock(return_value=created)
    monkeypatch.setattr(store, "register_policy", register)
    result = await rig.service.initialize(
        actor_id="requester", clients=(client_for(rig),), reason="정책 최초 등록"
    )
    assert result == {
        "initializedCount": int(created),
        "retainedCount": int(not created),
    }
    rig.admin._require_active_admin.assert_awaited_once_with(rig.connection, "requester")
    call = register.await_args
    assert call is not None
    assert call.kwargs["policy"] == rig.before
    rig.apply_policy.assert_not_awaited()
    audit = rig.mutations.create_admin_audit_log.await_args
    assert audit is not None
    assert audit.kwargs["event"].event_type == "admin_oidc_policy_initialized"
    assert audit.kwargs["event"].details_json == result


@pytest.mark.anyio
async def test_viewer_cannot_initialize(
    monkeypatch: pytest.MonkeyPatch, rig: SimpleNamespace
) -> None:
    register = AsyncMock()
    monkeypatch.setattr(store, "register_policy", register)
    rig.admin._require_active_admin.side_effect = DomainError(
        403, "FORBIDDEN", "관리자 권한이 필요합니다."
    )
    with pytest.raises(DomainError):
        await rig.service.initialize(
            actor_id="viewer", clients=(client_for(rig),), reason="정책 등록"
        )
    register.assert_not_awaited()


@pytest.mark.anyio
async def test_initialization_audit_failure_is_propagated(
    monkeypatch: pytest.MonkeyPatch, rig: SimpleNamespace
) -> None:
    monkeypatch.setattr(store, "register_policy", AsyncMock(return_value=True))
    rig.mutations.create_admin_audit_log.side_effect = RuntimeError("감사 저장 실패")
    with pytest.raises(RuntimeError, match="감사 저장 실패"):
        await rig.service.initialize(
            actor_id="requester", clients=(client_for(rig),), reason="정책 등록"
        )
