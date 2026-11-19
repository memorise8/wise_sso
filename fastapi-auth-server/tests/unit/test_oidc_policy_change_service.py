"""정책 변경 서비스의 권한 검사와 승인 절차를 검증합니다."""

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application import oidc_policy_changes as module
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence import oidc_policy_changes as policy_store


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    before = EditableOidcPolicy.model_validate(
        {
            "allowedUserTypes": ["EMPLOYEE"],
            "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
            "allowWithoutRequiredRole": False,
            "groupsServiceKeys": ["gitlab"],
            "ssoAutoLogin": False,
        }
    )
    proposed = before.model_copy(update={"sso_auto_login": True})
    connection = MagicMock(spec=AsyncConnection)

    async def transaction(
        work: Callable[[AsyncConnection], Awaitable[dict[str, object]]],
    ) -> dict[str, object]:
        return await work(connection)

    database = SimpleNamespace(transaction=AsyncMock(side_effect=transaction))
    mutations = SimpleNamespace(create_admin_audit_log=AsyncMock())
    admin = SimpleNamespace(
        _database=lambda: database,
        _require_active_admin=AsyncMock(),
        _mutations=mutations,
    )
    monkeypatch.setattr(module, "database_only_transaction", lambda work: work)
    current = {
        "clientId": "gitlab",
        "version": 1,
        "policy": before.public_payload(),
    }
    change = {
        "id": "request-1",
        "clientId": "gitlab",
        "baseVersion": 1,
        "status": "PENDING",
        "requestedById": "requester",
        "beforePolicy": before.public_payload(),
        "proposedPolicy": proposed.public_payload(),
    }
    mocks = {
        "read_current": AsyncMock(return_value=current),
        "read_change": AsyncMock(return_value=change),
        "insert_change": AsyncMock(),
        "insert_decision": AsyncMock(),
        "apply_policy": AsyncMock(return_value=2),
        "finish_change": AsyncMock(),
        "read_version": AsyncMock(return_value=before),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(policy_store, name, mock)
    service = module.OidcPolicyChangeService(
        admin=cast(Phase6AdminService, admin), client_ids=("gitlab",)
    )
    monkeypatch.setattr(service, "_email", AsyncMock(return_value="admin@example.invalid"))
    return SimpleNamespace(
        service=service,
        admin=admin,
        database=database,
        mutations=mutations,
        connection=connection,
        current=current,
        change=change,
        before=before,
        proposed=proposed,
        **mocks,
    )


@pytest.mark.anyio
async def test_request_records_snapshot_without_applying(rig: SimpleNamespace) -> None:
    await rig.service.request(
        actor_id="requester",
        client_id="gitlab",
        expected_version=1,
        proposed=rig.proposed,
        reason="접근 정책 변경",
    )
    rig.admin._require_active_admin.assert_awaited_once_with(rig.connection, "requester")
    call = rig.insert_change.await_args
    assert call is not None
    snapshot = call.args[1]
    assert snapshot.requester_id == "requester"
    assert snapshot.before == rig.before
    assert snapshot.proposed == rig.proposed
    rig.apply_policy.assert_not_awaited()
    rig.insert_decision.assert_not_awaited()
    audit = rig.mutations.create_admin_audit_log.await_args
    assert audit is not None
    assert audit.kwargs["event"].event_type == "admin_oidc_policy_requested"


@pytest.mark.anyio
async def test_self_approval_is_denied(rig: SimpleNamespace) -> None:
    with pytest.raises(DomainError):
        await rig.service.decide(
            actor_id="requester",
            client_id="gitlab",
            request_id="request-1",
            decision="APPROVE",
            reason="승인",
        )
    rig.apply_policy.assert_not_awaited()
    rig.insert_decision.assert_not_awaited()


@pytest.mark.anyio
async def test_approval_rechecks_both_admins(rig: SimpleNamespace) -> None:
    await rig.service.decide(
        actor_id="approver",
        client_id="gitlab",
        request_id="request-1",
        decision="APPROVE",
        reason="검토 완료",
    )
    assert [call.args[1] for call in rig.admin._require_active_admin.await_args_list] == [
        "approver",
        "requester",
    ]
    call = rig.apply_policy.await_args
    assert call is not None
    assert call.kwargs["expected_version"] == 1
    assert call.kwargs["policy"] == rig.proposed
    finish = rig.finish_change.await_args
    assert finish is not None
    assert finish.kwargs["status"] == "APPLIED"
    assert finish.kwargs["applied_version"] == 2


@pytest.mark.anyio
async def test_removed_requester_admin_role_blocks_approval(
    rig: SimpleNamespace,
) -> None:
    rig.admin._require_active_admin.side_effect = [
        None,
        DomainError(403, "FORBIDDEN", "관리자 권한이 필요합니다."),
    ]
    with pytest.raises(DomainError):
        await rig.service.decide(
            actor_id="approver",
            client_id="gitlab",
            request_id="request-1",
            decision="APPROVE",
            reason="승인",
        )
    rig.apply_policy.assert_not_awaited()
    rig.insert_decision.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize("stage", ["request", "approval"])
async def test_version_conflict_blocks_writes(rig: SimpleNamespace, stage: str) -> None:
    rig.current["version"] = 2
    with pytest.raises(DomainError):
        if stage == "request":
            await rig.service.request(
                actor_id="requester",
                client_id="gitlab",
                expected_version=1,
                proposed=rig.proposed,
                reason="정책 변경",
            )
        else:
            await rig.service.decide(
                actor_id="approver",
                client_id="gitlab",
                request_id="request-1",
                decision="APPROVE",
                reason="승인",
            )
    rig.insert_change.assert_not_awaited()
    rig.apply_policy.assert_not_awaited()
    rig.insert_decision.assert_not_awaited()


@pytest.mark.anyio
async def test_snapshot_mismatch_blocks_approval(rig: SimpleNamespace) -> None:
    rig.current["policy"] = rig.proposed.public_payload()
    with pytest.raises(DomainError):
        await rig.service.decide(
            actor_id="approver",
            client_id="gitlab",
            request_id="request-1",
            decision="APPROVE",
            reason="승인",
        )
    rig.apply_policy.assert_not_awaited()


@pytest.mark.anyio
async def test_rejection_does_not_apply_policy(rig: SimpleNamespace) -> None:
    await rig.service.decide(
        actor_id="approver",
        client_id="gitlab",
        request_id="request-1",
        decision="REJECT",
        reason="추가 검토 필요",
    )
    rig.apply_policy.assert_not_awaited()
    call = rig.finish_change.await_args
    assert call is not None
    assert call.kwargs["status"] == "REJECTED"
    assert call.kwargs["applied_version"] is None
    audit = rig.mutations.create_admin_audit_log.await_args
    assert audit is not None
    assert audit.kwargs["event"].event_type == "admin_oidc_policy_rejected"


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["APPLIED", "REJECTED"])
async def test_resolved_request_cannot_be_decided_again(rig: SimpleNamespace, status: str) -> None:
    rig.change["status"] = status
    with pytest.raises(DomainError):
        await rig.service.decide(
            actor_id="approver",
            client_id="gitlab",
            request_id="request-1",
            decision="APPROVE",
            reason="승인",
        )
    rig.apply_policy.assert_not_awaited()
    rig.insert_decision.assert_not_awaited()


@pytest.mark.anyio
async def test_rollback_creates_new_request_only(rig: SimpleNamespace) -> None:
    rig.current.update(version=2, policy=rig.proposed.public_payload())
    await rig.service.request(
        actor_id="requester",
        client_id="gitlab",
        expected_version=2,
        proposed=None,
        rollback_to_version=1,
        reason="이전 정책으로 복원 요청",
    )
    rig.read_version.assert_awaited_once_with(rig.connection, client_id="gitlab", version=1)
    call = rig.insert_change.await_args
    assert call is not None
    assert call.args[1].rollback_to_version == 1
    assert call.args[1].proposed == rig.before
    rig.apply_policy.assert_not_awaited()


@pytest.mark.anyio
async def test_audit_failure_reaches_transaction(rig: SimpleNamespace) -> None:
    rig.mutations.create_admin_audit_log.side_effect = RuntimeError("감사 저장 실패")
    with pytest.raises(RuntimeError, match="감사 저장 실패"):
        await rig.service.decide(
            actor_id="approver",
            client_id="gitlab",
            request_id="request-1",
            decision="APPROVE",
            reason="승인",
        )
    rig.database.transaction.assert_awaited_once()


@pytest.mark.anyio
async def test_viewer_cannot_create_request(rig: SimpleNamespace) -> None:
    rig.admin._require_active_admin.side_effect = DomainError(
        403, "FORBIDDEN", "관리자 권한이 필요합니다."
    )
    with pytest.raises(DomainError):
        await rig.service.request(
            actor_id="viewer",
            client_id="gitlab",
            expected_version=1,
            proposed=rig.proposed,
            reason="정책 변경",
        )
    rig.read_current.assert_not_awaited()
    rig.insert_change.assert_not_awaited()
