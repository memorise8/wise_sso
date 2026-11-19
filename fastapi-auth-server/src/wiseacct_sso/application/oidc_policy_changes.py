"""서로 다른 관리자의 요청과 승인으로 서비스 접근 정책을 변경합니다."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.admin import AdminAuditEventType, AdminAuditRecord, AuditDetailValue
from wiseacct_sso.domain.oidc_policy_changes import (
    EditableOidcPolicy,
    assert_other_approver,
    assert_policy_version,
    policy_reason,
)
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy
from wiseacct_sso.persistence import oidc_policy_changes as store
from wiseacct_sso.persistence.database import database_only_transaction
from wiseacct_sso.persistence.models import User, application_uuid, utc_now_ms

if TYPE_CHECKING:
    from wiseacct_sso.application.admin import Phase6AdminService


def _string(row: dict[str, object], key: str) -> str:
    value = row.get(key)
    if not isinstance(value, str) or not value:
        raise DomainError(503, "POLICY_DATA_INVALID", "정책 기록을 확인할 수 없습니다.")
    return value


def _version(row: dict[str, object], key: str) -> int:
    value = row.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DomainError(503, "POLICY_DATA_INVALID", "정책 버전을 확인할 수 없습니다.")
    return value


class OidcPolicyChangeService:
    def __init__(self, *, admin: Phase6AdminService, client_ids: tuple[str, ...]) -> None:
        self._admin = admin
        self._database = admin._database
        self._client_ids = frozenset(client_ids)

    def _client(self, client_id: str) -> None:
        if client_id not in self._client_ids:
            raise DomainError(404, "CLIENT_NOT_FOUND", "등록된 서비스를 찾지 못했습니다.")

    async def _email(self, connection: AsyncConnection, user_id: str) -> str | None:
        value = (
            await connection.execute(select(User.c.email).where(User.c.id == user_id))
        ).scalar_one_or_none()
        return value if isinstance(value, str) else None

    async def _audit(
        self,
        connection: AsyncConnection,
        *,
        event_type: AdminAuditEventType,
        actor_id: str,
        client_id: str,
        request_id: str,
        reason: str,
        now: datetime,
        version: int,
    ) -> None:
        details: dict[str, AuditDetailValue] = {
            "clientId": client_id,
            "requestId": request_id,
            "policyVersion": version,
        }
        await self._admin._mutations.create_admin_audit_log(
            connection,
            event=AdminAuditRecord(
                event_type=event_type,
                actor_user_id=actor_id,
                target_user_id=None,
                reason_code=reason,
                details_json=details,
            ),
            created_at=now,
        )

    async def request(
        self,
        *,
        actor_id: str,
        client_id: str,
        expected_version: int,
        proposed: EditableOidcPolicy | None,
        reason: str,
        rollback_to_version: int | None = None,
    ) -> dict[str, object]:
        self._client(client_id)
        reason = policy_reason(reason)
        if (proposed is None) == (rollback_to_version is None):
            raise DomainError(
                400, "INVALID_REQUEST", "변경 정책 또는 되돌릴 버전 중 하나를 지정하세요."
            )
        request_id = application_uuid()
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            current = await store.read_current(connection, client_id=client_id, lock=True)
            version = _version(current, "version")
            assert_policy_version(expected=expected_version, current=version)
            before = store.decode_policy(current["policy"])
            candidate = proposed
            if rollback_to_version is not None:
                if (
                    isinstance(rollback_to_version, bool)
                    or not isinstance(rollback_to_version, int)
                    or not 1 <= rollback_to_version < version
                ):
                    raise DomainError(400, "INVALID_REQUEST", "되돌릴 이전 버전을 확인하세요.")
                candidate = await store.read_version(
                    connection, client_id=client_id, version=rollback_to_version
                )
            if not isinstance(candidate, EditableOidcPolicy):
                raise DomainError(400, "INVALID_REQUEST", "변경 정책을 확인하세요.")
            if candidate == before:
                raise DomainError(400, "POLICY_UNCHANGED", "현재 정책과 같습니다.")
            await store.insert_change(
                connection,
                store.NewPolicyChange(
                    id=request_id,
                    client_id=client_id,
                    base_version=version,
                    before=before,
                    proposed=candidate,
                    requester_id=actor_id,
                    requester_email=await self._email(connection, actor_id),
                    reason=reason,
                    now=now,
                    rollback_to_version=rollback_to_version,
                ),
            )
            await self._audit(
                connection,
                event_type="admin_oidc_policy_requested",
                actor_id=actor_id,
                client_id=client_id,
                request_id=request_id,
                reason=reason,
                now=now,
                version=version,
            )
            return await store.read_change(connection, client_id=client_id, request_id=request_id)

        return await self._database().transaction(database_only_transaction(work))

    async def decide(
        self,
        *,
        actor_id: str,
        client_id: str,
        request_id: str,
        decision: Literal["APPROVE", "REJECT"],
        reason: str,
    ) -> dict[str, object]:
        self._client(client_id)
        reason = policy_reason(reason)
        if decision not in {"APPROVE", "REJECT"}:
            raise DomainError(400, "INVALID_REQUEST", "승인 또는 거절을 선택하세요.")
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            current = await store.read_current(connection, client_id=client_id, lock=True)
            change = await store.read_change(
                connection, client_id=client_id, request_id=request_id, lock=True
            )
            if change.get("status") != "PENDING":
                raise DomainError(409, "POLICY_REQUEST_RESOLVED", "이미 처리된 요청입니다.")
            requester = _string(change, "requestedById")
            assert_other_approver(requester_id=requester, approver_id=actor_id)
            applied_version = None
            event_type: AdminAuditEventType = "admin_oidc_policy_rejected"
            if decision == "APPROVE":
                await self._admin._require_active_admin(connection, requester)
                assert_policy_version(
                    expected=_version(change, "baseVersion"),
                    current=_version(current, "version"),
                )
                if store.decode_policy(change["beforePolicy"]) != store.decode_policy(
                    current["policy"]
                ):
                    raise DomainError(409, "POLICY_VERSION_CONFLICT", "기준 정책이 변경됐습니다.")
                applied_version = await store.apply_policy(
                    connection,
                    client_id=client_id,
                    expected_version=_version(change, "baseVersion"),
                    policy=store.decode_policy(change["proposedPolicy"]),
                    actor_id=actor_id,
                    actor_email=await self._email(connection, actor_id),
                    now=now,
                )
                event_type = "admin_oidc_policy_approved"
            await store.insert_decision(
                connection,
                request_id=request_id,
                requester_id=requester,
                decider_id=actor_id,
                decider_email=await self._email(connection, actor_id),
                decision=decision,
                reason=reason,
                now=now,
            )
            await store.finish_change(
                connection,
                client_id=client_id,
                request_id=request_id,
                status="APPLIED" if decision == "APPROVE" else "REJECTED",
                now=now,
                applied_version=applied_version,
            )
            await self._audit(
                connection,
                event_type=event_type,
                actor_id=actor_id,
                client_id=client_id,
                request_id=request_id,
                reason=reason,
                now=now,
                version=(
                    applied_version if applied_version is not None else _version(current, "version")
                ),
            )
            return await store.read_change(connection, client_id=client_id, request_id=request_id)

        return await self._database().transaction(database_only_transaction(work))

    async def _authorize_read(self, actor_id: str, client_id: str) -> None:
        self._client(client_id)
        await self._admin.authorize_admin(
            actor_id, route="/oauth2/admin/api/policy-changes", method="GET"
        )

    async def current(self, *, actor_id: str, client_id: str) -> dict[str, object]:
        await self._authorize_read(actor_id, client_id)
        async with self._database().connection() as connection:
            row = await store.read_current(connection, client_id=client_id)
        return {
            "clientId": client_id,
            "version": _version(row, "version"),
            "policy": store.decode_policy(row["policy"]).public_payload(),
            "updatedAt": row.get("updatedAt"),
            "updatedByEmail": row.get("updatedByEmail"),
            "actorUserId": actor_id,
        }

    async def history(
        self,
        *,
        actor_id: str,
        client_id: str,
        page: int = 1,
        page_size: int = 25,
        status: Literal["PENDING", "APPLIED", "REJECTED"] | None = None,
    ) -> dict[str, object]:
        await self._authorize_read(actor_id, client_id)
        if status not in {None, "PENDING", "APPLIED", "REJECTED"}:
            raise DomainError(400, "INVALID_REQUEST", "요청 상태를 확인하세요.")
        async with self._database().connection() as connection:
            await store.read_current(connection, client_id=client_id)
            return await store.list_changes(
                connection,
                client_id=client_id,
                page=page,
                page_size=page_size,
                status=status,
            )

    async def get(self, *, actor_id: str, client_id: str, request_id: str) -> dict[str, object]:
        await self._authorize_read(actor_id, client_id)
        async with self._database().connection() as connection:
            row = await store.read_change(connection, client_id=client_id, request_id=request_id)
            decision = await store.read_decision(connection, request_id=request_id)
        return {"request": row, "decision": decision}

    async def initialize(
        self,
        *,
        actor_id: str,
        clients: tuple[OidcClientPolicy, ...],
        reason: str,
    ) -> dict[str, object]:
        reason = policy_reason(reason)
        identifiers = tuple(client.client_id for client in clients)
        if (
            not clients
            or len(set(identifiers)) != len(identifiers)
            or frozenset(identifiers) != self._client_ids
        ):
            raise DomainError(400, "INVALID_REQUEST", "초기 등록할 서비스 목록을 확인하세요.")
        policies = tuple(
            (client.client_id, EditableOidcPolicy.from_client(client)) for client in clients
        )
        now = utc_now_ms()

        async def work(connection: AsyncConnection) -> dict[str, object]:
            await self._admin._require_active_admin(connection, actor_id)
            initialized = 0
            for client_id, policy in policies:
                created = await store.register_policy(
                    connection, client_id=client_id, policy=policy, now=now
                )
                initialized += int(created)
            retained = len(policies) - initialized
            await self._admin._mutations.create_admin_audit_log(
                connection,
                event=AdminAuditRecord(
                    event_type="admin_oidc_policy_initialized",
                    actor_user_id=actor_id,
                    target_user_id=None,
                    reason_code=reason,
                    details_json={
                        "initializedCount": initialized,
                        "retainedCount": retained,
                    },
                ),
                created_at=now,
            )
            return {"initializedCount": initialized, "retainedCount": retained}

        return await self._database().transaction(database_only_transaction(work))
