from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.admin import (
    AdminRoleProfile,
    AdminUserListInput,
    AuditRetentionCleanupResult,
)
from wiseacct_sso.domain.tokens import TokenValidationError
from wiseacct_sso.domain.users import DomainError, UserStatus
from wiseacct_sso.infrastructure.security import JwtTokenCodec
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.stores import AuditEventInsert

NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


class TrackingDatabase:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    @asynccontextmanager
    async def connection(self) -> AsyncIterator[AsyncConnection]:
        self.events.append("connection")
        yield cast(AsyncConnection, object())

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        self.events.append("begin")
        try:
            result = await work.callback(cast(AsyncConnection, object()))
        except Exception:
            self.events.append("rollback")
            raise
        self.events.append("commit")
        return result


class FakeTokens:
    def __init__(self, user_id: str | None, *, verification_error: Exception | None = None) -> None:
        self.user_id = user_id
        self.verification_error = verification_error

    def verify_admin_access_subject(self, token: str) -> str:
        if self.verification_error is not None:
            raise self.verification_error
        if self.user_id is None:
            raise TokenValidationError
        return self.user_id


class FakeDirectory:
    def __init__(self, events: list[str], *, authorized: bool = True) -> None:
        self.events = events
        self.authorized = authorized

    async def is_active_temis_admin(self, connection: object, *, user_id: str) -> bool:
        self.events.append(f"authorize:{user_id}")
        return self.authorized

    async def list_users(self, connection: object, *, input: AdminUserListInput) -> object:
        self.events.append("list-users")
        return input

    async def find_role_by_id(self, connection: object, *, role_id: str) -> AdminRoleProfile | None:
        self.events.append(f"role-id:{role_id}")
        return AdminRoleProfile(role_id, "temis", "admin")


class FakeAudit:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self.events = events
        self.fail = fail
        self.records: list[object] = []

    async def create(self, connection: object, *, event: object) -> None:
        self.events.append("denial-audit")
        if self.fail:
            raise RuntimeError("audit unavailable")
        self.records.append(event)


class FakeMutations:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.status_changed = True
        self.role_assigned = True
        self.role_removed = True
        self.role: AdminRoleProfile | None = AdminRoleProfile("role-1", "temis", "user")
        self.revoked = 2
        self.fail_audit = False
        self.audits: list[object] = []

    async def update_user_status(self, connection: object, **values: object) -> bool:
        self.events.append(f"status:{values['status']}")
        return self.status_changed

    async def revoke_all_refresh_tokens_for_user(self, connection: object, **values: object) -> int:
        self.events.append("revoke")
        return self.revoked

    async def upsert_role(self, connection: object, **values: object) -> AdminRoleProfile:
        self.events.append("upsert-role")
        assert self.role is not None
        return self.role

    async def assign_role_to_user(self, connection: object, **values: object) -> bool:
        self.events.append("assign-role")
        return self.role_assigned

    async def find_role(self, connection: object, **values: object) -> AdminRoleProfile | None:
        self.events.append("find-role")
        return self.role

    async def remove_role_from_user(self, connection: object, **values: object) -> bool:
        self.events.append("remove-role")
        return self.role_removed

    async def create_admin_audit_log(
        self, connection: object, *, event: object, created_at: datetime
    ) -> None:
        self.events.append("mutation-audit")
        if self.fail_audit:
            raise RuntimeError("audit insert failed")
        self.audits.append(event)


class FakeRetention:
    async def cleanup(self, connection: object, **values: object) -> AuditRetentionCleanupResult:
        now = cast(datetime, values["now"])
        retention_days = cast(int, values["retention_days"])
        return AuditRetentionCleanupResult(
            now, 4, not cast(bool, values["execute"]), retention_days
        )


def service(events: list[str], *, user_id: str | None = "admin") -> Phase6AdminService:
    database = TrackingDatabase(events)
    result = Phase6AdminService(
        database=lambda: cast(Database, database),
        tokens=cast(JwtTokenCodec, FakeTokens(user_id)),
    )
    result._directory = cast(object, FakeDirectory(events))  # type: ignore[assignment]
    result._audit = cast(object, FakeAudit(events))  # type: ignore[assignment]
    result._mutations = cast(object, FakeMutations(events))  # type: ignore[assignment]
    result._retention = cast(object, FakeRetention())  # type: ignore[assignment]
    return result


@pytest.mark.anyio
async def test_authenticate_admin_rejects_invalid_access_token_without_denial_audit() -> None:
    events: list[str] = []
    subject = service(events, user_id=None)

    with pytest.raises(DomainError) as caught:
        await subject.authenticate_admin("bad", route="/admin/users", method="GET")

    assert (caught.value.status_code, caught.value.code) == (401, "INVALID_TOKEN")
    assert events == []


@pytest.mark.anyio
async def test_authenticate_admin_rejects_empty_verified_subject_before_database_or_audit() -> None:
    events: list[str] = []
    subject = service(events, user_id="")

    with pytest.raises(DomainError) as caught:
        await subject.authenticate_admin("signed", route="/admin/users", method="GET")

    assert (caught.value.status_code, caught.value.code, caught.value.message) == (
        401,
        "UNAUTHORIZED",
        "Authentication is required",
    )
    assert events == []


@pytest.mark.anyio
async def test_authenticate_admin_preserves_jwt_verification_failure_for_generic_500() -> None:
    events: list[str] = []
    subject = service(events)
    subject._tokens = cast(
        JwtTokenCodec,
        FakeTokens("unused", verification_error=RuntimeError("jwt signature invalid")),
    )

    with pytest.raises(RuntimeError, match="jwt signature invalid"):
        await subject.authenticate_admin("bad", route="/admin/users", method="GET")

    assert events == []


@pytest.mark.anyio
async def test_valid_non_admin_is_audited_before_forbidden() -> None:
    events: list[str] = []
    subject = service(events)
    subject._directory = cast(object, FakeDirectory(events, authorized=False))  # type: ignore[assignment]

    with pytest.raises(DomainError) as caught:
        await subject.authenticate_admin("access", route="/manage-api/users", method="GET")

    assert (caught.value.status_code, caught.value.code) == (403, "FORBIDDEN")
    assert events == ["connection", "authorize:admin", "begin", "denial-audit", "commit"]
    audit = cast(AuditEventInsert, cast(FakeAudit, subject._audit).records[0])
    assert audit.details_json == {"route": "/manage-api/users", "method": "GET"}


@pytest.mark.anyio
async def test_authorized_admin_returns_token_subject() -> None:
    events: list[str] = []
    result = await service(events).authenticate_admin("access", route="/admin/users", method="GET")
    assert result == "admin"
    assert events == ["connection", "authorize:admin"]


@pytest.mark.anyio
async def test_denial_audit_failure_masks_forbidden_response() -> None:
    events: list[str] = []
    subject = service(events)
    subject._directory = cast(object, FakeDirectory(events, authorized=False))  # type: ignore[assignment]
    subject._audit = cast(object, FakeAudit(events, fail=True))  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await subject.authenticate_admin("access", route="/admin/users", method="GET")

    assert events == [
        "connection",
        "authorize:admin",
        "begin",
        "denial-audit",
        "rollback",
    ]


@pytest.mark.anyio
async def test_status_change_revokes_before_audit_in_one_transaction() -> None:
    events: list[str] = []
    result = await service(events).set_user_status(
        actor_user_id="admin",
        target_user_id="user",
        status="SUSPENDED",
        reason_code="ADMIN_STATUS_CHANGE",
        now=NOW,
    )

    assert (result.status_changed, result.revoked_refresh_token_count) == (True, 2)
    assert events == ["begin", "status:SUSPENDED", "revoke", "mutation-audit", "commit"]


@pytest.mark.anyio
async def test_mutation_audit_failure_rolls_back_status_and_revocation() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).fail_audit = True

    with pytest.raises(RuntimeError, match="audit insert failed"):
        await subject.set_user_status(
            actor_user_id="admin",
            target_user_id="user",
            status="SUSPENDED",
            reason_code="ADMIN_STATUS_CHANGE",
            now=NOW,
        )

    assert events == [
        "begin",
        "status:SUSPENDED",
        "revoke",
        "mutation-audit",
        "rollback",
    ]


@pytest.mark.anyio
async def test_idempotent_active_status_still_matches_express_update_many_semantics() -> None:
    events: list[str] = []
    subject = service(events)
    mutations = cast(FakeMutations, subject._mutations)
    mutations.status_changed = True

    result = await subject.set_user_status(
        actor_user_id="admin",
        target_user_id="user",
        status=UserStatus.ACTIVE,
        reason_code="ADMIN_STATUS_CHANGE",
        now=NOW,
    )

    assert result.status_changed is True
    assert result.revoked_refresh_token_count == 0
    assert events == ["begin", "status:ACTIVE", "mutation-audit", "commit"]


@pytest.mark.anyio
async def test_assign_role_duplicate_skips_audit() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).role_assigned = False

    result = await subject.assign_role(
        actor_user_id="admin",
        target_user_id="user",
        service_key="temis",
        name="user",
        reason_code="ADMIN_ROLE_ASSIGN",
    )

    assert (result.role_assigned, result.role_id) == (False, "role-1")
    assert events == ["begin", "upsert-role", "assign-role", "commit"]


@pytest.mark.anyio
async def test_remove_role_revokes_then_audits_only_when_removed() -> None:
    events: list[str] = []
    result = await service(events).remove_role(
        actor_user_id="admin",
        target_user_id="user",
        service_key="temis",
        name="user",
        reason_code="ADMIN_ROLE_REMOVE",
        now=NOW,
    )

    assert (result.role_removed, result.role_id, result.revoked_refresh_token_count) == (
        True,
        "role-1",
        2,
    )
    assert events == ["begin", "find-role", "remove-role", "revoke", "mutation-audit", "commit"]


@pytest.mark.anyio
async def test_missing_role_remove_is_an_idempotent_noop() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).role = None

    result = await subject.remove_role(
        actor_user_id="admin",
        target_user_id="user",
        service_key="temis",
        name="missing",
        reason_code="ADMIN_ROLE_REMOVE",
    )

    assert (result.role_removed, result.role_id, result.revoked_refresh_token_count) == (
        False,
        None,
        0,
    )
    assert events == ["begin", "find-role", "commit"]


@pytest.mark.anyio
async def test_self_protection_runs_before_mutation_io() -> None:
    subject = service([])

    with pytest.raises(DomainError, match="cannot suspend"):
        await subject.set_user_status(
            actor_user_id="admin",
            target_user_id="admin",
            status="DELETED",
            reason_code="reason",
        )
    with pytest.raises(DomainError, match="cannot revoke"):
        await subject.revoke_sessions(
            actor_user_id="admin", target_user_id="admin", reason_code="reason"
        )


@pytest.mark.anyio
async def test_self_admin_role_removal_is_rejected_before_transaction() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).role = AdminRoleProfile("admin-role", "temis", "admin")

    with pytest.raises(DomainError, match="cannot remove"):
        await subject.remove_role(
            actor_user_id="admin",
            target_user_id="admin",
            service_key="temis",
            name="admin",
            reason_code="reason",
        )
    assert events == []


@pytest.mark.anyio
async def test_revoke_sessions_always_records_success_audit() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).revoked = 0

    result = await subject.revoke_sessions(
        actor_user_id="admin", target_user_id="user", reason_code="ADMIN_SESSION_REVOKE", now=NOW
    )

    assert result.revoked_count == 0
    assert events == ["begin", "revoke", "mutation-audit", "commit"]


@pytest.mark.anyio
async def test_audit_cleanup_is_dry_run_by_default_and_transactional() -> None:
    events: list[str] = []
    result = await service(events).cleanup_audit_logs(now=NOW)

    assert result == AuditRetentionCleanupResult(NOW, 4, True, 180)
    assert events == ["begin", "commit"]
