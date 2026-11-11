from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.admin import (
    AdminAuditRecord,
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

    async def is_active_sso_admin(self, connection: object, *, user_id: str) -> bool:
        self.events.append(f"authorize:{user_id}")
        return self.authorized

    async def list_users(self, connection: object, *, input: AdminUserListInput) -> object:
        self.events.append("list-users")
        return input

    async def find_role_by_id(self, connection: object, *, role_id: str) -> AdminRoleProfile | None:
        self.events.append(f"role-id:{role_id}")
        return AdminRoleProfile(role_id, "sso", "admin")


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
        self.user_type: str | None = "EMPLOYEE"
        self.admin_count = 2
        self.has_admin_role = False
        self.status_changed = True
        self.role_assigned = True
        self.role_removed = True
        self.role: AdminRoleProfile | None = AdminRoleProfile("role-1", "temis", "user")
        self.revoked = 2
        self.fail_audit = False
        self.audits: list[object] = []

    async def lock_policy(self, connection: object) -> None:
        self.events.append("policy-lock")

    async def user_policy(
        self, connection: object, **values: object
    ) -> tuple[str | None, UserStatus]:
        self.events.append(f"target:{values['user_id']}")
        return self.user_type, UserStatus.ACTIVE

    async def active_admin_count(self, connection: object) -> int:
        return self.admin_count

    async def central_admin_assigned(self, connection: object, **values: object) -> bool:
        return self.has_admin_role

    async def update_user_type(self, connection: object, **values: object) -> bool:
        self.events.append("type-change")
        return True

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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "authorize:user",
        "status:SUSPENDED",
        "revoke",
        "mutation-audit",
        "commit",
    ]


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
        "policy-lock",
        "authorize:admin",
        "target:user",
        "authorize:user",
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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "status:ACTIVE",
        "mutation-audit",
        "commit",
    ]


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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "upsert-role",
        "assign-role",
        "commit",
    ]


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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "find-role",
        "remove-role",
        "revoke",
        "mutation-audit",
        "commit",
    ]


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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "find-role",
        "commit",
    ]


@pytest.mark.anyio
async def test_self_protection_runs_before_mutation_io() -> None:
    subject = service([])

    with pytest.raises(DomainError, match="must keep their own account active"):
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
    cast(FakeMutations, subject._mutations).role = AdminRoleProfile("admin-role", "sso", "admin")

    with pytest.raises(DomainError, match="cannot remove"):
        await subject.remove_role(
            actor_user_id="admin",
            target_user_id="admin",
            service_key="sso",
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
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "revoke",
        "mutation-audit",
        "commit",
    ]


@pytest.mark.anyio
async def test_audit_cleanup_is_dry_run_by_default_and_transactional() -> None:
    events: list[str] = []
    result = await service(events).cleanup_audit_logs(now=NOW)

    assert result == AuditRetentionCleanupResult(NOW, 4, True, 180)
    assert events == ["begin", "commit"]


@pytest.mark.anyio
@pytest.mark.parametrize("user_type", [None, "CUSTOMER"])
@pytest.mark.parametrize("service_key", ["sso", "lab-staff", "gitlab", "agent-hub"])
async def test_internal_role_assignment_requires_employee(
    user_type: str | None, service_key: str
) -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).user_type = user_type
    with pytest.raises(DomainError) as caught:
        await subject.assign_role(
            actor_user_id="admin",
            target_user_id="user",
            service_key=service_key,
            name="admin" if service_key == "sso" else "user",
            reason_code="TEST",
        )
    assert caught.value.code == "EMPLOYEE_REQUIRED"
    assert events == ["begin", "policy-lock", "authorize:admin", "target:user", "rollback"]


@pytest.mark.anyio
async def test_type_change_revokes_and_audits_in_same_transaction() -> None:
    events: list[str] = []
    subject = service(events)
    changed = await subject.set_user_type(
        actor_user_id="admin", target_user_id="user", user_type="CUSTOMER", reason_code="TEST"
    )
    assert changed
    assert events == [
        "begin",
        "policy-lock",
        "authorize:admin",
        "target:user",
        "authorize:user",
        "type-change",
        "revoke",
        "mutation-audit",
        "commit",
    ]
    audit = cast(FakeMutations, subject._mutations).audits[0]
    assert cast(AdminAuditRecord, audit).event_type == "admin_user_type_changed"


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["status", "role", "type"])
async def test_last_active_central_admin_is_protected(operation: str) -> None:
    events: list[str] = []
    subject = service(events)
    mutations = cast(FakeMutations, subject._mutations)
    mutations.admin_count = 1
    mutations.role = AdminRoleProfile("central-admin", "sso", "admin")
    with pytest.raises(DomainError) as caught:
        if operation == "status":
            await subject.set_user_status(
                actor_user_id="admin", target_user_id="user", status="SUSPENDED", reason_code="TEST"
            )
        elif operation == "type":
            await subject.set_user_type(
                actor_user_id="admin",
                target_user_id="user",
                user_type="CUSTOMER",
                reason_code="TEST",
            )
        else:
            await subject.remove_role(
                actor_user_id="admin",
                target_user_id="user",
                service_key="sso",
                name="admin",
                reason_code="TEST",
            )
    assert caught.value.code == "LAST_SSO_ADMIN"
    assert events[:4] == ["begin", "policy-lock", "authorize:admin", "target:user"]
    assert events[-1] == "rollback"
    assert "mutation-audit" not in events


@pytest.mark.anyio
async def test_type_demotion_requires_central_admin_role_removed_first() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).has_admin_role = True
    with pytest.raises(DomainError) as caught:
        await subject.set_user_type(
            actor_user_id="admin", target_user_id="user", user_type=None, reason_code="TEST"
        )
    assert caught.value.code == "SSO_ADMIN_MUST_BE_EMPLOYEE"
    assert "type-change" not in events


@pytest.mark.anyio
async def test_mutation_rechecks_actor_after_policy_lock_before_write() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeDirectory, subject._directory).authorized = False
    with pytest.raises(DomainError) as caught:
        await subject.set_user_type(
            actor_user_id="admin", target_user_id="user", user_type="CUSTOMER", reason_code="TEST"
        )
    assert caught.value.code == "FORBIDDEN"
    assert events == ["begin", "policy-lock", "authorize:admin", "rollback"]


class BulkMutations(FakeMutations):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.types: dict[str, str | None] = {
            "admin": "EMPLOYEE",
            "a": None,
            "b": "CUSTOMER",
            "c": "EMPLOYEE",
        }
        self.versions = dict.fromkeys(self.types, 0)
        self.central_admins = {"admin"}
        self.admin_count = 1
        self.fail_second_audit = False

    async def user_policy(
        self, connection: object, **values: object
    ) -> tuple[str | None, UserStatus]:
        uid = str(values["user_id"])
        self.events.append(f"target:{uid}")
        if uid not in self.types:
            raise DomainError(404, "USER_NOT_FOUND", "User not found")
        return self.types[uid], UserStatus.ACTIVE

    async def update_user_type(self, connection: object, **values: object) -> bool:
        uid = str(values["user_id"])
        self.events.append(f"type:{uid}")
        self.types[uid] = cast(str | None, values["user_type"])
        return True

    async def revoke_all_refresh_tokens_for_user(self, connection: object, **values: object) -> int:
        uid = str(values["user_id"])
        self.events.append(f"revoke:{uid}")
        self.versions[uid] += 1
        return 0

    async def central_admin_assigned(self, connection: object, **values: object) -> bool:
        return values["user_id"] in self.central_admins

    async def create_admin_audit_log(
        self, connection: object, *, event: object, created_at: datetime
    ) -> None:
        if self.fail_second_audit and self.audits:
            raise RuntimeError("second audit failed")
        await super().create_admin_audit_log(connection, event=event, created_at=created_at)


class BulkDirectory(FakeDirectory):
    async def is_active_sso_admin(self, connection: object, *, user_id: str) -> bool:
        self.events.append(f"authorize:{user_id}")
        return self.authorized and user_id in {"admin", "z-admin"}


class BulkDatabase(TrackingDatabase):
    def __init__(self, events: list[str], mutations: BulkMutations) -> None:
        super().__init__(events)
        self.mutations = mutations

    async def transaction[Result](
        self, work: DatabaseOnlyTransaction[Result], *, max_attempts: int = 3
    ) -> Result:
        types, versions, audits = (
            self.mutations.types.copy(),
            self.mutations.versions.copy(),
            self.mutations.audits.copy(),
        )
        try:
            return await super().transaction(work, max_attempts=max_attempts)
        except Exception:
            self.mutations.types = types
            self.mutations.versions = versions
            self.mutations.audits = audits
            raise


def bulk_subject(events: list[str]) -> tuple[Phase6AdminService, BulkMutations]:
    subject = service(events)
    mutations = BulkMutations(events)
    database = BulkDatabase(events, mutations)
    subject._database = lambda: cast(Database, database)
    subject._directory = cast(object, BulkDirectory(events))  # type: ignore[assignment]
    subject._mutations = cast(object, mutations)  # type: ignore[assignment]
    return subject, mutations


@pytest.mark.anyio
async def test_bulk_type_changes_lock_once_skip_noops_and_revoke_each_changed_user() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    result = await subject.set_user_types(
        actor_user_id="admin",
        target_user_ids=("c", "b", "a"),
        user_type="EMPLOYEE",
        reason_code="BULK_TEST",
    )
    assert result == (2, 1)
    assert store.types == {"admin": "EMPLOYEE", "a": "EMPLOYEE", "b": "EMPLOYEE", "c": "EMPLOYEE"}
    assert store.versions == {"admin": 0, "a": 1, "b": 1, "c": 0}
    assert events[:5] == ["begin", "policy-lock", "authorize:admin", "target:a", "target:b"]
    assert events.index("target:c") < events.index("type:a")
    assert events.count("policy-lock") == 1
    audits = cast(list[AdminAuditRecord], store.audits)
    assert [audit.target_user_id for audit in audits] == ["a", "b"]
    assert audits[0].details_json is not None and audits[1].details_json is not None
    assert audits[0].details_json["batchId"] == audits[1].details_json["batchId"]
    assert audits[0].details_json["batchSize"] == 3
    assert audits[0].details_json["previousUserType"] is None
    assert audits[1].details_json["previousUserType"] == "CUSTOMER"
    assert "assign-role" not in events
    assert events[-1] == "commit"


@pytest.mark.anyio
async def test_bulk_noops_do_not_revoke_sessions_or_audit() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    assert await subject.set_user_types(
        actor_user_id="admin",
        target_user_ids=("admin", "c"),
        user_type="EMPLOYEE",
        reason_code="TEST",
    ) == (0, 2)
    assert not store.audits
    assert all(value == 0 for value in store.versions.values())


@pytest.mark.anyio
@pytest.mark.parametrize(
    "ids,code", [(("a", "missing"), "USER_NOT_FOUND"), (("a", "admin"), "LAST_SSO_ADMIN")]
)
async def test_bulk_preflights_every_user_before_any_writes(
    ids: tuple[str, ...], code: str
) -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    original = store.types.copy()
    with pytest.raises(DomainError) as caught:
        await subject.set_user_types(
            actor_user_id="admin", target_user_ids=ids, user_type="CUSTOMER", reason_code="TEST"
        )
    assert caught.value.code == code
    assert store.types == original
    assert not any(event.startswith("type:") for event in events)
    assert not store.audits
    assert events[-1] == "rollback"


@pytest.mark.anyio
async def test_bulk_admin_demotion_is_denied_even_with_another_admin() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    store.types["z-admin"] = "EMPLOYEE"
    store.central_admins.add("z-admin")
    store.admin_count = 2
    with pytest.raises(DomainError) as caught:
        await subject.set_user_types(
            actor_user_id="admin",
            target_user_ids=("a", "z-admin"),
            user_type=None,
            reason_code="TEST",
        )
    assert caught.value.code == "SSO_ADMIN_MUST_BE_EMPLOYEE"
    assert not any(event.startswith("type:") for event in events)


@pytest.mark.anyio
async def test_bulk_audit_failure_rolls_back_all_types_session_versions_and_audits() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    original = store.types.copy()
    store.fail_second_audit = True
    with pytest.raises(RuntimeError, match="second audit failed"):
        await subject.set_user_types(
            actor_user_id="admin",
            target_user_ids=("a", "b"),
            user_type="EMPLOYEE",
            reason_code="TEST",
        )
    assert "type:a" in events and "type:b" in events
    assert store.types == original
    assert all(value == 0 for value in store.versions.values())
    assert not store.audits
    assert events[-1] == "rollback"


@pytest.mark.anyio
async def test_bulk_rechecks_admin_under_policy_lock() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    cast(BulkDirectory, subject._directory).authorized = False
    with pytest.raises(DomainError) as caught:
        await subject.set_user_types(
            actor_user_id="admin", target_user_ids=("a",), user_type="EMPLOYEE", reason_code="TEST"
        )
    assert caught.value.code == "FORBIDDEN"
    assert events == ["begin", "policy-lock", "authorize:admin", "rollback"]
    assert store.types["a"] is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "ids", [(), ("a", "a"), (" a",), ("",), ("x" * 129,), tuple(str(i) for i in range(101))]
)
async def test_bulk_invalid_ids_are_rejected_before_database(ids: tuple[str, ...]) -> None:
    events: list[str] = []
    subject, _ = bulk_subject(events)
    with pytest.raises(DomainError):
        await subject.set_user_types(
            actor_user_id="admin", target_user_ids=ids, user_type="EMPLOYEE", reason_code="TEST"
        )
    assert not events


@pytest.mark.anyio
@pytest.mark.parametrize("value,reason", [("ADMIN", "TEST"), ("EMPLOYEE", ""), ("EMPLOYEE", " ")])
async def test_bulk_rejects_invalid_type_or_reason_before_database(value: str, reason: str) -> None:
    events: list[str] = []
    subject, _ = bulk_subject(events)
    with pytest.raises(DomainError):
        await subject.set_user_types(
            actor_user_id="admin", target_user_ids=("a",), user_type=value, reason_code=reason
        )
    assert not events


@pytest.mark.anyio
async def test_bulk_accepts_hundred_users_without_implicit_role_grants() -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    ids = tuple(f"user-{i}" for i in range(100))
    store.types.update(dict.fromkeys(ids))
    store.versions.update(dict.fromkeys(ids, 0))
    assert await subject.set_user_types(
        actor_user_id="admin", target_user_ids=ids, user_type="EMPLOYEE", reason_code="TEST"
    ) == (100, 0)
    assert len(store.audits) == 100
    assert all(store.versions[uid] == 1 for uid in ids)
    assert "assign-role" not in events


@pytest.mark.anyio
@pytest.mark.parametrize("status", ["PENDING_EMAIL_VERIFICATION", "SUSPENDED", "DELETED"])
async def test_last_admin_cannot_enter_any_nonactive_state(status: str) -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).admin_count = 1
    with pytest.raises(DomainError) as caught:
        await subject.set_user_status(
            actor_user_id="admin", target_user_id="user", status=status, reason_code="TEST"
        )
    assert caught.value.code == "LAST_SSO_ADMIN"
    assert events[-1] == "rollback"


@pytest.mark.anyio
async def test_new_temis_admin_assignment_is_rejected_before_io() -> None:
    subject = service([])
    with pytest.raises(DomainError) as caught:
        await subject.assign_role(
            actor_user_id="admin",
            target_user_id="user",
            service_key="temis",
            name="admin",
            reason_code="TEST",
        )
    assert caught.value.code == "LEGACY_ADMIN_ROLE_DISABLED"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("service_key", "name", "allowed"),
    [("gitlab", "user", True), ("agent-hub", "user", False), ("sso", "admin", False)],
)
async def test_external_accounts_may_only_receive_gitlab_user(
    service_key: str, name: str, allowed: bool
) -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).user_type = "EXTERNAL"
    assignment = subject.assign_role(
        actor_user_id="admin",
        target_user_id="user",
        service_key=service_key,
        name=name,
        reason_code="TEST",
    )
    if allowed:
        await assignment
        assert events[-1] == "commit"
        return
    with pytest.raises(DomainError) as caught:
        await assignment
    assert caught.value.code == "EXTERNAL_ROLE_NOT_ALLOWED"
    assert events[-1] == "rollback"


@pytest.mark.anyio
async def test_external_account_type_cannot_be_reclassified() -> None:
    events: list[str] = []
    subject = service(events)
    cast(FakeMutations, subject._mutations).user_type = "EXTERNAL"
    with pytest.raises(DomainError) as caught:
        await subject.set_user_type(
            actor_user_id="admin", target_user_id="user", user_type="EMPLOYEE", reason_code="TEST"
        )
    assert caught.value.code == "EXTERNAL_ACCOUNT_MANAGED"
    assert "type-change" not in events


@pytest.mark.anyio
@pytest.mark.parametrize("user_type", ["EMPLOYEE", "CUSTOMER", None])
async def test_bulk_external_account_rejects_entire_batch(user_type: str | None) -> None:
    events: list[str] = []
    subject, store = bulk_subject(events)
    store.types["b"] = "EXTERNAL"
    original = store.types.copy()
    original_versions = store.versions.copy()

    with pytest.raises(DomainError) as caught:
        await subject.set_user_types(
            actor_user_id="admin",
            target_user_ids=("a", "b"),
            user_type=user_type,
            reason_code="TEST",
        )

    assert caught.value.code == "EXTERNAL_ACCOUNT_MANAGED"
    assert store.types == original
    assert store.versions == original_versions
    assert not store.audits
    assert not any(event.startswith(("type:", "revoke:")) for event in events)
    assert events[-1] == "rollback"
