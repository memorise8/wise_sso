"""Phase 6 administrator authorization, directory, mutation, and retention orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.admin import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    AdminAuditEventType,
    AdminAuditLogPage,
    AdminAuditRecord,
    AdminRoleProfile,
    AdminUserListInput,
    AdminUserPage,
    AuditDetailValue,
    AuditLogListInput,
    AuditRetentionCleanupResult,
    assert_role_input,
    assert_self_admin_role_removal_allowed,
    assert_self_session_revoke_allowed,
    assert_self_status_change_allowed,
    assert_user_id,
    parse_user_status,
    sanitize_audit_details,
    should_revoke_for_status,
)
from wiseacct_sso.domain.tokens import TokenValidationError
from wiseacct_sso.domain.users import DomainError, UserStatus, UserType
from wiseacct_sso.infrastructure.security import JwtTokenCodec
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import application_uuid, utc_now_ms
from wiseacct_sso.persistence.stores import (
    AdminAuditQueryStore,
    AdminDirectoryStore,
    AdminMutationStore,
    AuditEventInsert,
    AuditRetentionStore,
    AuditStore,
)

DatabaseProvider = Callable[[], Database]


@dataclass(frozen=True, slots=True)
class SetUserStatusResult:
    status_changed: bool
    revoked_refresh_token_count: int


@dataclass(frozen=True, slots=True)
class AssignRoleResult:
    role_assigned: bool
    role_id: str


@dataclass(frozen=True, slots=True)
class RemoveRoleResult:
    role_removed: bool
    role_id: str | None
    revoked_refresh_token_count: int


@dataclass(frozen=True, slots=True)
class RevokeSessionsResult:
    revoked_count: int


class Phase6AdminService:
    """Keep each Express mutation and its success audit in one DB transaction."""

    def __init__(self, *, database: DatabaseProvider, tokens: JwtTokenCodec) -> None:
        self._database = database
        self._tokens = tokens
        self._directory = AdminDirectoryStore()
        self._audit_query = AdminAuditQueryStore()
        self._mutations = AdminMutationStore()
        self._audit = AuditStore()
        self._retention = AuditRetentionStore()

    async def authenticate_admin(self, access_token: str, *, route: str, method: str) -> str:
        """Validate access-token kind/signature, then authorize its subject from the DB."""

        try:
            user_id = self._tokens.verify_admin_access_subject(access_token)
        except TokenValidationError:
            raise DomainError(401, "INVALID_TOKEN", "Invalid token") from None
        if not user_id:
            # Express verifyAccessToken accepts an empty string subject, but the
            # following actorUserId guard treats that verified value as absent.
            raise DomainError(401, "UNAUTHORIZED", "Authentication is required")
        await self.authorize_admin(user_id, route=route, method=method)
        return user_id

    async def authorize_admin(self, user_id: str, *, route: str, method: str) -> None:
        """Re-read DB authorization and persist a denial before returning 403."""

        assert_user_id(user_id)
        async with self._database().connection() as connection:
            authorized = await self._directory.is_active_sso_admin(connection, user_id=user_id)
        if authorized:
            return

        event = AuditEventInsert(
            id=self._new_id(),
            event_type="admin_authorization_failure",
            outcome="failure",
            created_at=utc_now_ms(),
            user_id=user_id,
            actor_user_id=user_id,
            target_user_id=None,
            reason_code="FORBIDDEN",
            details_json=sanitize_audit_details({"route": route, "method": method}),
        )

        async def record_denial(connection: AsyncConnection) -> None:
            await self._audit.create(connection, event=event)

        # Express also lets an audit-store failure mask the authorization response.
        await self._database().transaction(database_only_transaction(record_denial))
        raise DomainError(403, "FORBIDDEN", "Admin role is required")

    async def _authorize_mutation(
        self, connection: AsyncConnection, actor_user_id: str, target_user_id: str
    ) -> tuple[str | None, UserStatus]:
        await self._mutations.lock_policy(connection)
        if not await self._directory.is_active_sso_admin(connection, user_id=actor_user_id):
            raise DomainError(403, "FORBIDDEN", "Active employee SSO admin role is required")
        return await self._mutations.user_policy(connection, user_id=target_user_id)

    async def _protect_last_admin(self, connection: AsyncConnection, target_user_id: str) -> None:
        if (
            await self._directory.is_active_sso_admin(connection, user_id=target_user_id)
            and await self._mutations.active_admin_count(connection) <= 1
        ):
            raise DomainError(
                409, "LAST_SSO_ADMIN", "Cannot remove the last active SSO administrator"
            )

    async def set_user_type(
        self, *, actor_user_id: str, target_user_id: str, user_type: str | None, reason_code: str
    ) -> bool:
        assert_user_id(target_user_id)
        if user_type not in {None, "EMPLOYEE", "CUSTOMER"}:
            raise DomainError(400, "INVALID_USER_TYPE", "Unsupported user type")
        now = utc_now_ms()

        async def mutate(connection: AsyncConnection) -> bool:
            previous, _ = await self._authorize_mutation(connection, actor_user_id, target_user_id)
            if previous == user_type:
                return False
            await self._assert_user_type_change_allowed(connection, target_user_id, user_type)
            return await self._apply_user_type_change(
                connection, actor_user_id, target_user_id, previous, user_type, reason_code, now
            )

        return await self._database().transaction(database_only_transaction(mutate))

    async def set_user_types(
        self,
        *,
        actor_user_id: str,
        target_user_ids: tuple[str, ...],
        user_type: str | None,
        reason_code: str,
    ) -> tuple[int, int]:
        """Change at most 100 types atomically, applying the single-user safeguards."""
        if not 1 <= len(target_user_ids) <= 100 or len(set(target_user_ids)) != len(
            target_user_ids
        ):
            raise DomainError(400, "INVALID_REQUEST", "Select 1 to 100 unique users")
        for user_id in target_user_ids:
            assert_user_id(user_id)
            if user_id != user_id.strip() or len(user_id) > 128:
                raise DomainError(400, "INVALID_REQUEST", "Invalid user ID")
        if user_type not in {None, "EMPLOYEE", "CUSTOMER"}:
            raise DomainError(400, "INVALID_USER_TYPE", "Unsupported user type")
        if not reason_code.strip() or len(reason_code) > 128:
            raise DomainError(400, "INVALID_REQUEST", "A reason is required")
        now = utc_now_ms()
        batch_id = self._new_id()

        async def mutate(connection: AsyncConnection) -> tuple[int, int]:
            await self._mutations.lock_policy(connection)
            if not await self._directory.is_active_sso_admin(connection, user_id=actor_user_id):
                raise DomainError(403, "FORBIDDEN", "Active employee SSO admin role is required")
            # Lock in deterministic order; validate every target before any changes.
            pending: list[tuple[str, str | None]] = []
            for user_id in sorted(target_user_ids):
                previous, _ = await self._mutations.user_policy(connection, user_id=user_id)
                if previous == user_type:
                    continue
                await self._assert_user_type_change_allowed(connection, user_id, user_type)
                pending.append((user_id, previous))
            for user_id, previous in pending:
                await self._apply_user_type_change(
                    connection,
                    actor_user_id,
                    user_id,
                    previous,
                    user_type,
                    reason_code,
                    now,
                    batch_id=batch_id,
                    batch_size=len(target_user_ids),
                )
            return len(pending), len(target_user_ids) - len(pending)

        return await self._database().transaction(database_only_transaction(mutate))

    async def _assert_user_type_change_allowed(
        self, connection: AsyncConnection, user_id: str, user_type: str | None
    ) -> None:
        if user_type != "EMPLOYEE":
            await self._protect_last_admin(connection, user_id)
            if await self._mutations.central_admin_assigned(connection, user_id=user_id):
                raise DomainError(
                    409,
                    "SSO_ADMIN_MUST_BE_EMPLOYEE",
                    "Remove central admin role before changing user type",
                )

    async def _apply_user_type_change(
        self,
        connection: AsyncConnection,
        actor_user_id: str,
        user_id: str,
        previous: str | None,
        user_type: str | None,
        reason_code: str,
        now: datetime,
        *,
        batch_id: str | None = None,
        batch_size: int | None = None,
    ) -> bool:
        changed = await self._mutations.update_user_type(
            connection, user_id=user_id, user_type=user_type, updated_at=now
        )
        if not changed:
            raise DomainError(409, "USER_CHANGED", "User could not be updated")
        await self._mutations.revoke_all_refresh_tokens_for_user(
            connection, user_id=user_id, revoked_at=now
        )
        details: dict[str, AuditDetailValue] = {"previousUserType": previous, "userType": user_type}
        if batch_id is not None:
            details.update(batchId=batch_id, batchSize=batch_size)
        await self._record_mutation_audit(
            connection,
            event_type="admin_user_type_changed",
            actor_user_id=actor_user_id,
            target_user_id=user_id,
            reason_code=reason_code,
            details=details,
            created_at=now,
        )
        return changed

    async def list_users(self, input: AdminUserListInput) -> AdminUserPage:
        async with self._database().connection() as connection:
            return await self._directory.list_users(connection, input=input)

    async def list_audit_logs(self, input: AuditLogListInput) -> AdminAuditLogPage:
        async with self._database().connection() as connection:
            return await self._audit_query.query(connection, input=input)

    async def find_role_by_id(self, role_id: str) -> AdminRoleProfile | None:
        if not role_id.strip():
            raise DomainError(400, "INVALID_REQUEST", "Invalid request")
        async with self._database().connection() as connection:
            return await self._directory.find_role_by_id(connection, role_id=role_id)

    async def set_user_status(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        status: str | UserStatus,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> SetUserStatusResult:
        assert_user_id(target_user_id)
        parsed_status = parse_user_status(status)
        assert_self_status_change_allowed(actor_user_id, target_user_id, parsed_status)
        changed_at = now or utc_now_ms()
        audit_details = self._details(details)

        async def mutate(connection: AsyncConnection) -> SetUserStatusResult:
            await self._authorize_mutation(connection, actor_user_id, target_user_id)
            if should_revoke_for_status(parsed_status):
                await self._protect_last_admin(connection, target_user_id)
            changed = await self._mutations.update_user_status(
                connection,
                user_id=target_user_id,
                status=parsed_status,
                updated_at=changed_at,
            )
            revoked = (
                await self._mutations.revoke_all_refresh_tokens_for_user(
                    connection, user_id=target_user_id, revoked_at=changed_at
                )
                if should_revoke_for_status(parsed_status)
                else 0
            )
            if changed:
                await self._record_mutation_audit(
                    connection,
                    event_type="admin_user_status_changed",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    reason_code=reason_code,
                    details=audit_details,
                    created_at=changed_at,
                )
            return SetUserStatusResult(changed, revoked)

        return await self._database().transaction(database_only_transaction(mutate))

    async def assign_role(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        service_key: str,
        name: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
    ) -> AssignRoleResult:
        assert_user_id(target_user_id)
        assert_role_input(service_key, name)
        if service_key == "temis" and name == "admin":
            raise DomainError(
                403, "LEGACY_ADMIN_ROLE_DISABLED", "New temis:admin grants are disabled"
            )
        created_at = utc_now_ms()

        async def mutate(connection: AsyncConnection) -> AssignRoleResult:
            target_type, _ = await self._authorize_mutation(
                connection, actor_user_id, target_user_id
            )
            if (
                service_key not in {"temis", "fantra", "lab-customer"}
                and target_type != UserType.EMPLOYEE
            ):
                raise DomainError(
                    403,
                    "EMPLOYEE_REQUIRED",
                    "Internal service roles require employee classification",
                )
            role = await self._mutations.upsert_role(connection, service_key=service_key, name=name)
            assigned = await self._mutations.assign_role_to_user(
                connection, user_id=target_user_id, role_id=role.id
            )
            if assigned:
                audit_details = self._details(
                    details
                    if details is not None
                    else {"serviceKey": role.service_key, "roleName": role.name}
                )
                await self._record_mutation_audit(
                    connection,
                    event_type="admin_user_role_assigned",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    reason_code=reason_code,
                    details=audit_details,
                    created_at=created_at,
                )
            return AssignRoleResult(assigned, role.id)

        return await self._database().transaction(database_only_transaction(mutate))

    async def remove_role(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        service_key: str,
        name: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> RemoveRoleResult:
        assert_user_id(target_user_id)
        assert_role_input(service_key, name)
        assert_self_admin_role_removal_allowed(
            actor_user_id,
            target_user_id,
            AdminRoleProfile(id="", service_key=service_key, name=name),
        )
        removed_at = now or utc_now_ms()

        async def mutate(connection: AsyncConnection) -> RemoveRoleResult:
            await self._authorize_mutation(connection, actor_user_id, target_user_id)
            if service_key == "sso" and name == "admin":
                await self._protect_last_admin(connection, target_user_id)
            role = await self._mutations.find_role(connection, service_key=service_key, name=name)
            if role is None:
                return RemoveRoleResult(False, None, 0)
            removed = await self._mutations.remove_role_from_user(
                connection, user_id=target_user_id, role_id=role.id
            )
            revoked = (
                await self._mutations.revoke_all_refresh_tokens_for_user(
                    connection, user_id=target_user_id, revoked_at=removed_at
                )
                if removed
                else 0
            )
            if removed:
                audit_details = self._details(
                    details
                    if details is not None
                    else {"serviceKey": role.service_key, "roleName": role.name}
                )
                await self._record_mutation_audit(
                    connection,
                    event_type="admin_user_role_removed",
                    actor_user_id=actor_user_id,
                    target_user_id=target_user_id,
                    reason_code=reason_code,
                    details=audit_details,
                    created_at=removed_at,
                )
            return RemoveRoleResult(removed, role.id, revoked)

        return await self._database().transaction(database_only_transaction(mutate))

    async def revoke_sessions(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> RevokeSessionsResult:
        assert_user_id(target_user_id)
        assert_self_session_revoke_allowed(actor_user_id, target_user_id)
        revoked_at = now or utc_now_ms()
        audit_details = self._details(details)

        async def mutate(connection: AsyncConnection) -> RevokeSessionsResult:
            await self._authorize_mutation(connection, actor_user_id, target_user_id)
            revoked = await self._mutations.revoke_all_refresh_tokens_for_user(
                connection, user_id=target_user_id, revoked_at=revoked_at
            )
            # Express records this audit even when no live sessions existed.
            await self._record_mutation_audit(
                connection,
                event_type="admin_user_sessions_revoked",
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                reason_code=reason_code,
                details=audit_details,
                created_at=revoked_at,
            )
            return RevokeSessionsResult(revoked)

        return await self._database().transaction(database_only_transaction(mutate))

    async def cleanup_audit_logs(
        self,
        *,
        execute: bool = False,
        now: datetime | None = None,
        retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS,
    ) -> AuditRetentionCleanupResult:
        cleanup_at = now or utc_now_ms()

        async def cleanup(connection: AsyncConnection) -> AuditRetentionCleanupResult:
            return await self._retention.cleanup(
                connection,
                now=cleanup_at,
                retention_days=retention_days,
                execute=execute,
            )

        return await self._database().transaction(database_only_transaction(cleanup))

    async def _record_mutation_audit(
        self,
        connection: AsyncConnection,
        *,
        event_type: AdminAuditEventType,
        actor_user_id: str,
        target_user_id: str,
        reason_code: str,
        details: Mapping[str, AuditDetailValue] | None,
        created_at: datetime,
    ) -> None:
        await self._mutations.create_admin_audit_log(
            connection,
            event=AdminAuditRecord(
                event_type=event_type,
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
                reason_code=reason_code,
                details_json=details,
            ),
            created_at=created_at,
        )

    @staticmethod
    def _details(details: Mapping[str, object] | None) -> Mapping[str, AuditDetailValue] | None:
        return None if details is None else sanitize_audit_details(details)

    @staticmethod
    def _new_id() -> str:
        return application_uuid()
