from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql import ClauseElement, Executable

from wiseacct_sso.domain.admin import (
    AdminAuditRecord,
    AdminUserListInput,
    AuditLogListInput,
)
from wiseacct_sso.domain.users import UserStatus
from wiseacct_sso.persistence.stores import (
    AdminAuditQueryStore,
    AdminDirectoryStore,
    AdminMutationStore,
    AuditRetentionStore,
)

NOW = datetime(2026, 8, 31, 12, 0, 0)


class FakeResult:
    def __init__(
        self,
        row: object | None = None,
        *,
        rows: tuple[object, ...] = (),
        scalar: object | None = None,
        rowcount: int = 0,
    ) -> None:
        self._row = row
        self._rows = rows
        self._scalar = scalar
        self.rowcount = rowcount

    def one_or_none(self) -> object | None:
        return self._row

    def all(self) -> tuple[object, ...]:
        return self._rows

    def scalar_one(self) -> object:
        if self._scalar is None:
            raise RuntimeError("test result has no scalar")
        return self._scalar


class FakeConnection:
    def __init__(self, results: list[FakeResult]) -> None:
        self.results = iter(results)
        self.statements: list[Executable] = []

    async def execute(self, statement: Executable) -> FakeResult:
        self.statements.append(statement)
        return next(self.results)


def sql(statement: Executable) -> str:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return " ".join(str(compiled).replace("\n", " ").split())


def params(statement: Executable) -> dict[str, object]:
    dialect = postgresql.dialect()  # type: ignore[no-untyped-call]
    compiled = cast(ClauseElement, statement).compile(dialect=dialect)
    return cast(dict[str, object], compiled.params)


@pytest.mark.anyio
async def test_admin_directory_filters_pages_and_loads_minimal_roles() -> None:
    connection = FakeConnection(
        [
            FakeResult(
                rows=(
                    SimpleNamespace(
                        id="user-1",
                        email="user@example.test",
                        name="User",
                        status=UserStatus.ACTIVE,
                        createdAt=NOW,
                    ),
                )
            ),
            FakeResult(scalar=7),
            FakeResult(
                rows=(
                    SimpleNamespace(userId="user-1", id="role-1", serviceKey="temis", name="admin"),
                )
            ),
        ]
    )
    result = await AdminDirectoryStore().list_users(
        cast(AsyncConnection, connection),
        input=AdminUserListInput(
            page=2,
            page_size=5,
            status=UserStatus.ACTIVE,
            email=" newest@example.test ",
            role="temis:admin",
        ),
    )

    assert result.total == 7 and result.items[0].roles[0].name == "admin"
    list_sql = sql(connection.statements[0])
    assert 'EXISTS (SELECT 1 FROM "UserRole" JOIN "Role"' in list_sql
    assert 'ORDER BY "User"."createdAt" DESC' in list_sql
    assert params(connection.statements[0])["param_1"] == 5
    assert params(connection.statements[0])["param_2"] == 5
    assert "%newest@example.test%" in params(connection.statements[0]).values()
    assert 'FROM "UserRole" JOIN "Role"' in sql(connection.statements[2])


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("email_filter", "expected_pattern"),
    [
        ("50%owner", "%50%owner%"),
        ("team_owner", "%team_owner%"),
        (r"domain\\owner", r"%domain\\owner%"),
    ],
)
async def test_admin_email_contains_preserves_prisma_like_metacharacters(
    email_filter: str, expected_pattern: str
) -> None:
    connection = FakeConnection([FakeResult(rows=()), FakeResult(scalar=0)])

    await AdminDirectoryStore().list_users(
        cast(AsyncConnection, connection),
        input=AdminUserListInput(email=email_filter),
    )

    statement = connection.statements[0]
    assert " ESCAPE " not in sql(statement)
    assert expected_pattern in params(statement).values()


@pytest.mark.anyio
async def test_directory_role_lookup_and_current_db_admin_check_are_minimal() -> None:
    connection = FakeConnection(
        [
            FakeResult(SimpleNamespace(id="role-1", serviceKey="temis", name="admin")),
            FakeResult(SimpleNamespace(id="admin-1")),
        ]
    )
    store = AdminDirectoryStore()
    role = await store.find_role_by_id(cast(AsyncConnection, connection), role_id="role-1")
    allowed = await store.is_active_temis_admin(
        cast(AsyncConnection, connection), user_id="admin-1"
    )
    assert role is not None and role.service_key == "temis" and allowed
    assert 'SELECT "Role".id, "Role"."serviceKey", "Role".name' in sql(connection.statements[0])
    admin_sql = sql(connection.statements[1])
    assert '"User".status =' in admin_sql
    assert '"Role"."serviceKey" =' in admin_sql and '"Role".name =' in admin_sql


@pytest.mark.anyio
async def test_admin_mutations_lock_before_revocation_and_are_idempotent() -> None:
    store = AdminMutationStore()
    connection = FakeConnection(
        [
            FakeResult(rowcount=1),
            FakeResult(SimpleNamespace(id="target-1")),
            FakeResult(rowcount=2),
            FakeResult(SimpleNamespace(id="role-1", serviceKey="temis", name="user")),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
            FakeResult(rowcount=1),
        ]
    )
    changed = await store.update_user_status(
        cast(AsyncConnection, connection),
        user_id="target-1",
        status=UserStatus.SUSPENDED,
        updated_at=NOW,
    )
    revoked = await store.revoke_all_refresh_tokens_for_user(
        cast(AsyncConnection, connection), user_id="target-1", revoked_at=NOW
    )
    role = await store.upsert_role(
        cast(AsyncConnection, connection), service_key="temis", name="user"
    )
    assigned = await store.assign_role_to_user(
        cast(AsyncConnection, connection), user_id="target-1", role_id=role.id
    )
    removed = await store.remove_role_from_user(
        cast(AsyncConnection, connection), user_id="target-1", role_id=role.id
    )
    await store.create_admin_audit_log(
        cast(AsyncConnection, connection),
        event=AdminAuditRecord(
            event_type="admin_user_status_changed",
            actor_user_id="admin-1",
            target_user_id="target-1",
            reason_code="ADMIN_SUSPEND",
            details_json={"route": "/admin/users/:id/status"},
        ),
        created_at=NOW,
    )

    assert changed and revoked == 2 and assigned and removed
    assert "FOR UPDATE" in sql(connection.statements[1])
    assert connection.statements[2].is_update
    assert "ON CONFLICT" in sql(connection.statements[3])
    assert "ON CONFLICT" in sql(connection.statements[4])
    audit_values = params(connection.statements[6]).values()
    assert "admin-1" in audit_values and "target-1" in audit_values


@pytest.mark.anyio
async def test_missing_user_lock_skips_refresh_update() -> None:
    connection = FakeConnection([FakeResult()])
    result = await AdminMutationStore().revoke_all_refresh_tokens_for_user(
        cast(AsyncConnection, connection), user_id="missing", revoked_at=NOW
    )
    assert result == 0 and len(connection.statements) == 1


@pytest.mark.anyio
async def test_audit_query_filters_inclusively_and_redacts_details() -> None:
    connection = FakeConnection(
        [
            FakeResult(
                rows=(
                    SimpleNamespace(
                        id="audit-1",
                        eventType="admin_user_sessions_revoked",
                        outcome="success",
                        userId="target-1",
                        actorUserId="admin-1",
                        targetUserId="target-1",
                        reasonCode="ADMIN_REVOKE",
                        detailsJson={"resetCode": "raw-code", "route": "/admin/users"},
                        createdAt=NOW,
                    ),
                )
            ),
            FakeResult(scalar=1),
        ]
    )
    input = AuditLogListInput(
        created_at_from=NOW,
        created_at_to=NOW,
        event_type="admin_user_sessions_revoked",
        outcome="success",
        actor_user_id="admin-1",
    )
    result = await AdminAuditQueryStore().query(cast(AsyncConnection, connection), input=input)
    assert result.items[0].details_json == {
        "resetCode": "[REDACTED]",
        "route": "/admin/users",
    }
    query_sql = sql(connection.statements[0])
    assert '"AuditLog"."createdAt" >=' in query_sql
    assert '"AuditLog"."createdAt" <=' in query_sql
    assert 'ORDER BY "AuditLog"."createdAt" DESC' in query_sql


@pytest.mark.anyio
async def test_audit_query_normalizes_aware_bounds_for_timestamp_without_time_zone() -> None:
    connection = FakeConnection([FakeResult(rows=()), FakeResult(scalar=0)])
    korea = timezone(timedelta(hours=9))

    await AdminAuditQueryStore().query(
        cast(AsyncConnection, connection),
        input=AuditLogListInput(
            created_at_from=datetime(2026, 8, 31, 9, 0, tzinfo=korea),
            created_at_to=datetime(2026, 8, 31, 1, 0, tzinfo=UTC),
        ),
    )

    bound = set(params(connection.statements[0]).values())
    assert datetime(2026, 8, 31, 0, 0) in bound
    assert datetime(2026, 8, 31, 1, 0) in bound
    assert all(not isinstance(value, datetime) or value.tzinfo is None for value in bound)


@pytest.mark.anyio
async def test_audit_retention_is_dry_run_by_default_and_strictly_older_than_cutoff() -> None:
    dry_run_connection = FakeConnection([FakeResult(scalar=3)])
    result = await AuditRetentionStore().cleanup(
        cast(AsyncConnection, dry_run_connection), now=NOW, retention_days=180
    )
    assert result.dry_run and result.deleted_count == 3
    assert '"AuditLog"."createdAt" <' in sql(dry_run_connection.statements[0])

    execute_connection = FakeConnection([FakeResult(rowcount=2)])
    executed = await AuditRetentionStore().cleanup(
        cast(AsyncConnection, execute_connection),
        now=NOW,
        retention_days=180,
        execute=True,
    )
    assert not executed.dry_run and executed.deleted_count == 2
    assert sql(execute_connection.statements[0]).startswith('DELETE FROM "AuditLog"')
