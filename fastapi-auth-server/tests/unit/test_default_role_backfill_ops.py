from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.ops import default_role_backfill as backfill
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction
from wiseacct_sso.persistence.stores import DefaultRole

ROOT = Path(__file__).resolve().parents[2]


class MemoryStore:
    def __init__(self) -> None:
        self.roles: dict[str, list[str]] = {
            "active": [],
            "pending": [],
            "disabled": [],
            "existing-other-service": ["other:pending"],
            "existing-admin": ["temis:admin"],
        }
        self.calls = 0

    async def backfill(self, default_role: DefaultRole) -> int:
        self.calls += 1
        changed = 0
        for roles in self.roles.values():
            if not roles:
                roles.append(f"{default_role.service_key}:{default_role.name}")
                changed += 1
        return changed


@pytest.mark.anyio
async def test_backfill_is_idempotent_and_preserves_existing_roles() -> None:
    store = MemoryStore()
    role = DefaultRole("temis", "pending")
    first = await backfill.backfill_default_roles(store, role)
    second = await backfill.backfill_default_roles(store, role)
    assert first.default_role == role
    assert first.roleless_user_count == first.assigned_user_role_count == 3
    assert second.roleless_user_count == second.assigned_user_role_count == 0
    assert store.roles["existing-other-service"] == ["other:pending"]
    assert store.roles["existing-admin"] == ["temis:admin"]


@pytest.mark.anyio
@pytest.mark.parametrize("role", [DefaultRole("temis", "admin"), DefaultRole("other", "pending")])
async def test_invalid_default_role_rejected_before_store_mutation(role: DefaultRole) -> None:
    store = MemoryStore()
    with pytest.raises(backfill.BackfillConfigurationError):
        await backfill.backfill_default_roles(store, role)
    assert store.calls == 0


def test_assignment_sql_matches_express_scope_and_deterministic_ids() -> None:
    statement = backfill.roleless_assignment_statement("quoted-role'; DROP TABLE impossible;")
    compiled = statement.compile()
    sql = str(compiled)
    assert 'INSERT INTO "UserRole" (id, "userId", "roleId") SELECT concat(' in sql
    assert 'md5("User".id || ' in sql
    assert 'FROM "User"' in sql
    assert 'NOT (EXISTS (SELECT "UserRole".id' in sql
    assert '"UserRole"."userId" = "User".id' in sql
    assert 'ON CONFLICT ("userId", "roleId") DO NOTHING' in sql
    assert "status" not in sql  # Express includes every roleless user, not just ACTIVE.
    assert "DROP TABLE" not in sql
    assert "default-role-" in compiled.params.values()
    assert "quoted-role'; DROP TABLE impossible;" in compiled.params.values()


class RecordingConnection:
    def __init__(self, *, fail_assignment: bool = False) -> None:
        self.statements: list[Any] = []
        self.fail_assignment = fail_assignment

    async def execute(self, statement: Any) -> Any:
        self.statements.append(statement)
        if len(self.statements) == 7 and self.fail_assignment:
            raise RuntimeError("assignment failed")
        return SimpleNamespace(rowcount=4, one=lambda: SimpleNamespace(id="role-1"))


class RecordingDatabase:
    def __init__(self, *, fail_assignment: bool = False) -> None:
        self.connection = RecordingConnection(fail_assignment=fail_assignment)
        self.committed = False
        self.transaction_calls = 0

    async def transaction(self, work: DatabaseOnlyTransaction[int]) -> int:
        assert isinstance(work, DatabaseOnlyTransaction)
        self.transaction_calls += 1
        result = await work.callback(cast(AsyncConnection, self.connection))
        self.committed = True
        return result


@pytest.mark.anyio
async def test_serializable_role_seed_and_assignment_share_one_retry_safe_transaction() -> None:
    database = RecordingDatabase()
    store = backfill.SqlAlchemyDefaultRoleBackfillStore(cast(Database, database))
    result = await backfill.backfill_default_roles(store, DefaultRole("temis", "user"))
    assert result.assigned_user_role_count == 4
    assert database.transaction_calls == 1
    assert database.committed is True
    statements = database.connection.statements
    assert len(statements) == 7
    assert str(statements[0]) == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
    seeds = [statement.compile().params for statement in statements[1:5]]
    assert [(item["serviceKey"], item["name"]) for item in seeds] == [
        ("temis", "pending"),
        ("temis", "user"),
        ("temis", "admin"),
        ("temis", "user"),
    ]
    assert all(
        'ON CONFLICT ("serviceKey", name) DO NOTHING' in str(item) for item in statements[1:5]
    )
    assert str(statements[5]).startswith('SELECT "Role".id')
    assert 'INSERT INTO "UserRole"' in str(statements[6])


@pytest.mark.anyio
async def test_assignment_failure_does_not_commit_seeded_roles() -> None:
    database = RecordingDatabase(fail_assignment=True)
    store = backfill.SqlAlchemyDefaultRoleBackfillStore(cast(Database, database))
    with pytest.raises(RuntimeError, match="assignment failed"):
        await store.backfill(DefaultRole("temis", "pending"))
    assert database.committed is False


@pytest.mark.parametrize("arguments", [["--execute"], ["--dry-run"], ["--secret=do-not-print"]])
def test_cli_rejects_all_arguments_without_echoing_them(arguments: list[str]) -> None:
    with pytest.raises(backfill.BackfillConfigurationError) as error:
        backfill.parse_args(arguments)
    assert str(error.value) == "backfill-default-roles does not accept arguments"


def test_cli_requires_explicit_database_environment_without_loading_secrets() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wiseacct_sso.ops.default_role_backfill"],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "backfill-default-roles failed: DATABASE_URL is required\n"


def test_cli_uses_validated_temis_policy_and_reports_counts_only(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic@127.0.0.1/unit_test_only")
    monkeypatch.setattr(
        backfill,
        "get_settings",
        lambda: SimpleNamespace(
            auth_clients=[SimpleNamespace(default_role=DefaultRole("temis", "pending"))]
        ),
    )

    async def run(
        database_url: str, default_role: DefaultRole
    ) -> backfill.DefaultRoleBackfillResult:
        assert database_url.endswith("unit_test_only")
        assert default_role == DefaultRole("temis", "pending")
        return backfill.DefaultRoleBackfillResult(default_role, 2)

    monkeypatch.setattr(backfill, "_run", run)
    backfill.cli([])
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == (
        "backfill-default-roles success defaultRole=temis:pending "
        "rolelessUserCount=2 assignedUserRoleCount=2\n"
    )
