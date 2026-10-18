from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.ops import merge_split_identities as merge
from wiseacct_sso.persistence.database import Database, DatabaseOnlyTransaction

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = merge.SplitAccountCandidate(
    email="person@example.com",
    canonical_user_id="canonical-user",
    password_user_id="password-user",
    provider="google",
    provider_user_id="google-subject",
)


class MemoryStore:
    def __init__(self, candidates: tuple[merge.SplitAccountCandidate, ...]) -> None:
        self.candidates = list(candidates)
        self.merged: list[merge.SplitAccountCandidate] = []
        self.stale: set[str] = set()
        self.find_email: str | None = None

    async def find_candidates(self, email: str | None) -> tuple[merge.SplitAccountCandidate, ...]:
        self.find_email = email
        return tuple(self.candidates)

    async def merge_candidate(self, candidate: merge.SplitAccountCandidate) -> bool:
        if candidate.password_user_id in self.stale:
            return False
        self.merged.append(candidate)
        self.candidates.remove(candidate)
        return True


@pytest.mark.anyio
async def test_default_dry_run_has_no_mutation_and_preserves_candidates() -> None:
    store = MemoryStore((CANDIDATE,))
    result = await merge.merge_split_identities(store, merge.MergeSplitIdentityOptions())
    assert result == merge.MergeSplitIdentityResult("dry-run", (CANDIDATE,), 0, 0)
    assert store.merged == []
    assert store.candidates == [CANDIDATE]


@pytest.mark.anyio
async def test_apply_reports_actual_merges_and_skips_stale_candidates() -> None:
    stale = merge.SplitAccountCandidate(
        "stale@example.com", "canonical-2", "password-2", "google", "subject-2"
    )
    store = MemoryStore((CANDIDATE, stale))
    store.stale.add(stale.password_user_id)
    result = await merge.merge_split_identities(
        store, merge.MergeSplitIdentityOptions(apply=True, email="person@example.com")
    )
    assert result == merge.MergeSplitIdentityResult("apply", (CANDIDATE, stale), 1, 1)
    assert store.find_email == "person@example.com"
    assert store.merged == [CANDIDATE]


@pytest.mark.anyio
async def test_second_apply_is_idempotent() -> None:
    store = MemoryStore((CANDIDATE,))
    first = await merge.merge_split_identities(store, merge.MergeSplitIdentityOptions(apply=True))
    second = await merge.merge_split_identities(store, merge.MergeSplitIdentityOptions(apply=True))
    assert first.merged_count == 1
    assert second.merged_count == 0
    assert second.candidates == ()


def test_candidate_sql_matches_express_criteria_and_binds_email() -> None:
    statement = merge.candidate_discovery_statement("quoted@example.com' OR true --")
    compiled = statement.compile()
    sql = str(compiled)
    assert 'FROM "PasswordCredential" JOIN "SocialAccount"' in sql
    assert 'lower("SocialAccount"."providerEmail") = lower("PasswordCredential".email)' in sql
    assert '"SocialAccount".provider = ' in sql
    assert '"SocialAccount"."userId" != "PasswordCredential"."userId"' in sql
    assert "canonical_user.status = " in sql
    assert 'canonical_user."emailVerified" IS true' in sql
    assert 'password_user."emailVerified" IS true' in sql
    assert "NOT (EXISTS (SELECT existing_pc.id" in sql
    assert 'existing_pc."userId" = "SocialAccount"."userId"' in sql
    assert 'ORDER BY lower("PasswordCredential".email)' in sql
    assert "quoted@example.com' OR true --" not in sql
    assert "quoted@example.com' OR true --" in compiled.params.values()


class RecordingConnection:
    def __init__(
        self,
        *,
        stale: bool = False,
        fail_at: int | None = None,
        zero_rowcount_at: int | None = None,
    ) -> None:
        self.statements: list[Any] = []
        self.stale = stale
        self.fail_at = fail_at
        self.zero_rowcount_at = zero_rowcount_at

    async def execute(self, statement: Any) -> Any:
        self.statements.append(statement)
        if self.fail_at == len(self.statements):
            raise RuntimeError("transaction mutation failed")
        if len(self.statements) == 2:
            return SimpleNamespace(one_or_none=lambda: None if self.stale else SimpleNamespace())
        return SimpleNamespace(rowcount=0 if self.zero_rowcount_at == len(self.statements) else 1)


class RecordingDatabase:
    def __init__(
        self,
        *,
        stale: bool = False,
        fail_at: int | None = None,
        zero_rowcount_at: int | None = None,
    ) -> None:
        self.connection = RecordingConnection(
            stale=stale, fail_at=fail_at, zero_rowcount_at=zero_rowcount_at
        )
        self.committed = False

    async def transaction(self, work: DatabaseOnlyTransaction[bool]) -> bool:
        assert isinstance(work, DatabaseOnlyTransaction)
        result = await work.callback(cast(AsyncConnection, self.connection))
        self.committed = True
        return result


@pytest.mark.anyio
async def test_apply_revalidates_under_lock_then_performs_one_atomic_merge() -> None:
    database = RecordingDatabase()
    store = merge.SqlAlchemyMergeSplitIdentityStore(cast(Database, database))
    assert await store.merge_candidate(CANDIDATE) is True
    assert database.committed is True
    statements = database.connection.statements
    assert len(statements) == 7
    assert str(statements[0]) == "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"
    assert "FOR UPDATE" in str(statements[1])
    locked_params = statements[1].compile().params
    assert CANDIDATE.canonical_user_id in locked_params.values()
    assert CANDIDATE.password_user_id in locked_params.values()
    assert CANDIDATE.provider_user_id in locked_params.values()
    assert str(statements[2]).startswith('UPDATE "User" SET email=')
    assert str(statements[3]).startswith('UPDATE "User" SET email=')
    assert str(statements[4]).startswith('UPDATE "PasswordCredential" SET "userId"=')
    update_params = [statement.compile().params for statement in statements[2:5]]
    updated_at_values = [params["updatedAt"] for params in update_params]
    assert all(isinstance(value, datetime) for value in updated_at_values)
    assert updated_at_values[0] == updated_at_values[1] == updated_at_values[2]
    assert update_params[0]["email"] is None
    assert update_params[1]["email"] == CANDIDATE.email
    assert update_params[1]["emailVerified"] is True
    assert update_params[2]["userId"] == CANDIDATE.canonical_user_id
    audit = statements[5].compile().params
    assert audit["eventType"] == "identity_merge"
    assert audit["reasonCode"] == "OPS_MERGE_SPLIT_EMAIL_IDENTITIES"
    assert audit["userId"] == CANDIDATE.canonical_user_id
    assert audit["targetUserId"] == CANDIDATE.password_user_id
    assert audit["detailsJson"] == {
        "email": CANDIDATE.email,
        "providerUserId": CANDIDATE.provider_user_id,
        "canonicalUserId": CANDIDATE.canonical_user_id,
        "mergedPasswordUserId": CANDIDATE.password_user_id,
    }
    assert str(statements[6]).startswith('DELETE FROM "User"')


@pytest.mark.anyio
async def test_stale_candidate_makes_no_mutation() -> None:
    database = RecordingDatabase(stale=True)
    store = merge.SqlAlchemyMergeSplitIdentityStore(cast(Database, database))
    assert await store.merge_candidate(CANDIDATE) is False
    assert database.committed is True
    assert len(database.connection.statements) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("fail_at", [3, 4, 5, 6, 7])
async def test_any_merge_failure_aborts_candidate_transaction(fail_at: int) -> None:
    database = RecordingDatabase(fail_at=fail_at)
    store = merge.SqlAlchemyMergeSplitIdentityStore(cast(Database, database))
    with pytest.raises(RuntimeError, match="transaction mutation failed"):
        await store.merge_candidate(CANDIDATE)
    assert database.committed is False


@pytest.mark.anyio
@pytest.mark.parametrize("zero_rowcount_at", [3, 4, 5, 6, 7])
async def test_missing_mutation_target_aborts_candidate_transaction(
    zero_rowcount_at: int,
) -> None:
    database = RecordingDatabase(zero_rowcount_at=zero_rowcount_at)
    store = merge.SqlAlchemyMergeSplitIdentityStore(cast(Database, database))
    with pytest.raises(RuntimeError, match="affected an unexpected row count"):
        await store.merge_candidate(CANDIDATE)
    assert database.committed is False


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], merge.MergeSplitIdentityOptions()),
        (["--apply"], merge.MergeSplitIdentityOptions(apply=True)),
        (
            ["--email", " Person@Example.COM "],
            merge.MergeSplitIdentityOptions(email="person@example.com"),
        ),
        (
            ["--apply", "--email=Person@Example.COM"],
            merge.MergeSplitIdentityOptions(apply=True, email="person@example.com"),
        ),
    ],
)
def test_parse_args(arguments: list[str], expected: merge.MergeSplitIdentityOptions) -> None:
    assert merge.parse_args(arguments) == expected


@pytest.mark.parametrize(
    "arguments",
    [["--execute"], ["--email"], ["--email="], ["--email", "not-an-email"]],
)
def test_cli_rejects_invalid_arguments_without_echoing_them(arguments: list[str]) -> None:
    with pytest.raises(merge.MergeSplitIdentityConfigurationError) as error:
        merge.parse_args(arguments)
    assert "not-an-email" not in str(error.value)


def test_cli_requires_database_environment_without_loading_secrets() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wiseacct_sso.ops.merge_split_identities"],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "merge-split-email-identities failed: DATABASE_URL is required\n"


def test_cli_emits_express_compatible_dry_run_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic@127.0.0.1/unit_test_only")

    async def run(
        options: merge.MergeSplitIdentityOptions, *, database_url: str
    ) -> merge.MergeSplitIdentityResult:
        assert options == merge.MergeSplitIdentityOptions(email="person@example.com")
        assert database_url.endswith("unit_test_only")
        return merge.MergeSplitIdentityResult("dry-run", (CANDIDATE,), 0, 0)

    monkeypatch.setattr(merge, "_run", run)
    merge.cli(["--email=person@example.com"])
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "mode": "dry-run",
        "count": 1,
        "candidates": [
            {
                "email": CANDIDATE.email,
                "canonicalUserId": CANDIDATE.canonical_user_id,
                "passwordUserId": CANDIDATE.password_user_id,
                "provider": CANDIDATE.provider,
                "providerUserId": CANDIDATE.provider_user_id,
            }
        ],
    }
