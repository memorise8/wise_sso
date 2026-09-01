import copy
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from wiseacct_sso.ops.first_admin import (
    ActiveUserNotFoundError,
    GrantFirstAdminInput,
    grant_first_admin,
    parse_args,
)

ROOT = Path(__file__).parents[2]


class FakeTransaction:
    def __init__(self, state: dict[str, Any], *, fail_audit: bool = False) -> None:
        self.state = state
        self.fail_audit = fail_audit

    async def find_active_user_by_email(self, email: str) -> str | None:
        self.state["events"].append(("find", email))
        return self.state.get("active_user_id")

    async def upsert_admin_role(self) -> tuple[str, str, str]:
        self.state["events"].append(("upsert-role",))
        self.state["role_exists"] = True
        return "role-admin", "temis", "admin"

    async def assign_role(self, *, user_id: str, role_id: str) -> bool:
        self.state["events"].append(("assign", user_id, role_id))
        assigned = not self.state["assigned"]
        self.state["assigned"] = True
        return assigned

    async def revoke_refresh_tokens(self, *, user_id: str, revoked_at: datetime) -> int:
        self.state["events"].append(("revoke", user_id, revoked_at))
        count = int(self.state["active_refresh"])
        self.state["active_refresh"] = 0
        return count

    async def create_audit(
        self, *, user_id: str, service_key: str, role_name: str, created_at: datetime
    ) -> None:
        self.state["events"].append(("audit", user_id, service_key, role_name, created_at))
        if self.fail_audit:
            raise RuntimeError("audit unavailable")
        self.state["audit_count"] += 1


class FakeStore:
    def __init__(self, *, fail_audit: bool = False, active: bool = True) -> None:
        self.state: dict[str, Any] = {
            "active_user_id": "user-1" if active else None,
            "role_exists": False,
            "assigned": False,
            "active_refresh": 2,
            "audit_count": 0,
            "events": [],
        }
        self.fail_audit = fail_audit
        self.transaction_calls = 0

    async def run_in_transaction(self, work: Any) -> Any:
        self.transaction_calls += 1
        candidate = copy.deepcopy(self.state)
        result = await work(FakeTransaction(candidate, fail_audit=self.fail_audit))
        self.state = candidate
        return result


@pytest.mark.anyio
async def test_first_admin_normalizes_active_email_and_orders_atomic_mutations() -> None:
    store = FakeStore()
    now = datetime(2026, 8, 31, 12, 0, 0)

    result = await grant_first_admin(
        store, GrantFirstAdminInput(email="  Admin@Company.COM  ", now=now)
    )

    assert result.user_id == "user-1"
    assert result.role_assigned is True
    assert result.revoked_refresh_token_count == 2
    assert store.transaction_calls == 1
    assert store.state["events"] == [
        ("find", "admin@company.com"),
        ("upsert-role",),
        ("assign", "user-1", "role-admin"),
        ("revoke", "user-1", now),
        ("audit", "user-1", "temis", "admin", now),
    ]


@pytest.mark.anyio
async def test_first_admin_audit_failure_rolls_back_role_and_revocation() -> None:
    store = FakeStore(fail_audit=True)
    before = copy.deepcopy(store.state)

    with pytest.raises(RuntimeError, match="audit unavailable"):
        await grant_first_admin(store, GrantFirstAdminInput("admin@company.com"))

    assert store.transaction_calls == 1
    assert store.state == before


@pytest.mark.anyio
async def test_first_admin_requires_active_exact_email_before_mutation() -> None:
    store = FakeStore(active=False)

    with pytest.raises(ActiveUserNotFoundError, match="No active user found"):
        await grant_first_admin(store, GrantFirstAdminInput("admin@company.com"))

    assert store.state["role_exists"] is False
    assert store.state["audit_count"] == 0


def test_first_admin_cli_parser_matches_express_shape() -> None:
    assert parse_args(["--email", " Admin@Company.COM "]) == GrantFirstAdminInput(
        "admin@company.com"
    )
    with pytest.raises(ValueError, match="--email is required"):
        parse_args([])
    with pytest.raises(ValueError, match="Invalid email"):
        parse_args(["--email=invalid"])


def test_first_admin_module_execution_is_dormant_and_sanitized() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "wiseacct_sso.ops.first_admin", "--email=admin@company.com"],
        cwd=ROOT,
        env={
            "PATH": os.environ["PATH"],
            "PYTHONPATH": str(ROOT / "src"),
            "JWT_REFRESH_SECRET": "must-not-be-read-or-reported",
        },
        capture_output=True,
        check=False,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "grant-admin failed: DATABASE_URL is required\n"
    assert "must-not-be-read-or-reported" not in result.stderr
