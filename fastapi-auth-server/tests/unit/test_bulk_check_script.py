"""Check that the local live-check script restores fixture types even after a failed check."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

SCRIPT = Path(__file__).parents[3] / "integration-lab/bulk-check.py"


@pytest.mark.anyio
@pytest.mark.parametrize("wrong_count", [False, True])
async def test_live_bulk_script_restores_fixture_types_and_logs_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], wrong_count: bool
) -> None:
    spec = importlib.util.spec_from_file_location("bulk_check_script", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for key, value in {
        "DATABASE_URL": "postgresql://synthetic@postgres/fastapi_sso_dev",
        "NODE_ENV": "development",
        "JWT_ISSUER": "https://localhost:4444",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        module,
        "Path",
        lambda _: SimpleNamespace(
            read_text=lambda: json.dumps(
                [
                    {
                        "name": "employee",
                        "email": "employee@wise-lab.invalid",
                        "password": "synthetic-test-password",
                    }
                ]
            )
        ),
    )
    ids = {name: str(module.uid(name)) for name in ("employee", "unapproved", "suspended")}
    types = dict.fromkeys(ids.values(), "EMPLOYEE")
    records: list[dict[str, object]] = []
    calls: list[httpx.Request] = []
    writes = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal writes
        calls.append(request)
        if request.url.path == "/auth/login":
            return httpx.Response(200, json={"accessToken": "a" * 43, "refreshToken": "r" * 43})
        if request.url.path == "/auth/logout":
            assert json.loads(request.content)["refreshToken"] == "r" * 43
            return httpx.Response(204)
        if request.url.path == "/admin/users":
            name = request.url.params["email"].split("@")[0]
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "id": ids[name],
                            "email": name + "@wise-lab.invalid",
                            "userType": types[ids[name]],
                            "status": "SUSPENDED" if name == "suspended" else "ACTIVE",
                        }
                    ]
                },
            )
        if request.url.path == "/admin/audit-logs":
            return httpx.Response(200, json={"items": list(reversed(records))})
        assert request.method == "PATCH" and request.url.path == "/admin/users/type"
        data = json.loads(request.content)
        assert data.get("reasonCode")
        if ids["employee"] in data["userIds"]:
            return httpx.Response(409, json={"error": {"code": "LAST_SSO_ADMIN"}})
        changed = [uid for uid in data["userIds"] if types[uid] != data["userType"]]
        writes += 1
        for uid in changed:
            types[uid] = data["userType"]
            records.append(
                {
                    "targetUserId": uid,
                    "detailsJson": {"batchId": str(writes), "userType": data["userType"]},
                }
            )
        changed_count = 1 if wrong_count and writes == 1 else len(changed)
        return httpx.Response(
            200,
            json={
                "requestedCount": len(data["userIds"]),
                "changedCount": changed_count,
                "unchangedCount": len(data["userIds"]) - changed_count,
            },
        )

    original_client = httpx.AsyncClient

    def client_factory(**kwargs: Any) -> httpx.AsyncClient:
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", client_factory)
    if wrong_count:
        with pytest.raises(RuntimeError, match="Unexpected bulk result"):
            await module.main()
    else:
        await module.main()
        assert capsys.readouterr().out.count("PASS:") == 5
    assert all(kind == "EMPLOYEE" for kind in types.values())
    assert calls[-1].url.path == "/auth/logout"
    restorations = [
        r
        for r in calls
        if r.method == "PATCH"
        and json.loads(r.content).get("reasonCode") == "LOCAL_LAB_BULK_RESTORE"
    ]
    assert len(restorations) == 1
    assert json.loads(restorations[0].content)["userType"] == "EMPLOYEE"
