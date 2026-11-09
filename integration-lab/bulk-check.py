"""Explicit live bulk-type checks for disposable local fixtures; restore types on exit."""

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

import httpx


def uid(name):
    return str(uuid5(NAMESPACE_URL, "wise-sso-local-lab:" + name))


def require(response, status):
    if response.status_code != status:
        raise RuntimeError(f"Expected HTTP {status}; got {response.status_code}")


async def lookup(client, name):
    response = await client.get(
        "/admin/users", params={"email": f"{name}@wise-lab.invalid"}
    )
    require(response, 200)
    rows = [
        item
        for item in response.json()["items"]
        if item["id"] == uid(name) and item["email"] == f"{name}@wise-lab.invalid"
    ]
    if len(rows) != 1:
        raise RuntimeError("Unexpected fixture identity")
    return rows[0]


async def main():
    parsed = urlsplit(os.environ["DATABASE_URL"])
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != "https://localhost:4444"
    ):
        raise SystemExit("Refusing non-lab configuration")
    fixtures = json.loads(Path("/run/lab-fixtures.json").read_text())
    employee = next(item for item in fixtures if item["name"] == "employee")
    names = ("unapproved", "suspended")
    targets = [uid(name) for name in names]
    pair, touched = None, False
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:4001", timeout=20
    ) as client:
        response = await client.post(
            "/auth/login",
            json={"email": employee["email"], "password": employee["password"]},
        )
        require(response, 200)
        pair = response.json()
        client.headers["Authorization"] = "Bearer " + pair["accessToken"]
        try:
            original = {name: await lookup(client, name) for name in names}
            if any(item["userType"] != "EMPLOYEE" for item in original.values()):
                raise RuntimeError(
                    "Expected original EMPLOYEE fixtures; no bulk changes attempted"
                )
            payload = {
                "userIds": targets,
                "userType": None,
                "reasonCode": "LOCAL_LAB_BULK_CHECK",
            }
            touched = (
                True  # Even a lost success response must be followed by restoration.
            )
            response = await client.patch("/admin/users/type", json=payload)
            require(response, 200)
            if response.json() != {
                "requestedCount": 2,
                "changedCount": 2,
                "unchangedCount": 0,
            }:
                raise RuntimeError("Unexpected bulk result")
            for name in names:
                if (await lookup(client, name))["userType"] is not None:
                    raise RuntimeError("Bulk type change was not persisted")
            print("PASS: two fixture users changed to UNCLASSIFIED")
            response = await client.patch("/admin/users/type", json=payload)
            require(response, 200)
            if response.json() != {
                "requestedCount": 2,
                "changedCount": 0,
                "unchangedCount": 2,
            }:
                raise RuntimeError("Expected idempotent no-op")
            print("PASS: repeating the same bulk request changes no users")
            response = await client.get(
                "/admin/audit-logs",
                params={
                    "eventType": "admin_user_type_changed",
                    "reasonCode": "LOCAL_LAB_BULK_CHECK",
                    "pageSize": 100,
                },
            )
            require(response, 200)
            current = {}
            for event in response.json()["items"]:
                details = event.get("detailsJson") or {}
                if (
                    event.get("targetUserId") in targets
                    and details.get("userType") is None
                    and "batchId" in details
                ):
                    current.setdefault(event["targetUserId"], details["batchId"])
            if len(current) != 2 or len(set(current.values())) != 1:
                raise RuntimeError("Expected per-user audit records with one batch ID")
            print(
                "PASS: each changed user has an audit record with the shared batch ID"
            )
            response = await client.patch(
                "/admin/users/type",
                json={
                    "userIds": [uid("unapproved"), uid("employee")],
                    "userType": "CUSTOMER",
                    "reasonCode": "LOCAL_LAB_BULK_PROTECTED_CHECK",
                },
            )
            require(response, 409)
            if response.json().get("error", {}).get("code") not in {
                "LAST_SSO_ADMIN",
                "SSO_ADMIN_MUST_BE_EMPLOYEE",
            }:
                raise RuntimeError("Expected central administrator protection")
            if (await lookup(client, "unapproved"))["userType"] is not None or (
                await lookup(client, "employee")
            )["userType"] != "EMPLOYEE":
                raise RuntimeError("Rejected bulk request changed a user")
            print(
                "PASS: protected administrator makes the entire bulk request fail without changes"
            )
        finally:
            try:
                if touched:
                    response = await client.patch(
                        "/admin/users/type",
                        json={
                            "userIds": targets,
                            "userType": "EMPLOYEE",
                            "reasonCode": "LOCAL_LAB_BULK_RESTORE",
                        },
                    )
                    require(response, 200)
                    for name in names:
                        item = await lookup(client, name)
                        if (
                            item["userType"] != "EMPLOYEE"
                            or item["status"] != original[name]["status"]
                        ):
                            raise RuntimeError("Fixture restoration failed")
                    print(
                        "PASS: original fixture types restored; account statuses retained"
                    )
            finally:
                require(
                    await client.post(
                        "/auth/logout", json={"refreshToken": pair["refreshToken"]}
                    ),
                    204,
                )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        print("Bulk check failed:", type(error).__name__)
        print(
            "If no restoration PASS appeared after a change, check the two fixture types in the admin UI."
        )
        raise SystemExit(1) from None
