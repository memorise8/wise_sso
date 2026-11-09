"""Local fixtures only: prepare policy fixtures and exercise authenticated admin APIs.

Run with lab.sh policy-setup / policy-check, never against an operational DB.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from wiseacct_sso.ops.first_admin import GrantFirstAdminInput, _run


def identifier(label):
    return str(uuid5(NAMESPACE_URL, "wise-sso-local-lab:" + label))


def guard():
    url = os.environ["DATABASE_URL"]
    parsed = urlsplit(url)
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != "https://localhost:4444"
    ):
        raise SystemExit("Refusing non-lab DB/configuration")
    return url


async def prepare(engine, url):
    # Explicit operator action for four deterministic, disposable fixture IDs only.
    # This is the bootstrap, not a public account-classification endpoint.
    async with engine.begin() as conn:
        for name in ("employee", "customer", "unapproved", "suspended"):
            uid = identifier(name)
            row = (
                await conn.execute(
                    text(
                        'SELECT email,"userType" FROM "User" WHERE id=:uid FOR UPDATE'
                    ),
                    {"uid": uid},
                )
            ).one_or_none()
            if row is None or row.email != f"{name}@wise-lab.invalid":
                raise RuntimeError("Missing or unexpected fixture; run seed first")
            kind = "CUSTOMER" if name == "customer" else "EMPLOYEE"
            if row.userType == kind:
                continue
            await conn.execute(
                text(
                    'UPDATE "User" SET "userType"=CAST(:kind AS "UserType"),"updatedAt"=now() WHERE id=:uid'
                ),
                {"kind": kind, "uid": uid},
            )
            await conn.execute(
                text(
                    'INSERT INTO "AuditLog" (id,"eventType",outcome,"userId","targetUserId","reasonCode","detailsJson","createdAt") '
                    "VALUES (:id,'admin_user_type_changed','success',:uid,:uid,'LOCAL_LAB_BOOTSTRAP',CAST(:details AS jsonb),now())"
                ),
                {
                    "id": str(uuid4()),
                    "uid": uid,
                    "details": json.dumps(
                        {"previousUserType": row.userType, "userType": kind}
                    ),
                },
            )
    await _run(GrantFirstAdminInput("employee@wise-lab.invalid"), database_url=url)
    print(
        "Prepared four fixture types; employee fixture has sso:admin. No credentials printed."
    )


def require(response, status, code=None):
    if response.status_code != status:
        raise RuntimeError(f"Expected HTTP {status}; received {response.status_code}")
    if code and response.json().get("error", {}).get("code") != code:
        raise RuntimeError("Unexpected policy error code")


async def check():
    fixtures = json.loads(Path("/run/lab-fixtures.json").read_text())
    employee = next(item for item in fixtures if item["name"] == "employee")
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
            response = await client.get(
                "/admin/users", params={"email": "customer@wise-lab.invalid"}
            )
            require(response, 200)
            item = next(
                item
                for item in response.json()["items"]
                if item["id"] == identifier("customer")
            )
            if item["userType"] != "CUSTOMER":
                raise RuntimeError("Customer fixture not classified; run policy-setup")
            response = await client.post(
                f"/admin/users/{item['id']}/roles",
                json={"serviceKey": "lab-staff", "name": "user"},
            )
            require(response, 403, "EMPLOYEE_REQUIRED")
            print("PASS: admin API refuses staff role for CUSTOMER")
            response = await client.post(
                f"/admin/users/{item['id']}/roles",
                json={"serviceKey": "sso", "name": "admin"},
            )
            require(response, 403, "EMPLOYEE_REQUIRED")
            print("PASS: admin API refuses central admin role for CUSTOMER")
            response = await client.patch(
                f"/admin/users/{identifier('employee')}/type",
                json={"userType": "CUSTOMER"},
            )
            # In a fresh lab the employee fixture is the only central admin.
            # Existing extra administrators must not make this check unsafe.
            if response.status_code != 409:
                raise RuntimeError("Expected protected admin demotion (409)")
            print("PASS: central admin cannot be demoted while holding sso:admin")
        finally:
            logout = await client.post(
                "/auth/logout", json={"refreshToken": pair["refreshToken"]}
            )
            require(logout, 204)


async def main():
    url = guard()
    engine = create_async_engine(
        url.replace("postgresql://", "postgresql+asyncpg://", 1)
    )
    try:
        if sys.argv[1:] == ["setup"]:
            await prepare(engine, url)
        elif sys.argv[1:] == ["check"]:
            await check()
        else:
            raise SystemExit("Expected setup or check")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
