"""Explicit fixture seed for the disposable local DB; never imported by runtime."""

import asyncio
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from wiseacct_sso.infrastructure.security import build_password_hasher


def identifier(label):
    return str(uuid5(NAMESPACE_URL, "wise-sso-local-lab:" + label))


async def main():
    url = os.environ["DATABASE_URL"]
    parsed = urlsplit(url)
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != "https://localhost:4444"
    ):
        raise SystemExit("Refusing non-lab DB/configuration")
    fixtures = json.loads(Path("/run/lab-fixtures.json").read_text())
    engine = create_async_engine(
        url.replace("postgresql://", "postgresql+asyncpg://", 1)
    )
    try:
        async with engine.begin() as connection:
            for item in fixtures:
                name, email = item["name"], item["email"]
                uid = identifier(name)
                existing = (
                    await connection.execute(
                        text('SELECT id FROM "User" WHERE email=:email'),
                        {"email": email},
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    if existing != uid:
                        raise RuntimeError(
                            "Fixture email belongs to an unexpected user"
                        )
                    print(f"Already exists; left unchanged: {email}")
                    continue
                await connection.execute(
                    text(
                        'INSERT INTO "User" (id,email,"emailVerified",name,status,"userType","createdAt","updatedAt") VALUES (:id,:email,true,:name,CAST(:status AS "UserStatus"),CAST(:kind AS "UserType"),now(),now())'
                    ),
                    {
                        "id": uid,
                        "email": email,
                        "name": f"LOCAL LAB {name}",
                        "status": "SUSPENDED" if name == "suspended" else "ACTIVE",
                        "kind": "CUSTOMER" if name == "customer" else "EMPLOYEE",
                    },
                )
                await connection.execute(
                    text(
                        'INSERT INTO "PasswordCredential" (id,"userId",email,"passwordHash","updatedAt") VALUES (:id,:uid,:email,:hash,now())'
                    ),
                    {
                        "id": identifier(name + ":password"),
                        "uid": uid,
                        "email": email,
                        "hash": build_password_hasher().hash(item["password"]),
                    },
                )
                roles = [] if name == "unapproved" else ["customer"]
                if name == "employee":
                    roles.append("staff")
                for kind in roles:
                    service = f"lab-{kind}"
                    rid = identifier(service + ":role")
                    await connection.execute(
                        text(
                            'INSERT INTO "Role" (id,"serviceKey",name) VALUES (:id,:service,\'user\') ON CONFLICT ("serviceKey",name) DO NOTHING'
                        ),
                        {"id": rid, "service": service},
                    )
                    actual = (
                        await connection.execute(
                            text(
                                'SELECT id FROM "Role" WHERE "serviceKey"=:service AND name=\'user\''
                            ),
                            {"service": service},
                        )
                    ).scalar_one()
                    await connection.execute(
                        text(
                            'INSERT INTO "UserRole" (id,"userId","roleId") VALUES (:id,:uid,:rid)'
                        ),
                        {
                            "id": identifier(name + ":" + service),
                            "uid": uid,
                            "rid": actual,
                        },
                    )
                print(f"Created fixture: {email}")
    finally:
        await engine.dispose()


asyncio.run(main())
