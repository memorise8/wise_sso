"""Export synthetic test SQL only, for the WASM PostgreSQL replay test."""

import asyncio, json, sys, os
from datetime import datetime
from sqlalchemy.dialects import postgresql

sys.path.insert(0, "fastapi-auth-server/tests/unit")
from test_employee_invitations import fixture, mail_token

out = []


async def main():
    service, db, mail, _ = fixture()
    execute = db.execute

    async def capture(statement):
        c = statement.compile(dialect=postgresql.dialect(paramstyle="numeric_dollar"))
        values = []
        for name in c.positiontup:
            value = c.params[name]
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            elif isinstance(value, datetime):
                value = value.isoformat()
            values.append(value)
        out.append({"sql": str(c), "params": values})
        return await execute(statement)

    db.execute = capture
    identifier = await service.create(
        "admin", "real-sql@example.test", "SQL Employee", [{"serviceKey": "gitlab", "name": "user"}]
    )
    await service.resend("admin", identifier)
    await service.accept(mail_token(mail), "long-private-password")
    with open(os.environ.get("INVITATION_SQL_PATH", "/tmp/invitation-statements.json"), "w") as f:
        json.dump(out, f)


asyncio.run(main())
