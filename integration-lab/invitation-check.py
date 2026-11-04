"""Local employee invitation lifecycle check. No credentials or tokens printed."""

import asyncio
import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

ORIGIN = "https://localhost:4444"
ROOT = "/oauth2/admin"


class Loopback(httpx.AsyncBaseTransport):
    def __init__(self):
        self.transport = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        expected = urlsplit(ORIGIN)
        if (
            request.url.scheme != "https"
            or request.url.host != expected.hostname
            or request.url.port != expected.port
        ):
            raise RuntimeError("Unexpected test destination")
        forwarded = httpx.Request(
            request.method,
            request.url.copy_with(scheme="http", host="127.0.0.1", port=4001),
            headers=request.headers,
            content=await request.aread(),
            extensions=request.extensions,
        )
        return await self.transport.handle_async_request(forwarded)

    async def aclose(self):
        await self.transport.aclose()


def require(response, status):
    if response.status_code != status:
        raise RuntimeError(f"Expected HTTP {status}, received {response.status_code}")


def field(page, name):
    match = re.search(r'name="' + name + r'" (?:value|content)="([^"]+)"', page)
    if match is None:
        raise RuntimeError("Missing expected form field")
    return match[1]


async def login(client, fixture):
    response = await client.get(ROOT + "/login?reauth=1")
    require(response, 200)
    return await client.post(
        ROOT + "/login",
        headers={"origin": ORIGIN},
        data={
            "transaction": field(response.text, "transaction"),
            "csrf_token": field(response.text, "csrf_token"),
            "email": fixture["email"],
            "password": fixture["password"],
        },
    )


async def cleanup(client):
    response = await client.get("/oauth2/session")
    if response.status_code != 200:
        return
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if match:
        await client.post(
            "/oauth2/session/logout",
            headers={"origin": ORIGIN},
            data={"csrf_token": match[1]},
        )


async def captured_token(mailbox, email, previous=None):
    for _ in range(20):
        result = await mailbox.get("/api/v1/search", params={"query": "to:" + email})
        require(result, 200)
        for row in result.json().get("messages", []):
            message = await mailbox.get("/api/v1/message/" + row["ID"])
            require(message, 200)
            data = message.json()
            if not any(x.get("Address") == email for x in data.get("To", [])):
                continue
            found = re.search(
                r"https://localhost:4444/oauth2/invitations/accept#token=([A-Za-z0-9_-]{43})",
                data.get("Text", ""),
            )
            if found and found[1] != previous:
                return found[1]
        await asyncio.sleep(0.25)
    raise RuntimeError("Invitation mail not captured")


async def accept(client, token, expected, password):
    page = await client.get("/oauth2/invitations/accept")
    require(page, 200)
    result = await client.post(
        "/oauth2/invitations/accept",
        headers={"origin": ORIGIN},
        data={
            "token": token,
            "password": password,
            "csrf_token": field(page.text, "csrf_token"),
        },
    )
    require(result, expected)


async def main():
    parsed = urlsplit(os.environ["DATABASE_URL"])
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != ORIGIN
        or os.environ.get("MAIL_PROVIDER") != "smtp"
        or os.environ.get("SMTP_HOST") != "mailpit"
    ):
        raise SystemExit("Refusing non-lab configuration")
    fixtures = {row["name"]: row for row in json.loads(Path("/run/lab-fixtures.json").read_text())}  # noqa: ASYNC240
    email = "invite-" + secrets.token_hex(6) + "@wise-lab.invalid"
    password = secrets.token_urlsafe(32)
    identifiers = []
    async with (
        httpx.AsyncClient(
            base_url=ORIGIN, transport=Loopback(), timeout=20, follow_redirects=False
        ) as admin,
        httpx.AsyncClient(
            base_url=ORIGIN, transport=Loopback(), timeout=20, follow_redirects=False
        ) as employee,
        httpx.AsyncClient(base_url="http://mailpit:8025", timeout=10) as mailbox,
    ):
        try:
            require(await login(admin, fixtures["employee"]), 303)
            page = await admin.get(ROOT + "/dashboard")
            require(page, 200)
            headers = {"origin": ORIGIN, "x-admin-csrf": field(page.text, "admin-session-csrf")}
            body = {
                "email": email,
                "name": "Invited employee",
                "roles": [{"serviceKey": "lab-staff", "name": "user"}],
            }
            response = await admin.post(ROOT + "/api/invitations", headers=headers, json=body)
            require(response, 201)
            identifier = response.json()["id"]
            identifiers.append(identifier)
            first = await captured_token(mailbox, email)
            response = await admin.get(ROOT + "/api/invitations")
            require(response, 200)
            row = next(r for r in response.json()["items"] if r["id"] == identifier)
            expires = datetime.fromisoformat(row["expiresAt"]).replace(tzinfo=UTC)
            if not 71.9 < (expires - datetime.now(UTC)).total_seconds() / 3600 <= 72:
                raise RuntimeError("Expected 72-hour expiry")
            if "tokenHash" in row or first in response.text:
                raise RuntimeError("Invitation secret leaked")
            print("PASS: invitation email captured; 72-hour expiry and private token storage")
            require(
                await admin.post(
                    ROOT + "/api/invitations/" + identifier + "/resend", headers=headers, json={}
                ),
                204,
            )
            second = await captured_token(mailbox, email, first)
            await accept(employee, first, 400, password)
            print("PASS: resend rotates the token and invalidates the previous link")
            await accept(employee, second, 200, password)
            await accept(employee, second, 400, password)
            users = await admin.get(ROOT + "/api/users", params={"email": email})
            require(users, 200)
            user = next(x for x in users.json()["items"] if x["email"] == email)
            if (
                user["status"] != "ACTIVE"
                or user["userType"] != "EMPLOYEE"
                or not any(
                    r["serviceKey"] == "lab-staff" and r["name"] == "user" for r in user["roles"]
                )
            ):
                raise RuntimeError("Employee account or roles missing")
            print("PASS: accepting creates ACTIVE EMPLOYEE with assigned roles; replay denied")
            response = await employee.get(
                "/oauth2/authorize",
                params={
                    "client_id": "lab-staff",
                    "redirect_uri": "https://localhost:4446/callback",
                    "response_type": "code",
                    "scope": "openid email profile",
                    "state": "invitation-check",
                    "code_challenge_method": "S256",
                    "code_challenge": "67fSJzo57q68fn68Pk-Mni3vwtTVPnuCzXzT4SCa2uQ",
                    "prompt": "login",
                },
            )
            require(response, 303)
            page = await employee.get(response.headers["location"])
            require(page, 200)
            result = await employee.post(
                "/oauth2/login",
                headers={"origin": ORIGIN},
                data={
                    "transaction": field(page.text, "transaction"),
                    "csrf_token": field(page.text, "csrf_token"),
                    "email": email,
                    "password": password,
                },
            )
            require(result, 303)
            if "code" not in parse_qs(urlsplit(result.headers["location"]).query):
                raise RuntimeError("Invited employee could not authenticate")
            print("PASS: employee logs into staff OIDC with self-selected password")
            cancelled_email = "cancel-" + email
            result = await admin.post(
                ROOT + "/api/invitations", headers=headers, json=body | {"email": cancelled_email}
            )
            require(result, 201)
            cancelled_id = result.json()["id"]
            identifiers.append(cancelled_id)
            token = await captured_token(mailbox, cancelled_email)
            require(
                await admin.post(
                    ROOT + "/api/invitations/" + cancelled_id + "/cancel", headers=headers, json={}
                ),
                204,
            )
            await accept(employee, token, 400, password)
            print("PASS: cancelled invitation cannot create an employee account")
            logs = await admin.get(
                ROOT + "/api/audit-logs",
                params={"reasonCode": "EMPLOYEE_INVITATION", "pageSize": 100},
            )
            require(logs, 200)
            events = {
                x["eventType"]
                for x in logs.json()["items"]
                if (x.get("detailsJson") or {}).get("invitationId") in identifiers
            }
            if not {
                "employee_invitation_created",
                "employee_invitation_resent",
                "employee_invitation_cancelled",
                "employee_invitation_accepted",
            }.issubset(events):
                raise RuntimeError("Missing lifecycle audit")
            print("PASS: created, resent, cancelled and accepted actions have audit records")
            print("Synthetic employee retained:", email)
        finally:
            await cleanup(employee)
            await cleanup(admin)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        print("Invitation check failed:", type(error).__name__)
        raise SystemExit(1) from None
