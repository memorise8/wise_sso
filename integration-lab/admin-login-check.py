"""Live local admin-browser login checks. No token copy/paste or credential output."""

import asyncio
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

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


async def main():
    parsed = urlsplit(os.environ["DATABASE_URL"])
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != ORIGIN
    ):
        raise SystemExit("Refusing non-lab configuration")
    fixtures = {
        row["name"]: row
        for row in json.loads(
            Path("/run/lab-fixtures.json").read_text()  # noqa: ASYNC240 - tiny local fixture
        )
    }
    async with httpx.AsyncClient(
        base_url=ORIGIN, transport=Loopback(), timeout=20, follow_redirects=False
    ) as client:
        try:
            require(await client.get(ROOT + "/api/users"), 401)
            response = await client.get("/manage/dashboard")
            require(response, 303)
            if response.headers.get("location") != ORIGIN + ROOT + "/dashboard":
                raise RuntimeError("Expected fixed HTTPS administrator entry")
            print("PASS: administrator entry uses HTTPS and API requires login")
            response = await login(client, fixtures["employee"])
            require(response, 303)
            if "HttpOnly" not in ";".join(response.headers.get_list("set-cookie")):
                raise RuntimeError("Expected HttpOnly central session cookie")
            print("PASS: employee administrator logs in without copying a token")
            response = await client.get(ROOT + "/dashboard")
            require(response, 200)
            if (
                "Bearer token" in response.text
                or "관리자 Access Token" in response.text
            ):
                raise RuntimeError("Manual bearer-token panel is still present")
            csrf = field(response.text, "admin-session-csrf")
            response = await client.get(
                ROOT + "/api/users", params={"email": fixtures["employee"]["email"]}
            )
            require(response, 200)
            if not any(
                row["email"] == fixtures["employee"]["email"]
                for row in response.json()["items"]
            ):
                raise RuntimeError("Expected administrator user list")
            print("PASS: dashboard and user list use cookie authentication")
            response = await client.get(
                ROOT + "/api/users", params={"email": fixtures["unapproved"]["email"]}
            )
            require(response, 200)
            row = next(
                item
                for item in response.json()["items"]
                if item["email"] == fixtures["unapproved"]["email"]
            )
            body = {"userIds": [row["id"]], "userType": row["userType"], "reasonCode": "ADMIN_BULK_USER_TYPE_CHANGE"}
            require(
                await client.patch(
                    ROOT + "/api/users/type", headers={"origin": ORIGIN}, json=body
                ),
                403,
            )
            response = await client.patch(
                ROOT + "/api/users/type",
                headers={"origin": ORIGIN, "x-admin-csrf": csrf},
                json=body,
            )
            require(response, 200)
            if response.json().get("changedCount") != 0:
                raise RuntimeError("Expected no-op; no fixture type should change")
            print("PASS: mutations require Origin and CSRF; valid no-op succeeds")
            response = await client.get(ROOT + "/login")
            require(response, 303)
            if response.headers.get("location") != ROOT + "/dashboard":
                raise RuntimeError("Expected recent SSO reuse")
            print("PASS: recent central login is reused for administrator entry")
            response = await client.post(
                ROOT + "/logout", headers={"origin": ORIGIN}, data={"csrf_token": csrf}
            )
            require(response, 303)
            require(await client.get(ROOT + "/api/users"), 401)
            print("PASS: central logout prevents further administrator API use")
            for name in ("customer", "unapproved"):
                require(await login(client, fixtures[name]), 403)
            print("PASS: customer and non-admin employee cannot enter administrator UI")
        finally:
            await cleanup(client)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as error:
        print("Admin login check failed:", type(error).__name__)
        raise SystemExit(1) from None
