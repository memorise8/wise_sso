"""Local-only live OIDC session checks; no credentials or authorization codes printed.

This uses the real app/DB/Redis over container loopback. Virtual HTTPS request URLs
exercise Secure cookie handling without disabling TLS verification. Browser/TLS
proxy integration is a separate manual check documented in SSO_STEP2.md.
"""

import asyncio
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import NAMESPACE_URL, uuid5

import httpx
from wiseacct_sso.infrastructure.auth_state import sha256_base64url
from wiseacct_sso.infrastructure.sso_sessions import SSO_COOKIE_NAME

ORIGIN = "https://localhost:4444"


class Loopback(httpx.AsyncBaseTransport):
    def __init__(self):
        self.transport = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request):
        if (
            request.url.scheme != "https"
            or request.url.host != "localhost"
            or request.url.port != 4444
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


def require(response, expected):
    if response.status_code != expected:
        raise RuntimeError(f"Expected HTTP {expected}, received {response.status_code}")


def values(response):
    return parse_qs(urlsplit(response.headers.get("location", "")).query)


async def authorize(client, kind, **extra):
    response = await client.get(
        "/oauth2/authorize",
        params={
            "client_id": "lab-" + kind,
            "redirect_uri": "https://localhost:"
            + ("4445" if kind == "customer" else "4446")
            + "/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "state": secrets.token_urlsafe(24),
            "nonce": secrets.token_urlsafe(24),
            "code_challenge": sha256_base64url("v" * 43),
            "code_challenge_method": "S256",
            **extra,
        },
    )
    if response.status_code not in (302, 303):
        raise RuntimeError(f"Authorize failed: HTTP {response.status_code}")
    return response


async def login(client, fixture):
    start = await authorize(client, "customer", prompt="login")
    if not start.headers.get("location", "").startswith("/oauth2/login?"):
        raise RuntimeError("Expected interactive login")
    page = await client.get(start.headers["location"])
    require(page, 200)
    fields = {
        name: re.search(r'name="' + name + r'" value="([^"]+)"', page.text)
        for name in ("transaction", "csrf_token")
    }
    if any(value is None for value in fields.values()):
        raise RuntimeError("Missing login fields")
    result = await client.post(
        "/oauth2/login",
        headers={"origin": ORIGIN},
        data={
            **{name: match[1] for name, match in fields.items()},
            "email": fixture["email"],
            "password": fixture["password"],
        },
    )
    require(result, 303)
    if "code" not in values(result) or not client.cookies.get(SSO_COOKIE_NAME):
        raise RuntimeError("Expected authorization code and central cookie")


async def logout_central(client):
    page = await client.get("/oauth2/session")
    require(page, 200)
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    if csrf is not None:
        require(
            await client.post(
                "/oauth2/session/logout",
                headers={"origin": ORIGIN},
                data={"csrf_token": csrf[1]},
            ),
            200,
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
        x["name"]: x for x in json.loads(Path("/run/lab-fixtures.json").read_text())
    }
    pair = None
    async with httpx.AsyncClient(
        base_url=ORIGIN, transport=Loopback(), timeout=20, follow_redirects=False
    ) as client:
        try:
            response = await authorize(client, "customer", prompt="none")
            if values(response).get("error") != ["login_required"]:
                raise RuntimeError("Expected login_required before authentication")
            print("PASS: prompt=none without session returns login_required")
            await login(client, fixtures["employee"])
            old = client.cookies[SSO_COOKIE_NAME]
            response = await authorize(client, "staff", prompt="none")
            if "code" not in values(response):
                raise RuntimeError("Employee SSO reuse failed")
            print("PASS: employee reuses central session for staff service")
            response = await authorize(client, "staff", max_age="0")
            if not response.headers["location"].startswith("/oauth2/login?"):
                raise RuntimeError("Expected forced reauthentication")
            print("PASS: max_age=0 forces interactive authentication")
            await logout_central(client)
            if values(await authorize(client, "staff", prompt="none")).get("error") != [
                "login_required"
            ]:
                raise RuntimeError("Central session logout failed")
            print("PASS: CSRF-protected central logout prevents SSO reuse")
            await login(client, fixtures["employee"])
            if client.cookies[SSO_COOKIE_NAME] == old:
                raise RuntimeError("Expected fresh central session identifier")
            response = await client.post(
                "/auth/login",
                json={
                    "email": fixtures["employee"]["email"],
                    "password": fixtures["employee"]["password"],
                },
            )
            require(response, 200)
            pair = response.json()
            await login(client, fixtures["customer"])
            if values(await authorize(client, "staff", prompt="none")).get("error") != [
                "access_denied"
            ]:
                raise RuntimeError("Customer must be denied staff access")
            print("PASS: central CUSTOMER session cannot enter staff service")
            uid = str(uuid5(NAMESPACE_URL, "wise-sso-local-lab:customer"))
            response = await client.post(
                f"/admin/users/{uid}/revoke-sessions",
                headers={"authorization": "Bearer " + pair["accessToken"]},
                json={"reasonCode": "LOCAL_LAB_SSO_REVOKE_CHECK"},
            )
            require(response, 200)
            if values(await authorize(client, "customer", prompt="none")).get(
                "error"
            ) != ["login_required"]:
                raise RuntimeError("Revoked central session was reused")
            print("PASS: admin session revocation invalidates CUSTOMER central session")
        finally:
            await logout_central(client)
            if pair is not None:
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
        print("SSO check failed:", type(error).__name__)
        raise SystemExit(1) from None
