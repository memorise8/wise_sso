"""관리자 조회 분리와 기존 로그인·변경 요청 제한을 검증합니다."""

from typing import cast
from unittest.mock import AsyncMock

import httpx
import pytest
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.redis import RedisStateStore
from wiseacct_sso.main import create_app
from wiseacct_sso.oidc_runtime import RuntimeOidcRedis


class Counter:
    def __init__(self) -> None:
        self.counts: dict[str | bytes, int] = {}

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        assert ttl_seconds == 60
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]


async def probe(scope: Scope, receive: Receive, send: Send) -> None:
    await JSONResponse({"ok": True})(scope, receive, send)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "method,path,read",
    [
        ("GET", "/oauth2/admin/dashboard", True),
        ("HEAD", "/oauth2/admin/dashboard", True),
        ("GET", "/oauth2/admin/users/example-user", True),
        ("GET", "/oauth2/admin/api/users", True),
        ("HEAD", "/oauth2/admin/api/audit-logs", True),
        ("GET", "/oauth2/admin/api/clients/example/members", True),
        ("GET", "/oauth2/admin/login", False),
        ("POST", "/oauth2/admin/login", False),
        ("POST", "/oauth2/admin/api/users/example/roles", False),
        ("PATCH", "/oauth2/admin/api/users/example/status", False),
        ("DELETE", "/oauth2/admin/api/users/example/roles/role", False),
        ("OPTIONS", "/oauth2/admin/api/users", False),
        ("POST", "/oauth2/token", False),
        ("GET", "/oauth2/authorize", False),
        ("GET", "/oauth2/login", False),
        ("GET", "/oauth2/userinfo", False),
        ("GET", "/oauth2/admin/dashboard-extra", False),
        ("GET", "/oauth2/admin/api-extra/users", False),
    ],
)
async def test_only_admin_reads_use_separate_budget(
    synthetic_settings: Settings, method: str, path: str, read: bool
) -> None:
    sensitive = AsyncMock(return_value=False)
    reading = AsyncMock(return_value=True)
    app = create_app(
        settings=synthetic_settings.model_copy(update={"oidc_enabled": True}),
        oidc_app=probe,
        oidc_rate_check=sensitive,
        oidc_admin_read_rate_check=reading,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://auth.example.test",
    ) as client:
        response = await client.request(method, path)
    assert response.status_code == (200 if read else 429)
    if read:
        reading.assert_awaited_once_with(path, "127.0.0.1")
        sensitive.assert_not_awaited()
    else:
        sensitive.assert_awaited_once_with(path, "127.0.0.1")
        reading.assert_not_awaited()


@pytest.mark.anyio
async def test_read_budget_is_bounded_and_does_not_consume_login_budget() -> None:
    counter = Counter()
    runtime = RuntimeOidcRedis(lambda: cast(RedisStateStore, counter))
    for index in range(300):
        assert await runtime.admin_read_rate_check(
            f"/oauth2/admin/api/users/user-{index}", "192.0.2.10"
        )
    assert not await runtime.admin_read_rate_check("/oauth2/admin/dashboard", "192.0.2.10")
    for _ in range(60):
        assert await runtime.rate_check("/oauth2/login", "192.0.2.10")
    assert not await runtime.rate_check("/oauth2/login", "192.0.2.10")
    assert len(counter.counts) == 2


@pytest.mark.anyio
async def test_mutations_keep_original_shared_limit() -> None:
    counter = Counter()
    runtime = RuntimeOidcRedis(lambda: cast(RedisStateStore, counter))
    for index in range(60):
        assert await runtime.rate_check(f"/oauth2/admin/api/users/user-{index}/roles", "192.0.2.10")
    assert not await runtime.rate_check("/oauth2/admin/api/users/another/status", "192.0.2.10")
    assert len(counter.counts) == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "path,html",
    [
        ("/oauth2/admin/dashboard", True),
        ("/oauth2/admin/users/example", True),
        ("/oauth2/admin/login", True),
        ("/oauth2/admin/api/users", False),
        ("/oauth2/token", False),
    ],
)
async def test_rate_response_keeps_retry_header_and_api_json(
    synthetic_settings: Settings, path: str, html: bool
) -> None:
    denied = AsyncMock(return_value=False)
    app = create_app(
        settings=synthetic_settings.model_copy(update={"oidc_enabled": True}),
        oidc_app=probe,
        oidc_rate_check=denied,
        oidc_admin_read_rate_check=denied,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://auth.example.test",
    ) as client:
        response = await client.get(path, headers={"accept": "text/html"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"
    assert response.headers["cache-control"] == "no-store"
    if html:
        assert "text/html" in response.headers["content-type"]
        assert "60초" in response.text
    else:
        assert response.json() == {"error": "slow_down"}


@pytest.mark.anyio
async def test_read_rate_store_failure_still_fails_closed(
    synthetic_settings: Settings,
) -> None:
    app = create_app(
        settings=synthetic_settings.model_copy(update={"oidc_enabled": True}),
        oidc_app=probe,
        oidc_rate_check=AsyncMock(return_value=True),
        oidc_admin_read_rate_check=AsyncMock(side_effect=RuntimeError("비공개 오류")),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://auth.example.test",
    ) as client:
        response = await client.get("/oauth2/admin/api/users")
    assert response.status_code == 503
    assert response.json() == {"error": "temporarily_unavailable"}
    assert "비공개 오류" not in response.text
