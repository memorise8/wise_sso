"""Uvicorn factory that binds the A04 transport only in an explicit test process."""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from pathlib import Path
from typing import cast

import httpx
from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT_PATH = ROOT / "contracts" / "bin" / "provider_transport.py"
SPEC = importlib.util.spec_from_file_location(
    "contract_provider_transport_bootstrap", TRANSPORT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("test-only provider transport could not be loaded")
transport_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport_module
SPEC.loader.exec_module(transport_module)

from wiseacct_sso import main as runtime_main
from wiseacct_sso.infrastructure.oauth_providers import OAuthProviderClient


class _OwnedTestOAuthProviderClient(OAuthProviderClient):
    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self._test_http_client = httpx.AsyncClient(transport=transport)
        super().__init__(self._test_http_client)

    async def close(self) -> None:
        await self._test_http_client.aclose()


def create_test_app() -> FastAPI:
    """Create the ordinary runtime app with only its OAuth HTTP client replaced."""

    config_path = os.environ.get("WISEACCT_TEST_PROVIDER_CONFIG")
    if not config_path:
        raise RuntimeError("WISEACCT_TEST_PROVIDER_CONFIG is required")
    scenarios = transport_module.load_scenarios(Path(config_path))

    def new_test_oauth_client() -> OAuthProviderClient:
        transport = transport_module.TestOnlyProviderTransport(scenarios)
        return _OwnedTestOAuthProviderClient(transport)

    original_oauth_factory = runtime_main._new_oauth_client
    application = runtime_main.create_runtime_app()
    original_lifespan = cast(
        Callable[[FastAPI], AbstractAsyncContextManager[None]],
        application.router.lifespan_context,
    )

    @asynccontextmanager
    async def test_lifespan(app: FastAPI) -> AsyncIterator[None]:
        if runtime_main._new_oauth_client is not original_oauth_factory:
            raise RuntimeError(
                "OAuth client factory changed before test lifespan startup"
            )
        runtime_main._new_oauth_client = new_test_oauth_client
        try:
            async with original_lifespan(app) as state:
                if runtime_main._new_oauth_client is new_test_oauth_client:
                    runtime_main._new_oauth_client = original_oauth_factory
                yield state
        finally:
            if runtime_main._new_oauth_client is new_test_oauth_client:
                runtime_main._new_oauth_client = original_oauth_factory

    application.router.lifespan_context = test_lifespan
    return application
