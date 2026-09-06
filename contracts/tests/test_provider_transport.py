from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Literal
from unittest.mock import AsyncMock, Mock, patch

import httpx

ROOT = Path(__file__).resolve().parents[2]
TRANSPORT_PATH = ROOT / "contracts" / "bin" / "provider_transport.py"
FASTAPI_SRC = ROOT / "fastapi-auth-server" / "src"
if str(FASTAPI_SRC) not in sys.path:
    sys.path.insert(0, str(FASTAPI_SRC))

SPEC = importlib.util.spec_from_file_location(
    "contract_provider_transport", TRANSPORT_PATH
)
assert SPEC and SPEC.loader
transport_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transport_module
SPEC.loader.exec_module(transport_module)

from wiseacct_sso.infrastructure.oauth_providers import (  # noqa: I001
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderInfrastructureError,
    OAuthProviderInvalidResponseError,
)
from wiseacct_sso.config import Settings


ProviderName = Literal["google", "naver", "kakao"]


def scenario(
    provider: ProviderName = "google",
    *,
    token_outcome: str = "success",
    user_outcome: str = "success",
    profile: object | None = None,
) -> object:
    endpoints = transport_module.ENDPOINTS[provider]
    default_profiles = {
        "google": {
            "sub": "google-subject",
            "email": "google@example.com",
            "email_verified": True,
        },
        "naver": {"response": {"id": "naver-subject", "email": "naver@example.com"}},
        "kakao": {"id": 42, "kakao_account": {"email": "kakao@example.com"}},
    }
    return transport_module.ProviderScenario(
        provider=provider,
        issuer=endpoints.issuer,
        code=f"{provider}-code",
        access_token=f"{provider}-access",
        profile=default_profiles[provider] if profile is None else profile,
        token_outcome=token_outcome,
        user_outcome=user_outcome,
        client_id=f"{provider}-client",
        client_secret=f"{provider}-secret",
        redirect_uri=f"http://127.0.0.1:4000/auth/{provider}/callback",
    )


def provider_config(provider: ProviderName) -> OAuthProviderConfig:
    endpoints = transport_module.ENDPOINTS[provider]
    return OAuthProviderConfig(
        authorize_endpoint=endpoints.issuer + "/authorize",
        token_endpoint=endpoints.token,
        user_info_endpoint=endpoints.user_info,
        client_id=f"{provider}-client",
        client_secret=f"{provider}-secret",
        redirect_uri=f"http://127.0.0.1:4000/auth/{provider}/callback",
        scope="contract",
    )


class FastApiActualProviderBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_fixed_provider_calls_use_the_actual_fastapi_http_boundary(
        self,
    ) -> None:
        provider_cases: tuple[tuple[ProviderName, str], ...] = (
            ("google", "google-subject"),
            ("naver", "naver-subject"),
            ("kakao", "42"),
        )
        for provider, expected_subject in provider_cases:
            with self.subTest(provider=provider):
                transport = transport_module.TestOnlyProviderTransport(
                    (scenario(provider),)
                )
                async with httpx.AsyncClient(transport=transport) as http_client:
                    client = OAuthProviderClient(http_client)
                    profile = await client.fetch_profile(
                        provider, provider_config(provider), f"{provider}-code"
                    )
                self.assertEqual(profile.provider, provider)
                self.assertEqual(profile.provider_user_id, expected_subject)
                self.assertEqual(
                    [
                        (record.operation, record.method, record.url)
                        for record in transport.records
                    ],
                    [
                        ("token", "POST", transport_module.ENDPOINTS[provider].token),
                        (
                            "user-info",
                            "GET",
                            transport_module.ENDPOINTS[provider].user_info,
                        ),
                    ],
                )

    async def test_external_endpoint_and_wrong_method_fail_without_network_fallback(
        self,
    ) -> None:
        transport = transport_module.TestOnlyProviderTransport((scenario(),))
        async with httpx.AsyncClient(transport=transport) as http_client:
            with self.assertRaisesRegex(
                transport_module.ProviderTransportError, "allowlist"
            ):
                await http_client.get("https://example.com/not-a-provider")
            with self.assertRaisesRegex(
                transport_module.ProviderTransportError, "method"
            ):
                await http_client.get(transport_module.ENDPOINTS["google"].token)
        self.assertEqual(transport.records, [])

    async def test_timeout_redirect_and_invalid_payload_are_rejected_by_actual_client(
        self,
    ) -> None:
        for outcome, error in (
            ("timeout", OAuthProviderInfrastructureError),
            ("redirect", OAuthProviderInfrastructureError),
            ("malformed-json", OAuthProviderInfrastructureError),
            ("invalid-payload", OAuthProviderInvalidResponseError),
        ):
            with self.subTest(outcome=outcome):
                transport = transport_module.TestOnlyProviderTransport(
                    (scenario(user_outcome=outcome),)
                )
                async with httpx.AsyncClient(transport=transport) as http_client:
                    client = OAuthProviderClient(http_client)
                    with self.assertRaises(error):
                        await client.fetch_profile(
                            "google", provider_config("google"), "google-code"
                        )

    async def test_response_and_request_bounds_fail_closed(self) -> None:
        oversized_profile = {"sub": "x" * (transport_module.MAX_RESPONSE_BYTES + 1)}
        transport = transport_module.TestOnlyProviderTransport(
            (scenario(profile=oversized_profile),)
        )
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = OAuthProviderClient(http_client)
            with self.assertRaises(OAuthProviderInfrastructureError):
                await client.fetch_profile(
                    "google", provider_config("google"), "google-code"
                )

        request = httpx.Request(
            "POST",
            transport_module.ENDPOINTS["google"].token,
            headers={"content-type": "application/x-www-form-urlencoded"},
            content=b"x" * (transport_module.MAX_REQUEST_BYTES + 1),
        )
        with self.assertRaisesRegex(
            transport_module.ProviderTransportError, "too large"
        ):
            await transport.handle_async_request(request)

    def test_wrong_issuer_is_rejected_before_transport_creation(self) -> None:
        with self.assertRaisesRegex(ValueError, "issuer does not match"):
            transport_module.ProviderScenario(
                provider="google",
                issuer="https://issuer.invalid",
                code="code",
                access_token="access",
                profile={"sub": "subject"},
                client_id="client",
                client_secret="secret",
                redirect_uri="http://127.0.0.1/callback",
            )

    def test_python_bootstrap_config_is_private_bounded_and_no_follow(self) -> None:
        config = {
            "scenarios": [
                {
                    "provider": "google",
                    "issuer": transport_module.ENDPOINTS["google"].issuer,
                    "code": "google-code",
                    "accessToken": "google-access",
                    "profile": {"sub": "subject"},
                    "clientId": "google-client",
                    "clientSecret": "google-secret",
                    "redirectUri": "http://127.0.0.1:4000/auth/google/callback",
                    "tokenOutcome": "success",
                    "userOutcome": "success",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "scenario.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                transport_module.load_scenarios(path)[0].provider, "google"
            )
            path.chmod(0o640)
            with self.assertRaisesRegex(
                transport_module.ProviderTransportConfigurationError, "owned, private"
            ):
                transport_module.load_scenarios(path)
            path.chmod(0o400)
            with self.assertRaisesRegex(
                transport_module.ProviderTransportConfigurationError, "owned, private"
            ):
                transport_module.load_scenarios(path)
            path.chmod(0o600)
            link = Path(raw_directory) / "scenario-link.json"
            os.symlink(path, link)
            with self.assertRaisesRegex(
                transport_module.ProviderTransportConfigurationError,
                "could not be opened",
            ):
                transport_module.load_scenarios(link)
            with (
                patch.object(transport_module.os, "O_NOFOLLOW", new=None),
                self.assertRaisesRegex(
                    transport_module.ProviderTransportConfigurationError,
                    "requires no-follow",
                ),
            ):
                transport_module.load_scenarios(path)

    async def test_fastapi_factory_lifespan_binds_closes_and_unbinds_owned_client(
        self,
    ) -> None:
        bootstrap_path = (
            ROOT / "contracts" / "adapters" / "provider_transport_fastapi_bootstrap.py"
        )
        bootstrap_spec = importlib.util.spec_from_file_location(
            "contract_provider_transport_fastapi_bootstrap", bootstrap_path
        )
        assert bootstrap_spec and bootstrap_spec.loader
        bootstrap = importlib.util.module_from_spec(bootstrap_spec)
        sys.modules[bootstrap_spec.name] = bootstrap
        bootstrap_spec.loader.exec_module(bootstrap)
        runtime_main = bootstrap.runtime_main
        original_oauth_factory = runtime_main._new_oauth_client
        settings = Settings(  # type: ignore[call-arg]
            _env_file=ROOT / "fastapi-auth-server" / ".env.example"
        )
        database = Mock()
        database.ping = AsyncMock()
        database.close = AsyncMock()
        redis = Mock()
        redis.start = AsyncMock()
        redis.close = AsyncMock()

        config = {
            "scenarios": [
                {
                    "provider": "google",
                    "issuer": transport_module.ENDPOINTS["google"].issuer,
                    "code": "google-code",
                    "accessToken": "google-access",
                    "profile": {"sub": "subject"},
                    "clientId": "google-client",
                    "clientSecret": "google-secret",
                    "redirectUri": "http://127.0.0.1:4000/auth/google/callback",
                    "tokenOutcome": "success",
                    "userOutcome": "success",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as raw_directory:
            path = Path(raw_directory) / "scenario.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            path.chmod(0o600)
            with (
                patch.dict(
                    os.environ,
                    {"WISEACCT_TEST_PROVIDER_CONFIG": str(path)},
                    clear=False,
                ),
                patch.object(runtime_main, "get_settings", return_value=settings),
                patch.object(runtime_main, "_new_database", return_value=database),
                patch.object(runtime_main, "_new_redis_store", return_value=redis),
            ):
                app = bootstrap.create_test_app()
                self.assertIs(runtime_main._new_oauth_client, original_oauth_factory)
                service = None
                owned_client = None
                async with app.router.lifespan_context(app):
                    service = app.state.phase4_services
                    owned_client = service._oauth_client
                    self.assertIsInstance(
                        owned_client, bootstrap._OwnedTestOAuthProviderClient
                    )
                    self.assertIs(
                        runtime_main._new_oauth_client, original_oauth_factory
                    )
                    self.assertFalse(owned_client._test_http_client.is_closed)
                self.assertIsNone(service._oauth_client)
                self.assertTrue(owned_client._test_http_client.is_closed)
                self.assertIsNone(app.state.phase4_services)
                self.assertIs(runtime_main._new_oauth_client, original_oauth_factory)
                database.ping.assert_awaited_once()
                database.close.assert_awaited_once()
                redis.start.assert_awaited_once()
                redis.close.assert_awaited_once()


class ExpressActualProviderBoundaryTests(unittest.TestCase):
    def test_actual_express_ky_boundary_uses_the_fail_closed_preload(self) -> None:
        vitest = ROOT / "auth-server" / "node_modules" / ".bin" / "vitest"
        self.assertTrue(
            vitest.is_file(), "the pinned local Vitest executable is missing"
        )
        self.assertTrue(
            os.access(vitest, os.X_OK), "the pinned local Vitest is not executable"
        )
        command = [
            str(vitest),
            "run",
            "--root",
            "..",
            "--config",
            "contracts/adapters/provider_transport_vitest.config.mjs",
            "contracts/adapters/provider_transport_express.test.ts",
        ]
        child_environment = os.environ.copy()
        for name in (
            "NODE_OPTIONS",
            "NODE_PATH",
            "WISEACCT_TEST_PROVIDER_CONFIG",
        ):
            child_environment.pop(name, None)
        result = subprocess.run(
            command,
            cwd=ROOT / "auth-server",
            env=child_environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
