from __future__ import annotations

import importlib.util
import json
import os
import shutil
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

RECORD_PATH = ROOT / "contracts" / "bin" / "private_provider_record.py"
RECORD_SPEC = importlib.util.spec_from_file_location(
    "contract_private_provider_record", RECORD_PATH
)
assert RECORD_SPEC and RECORD_SPEC.loader
record_module = importlib.util.module_from_spec(RECORD_SPEC)
sys.modules[RECORD_SPEC.name] = record_module
RECORD_SPEC.loader.exec_module(record_module)

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


class PrivateProviderRecordBridgeTests(unittest.TestCase):
    def _config(self, directory: Path) -> Path:
        path = directory / "scenario.json"
        path.write_text(
            json.dumps(
                {
                    "scenarios": [
                        {
                            "provider": "google",
                            "issuer": transport_module.ENDPOINTS["google"].issuer,
                            "code": "google-code",
                            "accessToken": "google-access",
                            "profile": {"sub": "google-subject"},
                            "clientId": "google-client",
                            "clientSecret": "google-secret",
                            "redirectUri": "http://127.0.0.1:4000/auth/google/callback",
                            "tokenOutcome": "success",
                            "userOutcome": "success",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def test_actual_node_child_emits_only_bound_secret_free_invocation_records(
        self,
    ) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node, "the installed Node executable is required")
        assert node is not None
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config_path = self._config(directory)
            entry = (
                ROOT / "contracts" / "adapters" / "provider_transport_preload_entry.mjs"
            )
            with record_module.PrivateProviderRecordChannel(
                run_id="a05-node-run", runtime="express"
            ) as channel:
                binding = channel.child_binding()
                environment = {
                    "WISEACCT_TEST_PROVIDER_CONFIG": str(config_path),
                    **binding.environment,
                }
                script = f"""
                    const token = await fetch({json.dumps(transport_module.ENDPOINTS["google"].token)}, {{
                      method: 'POST', headers: {{'content-type':'application/x-www-form-urlencoded'}},
                      body: new URLSearchParams({{
                        grant_type:'authorization_code', client_id:'google-client',
                        client_secret:'google-secret', redirect_uri:'http://127.0.0.1:4000/auth/google/callback',
                        code:'google-code'
                      }})
                    }});
                    const access = (await token.json()).access_token;
                    await fetch({json.dumps(transport_module.ENDPOINTS["google"].user_info)}, {{
                      headers: {{authorization: `Bearer ${{access}}`}}
                    }});
                """
                process = subprocess.Popen(
                    [
                        node,
                        "--import",
                        entry.as_uri(),
                        "--input-type=module",
                        "--eval",
                        script,
                    ],
                    cwd=ROOT,
                    env=environment,
                    pass_fds=(binding.fd,),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                channel.handoff()
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                snapshot = channel.consume()
        self.assertEqual(
            snapshot["source"], "launcher-owned-private-provider-record-pipe-v1"
        )
        self.assertTrue(snapshot["consumed"])
        self.assertEqual(
            snapshot["records"],
            [
                {
                    "schemaVersion": 1,
                    "runId": "a05-node-run",
                    "runtime": "express",
                    "source": "provider-transport",
                    "provider": "google",
                    "operation": "token",
                    "sequence": 1,
                },
                {
                    "schemaVersion": 1,
                    "runId": "a05-node-run",
                    "runtime": "express",
                    "source": "provider-transport",
                    "provider": "google",
                    "operation": "user-info",
                    "sequence": 2,
                },
            ],
        )
        serialized = json.dumps(snapshot)
        for secret in (
            "google-code",
            "google-access",
            "google-secret",
            "google-subject",
        ):
            self.assertNotIn(secret, serialized)

    def test_actual_python_child_emits_fastapi_bound_records(self) -> None:
        python = ROOT / "fastapi-auth-server" / ".venv" / "bin" / "python"
        self.assertTrue(python.is_file() and os.access(python, os.X_OK))
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            config_path = self._config(directory)
            with record_module.PrivateProviderRecordChannel(
                run_id="a05-fastapi-run", runtime="fastapi"
            ) as channel:
                binding = channel.child_binding()
                environment = {
                    "PYTHONPATH": str(FASTAPI_SRC),
                    **binding.environment,
                }
                script = f"""
import asyncio, importlib.util, pathlib, sys
import httpx
spec = importlib.util.spec_from_file_location('child_provider_transport', {str(TRANSPORT_PATH)!r})
module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
from wiseacct_sso.infrastructure.oauth_providers import OAuthProviderClient, OAuthProviderConfig
async def main():
    scenarios = module.load_scenarios(pathlib.Path({str(config_path)!r}))
    writer = module.PrivateProviderRecordWriter.from_environment()
    transport = module.TestOnlyProviderTransport(scenarios, recorder=writer)
    async with httpx.AsyncClient(transport=transport) as http_client:
        client = OAuthProviderClient(http_client)
        await client.fetch_profile('google', OAuthProviderConfig(
            'https://accounts.google.com/authorize', module.ENDPOINTS['google'].token,
            module.ENDPOINTS['google'].user_info, 'google-client', 'google-secret',
            'http://127.0.0.1:4000/auth/google/callback', 'contract'), 'google-code')
asyncio.run(main())
"""
                process = subprocess.Popen(
                    [str(python), "-c", script],
                    cwd=ROOT,
                    env=environment,
                    pass_fds=(binding.fd,),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                channel.handoff()
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                snapshot = channel.consume()
        records = snapshot["records"]
        self.assertEqual(
            [record["operation"] for record in records], ["token", "user-info"]
        )
        self.assertTrue(all(record["runId"] == "a05-fastapi-run" for record in records))
        self.assertTrue(all(record["runtime"] == "fastapi" for record in records))

    def test_consumer_rejects_cross_binding_oversize_and_replay(self) -> None:
        def encoded(run_id: str, runtime: str, *, extra: str = "") -> bytes:
            record = {
                "schemaVersion": 1,
                "runId": run_id,
                "runtime": runtime,
                "source": "provider-transport",
                "provider": "google",
                "operation": "token",
                "sequence": 1,
            }
            if extra:
                record["extra"] = extra
            return json.dumps(record, separators=(",", ":")).encode() + b"\n"

        for run_id, runtime in (("wrong-run", "express"), ("expected-run", "fastapi")):
            with (
                self.subTest(run_id=run_id, runtime=runtime),
                record_module.PrivateProviderRecordChannel(
                    run_id="expected-run", runtime="express"
                ) as channel,
            ):
                binding = channel.child_binding()
                os.write(binding.fd, encoded(run_id, runtime))
                channel.handoff()
                with self.assertRaisesRegex(
                    record_module.PrivateProviderRecordError,
                    "binding does not match",
                ):
                    channel.consume()

        with record_module.PrivateProviderRecordChannel(
            run_id="oversize-run", runtime="express"
        ) as channel:
            binding = channel.child_binding()
            os.write(binding.fd, b"{" + b"x" * 600 + b"}\n")
            channel.handoff()
            with self.assertRaisesRegex(
                record_module.PrivateProviderRecordError, "record is too large"
            ):
                channel.consume()

        with record_module.PrivateProviderRecordChannel(
            run_id="replay-run", runtime="express"
        ) as channel:
            binding = channel.child_binding()
            os.write(binding.fd, encoded("replay-run", "express"))
            channel.handoff()
            channel.consume()
            with self.assertRaisesRegex(
                record_module.PrivateProviderRecordError, "already consumed"
            ):
                channel.consume()

    def test_descriptor_replacement_is_rejected_without_closing_reused_fd(self) -> None:
        channel = record_module.PrivateProviderRecordChannel(
            run_id="replace-run", runtime="express"
        )
        binding = channel.child_binding()
        os.close(binding.fd)
        replacement = os.open(os.devnull, os.O_WRONLY)
        try:
            if replacement != binding.fd:
                os.dup2(replacement, binding.fd)
                os.close(replacement)
                replacement = binding.fd
            with self.assertRaisesRegex(
                record_module.PrivateProviderRecordError, "identity changed"
            ):
                channel.child_binding()
            channel.close()
            os.fstat(replacement)
        finally:
            os.close(replacement)

    def test_node_writer_rejects_read_end_and_blocking_write_end_before_emit(
        self,
    ) -> None:
        node = shutil.which("node")
        assert node is not None
        library = ROOT / "contracts" / "adapters" / "provider_transport_preload.mjs"

        def rejected(descriptor: int, expected: str) -> None:
            environment = {
                "WISEACCT_TEST_PROVIDER_RECORD_FD": str(descriptor),
                "WISEACCT_TEST_PROVIDER_RUN_ID": "hostile-fd-run",
                "WISEACCT_TEST_PROVIDER_RUNTIME": "express",
            }
            result = subprocess.run(
                [
                    node,
                    "--input-type=module",
                    "--eval",
                    (
                        f"const module = await import({json.dumps(library.as_uri())});"
                        "module.createProviderRecordWriterFromEnvironment();"
                    ),
                ],
                env=environment,
                pass_fds=(descriptor,),
                text=True,
                capture_output=True,
                timeout=3,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

        read_fd, nonblocking_write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            rejected(read_fd, "nonblocking write pipe")
        finally:
            os.close(read_fd)
            os.close(nonblocking_write_fd)

        blocking_read_fd, blocking_write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            rejected(blocking_write_fd, "nonblocking write pipe")
        finally:
            os.close(blocking_read_fd)
            os.close(blocking_write_fd)

    def test_unhashable_record_values_fail_closed_and_pipe_init_failure_closes_fds(
        self,
    ) -> None:
        for field, value in (("provider", []), ("operation", {})):
            with (
                self.subTest(field=field),
                record_module.PrivateProviderRecordChannel(
                    run_id="typed-record-run", runtime="express"
                ) as channel,
            ):
                binding = channel.child_binding()
                record = {
                    "schemaVersion": 1,
                    "runId": "typed-record-run",
                    "runtime": "express",
                    "source": "provider-transport",
                    "provider": "google",
                    "operation": "token",
                    "sequence": 1,
                }
                record[field] = value
                os.write(
                    binding.fd,
                    json.dumps(record, separators=(",", ":")).encode() + b"\n",
                )
                channel.handoff()
                with self.assertRaisesRegex(
                    record_module.PrivateProviderRecordError,
                    "binding does not match",
                ):
                    channel.consume()

        created: list[int] = []
        real_pipe2 = os.pipe2
        real_identity = record_module._identity
        identity_calls = 0

        def capture_pipe(flags: int) -> tuple[int, int]:
            descriptors = real_pipe2(flags)
            created.extend(descriptors)
            return descriptors

        def fail_second_identity(descriptor: int) -> object:
            nonlocal identity_calls
            identity_calls += 1
            if identity_calls == 2:
                raise RuntimeError("synthetic second identity failure")
            return real_identity(descriptor)

        with (
            patch.object(record_module.os, "pipe2", side_effect=capture_pipe),
            patch.object(record_module, "_identity", side_effect=fail_second_identity),
            self.assertRaisesRegex(RuntimeError, "second identity failure"),
        ):
            record_module.PrivateProviderRecordChannel(
                run_id="pipe-init-run", runtime="express"
            )
        self.assertEqual(len(created), 2)
        for descriptor in created:
            with self.assertRaises(OSError):
                os.fstat(descriptor)


if __name__ == "__main__":
    unittest.main()
