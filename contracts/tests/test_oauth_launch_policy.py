from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "contracts" / "bin" / "oauth_launch_policy.py"
SPEC = importlib.util.spec_from_file_location(
    "contract_oauth_launch_policy", MODULE_PATH
)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


class OAuthLaunchPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        private_root = Path(self.directory.name)
        adapters = private_root / "contracts" / "adapters"
        express_cwd = private_root / "auth-server"
        fastapi_cwd = private_root / "fastapi-auth-server"
        fastapi_src = fastapi_cwd / "src"
        for directory in (adapters, express_cwd / "dist" / "src", fastapi_src):
            directory.mkdir(parents=True)
        paths: dict[str, Any] = {
            "ADAPTERS": adapters,
            "PRELOAD_ENTRY": adapters / "provider_transport_preload_entry.mjs",
            "FASTAPI_BOOTSTRAP": adapters / "provider_transport_fastapi_bootstrap.py",
            "EXPRESS_LOOPBACK": private_root / "runtime_express_loopback.mjs",
            "EXPRESS_SERVER": express_cwd / "dist" / "src" / "server.js",
            "EXPRESS_CWD": express_cwd,
            "FASTAPI_CWD": fastapi_cwd,
            "FASTAPI_SRC": fastapi_src,
            "UVICORN": fastapi_cwd / ".venv" / "bin" / "uvicorn",
            "GOOGLE_FIXTURE": adapters / "google_oauth_fixture.py",
        }
        for name in (
            "PRELOAD_ENTRY",
            "FASTAPI_BOOTSTRAP",
            "EXPRESS_LOOPBACK",
            "EXPRESS_SERVER",
            "GOOGLE_FIXTURE",
        ):
            paths[name].write_text("test-only\n", encoding="utf-8")
        paths["UVICORN"].parent.mkdir(parents=True)
        paths["UVICORN"].write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        paths["UVICORN"].chmod(0o755)
        self.node = private_root / "node"
        self.node.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        self.node.chmod(0o755)
        self.constant_patch = mock.patch.multiple(policy, **paths)
        self.constant_patch.start()
        self.which_patch = mock.patch.object(
            policy.shutil, "which", return_value=str(self.node)
        )
        self.which_patch.start()
        self.provider_config = private_root / "provider.json"
        self.config = self._config()
        self._write_provider_config(4400)

    def tearDown(self) -> None:
        self.which_patch.stop()
        self.constant_patch.stop()
        self.directory.cleanup()

    def _write_provider_config(self, producer_port: int) -> None:
        self.provider_config.write_text(
            json.dumps(
                {
                    "scenarios": [
                        {
                            "provider": "google",
                            "issuer": "https://accounts.google.com",
                            "code": "synthetic-google-code",
                            "accessToken": "synthetic-google-access",
                            "profile": {
                                "sub": "synthetic-google-subject",
                                "email": "google@example.invalid",
                                "email_verified": True,
                            },
                            "clientId": "synthetic-google-client",
                            "clientSecret": "synthetic-google-secret",
                            "redirectUri": f"http://127.0.0.1:{producer_port}/auth/google/callback",
                            "tokenOutcome": "success",
                            "userOutcome": "success",
                        }
                    ]
                },
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self.provider_config.chmod(0o600)

    def _environment(self, port: int, database_url: str) -> dict[str, str]:
        return {
            "NODE_ENV": "test",
            "PORT": str(port),
            "DATABASE_URL": database_url,
            "REDIS_URL": "redis://:synthetic@127.0.0.1:6380/11",
            "JWT_ISSUER": "https://auth.example.invalid",
            "JWT_AUDIENCE": "contract-fixture",
            "JWT_REFRESH_SECRET": "private-contract-refresh-secret",
            "OAUTH_ENABLED_PROVIDERS": "google",
            "GOOGLE_CLIENT_ID": "synthetic-google-client",
            "GOOGLE_CLIENT_SECRET": "synthetic-google-secret",
            "GOOGLE_REDIRECT_URI": "http://127.0.0.1:4400/auth/google/callback",
            "WISEACCT_TEST_PROVIDER_CONFIG": str(self.provider_config),
        }

    def _config(self) -> dict[str, Any]:
        express_env = self._environment(
            4400,
            "postgresql://fixture:synthetic@127.0.0.1:5433/oauth_contract_test",
        )
        express_env["WISEACCT_PHASE7_EXPRESS_LOOPBACK"] = "1"
        fastapi_env = self._environment(
            4401,
            "postgresql+asyncpg://fixture:synthetic@127.0.0.1:5433/oauth_contract_test",
        )
        fastapi_env["PYTHONPATH"] = str(policy.FASTAPI_SRC)
        return {
            "version": 1,
            "runId": "oauth-policy-test-001",
            "producerRole": "express",
            "consumerRole": "fastapi",
            "expectedIssuer": "https://auth.example.invalid",
            "producer": {
                "command": [
                    str(self.node),
                    "--import",
                    str(policy.PRELOAD_ENTRY),
                    str(policy.EXPRESS_LOOPBACK),
                    str(policy.EXPRESS_SERVER),
                ],
                "cwd": str(policy.EXPRESS_CWD),
                "healthUrl": "http://127.0.0.1:4400/healthz",
                "environment": express_env,
            },
            "consumer": {
                "command": [
                    str(policy.UVICORN),
                    "provider_transport_fastapi_bootstrap:create_test_app",
                    "--factory",
                    "--app-dir",
                    str(policy.ADAPTERS),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "4401",
                    "--no-proxy-headers",
                    "--no-server-header",
                    "--no-access-log",
                ],
                "cwd": str(policy.FASTAPI_CWD),
                "healthUrl": "http://127.0.0.1:4401/healthz",
                "environment": fastapi_env,
            },
            "fixtureAdapter": str(policy.GOOGLE_FIXTURE),
            "fixtureEnvironment": {
                "CONTRACT_FIXTURE_MODE": "1",
                "CONTRACT_FASTAPI_RUNTIME": "1",
                "CONTRACT_REDIS_ISOLATED_DB": "1",
                "CONTRACT_BASE_URL": "http://127.0.0.1:4400",
                "CONTRACT_DATABASE_URL": "postgresql://fixture:synthetic@127.0.0.1:5433/oauth_contract_test",
                "CONTRACT_REDIS_URL": "redis://:synthetic@127.0.0.1:6380/11",
                "CONTRACT_REFRESH_SECRET": "private-contract-refresh-secret",
                "CONTRACT_FIXTURE_AUDIENCE": "contract-fixture",
            },
        }

    def assert_refused(self, config: dict[str, Any], message: str) -> None:
        with self.assertRaisesRegex(ValueError, message):
            policy.validate_launch_config(config)

    def test_accepts_exact_repository_owned_offline_bootstraps(self) -> None:
        policy.validate_launch_config(self.config)

    def test_accepts_reverse_direction_when_callback_follows_producer(self) -> None:
        config = deepcopy(self.config)
        config["producerRole"] = "fastapi"
        config["consumerRole"] = "express"
        config["producer"], config["consumer"] = config["consumer"], config["producer"]
        self._write_provider_config(4401)
        config["fixtureEnvironment"]["CONTRACT_BASE_URL"] = "http://127.0.0.1:4401"
        for runtime in (config["producer"], config["consumer"]):
            runtime["environment"]["GOOGLE_REDIRECT_URI"] = (
                "http://127.0.0.1:4401/auth/google/callback"
            )
        policy.validate_launch_config(config)

    def test_rejects_direct_express_server_without_preload(self) -> None:
        config = deepcopy(self.config)
        config["producer"]["command"] = [
            config["producer"]["command"][0],
            str(policy.EXPRESS_SERVER),
        ]
        self.assert_refused(config, "recognized bootstrap")

    def test_rejects_ordinary_fastapi_runtime_factory(self) -> None:
        config = deepcopy(self.config)
        config["consumer"]["command"][1] = "wiseacct_sso.main:create_runtime_app"
        self.assert_refused(config, "recognized bootstrap")

    def test_rejects_database_outside_disposable_fixture(self) -> None:
        config = deepcopy(self.config)
        config["producer"]["environment"]["DATABASE_URL"] = (
            "postgresql://auth:secret@db.example.invalid:5432/auth_db"
        )
        self.assert_refused(config, "database binding is invalid")

    def test_rejects_runtime_database_different_from_fixture(self) -> None:
        config = deepcopy(self.config)
        config["consumer"]["environment"]["DATABASE_URL"] = (
            "postgresql+asyncpg://fixture:synthetic@127.0.0.1:5433/other_contract_test"
        )
        self.assert_refused(config, "database binding does not match")

    def test_rejects_redis_database_zero(self) -> None:
        config = deepcopy(self.config)
        config["producer"]["environment"]["REDIS_URL"] = "redis://127.0.0.1:6379/0"
        self.assert_refused(config, "Redis binding is invalid")

    def test_rejects_health_port_different_from_runtime_port(self) -> None:
        config = deepcopy(self.config)
        config["consumer"]["environment"]["PORT"] = "4499"
        self.assert_refused(config, "port binding does not match")

    def test_rejects_node_options_override(self) -> None:
        config = deepcopy(self.config)
        config["producer"]["environment"]["NODE_OPTIONS"] = "--import=/tmp/live.mjs"
        self.assert_refused(config, "blocked override")

    def test_rejects_fixture_interpreter_and_loader_overrides(self) -> None:
        for name in ("PATH", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "NODE_OPTIONS"):
            with self.subTest(name=name):
                config = deepcopy(self.config)
                config["fixtureEnvironment"][name] = "/untrusted/override"
                self.assert_refused(
                    config, "fixture environment contains a blocked override"
                )

    def test_rejects_mixed_fixture_without_full_prisma_schema_guard(self) -> None:
        config = deepcopy(self.config)
        config["fixtureEnvironment"].pop("CONTRACT_FASTAPI_RUNTIME", None)
        self.assert_refused(config, "fixture isolation acknowledgement is missing")

    def test_rejects_non_private_provider_config(self) -> None:
        self.provider_config.chmod(0o644)
        self.assert_refused(self.config, "provider config was refused")

    def test_rejects_provider_callback_not_owned_by_producer(self) -> None:
        config = deepcopy(self.config)
        config["producer"]["environment"]["GOOGLE_REDIRECT_URI"] = (
            "http://127.0.0.1:4499/auth/google/callback"
        )
        self.assert_refused(config, "scenario binding does not match")

    def test_rejects_fastapi_reload_or_worker_options(self) -> None:
        config = deepcopy(self.config)
        config["consumer"]["command"].extend(["--workers", "2"])
        self.assert_refused(config, "recognized bootstrap")


if __name__ == "__main__":
    unittest.main()
