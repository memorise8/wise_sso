from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ADAPTER_PATH = Path(__file__).resolve().parents[1] / "adapters" / "fastapi_fixture.py"
SPEC = importlib.util.spec_from_file_location("fastapi_fixture_adapter", ADAPTER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load FastAPI fixture adapter from {ADAPTER_PATH}")
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def environment(**overrides: str) -> dict[str, str]:
    values = {
        "CONTRACT_FASTAPI_RUNTIME": "1",
        "CONTRACT_FIXTURE_MODE": "1",
        "CONTRACT_SERVER_MAIL_MODE": "dev",
        "CONTRACT_REDIS_ISOLATED_DB": "1",
        "CONTRACT_REFRESH_SECRET": "isolated-refresh-secret-2026",
        "CONTRACT_BASE_URL": "http://127.0.0.1:4500",
        "CONTRACT_DATABASE_URL": (
            "postgresql://fixture:synthetic@127.0.0.1:5432/auth_fastapi_contract_test"
        ),
        "CONTRACT_REDIS_URL": "redis://:synthetic@127.0.0.1:6379/10",
        "CONTRACT_FIXTURE_EMAIL_DOMAIN": "example.invalid",
    }
    values.update(overrides)
    return values


class FastApiPreflightTests(unittest.TestCase):
    def test_requires_explicit_fastapi_runtime_acknowledgement(self) -> None:
        values = environment()
        values.pop("CONTRACT_FASTAPI_RUNTIME")
        with (
            mock.patch.dict(os.environ, values, clear=True),
            self.assertRaisesRegex(adapter.AdapterError, "FASTAPI_RUNTIME"),
        ):
            adapter.load_config()

    def test_inherits_loopback_database_and_redis_guards(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                environment(CONTRACT_BASE_URL="https://candidate.example.invalid"),
                clear=True,
            ),
            self.assertRaisesRegex(adapter.AdapterError, "loopback"),
        ):
            adapter.load_config()
        with (
            mock.patch.dict(
                os.environ,
                environment(CONTRACT_REDIS_URL="redis://127.0.0.1:6379/0"),
                clear=True,
            ),
            self.assertRaisesRegex(adapter.AdapterError, "database 0"),
        ):
            adapter.load_config()

    def test_preflight_requires_prisma_compatible_schema(self) -> None:
        with mock.patch.dict(os.environ, environment(), clear=True):
            config = adapter.load_config()
        with (
            mock.patch.object(
                adapter._shared,
                "preflight",
                return_value={
                    "status": "ok",
                    "database": "auth_fastapi_contract_test",
                    "redisDatabase": 10,
                    "mailMode": "dev",
                },
            ),
            mock.patch.object(adapter, "psql", return_value="prisma-compatible") as psql,
        ):
            result = adapter.preflight(config)
        self.assertEqual(result["runtime"], "fastapi")
        self.assertEqual(result["schema"], "prisma-compatible")
        self.assertIn("to_regclass", psql.call_args.args[1])

        with (
            mock.patch.object(adapter._shared, "preflight", return_value={"status": "ok"}),
            mock.patch.object(adapter, "psql", return_value="missing"),
            self.assertRaisesRegex(adapter.AdapterError, "Prisma-compatible"),
        ):
            adapter.preflight(config)


class FastApiProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, environment(), clear=True)
        self.addCleanup(patcher.stop)
        patcher.start()
        self.config = adapter.load_config()

    def test_setup_uses_runtime_neutral_fixture_shape(self) -> None:
        with (
            mock.patch.object(adapter._shared, "reset"),
            mock.patch.object(adapter._shared, "seed"),
            mock.patch.object(adapter._shared, "seed_refresh_token"),
        ):
            fixture = adapter.setup(self.config, "active-user-refresh-hs256")
        self.assertEqual(fixture["userId"], adapter.ACTIVE_USER_ID)
        self.assertEqual(fixture["algorithm"], "HS256")
        self.assertNotIn(self.config.refresh_secret, json.dumps(fixture))

    def test_main_emits_exactly_one_json_value(self) -> None:
        with (
            mock.patch.object(adapter, "load_config", return_value=self.config),
            mock.patch.object(
                adapter,
                "preflight",
                return_value={"status": "ok", "runtime": "fastapi"},
            ),
            mock.patch("builtins.print") as printer,
        ):
            self.assertEqual(adapter.main(["preflight", "fastapi"]), 0)
        printer.assert_called_once_with('{"runtime":"fastapi","status":"ok"}')

    def test_main_fails_closed_before_setup_when_preflight_fails(self) -> None:
        with (
            mock.patch.object(adapter, "load_config", return_value=self.config),
            mock.patch.object(
                adapter,
                "preflight",
                side_effect=adapter.AdapterError("schema mismatch"),
            ),
            mock.patch.object(adapter, "setup") as setup,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(adapter.main(["setup", "active-password-user"]), 2)
        setup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
