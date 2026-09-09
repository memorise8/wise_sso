from __future__ import annotations

import importlib.util
import io
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest import mock

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "adapters" / "google_oauth_fixture.py"
)
SPEC = importlib.util.spec_from_file_location(
    "contract_google_oauth_fixture", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
adapter: ModuleType = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


class GoogleOAuthFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SimpleNamespace(
            audience="contract-fixture",
            client_id="google-client",
            redirect_uri="http://127.0.0.1:4101/auth/callback",
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "CONTRACT_OAUTH_RUN_ID": "oauth-run-001",
                "CONTRACT_GOOGLE_PROVIDER_SUBJECT": "google-subject-001",
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()

    def test_setup_resets_seeds_and_returns_exact_driver_fields(self) -> None:
        email = "contract-active@example.invalid"
        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "seed") as seed,
            mock.patch.object(
                adapter.shared,
                "emails",
                return_value={adapter.shared.ACTIVE_USER_ID: email},
            ),
        ):
            fixture = adapter.setup(self.config, "google-oauth-user")
        reset.assert_called_once_with(self.config)
        seed.assert_called_once_with(self.config)
        self.assertEqual(
            fixture,
            {
                "userId": adapter.shared.ACTIVE_USER_ID,
                "email": email,
                "name": "Contract Active",
                "roles": [{"serviceKey": "temis", "name": "user"}],
                "audience": "contract-fixture",
                "clientId": "google-client",
                "redirectUri": "http://127.0.0.1:4101/auth/callback",
                "provider": "google",
                "providerSubject": "google-subject-001",
                "runId": "oauth-run-001",
            },
        )
        self.assertNotIn("issuer", fixture)

    def test_preflight_uses_fastapi_guard_and_schema_path_when_selected(self) -> None:
        with (
            mock.patch.dict(os.environ, {"CONTRACT_FASTAPI_RUNTIME": "1"}),
            mock.patch.object(
                adapter.fastapi,
                "preflight",
                return_value={"status": "ok", "schema": "prisma-compatible"},
            ) as preflight,
            mock.patch.object(
                adapter.shared,
                "psql",
                return_value="prisma-google-compatible",
            ),
        ):
            result = adapter.preflight(self.config)
        self.assertEqual(result["schema"], "prisma-compatible")
        self.assertEqual(result["googleIdentitySchema"], "prisma-google-compatible")
        preflight.assert_called_once_with(self.config)

    def test_state_snapshot_projects_database_and_redis_exactly(self) -> None:
        digest = "a" * 64

        def psql(_config: Any, sql: str) -> str:
            if 'FROM "SocialAccount"' in sql:
                return "google|google-subject-001|" + cast(
                    str, adapter.shared.ACTIVE_USER_ID
                )
            if 'FROM "RefreshToken"' in sql:
                return digest
            if 'FROM "User"' in sql:
                return "1"
            raise AssertionError(sql)

        def redis_count(_config: Any, prefix: str) -> int:
            return {"wiseacct:oauth-state:": 0, "wiseacct:auth-handoff:": 0}[prefix]

        with (
            mock.patch.object(adapter.shared, "psql", side_effect=psql),
            mock.patch.object(
                adapter.shared, "redis_key_count", side_effect=redis_count
            ),
        ):
            state = adapter.snapshot(self.config, "oauth-google-state")
        self.assertEqual(
            state,
            {
                "canonicalUsers": 1,
                "providerIdentities": 1,
                "provider": "google",
                "providerSubject": "google-subject-001",
                "linkedUserId": adapter.shared.ACTIVE_USER_ID,
                "oauthStatesRemaining": 0,
                "handoffsRemaining": 0,
                "activeRefreshTokens": 1,
                "activeTokenHashes": [digest],
            },
        )

    def test_preflight_rejects_missing_google_identity_schema(self) -> None:
        with (
            mock.patch.object(
                adapter.shared, "preflight", return_value={"status": "ok"}
            ),
            mock.patch.object(adapter.shared, "psql", return_value="missing"),
            self.assertRaisesRegex(adapter.AdapterError, "Google identity schema"),
        ):
            adapter.preflight(self.config)

    def test_malformed_identity_projection_fails_closed(self) -> None:
        with (
            mock.patch.object(adapter.shared, "psql", return_value="malformed"),
            self.assertRaisesRegex(adapter.AdapterError, "projection was malformed"),
        ):
            adapter.snapshot(self.config, "oauth-google-state")

    def test_provider_invocations_are_never_synthesized_by_base_adapter(self) -> None:
        with self.assertRaisesRegex(adapter.AdapterError, "owned launcher"):
            adapter.snapshot(self.config, "oauth-google-provider-invocations")

    def test_teardown_residual_failure_is_not_reported_clean(self) -> None:
        residual = {
            "oauthStates": 0,
            "handoffs": 0,
            "activeRefreshTokens": 1,
            "activeTokenHashes": ["b" * 64],
            "providerRecords": 0,
        }
        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter, "snapshot", return_value=residual),
            self.assertRaisesRegex(adapter.AdapterError, "residual state"),
        ):
            adapter.teardown(self.config, "google-oauth-user")
        reset.assert_called_once_with(self.config)

    def test_teardown_queries_provider_links_and_rejects_retained_identity(
        self,
    ) -> None:
        for remaining in (0, 1):
            with self.subTest(remaining=remaining):

                def psql(_config: Any, sql: str, count: int = remaining) -> str:
                    if 'FROM "RefreshToken"' in sql:
                        return ""
                    self.assertIn('FROM "SocialAccount"', sql)
                    self.assertIn("COUNT(*)", sql)
                    self.assertIn("\"provider\" = 'google'", sql)
                    self.assertIn("\"providerUserId\" = 'google-subject-001'", sql)
                    return str(count)

                with (
                    mock.patch.object(adapter.shared, "reset"),
                    mock.patch.object(
                        adapter.shared, "psql", side_effect=psql
                    ) as query,
                    mock.patch.object(
                        adapter.shared, "redis_key_count", return_value=0
                    ),
                ):
                    if remaining:
                        with self.assertRaisesRegex(
                            adapter.AdapterError, "residual state"
                        ):
                            adapter.teardown(self.config, "google-oauth-user")
                    else:
                        self.assertEqual(
                            adapter.teardown(self.config, "google-oauth-user"),
                            {"status": "clean"},
                        )
                    self.assertEqual(query.call_count, 2)

    def test_unsafe_binding_rejected_before_database_mutation(self) -> None:
        with (
            mock.patch.dict(os.environ, {"CONTRACT_OAUTH_RUN_ID": ""}),
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "seed") as seed,
            self.assertRaisesRegex(adapter.AdapterError, "safe non-empty"),
        ):
            adapter.setup(self.config, "google-oauth-user")
        reset.assert_not_called()
        seed.assert_not_called()

    def test_cli_checks_preflight_before_every_command(self) -> None:
        for command in ("setup", "snapshot", "teardown"):
            with self.subTest(command=command):
                events: list[str] = []

                def preflight(_config: Any, log: list[str] = events) -> dict[str, str]:
                    log.append("preflight")
                    return {"status": "ok"}

                def operation(
                    _config: Any, _name: str, log: list[str] = events
                ) -> dict[str, str]:
                    log.append("operation")
                    return {"status": "ok"}

                with (
                    mock.patch.object(adapter, "load_config", return_value=self.config),
                    mock.patch.object(adapter, "preflight", side_effect=preflight),
                    mock.patch.object(adapter, command, side_effect=operation),
                    mock.patch("sys.stdout", new=io.StringIO()),
                ):
                    self.assertEqual(adapter.main([command, "google-oauth-user"]), 0)
                self.assertEqual(events, ["preflight", "operation"])

    def test_cli_preflight_failure_never_mutates_or_cleans_database(self) -> None:
        for command in ("setup", "snapshot", "teardown"):
            with (
                self.subTest(command=command),
                mock.patch.object(adapter, "load_config", return_value=self.config),
                mock.patch.object(
                    adapter, "preflight", side_effect=adapter.AdapterError("refused")
                ),
                mock.patch.object(adapter.shared, "reset") as reset,
                mock.patch.object(adapter.shared, "seed") as seed,
                mock.patch("sys.stderr", new=io.StringIO()),
            ):
                self.assertEqual(adapter.main([command, "google-oauth-user"]), 2)
                reset.assert_not_called()
                seed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
