from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parents[1] / "adapters" / "admin_flow_fixture.py"
SPEC = importlib.util.spec_from_file_location(
    "contract_admin_flow_fixture", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
adapter: ModuleType = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


class AdminFlowFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = SimpleNamespace(audience="contract-fixture")

    def test_load_config_requires_fastapi_runtime_before_delegate(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(adapter.fastapi, "load_config") as delegate,
            self.assertRaisesRegex(adapter.AdapterError, "CONTRACT_FASTAPI_RUNTIME=1"),
        ):
            adapter.load_config()
        delegate.assert_not_called()

        with (
            mock.patch.dict(os.environ, {"CONTRACT_FASTAPI_RUNTIME": "1"}, clear=True),
            mock.patch.object(
                adapter.fastapi, "load_config", return_value=self.config
            ) as delegate,
        ):
            self.assertIs(adapter.load_config(), self.config)
        delegate.assert_called_once_with()

    def test_preflight_uses_full_fastapi_schema_path_without_extra_metadata(
        self,
    ) -> None:
        expected = {
            "status": "ok",
            "database": "auth_fastapi_contract_test",
            "redisDatabase": 10,
            "mailMode": "dev",
            "runtime": "fastapi",
            "schema": "prisma-compatible",
        }
        with mock.patch.object(
            adapter.fastapi, "preflight", return_value=expected
        ) as preflight:
            self.assertIs(adapter.preflight(self.config, "admin-flow-users"), expected)
        preflight.assert_called_once_with(self.config)

    def test_setup_reuses_reset_seed_and_returns_observed_role_id(self) -> None:
        admin_role_id = "20000000-0000-4000-8000-000000000001"
        emails = {
            adapter.shared.ADMIN_USER_ID: "contract-admin@example.invalid",
            adapter.shared.ACTIVE_USER_ID: "contract-active@example.invalid",
        }
        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "seed") as seed,
            mock.patch.object(adapter.shared, "emails", return_value=emails),
            mock.patch.object(
                adapter.shared, "psql", return_value=admin_role_id
            ) as psql,
        ):
            result = adapter.setup(self.config, "admin-flow-users")
        reset.assert_called_once_with(self.config)
        seed.assert_called_once_with(self.config)
        self.assertEqual(
            result,
            {
                "admin": {
                    "userId": adapter.shared.ADMIN_USER_ID,
                    "email": "contract-admin@example.invalid",
                    "password": adapter.shared.PASSWORD,
                    "name": "Contract Admin",
                    "roles": [{"serviceKey": "temis", "name": "admin"}],
                    "audience": "contract-fixture",
                },
                "target": {
                    "userId": adapter.shared.ACTIVE_USER_ID,
                    "email": "contract-active@example.invalid",
                    "password": adapter.shared.PASSWORD,
                    "name": "Contract Active",
                    "roles": [{"serviceKey": "temis", "name": "user"}],
                    "audience": "contract-fixture",
                },
                "adminRoleId": admin_role_id,
            },
        )
        sql = cast(str, psql.call_args.args[1])
        self.assertIn('FROM "UserRole"', sql)
        self.assertIn('JOIN "Role"', sql)
        self.assertIn(cast(str, adapter.shared.ADMIN_USER_ID), sql)
        self.assertIn("'temis'", sql)
        self.assertIn("'admin'", sql)
        self.assertNotIn("INSERT", sql)

    def test_wrong_names_fail_before_reset_seed_or_sql(self) -> None:
        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "seed") as seed,
            mock.patch.object(adapter.shared, "psql") as psql,
            self.assertRaisesRegex(adapter.AdapterError, "unsupported fixture"),
        ):
            adapter.setup(self.config, "admin-flow-state")
        reset.assert_not_called()
        seed.assert_not_called()
        psql.assert_not_called()

        with (
            mock.patch.object(adapter.shared, "psql") as psql,
            self.assertRaisesRegex(adapter.AdapterError, "unsupported snapshot"),
        ):
            adapter.snapshot(self.config, "target-user")
        psql.assert_not_called()

        with (
            mock.patch.object(adapter.shared, "psql") as psql,
            self.assertRaisesRegex(adapter.AdapterError, "unsupported control"),
        ):
            adapter.control(self.config, "suspend-target")
        psql.assert_not_called()

    def test_state_snapshot_projects_observed_state_and_redacts_pii(self) -> None:
        admin_id = cast(str, adapter.shared.ADMIN_USER_ID)
        target_id = cast(str, adapter.shared.ACTIVE_USER_ID)
        admin_role_id = "20000000-0000-4000-8000-000000000001"
        target_role_id = "20000000-0000-4000-8000-000000000002"
        admin_hash = "a" * 64
        target_hash = "b" * 64
        audit = {
            "id": "90000000-0000-4000-8000-000000000007",
            "eventType": "admin_user_status_changed",
            "outcome": "success",
            "userId": target_id,
            "actorUserId": admin_id,
            "targetUserId": target_id,
            "reasonCode": None,
            "detailsJson": {
                "status": "suspended",
                "email": "private@example.invalid",
                "note": "Bearer raw-access-token",
                "nested": {"token": "raw"},
            },
            "createdAt": "2026-09-09T12:34:56.789Z",
        }

        def psql(_config: Any, sql: str) -> str:
            if 'lower("status"::text)' in sql:
                return f"{target_id}|active\n{admin_id}|suspended"
            if 'FROM "UserRole"' in sql:
                return (
                    f"{target_id}|{target_role_id}|temis|user\n"
                    f"{admin_id}|{admin_role_id}|temis|admin"
                )
            if 'FROM "RefreshToken"' in sql:
                return f"{admin_id}|{admin_hash}\n{target_id}|{target_hash}"
            if 'FROM "AuditLog"' in sql and "json_build_object" in sql:
                return json.dumps(audit, separators=(",", ":"))
            raise AssertionError(sql)

        with mock.patch.object(adapter.shared, "psql", side_effect=psql) as query:
            result = adapter.snapshot(self.config, "admin-flow-state")
        self.assertEqual(
            result,
            {
                "adminStatus": "suspended",
                "adminRoles": [
                    {
                        "id": admin_role_id,
                        "serviceKey": "temis",
                        "name": "admin",
                    }
                ],
                "targetStatus": "active",
                "targetRoles": [
                    {
                        "id": target_role_id,
                        "serviceKey": "temis",
                        "name": "user",
                    }
                ],
                "adminActiveTokenHashes": [admin_hash],
                "targetActiveTokenHashes": [target_hash],
                "audits": [
                    {
                        **audit,
                        "detailsJson": {
                            "status": "suspended",
                            "email": "[REDACTED]",
                            "note": "[REDACTED]",
                            "nested": "[REDACTED]",
                        },
                    }
                ],
            },
        )
        all_sql = "\n".join(cast(str, call.args[1]) for call in query.call_args_list)
        self.assertIn('"revokedAt" IS NULL', all_sql)
        self.assertIn('ORDER BY "userId", "tokenHash"', all_sql)
        self.assertIn("LIKE 'admin\\_%'", all_sql)
        self.assertIn('ORDER BY "createdAt", "id"', all_sql)
        self.assertIn("'id', \"id\"", all_sql)
        self.assertIn("'userId', \"userId\"", all_sql)
        self.assertIn('to_char("createdAt"', all_sql)
        self.assertNotIn(cast(str, adapter.shared.PENDING_USER_ID), all_sql)
        self.assertNotIn(cast(str, adapter.shared.TARGET_USER_ID), all_sql)
        self.assertNotIn('"email"', all_sql)
        self.assertNotIn('"passwordHash"', all_sql)

    def test_snapshot_rejects_malformed_database_projections(self) -> None:
        admin_id = cast(str, adapter.shared.ADMIN_USER_ID)
        target_id = cast(str, adapter.shared.ACTIVE_USER_ID)
        valid = {
            "status": f"{target_id}|active\n{admin_id}|active",
            "roles": (
                f"{target_id}|20000000-0000-4000-8000-000000000002|temis|user\n"
                f"{admin_id}|20000000-0000-4000-8000-000000000001|temis|admin"
            ),
            "hashes": "",
            "audits": json.dumps(
                {
                    "id": "90000000-0000-4000-8000-000000000008",
                    "eventType": "admin_user_status_changed",
                    "outcome": "success",
                    "userId": target_id,
                    "actorUserId": admin_id,
                    "targetUserId": target_id,
                    "reasonCode": "CONTRACT_STATUS",
                    "detailsJson": {"status": "active"},
                    "createdAt": "2026-09-09T12:34:56.789Z",
                }
            ),
        }
        cases = {
            "status": "unknown-user|active",
            "roles": f"{admin_id}|not-a-uuid|temis|admin",
            "hashes": f"{admin_id}|not-a-hash",
            "audits": "not-json",
        }
        for stage, malformed in cases.items():
            responses = {**valid, stage: malformed}

            def psql(
                _config: Any, sql: str, selected: dict[str, str] = responses
            ) -> str:
                if 'lower("status"::text)' in sql:
                    return selected["status"]
                if 'FROM "UserRole"' in sql:
                    return selected["roles"]
                if 'FROM "RefreshToken"' in sql:
                    return selected["hashes"]
                if 'FROM "AuditLog"' in sql:
                    return selected["audits"]
                raise AssertionError(sql)

            with (
                self.subTest(stage=stage),
                mock.patch.object(adapter.shared, "psql", side_effect=psql),
                self.assertRaisesRegex(
                    adapter.AdapterError, "projection was malformed"
                ),
            ):
                adapter.snapshot(self.config, "admin-flow-state")

    def test_audit_identity_user_and_timestamp_are_observed_not_synthesized(
        self,
    ) -> None:
        observed = {
            "id": "90000000-0000-4000-8000-000000000009",
            "eventType": "admin_user_sessions_revoked",
            "outcome": "success",
            "userId": adapter.shared.ACTIVE_USER_ID,
            "actorUserId": adapter.shared.ADMIN_USER_ID,
            "targetUserId": adapter.shared.ACTIVE_USER_ID,
            "reasonCode": "CONTRACT_REVOKE",
            "detailsJson": {"revokedCount": 1},
            "createdAt": "2026-09-09T23:59:58.321Z",
        }
        with mock.patch.object(
            adapter.shared,
            "psql",
            return_value=json.dumps(observed, separators=(",", ":")),
        ):
            self.assertEqual(adapter._audits(self.config), [observed])

    def test_setup_rejects_missing_or_ambiguous_admin_role_projection(self) -> None:
        results = (
            "",
            "not-a-uuid",
            "20000000-0000-4000-8000-000000000001\n"
            + "20000000-0000-4000-8000-000000000009",
        )
        for result in results:
            with (
                self.subTest(result=result),
                mock.patch.object(adapter.shared, "reset"),
                mock.patch.object(adapter.shared, "seed"),
                mock.patch.object(adapter.shared, "emails", return_value={}),
                mock.patch.object(adapter.shared, "psql", return_value=result),
                self.assertRaisesRegex(adapter.AdapterError, "role projection"),
            ):
                adapter.setup(self.config, "admin-flow-users")

    def test_control_updates_only_admin_status_without_token_mutation(self) -> None:
        for operation, expected in (
            ("suspend-admin", "SUSPENDED"),
            ("restore-admin", "ACTIVE"),
        ):
            with (
                self.subTest(operation=operation),
                mock.patch.object(
                    adapter.shared, "psql", return_value=expected.lower()
                ) as psql,
            ):
                result = adapter.control(self.config, operation)
            self.assertEqual(result, {"status": "controlled"})
            sql = cast(str, psql.call_args.args[1])
            self.assertIn(f"'{expected}'::\"UserStatus\"", sql)
            self.assertIn(cast(str, adapter.shared.ADMIN_USER_ID), sql)
            self.assertNotIn(cast(str, adapter.shared.ACTIVE_USER_ID), sql)
            self.assertNotIn('"RefreshToken"', sql)

    def test_control_requires_exactly_one_observed_update(self) -> None:
        for result in ("", "active\nactive", "suspended"):
            with (
                self.subTest(result=result),
                mock.patch.object(adapter.shared, "psql", return_value=result),
                self.assertRaisesRegex(adapter.AdapterError, "exactly one user"),
            ):
                adapter.control(self.config, "restore-admin")

    def test_residual_and_teardown_use_observed_counts(self) -> None:
        with mock.patch.object(adapter.shared, "psql", return_value="0|0|0") as psql:
            self.assertEqual(
                adapter.snapshot(self.config, "admin-flow-residual"),
                {"users": 0, "activeRefreshTokens": 0, "adminAudits": 0},
            )
        sql = cast(str, psql.call_args.args[1])
        self.assertIn('FROM "User"', sql)
        self.assertIn('FROM "RefreshToken"', sql)
        self.assertIn('FROM "AuditLog"', sql)
        for fixture_id in adapter.shared.FIXTURE_IDS:
            self.assertIn(fixture_id, sql)

        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "psql", return_value="0|0|0"),
        ):
            result = adapter.teardown(self.config, "admin-flow-users")
        reset.assert_called_once_with(self.config)
        self.assertEqual(
            result, {"users": 0, "activeRefreshTokens": 0, "adminAudits": 0}
        )

        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "psql", return_value="0|1|2"),
            self.assertRaisesRegex(adapter.AdapterError, "residual state"),
        ):
            adapter.teardown(self.config, "admin-flow-users")
        reset.assert_called_once_with(self.config)

    def test_teardown_cannot_ignore_other_seeded_user_residuals(self) -> None:
        other_ids = {
            cast(str, adapter.shared.PENDING_USER_ID),
            cast(str, adapter.shared.TARGET_USER_ID),
        }

        def residual(_config: Any, sql: str) -> str:
            for fixture_id in adapter.shared.FIXTURE_IDS:
                self.assertIn(fixture_id, sql)
            self.assertTrue(other_ids.issubset(set(sql.split("'"))))
            return "1|1|1"

        with (
            mock.patch.object(adapter.shared, "reset") as reset,
            mock.patch.object(adapter.shared, "psql", side_effect=residual),
            self.assertRaisesRegex(adapter.AdapterError, "residual state"),
        ):
            adapter.teardown(self.config, "admin-flow-users")
        reset.assert_called_once_with(self.config)

    def test_cli_validates_bindings_before_load_and_preflights_every_command(
        self,
    ) -> None:
        with (
            mock.patch.object(adapter, "load_config") as load_config,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(adapter.main(["snapshot", "target-user"]), 2)
        load_config.assert_not_called()

        for command, name in (
            ("setup", "admin-flow-users"),
            ("snapshot", "admin-flow-state"),
            ("control", "suspend-admin"),
            ("teardown", "admin-flow-users"),
        ):
            with (
                self.subTest(command=command),
                mock.patch.object(adapter, "load_config", return_value=self.config),
                mock.patch.object(
                    adapter,
                    "preflight",
                    side_effect=adapter.AdapterError("schema mismatch"),
                ) as preflight,
                mock.patch.object(adapter, "setup") as setup,
                mock.patch.object(adapter, "snapshot") as snapshot,
                mock.patch.object(adapter, "control") as control,
                mock.patch.object(adapter, "teardown") as teardown,
                mock.patch("builtins.print"),
            ):
                self.assertEqual(adapter.main([command, name]), 2)
            preflight.assert_called_once_with(self.config, "admin-flow-users")
            setup.assert_not_called()
            snapshot.assert_not_called()
            control.assert_not_called()
            teardown.assert_not_called()

    def test_main_emits_exactly_one_json_value(self) -> None:
        result = {
            "status": "ok",
            "runtime": "fastapi",
            "schema": "prisma-compatible",
        }
        with (
            mock.patch.object(adapter, "load_config", return_value=self.config),
            mock.patch.object(adapter, "preflight", return_value=result),
            mock.patch("builtins.print") as printer,
        ):
            self.assertEqual(adapter.main(["preflight", "admin-flow-users"]), 0)
        printer.assert_called_once_with(
            '{"runtime":"fastapi","schema":"prisma-compatible","status":"ok"}'
        )


if __name__ == "__main__":
    unittest.main()
