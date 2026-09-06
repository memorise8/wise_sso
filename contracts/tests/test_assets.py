import ast
import json
import re
import unittest
from pathlib import Path

from schema_subset import SchemaValidationError, pointer, validate

CONTRACTS = Path(__file__).resolve().parents[1]


def load_fragment(reference):
    path_text, _, fragment = reference.partition("#")
    value = json.loads((CONTRACTS / path_text).read_text(encoding="utf-8"))
    return pointer(value, fragment)


class ContractAssetTests(unittest.TestCase):
    def test_development_driver_does_not_promote_qualification(self):
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        driver = manifest["phase7DevelopmentFlowDriver"]
        self.assertTrue((CONTRACTS / driver["runner"]).is_file())
        self.assertTrue((CONTRACTS / driver["tests"]).is_file())
        for mail_test in driver["mailTests"]:
            self.assertTrue((CONTRACTS / mail_test).is_file())
        source = ast.parse((CONTRACTS / driver["runner"]).read_text(encoding="utf-8"))
        flow_constants = [
            ast.literal_eval(node.value)
            for node in source.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "FLOWS"
                for target in node.targets
            )
        ]
        self.assertEqual(flow_constants, [tuple(driver["flows"])])
        self.assertEqual(
            driver["flows"],
            [flow["id"] for flow in manifest["phase7ApprovedCoreFlows"][:4]],
        )
        for claim in (
            "qualifyingEvidence",
            "fullPhase7SampleSatisfied",
            "overallReplacementReady",
        ):
            self.assertIs(driver[claim], False)
        self.assertEqual(
            [flow["status"] for flow in manifest["phase7ApprovedCoreFlows"]],
            ["partial"] * 9 + ["unsupported"],
        )

    def test_all_json_assets_are_valid(self):
        for path in CONTRACTS.rglob("*.json"):
            with self.subTest(path=path.relative_to(CONTRACTS)):
                json.loads(path.read_text(encoding="utf-8"))

    def test_manifest_references_existing_assets_and_scenarios(self):
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        scenario_ids = set()
        for path in (CONTRACTS / "scenarios").glob("*.json"):
            scenario_document = json.loads(path.read_text(encoding="utf-8"))
            for scenario in scenario_document["scenarios"]:
                with self.subTest(path=path.name, scenario=scenario.get("id")):
                    self.assertIsInstance(scenario.get("id"), str)
                    self.assertTrue(scenario["id"])
                    self.assertNotIn(scenario["id"], scenario_ids)
                    scenario_ids.add(scenario["id"])
        behavior_ids = set()
        for behavior in manifest["behaviors"]:
            with self.subTest(behavior=behavior["id"]):
                self.assertNotIn(behavior["id"], behavior_ids)
                behavior_ids.add(behavior["id"])
                self.assertTrue(set(behavior["scenarios"]).issubset(scenario_ids))
                for reference in behavior["schemas"]:
                    self.assertTrue((CONTRACTS / reference).is_file(), reference)
                for reference in behavior["snapshots"]:
                    asset = reference.split("#", 1)[0]
                    self.assertTrue((CONTRACTS / asset).is_file(), reference)
                for reference in behavior["evidence"]:
                    self.assertTrue((CONTRACTS.parent / reference).is_file(), reference)

        traced_scenarios = {
            scenario
            for behavior in manifest["behaviors"]
            for scenario in behavior["scenarios"]
        }
        traced_scenarios.update(
            scenario
            for group in manifest["phase7FlowGroups"]
            for scenario in group["scenarios"]
        )
        traced_scenarios.update(
            scenario
            for flow in manifest["phase7ApprovedCoreFlows"]
            for scenario in flow["scenarios"]
        )
        self.assertEqual(scenario_ids, traced_scenarios)

    def test_phase7_flow_matrix_is_complete_and_honest(self):
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        semantics = manifest["phase7FlowStatusSemantics"]
        self.assertEqual(semantics["scope"], "executable-contract-corpus-only")
        self.assertEqual(semantics["qualification"], "not-assessed")
        self.assertIn("never means Phase 7 qualification", semantics["complete"])
        approved_flow_ids = [
            "password-direct-login-token",
            "password-handoff-exchange",
            "email-verification-attach-handoff-exchange",
            "password-reset-session-revoke",
            "oauth-google",
            "oauth-naver",
            "oauth-kakao",
            "refresh-logout-race",
            "admin-status-role-session-audit",
            "global-rate-limit",
        ]
        approved_flow_names = [
            "Password direct login/token",
            "Password handoff/exchange",
            "Email verification/attach/handoff/exchange",
            "Password reset/session revoke",
            "Google",
            "Naver",
            "Kakao",
            "Refresh/logout race",
            "Admin status/role/session/audit",
            "Global rate-limit",
        ]
        approved_flows = manifest["phase7ApprovedCoreFlows"]
        self.assertEqual(approved_flow_ids, [flow["id"] for flow in approved_flows])
        self.assertEqual(approved_flow_names, [flow["name"] for flow in approved_flows])
        self.assertEqual(list(range(1, 11)), [flow["order"] for flow in approved_flows])
        self.assertNotIn("complete", {flow["status"] for flow in approved_flows})
        for flow in approved_flows:
            with self.subTest(approved_flow=flow["id"]):
                self.assertIn(flow["status"], {"partial", "unsupported"})
                self.assertTrue(flow["gaps"])
                self.assertTrue(
                    all(gap.startswith("Unsupported:") for gap in flow["gaps"])
                )
                if flow["status"] == "partial":
                    self.assertTrue(flow["scenarios"])
                else:
                    self.assertEqual(flow["scenarios"], [])
        expected_groups = {
            "public-oidc",
            "registration",
            "email-verification",
            "login-handoff-exchange-me",
            "refresh",
            "logout-session",
            "password-reset",
            "oauth-three-provider",
            "admin-mutations",
            "admin-directory-audit",
        }
        groups = manifest["phase7FlowGroups"]
        self.assertEqual(expected_groups, {group["id"] for group in groups})
        self.assertEqual(len(groups), len({group["id"] for group in groups}))
        self.assertNotIn("complete", {group["status"] for group in groups})
        for group in groups:
            with self.subTest(group=group["id"]):
                self.assertIn(group["status"], {"complete", "partial", "unsupported"})
                self.assertIsInstance(group["scenarios"], list)
                self.assertIsInstance(group["gaps"], list)
                if group["status"] == "complete":
                    self.assertTrue(group["scenarios"])
                    self.assertEqual(group["gaps"], [])
                else:
                    self.assertTrue(group["gaps"])
                    self.assertTrue(
                        all(gap.startswith("Unsupported:") for gap in group["gaps"])
                    )

        groups_by_id = {group["id"]: group for group in groups}
        for group_id in ("refresh", "logout-session"):
            with self.subTest(group=group_id):
                group = groups_by_id[group_id]
                self.assertEqual(group["status"], "partial")
                combined_gaps = " ".join(group["gaps"])
                self.assertIn("mixed-runtime", combined_gaps)
                self.assertIn("per-runtime repeated-sample threshold", combined_gaps)

    def test_logout_contract_preserves_idempotent_unknown_and_replay_semantics(self):
        guards = json.loads(
            (CONTRACTS / "scenarios" / "guards.json").read_text(encoding="utf-8")
        )
        guard_by_id = {scenario["id"]: scenario for scenario in guards["scenarios"]}
        unknown_logout = guard_by_id["session.logout-accepts-unknown-refresh"]
        self.assertEqual(
            unknown_logout["request"]["json"],
            {"refreshToken": "contract-invalid-refresh-token"},
        )
        self.assertEqual(unknown_logout["expect"], {"status": 204, "json": None})
        self.assertEqual(unknown_logout["stateProbe"], "auth-lifecycle")
        self.assertEqual(unknown_logout["stateAssertions"], [{"type": "unchanged"}])
        self.assertNotIn("session.logout-rejects-invalid-refresh", guard_by_id)

        fixtures = json.loads(
            (CONTRACTS / "scenarios" / "fixtures.json").read_text(encoding="utf-8")
        )
        fixture_by_id = {scenario["id"]: scenario for scenario in fixtures["scenarios"]}
        logout_steps = fixture_by_id["session.login-logout-replay"]["steps"][1:]
        self.assertEqual(len(logout_steps), 2)
        for step in logout_steps:
            self.assertEqual(step["request"]["path"], "/auth/logout")
            self.assertEqual(step["expect"], {"status": 204, "json": None})
        self.assertEqual(
            logout_steps[0]["stateAssertions"],
            [
                {"type": "numeric-delta", "path": "$.activeRefreshTokens", "by": -1},
                {"type": "numeric-delta", "path": "$.authHandoffKeys", "by": 0},
            ],
        )
        self.assertEqual(logout_steps[1]["stateAssertions"], [{"type": "unchanged"}])

        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        approved_by_id = {
            flow["id"]: flow for flow in manifest["phase7ApprovedCoreFlows"]
        }
        self.assertIn(
            "session.logout-accepts-unknown-refresh",
            approved_by_id["refresh-logout-race"]["scenarios"],
        )
        self.assertIn(
            "session.login-logout-replay",
            approved_by_id["refresh-logout-race"]["scenarios"],
        )
        traced_ids = {
            scenario
            for collection in (
                manifest["phase7ApprovedCoreFlows"],
                manifest["phase7FlowGroups"],
                manifest["behaviors"],
            )
            for item in collection
            for scenario in item["scenarios"]
        }
        self.assertIn("session.logout-accepts-unknown-refresh", traced_ids)
        self.assertNotIn("session.logout-rejects-invalid-refresh", traced_ids)

    def test_manifest_snapshot_validations_pass_full_wrappers(self):
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (CONTRACTS / "schemas").glob("*.json")
        }
        schemas_by_id = {
            schema["$id"]: schema for schema in schemas.values() if "$id" in schema
        }
        for validation in manifest["validations"]:
            with self.subTest(snapshot=validation["snapshot"]):
                snapshot = load_fragment(validation["snapshot"])
                schema_path, _, schema_fragment = validation["schema"].partition("#")
                schema_root = schemas[Path(schema_path).name]
                schema = pointer(schema_root, schema_fragment)
                validate(
                    snapshot,
                    schema,
                    root=schema_root,
                    schemas_by_name=schemas,
                    schemas_by_id=schemas_by_id,
                )

    def test_stdlib_schema_subset_rejects_invalid_state_hash(self):
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (CONTRACTS / "schemas").glob("*.json")
        }
        schema = schemas["auth-state.schema.json"]
        snapshot = json.loads(
            (CONTRACTS / "snapshots" / "state.json").read_text(encoding="utf-8")
        )
        snapshot["refreshToken"]["tokenHash"] = "not-a-sha256-hash"
        with self.assertRaisesRegex(SchemaValidationError, "pattern"):
            validate(
                snapshot,
                schema,
                root=schema,
                schemas_by_name=schemas,
                schemas_by_id={
                    item["$id"]: item for item in schemas.values() if "$id" in item
                },
            )

    def test_snapshots_are_marked_synthetic_and_contain_no_password_field(self):
        for path in (CONTRACTS / "snapshots").glob("*.json"):
            with self.subTest(path=path.name):
                content = path.read_text(encoding="utf-8")
                document = json.loads(content)
                self.assertIn("Synthetic", document["_notice"])
                self.assertIsNone(re.search(r'"password"\s*:', content, re.IGNORECASE))


if __name__ == "__main__":
    unittest.main()
