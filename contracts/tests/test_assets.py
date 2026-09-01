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

    def test_manifest_snapshot_validations_pass_full_wrappers(self):
        manifest = json.loads((CONTRACTS / "manifest.json").read_text(encoding="utf-8"))
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (CONTRACTS / "schemas").glob("*.json")
        }
        schemas_by_id = {schema["$id"]: schema for schema in schemas.values() if "$id" in schema}
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
        snapshot = json.loads((CONTRACTS / "snapshots" / "state.json").read_text(encoding="utf-8"))
        snapshot["refreshToken"]["tokenHash"] = "not-a-sha256-hash"
        with self.assertRaisesRegex(SchemaValidationError, "pattern"):
            validate(
                snapshot,
                schema,
                root=schema,
                schemas_by_name=schemas,
                schemas_by_id={item["$id"]: item for item in schemas.values() if "$id" in item},
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
