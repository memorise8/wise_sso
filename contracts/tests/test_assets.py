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
            scenario_ids.update(scenario["id"] for scenario in scenario_document["scenarios"])
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
