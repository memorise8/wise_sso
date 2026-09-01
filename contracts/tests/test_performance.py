import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

JsonObject = dict[str, Any]

CONTRACTS = Path(__file__).resolve().parents[1]
PROFILE = CONTRACTS / "performance" / "profile-v1.json"
MANIFEST = CONTRACTS / "manifest.json"
SPEC = importlib.util.spec_from_file_location(
    "contract_performance", CONTRACTS / "bin" / "performance.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the performance contract evaluator")
performance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(performance)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def make_evidence() -> JsonObject:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    epochs = []
    reset_ids = {}
    reset_block_number = 0
    for epoch, order in enumerate(profile["epochRuntimeOrder"], start=1):
        resets = []
        for runtime in order:
            reset_id = f"epoch-{epoch:02d}-{runtime}"
            reset_ids[(epoch, runtime)] = reset_id
            resets.append(
                {
                    "runtime": runtime,
                    "resetId": reset_id,
                    "stateSha256": digest(reset_id),
                    "boundaryNs": reset_block_number * 100_000_000_000,
                    "status": "PASS",
                }
            )
            reset_block_number += 1
        epochs.append(
            {
                "epoch": epoch,
                "runtimeOrder": order,
                "warmupCompletedPerFlowRuntime": 20,
                "warmupIncluded": False,
                "resets": resets,
            }
        )
    samples = []
    block_number = 0
    for epoch, order in enumerate(profile["epochRuntimeOrder"], start=1):
        for runtime in order:
            block_base = block_number * 100_000_000_000
            offset = 0
            for flow_id in profile["flowIds"]:
                for trial in range(1, 101):
                    scheduled = block_base + offset * 50_000_000
                    expected_failure = trial > 80
                    samples.append(
                        {
                            "flowId": flow_id,
                            "runtime": runtime,
                            "epoch": epoch,
                            "trial": trial,
                            "kind": "expected-failure" if expected_failure else "success",
                            "scheduledNs": scheduled,
                            "completedNs": scheduled + 100_000,
                            "outcome": "expected-failure" if expected_failure else "success",
                            "attempt": 1,
                            "retryCount": 0,
                            "outlierRemoved": False,
                            "resetId": reset_ids[(epoch, runtime)],
                        }
                    )
                    offset += 1
            block_number += 1
    return {
        "schemaVersion": 1,
        "suiteId": "phase7-performance-v1",
        "profileSha256": hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
        "manifestSha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
        "runId": "contract-run-001",
        "sourceRevision": "a" * 40,
        "provenance": {
            "databaseSnapshotSha256": digest("database"),
            "redisNamespace": "contract.performance.001",
            "harnessRevision": "b" * 40,
            "runtimes": {
                "express": {
                    "imageDigest": "sha256:" + digest("express-image"),
                    "configSha256": digest("express-config"),
                },
                "fastapi": {
                    "imageDigest": "sha256:" + digest("fastapi-image"),
                    "configSha256": digest("fastapi-config"),
                },
            },
        },
        "epochs": epochs,
        "samples": samples,
    }


def selected(
    evidence: JsonObject, flow: str, runtime: str, kind: str = "success"
) -> list[JsonObject]:
    return [
        row
        for row in evidence["samples"]
        if row["flowId"] == flow and row["runtime"] == runtime and row["kind"] == kind
    ]


class PerformanceContractTests(unittest.TestCase):
    base: ClassVar[JsonObject]

    @classmethod
    def setUpClass(cls) -> None:
        cls.base = make_evidence()

    def test_profile_is_bound_to_exact_approved_flows_and_generator(self) -> None:
        profile = performance.load_profile(PROFILE, MANIFEST)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            profile["flowIds"],
            [flow["id"] for flow in manifest["phase7ApprovedCoreFlows"]],
        )
        self.assertEqual(profile["warmupTrialsPerFlowRuntimeEpoch"], 20)
        plan = performance.generate_plan(profile, hashlib.sha256(PROFILE.read_bytes()).hexdigest())
        self.assertEqual(plan["measurementRows"], 20_000)
        self.assertFalse(plan["qualifyingEvidence"])
        counts: dict[tuple[str, str], int] = {}
        for row in plan["samples"]:
            key = (row["flowId"], row["runtime"])
            counts[key] = counts.get(key, 0) + 1
        self.assertEqual(set(counts.values()), {1000})

    def test_exact_complete_evidence_passes_but_never_authorizes_replacement(
        self,
    ) -> None:
        result = performance.evaluate(copy.deepcopy(self.base))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["reasonCodes"], [])
        self.assertEqual(result["validatedSampleCount"], 20_000)
        self.assertEqual(result["observedSampleCount"], 20_000)
        self.assertFalse(result["observedSampleCountCapped"])
        self.assertFalse(result["qualifyingEvidence"])
        self.assertFalse(result["overallReplacementReady"])

    def test_duplicate_and_missing_samples_are_incomplete(self) -> None:
        duplicate = copy.deepcopy(self.base)
        duplicate["samples"][-1] = copy.deepcopy(duplicate["samples"][0])
        self.assertEqual(performance.evaluate(duplicate)["status"], "INCOMPLETE")
        missing = copy.deepcopy(self.base)
        missing["samples"].pop()
        self.assertEqual(performance.evaluate(missing)["status"], "INCOMPLETE")
        oversized = copy.deepcopy(self.base)
        oversized["samples"].append(copy.deepcopy(oversized["samples"][-1]))
        result = performance.evaluate(oversized)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["validatedSampleCount"], 0)
        self.assertEqual(result["observedSampleCount"], 20_001)
        self.assertFalse(result["observedSampleCountCapped"])

    def test_retry_outlier_and_override_are_incomplete(self) -> None:
        for field, value in (("retryCount", 1), ("outlierRemoved", True)):
            evidence = copy.deepcopy(self.base)
            evidence["samples"][0][field] = value
            self.assertEqual(performance.evaluate(evidence)["status"], "INCOMPLETE")
        override = copy.deepcopy(self.base)
        override["thresholdOverride"] = {"approved": True}
        self.assertEqual(performance.evaluate(override)["status"], "INCOMPLETE")
        for field, value in (("attempt", True), ("retryCount", False)):
            evidence = copy.deepcopy(self.base)
            evidence["samples"][0][field] = value
            self.assertEqual(performance.evaluate(evidence)["status"], "INCOMPLETE")

    def test_runtime_order_and_open_loop_rate_are_exact(self) -> None:
        order = copy.deepcopy(self.base)
        order["samples"][0], order["samples"][1] = (
            order["samples"][1],
            order["samples"][0],
        )
        self.assertEqual(performance.evaluate(order)["status"], "INCOMPLETE")
        rate = copy.deepcopy(self.base)
        rate["samples"][1]["scheduledNs"] += 1
        rate["samples"][1]["completedNs"] += 1
        self.assertEqual(performance.evaluate(rate)["status"], "INCOMPLETE")

        concurrency = copy.deepcopy(self.base)
        for row in concurrency["samples"][:17]:
            row["completedNs"] = row["scheduledNs"] + 1_000_000_000
        result = performance.evaluate(concurrency)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reasonCodes"], ["max-in-flight-exceeded"])

        identical_window = copy.deepcopy(self.base)
        first_block = identical_window["samples"][:1000]
        second_block = identical_window["samples"][1000:2000]
        for source, target in zip(first_block, second_block, strict=True):
            target["scheduledNs"] = source["scheduledNs"]
            target["completedNs"] = source["completedNs"]
        identical_window["epochs"][0]["resets"][1]["boundaryNs"] = 0
        result = performance.evaluate(identical_window)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reasonCodes"], ["global-block-overlap-or-order-mismatch"])

        crossing_reset = copy.deepcopy(self.base)
        for row in crossing_reset["samples"][1000:2000]:
            row["scheduledNs"] -= 50_000_000_000
            row["completedNs"] -= 50_000_000_000
        crossing_reset["epochs"][0]["resets"][1]["boundaryNs"] = 50_000_000_000
        crossing_reset["samples"][999]["completedNs"] = 50_650_000_000
        result = performance.evaluate(crossing_reset)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["reasonCodes"], ["global-block-overlap-or-order-mismatch"])

    def test_error_rate_integer_boundary_and_timeout_accounting(self) -> None:
        flow = "password-handoff-exchange"
        absolute_failure = copy.deepcopy(self.base)
        selected(absolute_failure, flow, "fastapi")[0]["outcome"] = "unexpected-error"
        result = performance.evaluate(absolute_failure)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"absolute-error-fastapi-{flow}", result["reasonCodes"])
        over_boundary = copy.deepcopy(self.base)
        for row in selected(over_boundary, flow, "fastapi")[:11]:
            row["outcome"] = "timeout"
            row["completedNs"] = row["scheduledNs"] + 5_000_000_000
        result = performance.evaluate(over_boundary)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"error-threshold-{flow}", result["reasonCodes"])
        early_timeout = copy.deepcopy(self.base)
        early_timeout["samples"][0]["outcome"] = "timeout"
        self.assertEqual(performance.evaluate(early_timeout)["status"], "INCOMPLETE")

    def test_symmetric_catastrophic_failures_cannot_pass_relative_comparison(
        self,
    ) -> None:
        evidence = copy.deepcopy(self.base)
        for row in evidence["samples"]:
            if row["kind"] == "success":
                row["outcome"] = "unexpected-error"
        result = performance.evaluate(evidence)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("absolute-error-express-aggregate", result["reasonCodes"])
        self.assertIn("absolute-error-fastapi-aggregate", result["reasonCodes"])
        self.assertNotIn("error-threshold-aggregate", result["reasonCodes"])

    def test_nearest_rank_p95_integer_boundary(self) -> None:
        flow = "oauth-google"
        at_boundary = copy.deepcopy(self.base)
        for row in selected(at_boundary, flow, "fastapi")[-51:]:
            row["completedNs"] = row["scheduledNs"] + 120_000
        self.assertEqual(performance.evaluate(at_boundary)["status"], "PASS")
        over_boundary = copy.deepcopy(self.base)
        for row in selected(over_boundary, flow, "fastapi")[-51:]:
            row["completedNs"] = row["scheduledNs"] + 120_001
        result = performance.evaluate(over_boundary)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"p95-threshold-{flow}", result["reasonCodes"])

    def test_login_outcome_contract_precedes_comparative_threshold(self) -> None:
        flow = "password-direct-login-token"
        at_boundary = copy.deepcopy(self.base)
        for row in selected(at_boundary, flow, "fastapi")[:16]:
            row["outcome"] = "unexpected-outcome"
        result = performance.evaluate(at_boundary)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"absolute-error-fastapi-{flow}", result["reasonCodes"])
        self.assertNotIn("login-success-threshold-aggregate", result["reasonCodes"])
        over_boundary = copy.deepcopy(self.base)
        for row in selected(over_boundary, flow, "fastapi")[:17]:
            row["outcome"] = "unexpected-outcome"
        result = performance.evaluate(over_boundary)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("login-success-threshold-aggregate", result["reasonCodes"])

        symmetric_collapse = copy.deepcopy(self.base)
        for runtime in ("express", "fastapi"):
            for row in selected(symmetric_collapse, flow, runtime):
                row["outcome"] = "unexpected-outcome"
        result = performance.evaluate(symmetric_collapse)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn(f"absolute-error-express-{flow}", result["reasonCodes"])
        self.assertIn(f"absolute-error-fastapi-{flow}", result["reasonCodes"])

    def test_reset_and_provenance_fail_closed(self) -> None:
        reset = copy.deepcopy(self.base)
        reset["epochs"][0]["resets"][0]["status"] = "FAIL"
        self.assertEqual(performance.evaluate(reset)["status"], "INCOMPLETE")
        provenance = copy.deepcopy(self.base)
        provenance["provenance"]["redisNamespace"] = "../shared"
        self.assertEqual(performance.evaluate(provenance)["status"], "INCOMPLETE")
        hash_binding = copy.deepcopy(self.base)
        hash_binding["profileSha256"] = "0" * 64
        self.assertEqual(performance.evaluate(hash_binding)["status"], "INCOMPLETE")

    def test_boolean_time_and_contract_drift_are_incomplete(self) -> None:
        boolean_index = copy.deepcopy(self.base)
        boolean_index["samples"][0]["epoch"] = True
        self.assertEqual(performance.evaluate(boolean_index)["status"], "INCOMPLETE")
        boolean_epoch_metadata = copy.deepcopy(self.base)
        boolean_epoch_metadata["epochs"][0]["epoch"] = True
        self.assertEqual(performance.evaluate(boolean_epoch_metadata)["status"], "INCOMPLETE")
        negative_time = copy.deepcopy(self.base)
        negative_time["samples"][0]["scheduledNs"] = -1
        self.assertEqual(performance.evaluate(negative_time)["status"], "INCOMPLETE")

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            drifted_profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            drifted_profile["policy"]["allowOverrides"] = True
            profile_path = directory_path / "profile.json"
            profile_path.write_text(json.dumps(drifted_profile), encoding="utf-8")
            evidence = copy.deepcopy(self.base)
            evidence["profileSha256"] = hashlib.sha256(profile_path.read_bytes()).hexdigest()
            self.assertEqual(
                performance.evaluate(evidence, profile_path=profile_path)["status"],
                "INCOMPLETE",
            )

            drifted_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            drifted_manifest["phase7ApprovedCoreFlows"][0]["id"] = "drifted-flow"
            manifest_path = directory_path / "manifest.json"
            manifest_path.write_text(json.dumps(drifted_manifest), encoding="utf-8")
            self.assertEqual(
                performance.evaluate(self.base, manifest_path=manifest_path)["status"],
                "INCOMPLETE",
            )

            substituted_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            substituted_manifest["phase7ApprovedCoreFlows"][-1]["id"] = "attacker-substitute-flow"
            substituted_manifest_path = directory_path / "substituted-manifest.json"
            substituted_manifest_path.write_text(json.dumps(substituted_manifest), encoding="utf-8")
            substituted_profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            substituted_profile["flowIds"][-1] = "attacker-substitute-flow"
            substituted_profile["expectedFailureFlowIds"][-1] = "attacker-substitute-flow"
            substituted_profile["outcomeContract"]["attacker-substitute-flow"] = (
                substituted_profile["outcomeContract"].pop("global-rate-limit")
            )
            substituted_profile["manifestSha256"] = hashlib.sha256(
                substituted_manifest_path.read_bytes()
            ).hexdigest()
            substituted_profile_path = directory_path / "substituted-profile.json"
            substituted_profile_path.write_text(json.dumps(substituted_profile), encoding="utf-8")
            substituted_evidence = copy.deepcopy(self.base)
            substituted_evidence["profileSha256"] = hashlib.sha256(
                substituted_profile_path.read_bytes()
            ).hexdigest()
            substituted_evidence["manifestSha256"] = substituted_profile["manifestSha256"]
            self.assertEqual(
                performance.evaluate(
                    substituted_evidence,
                    profile_path=substituted_profile_path,
                    manifest_path=substituted_manifest_path,
                )["status"],
                "INCOMPLETE",
            )

    def test_profile_and_evidence_schemas_are_exact_at_every_object_boundary(
        self,
    ) -> None:
        for name in (
            "profile.schema.json",
            "evidence.schema.json",
            "result.schema.json",
        ):
            schema = json.loads((CONTRACTS / "performance" / name).read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])

    def test_cli_bounds_json_before_decoding(self) -> None:
        with tempfile.NamedTemporaryFile() as input_file:
            input_file.seek(performance.MAX_INPUT_BYTES)
            input_file.write(b"x")
            input_file.flush()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = performance.main(["evaluate", "--input", input_file.name])
        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 2)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertFalse(result["qualifyingEvidence"])

    def test_operational_refusals_and_reason_codes_are_safe(self) -> None:
        safe_reason = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            oversized_paths = []
            for name in ("profile.json", "manifest.json"):
                path = directory_path / name
                with path.open("wb") as oversized_file:
                    oversized_file.seek(performance.MAX_INPUT_BYTES)
                    oversized_file.write(b"x")
                oversized_paths.append(path)
            for profile_path, manifest_path in (
                (oversized_paths[0], MANIFEST),
                (PROFILE, oversized_paths[1]),
            ):
                result = performance.evaluate(
                    self.base,
                    profile_path=profile_path,
                    manifest_path=manifest_path,
                )
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertTrue(
                    all(safe_reason.fullmatch(reason) for reason in result["reasonCodes"])
                )

            drifted_profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            drifted_profile["flowIds"][-1] = "attacker-substitute-flow"
            drifted_path = directory_path / "drifted-profile.json"
            drifted_path.write_text(json.dumps(drifted_profile), encoding="utf-8")
            evidence = copy.deepcopy(self.base)
            evidence["profileSha256"] = hashlib.sha256(drifted_path.read_bytes()).hexdigest()
            result = performance.evaluate(evidence, profile_path=drifted_path)
            self.assertEqual(result["reasonCodes"], ["profile-drift-flow-ids"])
            self.assertTrue(safe_reason.fullmatch(result["reasonCodes"][0]))

            input_path = directory_path / "invalid-evidence.json"
            input_path.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = performance.main(
                    [
                        "evaluate",
                        "--input",
                        str(input_path),
                        "--output",
                        str(directory_path),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("output refused", stderr.getvalue())

            stderr = io.StringIO()
            with (
                mock.patch.object(
                    performance.tempfile,
                    "mkstemp",
                    side_effect=PermissionError("unwritable output"),
                ),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = performance.main(
                    [
                        "evaluate",
                        "--input",
                        str(input_path),
                        "--output",
                        str(directory_path / "result.json"),
                    ]
                )
            self.assertEqual(exit_code, 2)
            self.assertIn("output refused", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
