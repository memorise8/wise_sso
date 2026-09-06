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
from typing import Any, ClassVar, cast
from unittest import mock

JsonObject = dict[str, Any]

CONTRACTS = Path(__file__).resolve().parents[1]
PROFILE = CONTRACTS / "performance" / "profile-v1.json"
PROFILE_V2_TEMPLATE = CONTRACTS / "performance" / "profile-v2.template.json"
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


def make_v2_profile(p50_cutoff: int | None = 100) -> JsonObject:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["$schema"] = "profile-v2.schema.json"
    profile["schemaVersion"] = 2
    profile["suiteId"] = "phase7-performance-v2"
    profile["policyVersion"] = 2
    profile["policy"]["candidateP50MaxPercentOfBaseline"] = p50_cutoff
    return cast(JsonObject, profile)


def bind_v2_evidence(evidence: JsonObject, profile_path: Path) -> JsonObject:
    evidence["schemaVersion"] = 2
    evidence["suiteId"] = "phase7-performance-v2"
    evidence["profileSha256"] = hashlib.sha256(profile_path.read_bytes()).hexdigest()
    return evidence


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

    def test_v2_requires_and_enforces_reviewed_p50_cutoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile_path = Path(directory) / "profile-v2.json"
            profile_path.write_text(json.dumps(make_v2_profile(101)), encoding="utf-8")
            evidence = bind_v2_evidence(copy.deepcopy(self.base), profile_path)
            passing = performance.evaluate(evidence, profile_path=profile_path)
            self.assertEqual(passing["status"], "PASS")
            self.assertEqual(passing["schemaVersion"], 2)
            self.assertEqual(passing["suiteId"], "phase7-performance-v2")
            self.assertEqual(passing["metrics"]["aggregate"]["fastapi"]["p50Ns"], 100_000)
            self.assertFalse(passing["qualifyingEvidence"])

            for row in evidence["samples"]:
                if row["runtime"] == "fastapi":
                    row["completedNs"] += 2_000
            result = performance.evaluate(evidence, profile_path=profile_path)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("p50-threshold-aggregate", result["reasonCodes"])
            self.assertNotIn("p95-threshold-aggregate", result["reasonCodes"])

    def test_v2_rejects_missing_null_and_boolean_p50_cutoffs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            for label, cutoff in (("null", None), ("boolean", True)):
                with self.subTest(cutoff=label):
                    profile = make_v2_profile(cutoff)
                    profile_path = directory_path / f"profile-v2-{label}.json"
                    profile_path.write_text(json.dumps(profile), encoding="utf-8")
                    evidence = bind_v2_evidence(copy.deepcopy(self.base), profile_path)
                    result = performance.evaluate(evidence, profile_path=profile_path)
                    self.assertEqual(result["status"], "INCOMPLETE")
                    self.assertEqual(result["reasonCodes"], ["profile-p50-cutoff-unset"])
                    self.assertEqual(result["schemaVersion"], 2)
                    self.assertEqual(result["suiteId"], "phase7-performance-v2")

            missing = make_v2_profile()
            del missing["policy"]["candidateP50MaxPercentOfBaseline"]
            missing_path = directory_path / "profile-v2-missing.json"
            missing_path.write_text(json.dumps(missing), encoding="utf-8")
            evidence = bind_v2_evidence(copy.deepcopy(self.base), missing_path)
            result = performance.evaluate(evidence, profile_path=missing_path)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reasonCodes"], ["profile-p50-cutoff-unset"])
            self.assertEqual(result["schemaVersion"], 2)

    def test_unfrozen_v2_error_preserves_result_schema_constants(self) -> None:
        schema = json.loads(
            (CONTRACTS / "performance" / "result-v2.schema.json").read_text(encoding="utf-8")
        )
        result = performance.evaluate({}, profile_path=PROFILE_V2_TEMPLATE)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(set(result), set(schema["required"]))
        for name, contract in schema["properties"].items():
            if "const" in contract:
                self.assertEqual(result[name], contract["const"])
        self.assertEqual(result["validatedSampleCount"], 0)
        self.assertEqual(result["metrics"], {})

    def test_p50_uses_nearest_rank_not_interpolated_even_sample_median(self) -> None:
        self.assertEqual(performance._percentile([90, 10, 20, 100], 50), 20)
        self.assertEqual(performance._percentile([90, 10, 20, 100], 95), 100)

    def test_v2_rejects_policy_version_and_mixed_profile_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            profile = make_v2_profile()
            profile["policyVersion"] = 1
            wrong_policy_path = directory_path / "wrong-policy.json"
            wrong_policy_path.write_text(json.dumps(profile), encoding="utf-8")
            evidence = bind_v2_evidence(copy.deepcopy(self.base), wrong_policy_path)
            result = performance.evaluate(evidence, profile_path=wrong_policy_path)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reasonCodes"], ["profile-drift-policy-version"])

            profile = make_v2_profile()
            profile_path = directory_path / "profile-v2.json"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            old_evidence = copy.deepcopy(self.base)
            result = performance.evaluate(old_evidence, profile_path=profile_path)
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reasonCodes"], ["evidence-version-or-suite-mismatch"])

            mixed_manifest = directory_path / "manifest.json"
            mixed_manifest.write_text(MANIFEST.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            evidence = bind_v2_evidence(copy.deepcopy(self.base), profile_path)
            result = performance.evaluate(
                evidence,
                profile_path=profile_path,
                manifest_path=mixed_manifest,
            )
            self.assertEqual(result["status"], "INCOMPLETE")
            self.assertEqual(result["reasonCodes"], ["manifest-hash-mismatch"])

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

    def test_pre_driver_corpus_evidence_cannot_be_relabelled(self) -> None:
        old_bindings = {
            "manifestSha256": "7b814d65be9a0feed96a5727e4341f8d26b39a709b4a4c764eec6b896f362276",
            "profileSha256": "96b39cd0bbe953a400fbabbe51c57c861805696b03293279e71466a24c9a244d",
        }
        for field, old_hash in old_bindings.items():
            with self.subTest(field=field):
                evidence = copy.deepcopy(self.base)
                evidence[field] = old_hash
                result = performance.evaluate(evidence)
                self.assertEqual(result["status"], "INCOMPLETE")
                self.assertFalse(result["qualifyingEvidence"])

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
            "profile-v2.schema.json",
            "evidence.schema.json",
            "evidence-v2.schema.json",
            "result.schema.json",
            "result-v2.schema.json",
        ):
            schema = json.loads((CONTRACTS / "performance" / name).read_text(encoding="utf-8"))
            self.assertFalse(schema["additionalProperties"])

        evidence_v2_schema = json.loads(
            (CONTRACTS / "performance" / "evidence-v2.schema.json").read_text(encoding="utf-8")
        )
        result_v2_schema = json.loads(
            (CONTRACTS / "performance" / "result-v2.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evidence_v2_schema["properties"]["schemaVersion"]["const"], 2)
        self.assertIn("p50Ns", result_v2_schema["$defs"]["metric"]["required"])

        template = json.loads(PROFILE_V2_TEMPLATE.read_text(encoding="utf-8"))
        self.assertIsNone(template["manifestSha256"])
        self.assertIsNone(template["policy"]["candidateP50MaxPercentOfBaseline"])
        with self.assertRaisesRegex(
            performance.IncompleteEvidence,
            "profile-p50-cutoff-unset",
        ):
            performance.load_profile(PROFILE_V2_TEMPLATE, MANIFEST)

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
