#!/usr/bin/env python3
"""Deterministic offline Phase 7 performance evidence evaluator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

CONTRACTS_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = CONTRACTS_DIR / "performance" / "profile-v1.json"
DEFAULT_MANIFEST = CONTRACTS_DIR / "manifest.json"
MAX_INPUT_BYTES = 32 * 1024 * 1024
RUNTIMES = ("express", "fastapi")
FROZEN_FLOW_IDS = (
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
)
FROZEN_OUTCOME_CONTRACT = {
    flow_id: {"success": "success", "expectedFailure": "expected-failure"}
    for flow_id in FROZEN_FLOW_IDS
}
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SAMPLE_KEYS = {
    "flowId",
    "runtime",
    "epoch",
    "trial",
    "kind",
    "scheduledNs",
    "completedNs",
    "outcome",
    "attempt",
    "retryCount",
    "outlierRemoved",
    "resetId",
}
PROFILE_KEYS = {
    "$schema",
    "schemaVersion",
    "suiteId",
    "manifestPath",
    "manifestSha256",
    "flowIds",
    "loginFlowIds",
    "expectedFailureFlowIds",
    "outcomeContract",
    "epochs",
    "warmupTrialsPerFlowRuntimeEpoch",
    "measuredTrialsPerFlowRuntimeEpoch",
    "successTrialsPerApplicableFlowRuntimeEpoch",
    "expectedFailureTrialsPerApplicableFlowRuntimeEpoch",
    "epochRuntimeOrder",
    "load",
    "latency",
    "policy",
    "overallReplacementReady",
}


class IncompleteEvidence(Exception):
    """Evidence cannot support a threshold verdict."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded_regular(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_BYTES:
            raise IncompleteEvidence(f"invalid-{label}-file")
        with path.open("rb") as input_file:
            opened = os.fstat(input_file.fileno())
            data = input_file.read(MAX_INPUT_BYTES + 1)
            after_read = os.fstat(input_file.fileno())
        after = path.lstat()
    except OSError as exc:
        raise IncompleteEvidence(f"unreadable-{label}") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        len(data) > MAX_INPUT_BYTES
        or len(data) != before.st_size
        or any(getattr(before, field) != getattr(opened, field) for field in stable_fields)
        or any(getattr(opened, field) != getattr(after_read, field) for field in stable_fields)
        or any(getattr(after_read, field) != getattr(after, field) for field in stable_fields)
    ):
        raise IncompleteEvidence(f"unstable-{label}-file")
    return data


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _exact_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IncompleteEvidence(f"invalid-{label}-shape")
    return value


def _same_json(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _same_json(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _same_json(item, expected_item)
            for item, expected_item in zip(value, expected, strict=True)
        )
    return bool(value == expected)


def _reason_label(value: str) -> str:
    without_camel_case = re.sub(r"(?<!^)(?=[A-Z])", "-", value)
    return without_camel_case.lstrip("$").lower()


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise IncompleteEvidence(f"unsafe-{label}")
    return value


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX_64.fullmatch(value) is None:
        raise IncompleteEvidence(f"invalid-{label}")
    return value


def load_profile(
    profile_path: Path,
    manifest_path: Path,
    *,
    profile_bytes: bytes | None = None,
    manifest_bytes: bytes | None = None,
) -> dict[str, Any]:
    try:
        profile_bytes = profile_bytes or _read_bounded_regular(profile_path, "profile")
        manifest_bytes = manifest_bytes or _read_bounded_regular(manifest_path, "manifest")
        profile = json.loads(profile_bytes.decode("utf-8"))
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IncompleteEvidence("unreadable-contract-input") from exc
    if not isinstance(profile, dict):
        raise IncompleteEvidence("invalid-profile-shape")
    schema_version = profile.get("schemaVersion")
    if not _integer(schema_version) or schema_version not in {1, 2}:
        raise IncompleteEvidence("unsupported-profile-version")
    expected_keys = PROFILE_KEYS | ({"policyVersion"} if schema_version == 2 else set())
    profile = _exact_object(profile, expected_keys, "profile")
    manifest_flows = manifest.get("phase7ApprovedCoreFlows") if isinstance(manifest, dict) else None
    manifest_ids = (
        [flow.get("id") for flow in manifest_flows]
        if isinstance(manifest_flows, list)
        and all(isinstance(flow, dict) for flow in manifest_flows)
        else []
    )
    alternating = [
        list(RUNTIMES) if index % 2 == 0 else list(reversed(RUNTIMES)) for index in range(10)
    ]
    frozen: dict[str, Any] = {
        "manifestPath": "contracts/manifest.json",
        "flowIds": list(FROZEN_FLOW_IDS),
        "loginFlowIds": ["password-direct-login-token"],
        "expectedFailureFlowIds": list(FROZEN_FLOW_IDS),
        "outcomeContract": FROZEN_OUTCOME_CONTRACT,
        "epochs": 10,
        "warmupTrialsPerFlowRuntimeEpoch": 20,
        "measuredTrialsPerFlowRuntimeEpoch": 100,
        "successTrialsPerApplicableFlowRuntimeEpoch": 80,
        "expectedFailureTrialsPerApplicableFlowRuntimeEpoch": 20,
        "epochRuntimeOrder": alternating,
        "load": {
            "model": "open-loop",
            "ratePerSecond": 20,
            "timeoutMs": 5000,
            "maxInFlight": 16,
        },
        "latency": {
            "clock": "monotonic",
            "interval": "scheduled-to-completed",
            "percentile": "nearest-rank-p95",
        },
        "overallReplacementReady": False,
    }
    policy: dict[str, Any] = {
        "allowOverrides": False,
        "retries": 0,
        "allowOutlierRemoval": False,
        "unexpectedOutcomeCountMax": 0,
        "candidateP95MaxPercentOfBaseline": 120,
        "candidateErrorIncreasePer1000": 10,
        "candidateLoginSuccessDecreasePer1000": 20,
    }
    if schema_version == 1:
        frozen.update(
            {
                "$schema": "profile.schema.json",
                "schemaVersion": 1,
                "suiteId": "phase7-performance-v1",
                "policy": policy,
            }
        )
    else:
        if profile.get("policyVersion") != 2:
            raise IncompleteEvidence("profile-drift-policy-version")
        policy_value = profile.get("policy")
        p50_cutoff = (
            policy_value.get("candidateP50MaxPercentOfBaseline")
            if isinstance(policy_value, dict)
            else None
        )
        if not _integer(p50_cutoff) or cast(int, p50_cutoff) <= 0:
            raise IncompleteEvidence("profile-p50-cutoff-unset")
        policy["candidateP50MaxPercentOfBaseline"] = p50_cutoff
        frozen.update(
            {
                "$schema": "profile-v2.schema.json",
                "schemaVersion": 2,
                "suiteId": "phase7-performance-v2",
                "policyVersion": 2,
                "policy": policy,
            }
        )
    for key, expected in frozen.items():
        if not _same_json(profile.get(key), expected):
            raise IncompleteEvidence(f"profile-drift-{_reason_label(key)}")
    if (
        manifest_ids != list(FROZEN_FLOW_IDS)
        or any(
            not isinstance(flow_id, str) or SAFE_ID.fullmatch(flow_id) is None
            for flow_id in manifest_ids
        )
        or len(set(manifest_ids)) != 10
    ):
        raise IncompleteEvidence("manifest-flow-set-invalid")
    actual_manifest_hash = _sha256(manifest_bytes)
    if profile.get("manifestSha256") != actual_manifest_hash:
        raise IncompleteEvidence("manifest-hash-mismatch")
    return profile


def generate_plan(profile: dict[str, Any], profile_hash: str) -> dict[str, Any]:
    """Generate identities only; this never creates measurements or qualifying evidence."""
    samples = []
    failure_flows = set(profile["expectedFailureFlowIds"])
    for epoch, order in enumerate(profile["epochRuntimeOrder"], start=1):
        for runtime in order:
            for flow_id in profile["flowIds"]:
                for trial in range(1, 101):
                    kind = (
                        "expected-failure" if flow_id in failure_flows and trial > 80 else "success"
                    )
                    samples.append(
                        {
                            "flowId": flow_id,
                            "runtime": runtime,
                            "epoch": epoch,
                            "trial": trial,
                            "kind": kind,
                        }
                    )
    return {
        "schemaVersion": profile["schemaVersion"],
        "suiteId": profile["suiteId"],
        "profileSha256": profile_hash,
        "manifestSha256": profile["manifestSha256"],
        "measurementRows": len(samples),
        "qualifyingEvidence": False,
        "samples": samples,
    }


def _validate_provenance(document: dict[str, Any]) -> None:
    _safe_id(document.get("runId"), "run-id")
    revision = document.get("sourceRevision")
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise IncompleteEvidence("invalid-source-revision")
    provenance = _exact_object(
        document.get("provenance"),
        {"databaseSnapshotSha256", "redisNamespace", "harnessRevision", "runtimes"},
        "provenance",
    )
    _hex64(provenance.get("databaseSnapshotSha256"), "database-snapshot-hash")
    _safe_id(provenance.get("redisNamespace"), "redis-namespace")
    harness_revision = provenance.get("harnessRevision")
    if not isinstance(harness_revision, str) or REVISION.fullmatch(harness_revision) is None:
        raise IncompleteEvidence("invalid-harness-revision")
    runtimes = _exact_object(provenance.get("runtimes"), set(RUNTIMES), "runtime-provenance")
    for runtime in RUNTIMES:
        item = _exact_object(
            runtimes.get(runtime),
            {"imageDigest", "configSha256"},
            "runtime-provenance-item",
        )
        digest = item.get("imageDigest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise IncompleteEvidence("invalid-image-digest")
        _hex64(digest[7:], "image-digest")
        _hex64(item.get("configSha256"), "config-hash")


def _validate_epochs(
    document: dict[str, Any], profile: dict[str, Any]
) -> dict[tuple[int, str], tuple[str, int]]:
    epochs = document.get("epochs")
    if not isinstance(epochs, list) or len(epochs) != 10:
        raise IncompleteEvidence("invalid-epoch-count")
    resets_by_block: dict[tuple[int, str], tuple[str, int]] = {}
    for number, item in enumerate(epochs, start=1):
        epoch = _exact_object(
            item,
            {
                "epoch",
                "runtimeOrder",
                "warmupCompletedPerFlowRuntime",
                "warmupIncluded",
                "resets",
            },
            "epoch",
        )
        if (
            not _integer(epoch.get("epoch"))
            or epoch.get("epoch") != number
            or epoch.get("runtimeOrder") != profile["epochRuntimeOrder"][number - 1]
            or not _integer(epoch.get("warmupCompletedPerFlowRuntime"))
            or epoch.get("warmupCompletedPerFlowRuntime") != 20
            or epoch.get("warmupIncluded") is not False
        ):
            raise IncompleteEvidence("epoch-order-or-warmup-mismatch")
        resets = epoch.get("resets")
        if not isinstance(resets, list) or len(resets) != 2:
            raise IncompleteEvidence("invalid-reset-count")
        if [reset.get("runtime") if isinstance(reset, dict) else None for reset in resets] != epoch[
            "runtimeOrder"
        ]:
            raise IncompleteEvidence("reset-order-mismatch")
        for reset in resets:
            reset = _exact_object(
                reset,
                {"runtime", "resetId", "stateSha256", "boundaryNs", "status"},
                "reset",
            )
            runtime = reset.get("runtime")
            if runtime not in RUNTIMES or reset.get("status") != "PASS":
                raise IncompleteEvidence("reset-not-proven")
            reset_id = _safe_id(reset.get("resetId"), "reset-id")
            _hex64(reset.get("stateSha256"), "reset-state-hash")
            boundary_ns = reset.get("boundaryNs")
            if not _integer(boundary_ns):
                raise IncompleteEvidence("invalid-reset-boundary")
            boundary_ns = cast(int, boundary_ns)
            if boundary_ns < 0:
                raise IncompleteEvidence("invalid-reset-boundary")
            if reset_id in {value[0] for value in resets_by_block.values()}:
                raise IncompleteEvidence("duplicate-reset-id")
            resets_by_block[(number, runtime)] = (reset_id, boundary_ns)
    return resets_by_block


def _expected_identities(
    profile: dict[str, Any],
) -> list[tuple[int, str, str, int, str]]:
    return [
        (row["epoch"], row["runtime"], row["flowId"], row["trial"], row["kind"])
        for row in generate_plan(profile, "0" * 64)["samples"]
    ]


def _validate_samples(
    document: dict[str, Any],
    profile: dict[str, Any],
    resets_by_block: dict[tuple[int, str], tuple[str, int]],
) -> list[dict[str, Any]]:
    samples = document.get("samples")
    if not isinstance(samples, list) or len(samples) != 20_000:
        raise IncompleteEvidence("invalid-sample-count")
    identities: list[tuple[int, str, str, int, str]] = []
    spacing_ns = 1_000_000_000 // profile["load"]["ratePerSecond"]
    timeout_ns = profile["load"]["timeoutMs"] * 1_000_000
    scheduled_by_block: dict[tuple[int, str], list[int]] = {}
    intervals_by_block: dict[tuple[int, str], list[tuple[int, int]]] = {}
    for raw in samples:
        sample = _exact_object(raw, SAMPLE_KEYS, "sample")
        flow_id = sample.get("flowId")
        runtime = sample.get("runtime")
        epoch = sample.get("epoch")
        trial = sample.get("trial")
        kind = sample.get("kind")
        outcome = sample.get("outcome")
        scheduled = sample.get("scheduledNs")
        completed = sample.get("completedNs")
        if flow_id not in profile["flowIds"] or runtime not in RUNTIMES:
            raise IncompleteEvidence("unknown-flow-or-runtime")
        if (
            not _integer(epoch)
            or not _integer(trial)
            or not _integer(scheduled)
            or not _integer(completed)
        ):
            raise IncompleteEvidence("invalid-sample-integer")
        epoch = cast(int, epoch)
        trial = cast(int, trial)
        scheduled = cast(int, scheduled)
        completed = cast(int, completed)
        runtime = cast(str, runtime)
        flow_id = cast(str, flow_id)
        kind = cast(str, kind)
        if kind not in {"success", "expected-failure"} or outcome not in {
            "success",
            "expected-failure",
            "unexpected-outcome",
            "unexpected-error",
            "timeout",
        }:
            raise IncompleteEvidence("invalid-sample-class")
        if not 1 <= epoch <= 10 or not 1 <= trial <= 100:
            raise IncompleteEvidence("sample-index-out-of-range")
        if scheduled < 0 or completed < 0:
            raise IncompleteEvidence("sample-time-out-of-range")
        if (
            not _integer(sample.get("attempt"))
            or sample.get("attempt") != 1
            or not _integer(sample.get("retryCount"))
            or sample.get("retryCount") != 0
        ):
            raise IncompleteEvidence("retry-present")
        if sample.get("outlierRemoved") is not False:
            raise IncompleteEvidence("outlier-removal-present")
        reset = resets_by_block.get((epoch, runtime))
        if reset is None or sample.get("resetId") != reset[0]:
            raise IncompleteEvidence("sample-reset-mismatch")
        if completed < scheduled:
            raise IncompleteEvidence("negative-latency")
        latency = completed - scheduled
        if outcome == "timeout" and latency < timeout_ns:
            raise IncompleteEvidence("early-timeout")
        if outcome != "timeout" and latency > timeout_ns:
            raise IncompleteEvidence("timeout-not-recorded")
        identities.append((epoch, runtime, flow_id, trial, kind))
        block = (epoch, runtime)
        scheduled_by_block.setdefault(block, []).append(scheduled)
        intervals_by_block.setdefault(block, []).append((scheduled, completed))
    if identities != _expected_identities(profile):
        raise IncompleteEvidence("sample-identity-order-or-count-mismatch")
    if len(set(identities)) != len(identities):
        raise IncompleteEvidence("duplicate-sample")
    block_order = [
        (epoch, runtime)
        for epoch, runtime_order in enumerate(profile["epochRuntimeOrder"], start=1)
        for runtime in runtime_order
    ]
    previous_block_end: int | None = None
    all_intervals: list[tuple[int, int]] = []
    for block in block_order:
        scheduled_values = scheduled_by_block[block]
        if any(right - left != spacing_ns for left, right in pairwise(scheduled_values)):
            raise IncompleteEvidence("open-loop-rate-mismatch")
        window_start = scheduled_values[0]
        if resets_by_block[block][1] != window_start:
            raise IncompleteEvidence("reset-boundary-mismatch")
        if previous_block_end is not None and window_start < previous_block_end:
            raise IncompleteEvidence("global-block-overlap-or-order-mismatch")
        nominal_window_end = window_start + len(scheduled_values) * spacing_ns
        maximum_completed = max(completed for _scheduled, completed in intervals_by_block[block])
        previous_block_end = max(nominal_window_end, maximum_completed)
        all_intervals.extend(intervals_by_block[block])
    active_completed: list[int] = []
    for scheduled, completed in all_intervals:
        active_completed = [end for end in active_completed if end > scheduled]
        active_completed.append(completed)
        if len(active_completed) > profile["load"]["maxInFlight"]:
            raise IncompleteEvidence("max-in-flight-exceeded")
    return samples


def _percentile(values: list[int], percentile: int) -> int:
    if not values:
        raise IncompleteEvidence("empty-metric-sample")
    ordered = sorted(values)
    return ordered[(percentile * len(ordered) + 99) // 100 - 1]


def _metrics(
    samples: list[dict[str, Any]], profile: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    metrics: dict[str, Any] = {"flows": {}, "aggregate": {}}
    reasons: list[str] = []
    groups = [*profile["flowIds"], "aggregate"]
    for group in groups:
        selected = (
            samples if group == "aggregate" else [row for row in samples if row["flowId"] == group]
        )
        runtime_metrics: dict[str, Any] = {}
        for runtime in RUNTIMES:
            rows = [row for row in selected if row["runtime"] == runtime]
            latencies = [row["completedNs"] - row["scheduledNs"] for row in rows]
            errors = sum(
                row["outcome"]
                != profile["outcomeContract"][row["flowId"]][
                    "success" if row["kind"] == "success" else "expectedFailure"
                ]
                for row in rows
            )
            runtime_metric = {
                "samples": len(rows),
                "p95Ns": _percentile(latencies, 95),
                "errors": errors,
            }
            if profile["schemaVersion"] == 2:
                runtime_metric["p50Ns"] = _percentile(latencies, 50)
            runtime_metrics[runtime] = runtime_metric
        baseline = runtime_metrics["express"]
        candidate = runtime_metrics["fastapi"]
        for runtime in RUNTIMES:
            if runtime_metrics[runtime]["errors"] > profile["policy"]["unexpectedOutcomeCountMax"]:
                reasons.append(f"absolute-error-{runtime}-{group}")
        if (
            profile["schemaVersion"] == 2
            and candidate["p50Ns"] * 100
            > baseline["p50Ns"] * profile["policy"]["candidateP50MaxPercentOfBaseline"]
        ):
            reasons.append(f"p50-threshold-{group}")
        if (
            candidate["p95Ns"] * 100
            > baseline["p95Ns"] * profile["policy"]["candidateP95MaxPercentOfBaseline"]
        ):
            reasons.append(f"p95-threshold-{group}")
        error_delta_scaled = (
            candidate["errors"] * baseline["samples"] - baseline["errors"] * candidate["samples"]
        ) * 1000
        if (
            error_delta_scaled
            > profile["policy"]["candidateErrorIncreasePer1000"]
            * candidate["samples"]
            * baseline["samples"]
        ):
            reasons.append(f"error-threshold-{group}")
        if group == "aggregate":
            metrics["aggregate"] = runtime_metrics
        else:
            metrics["flows"][group] = runtime_metrics
    login_rows = [
        row
        for row in samples
        if row["flowId"] in profile["loginFlowIds"] and row["kind"] == "success"
    ]
    login: dict[str, Any] = {}
    for runtime in RUNTIMES:
        rows = [row for row in login_rows if row["runtime"] == runtime]
        login[runtime] = {
            "samples": len(rows),
            "successes": sum(row["outcome"] == "success" for row in rows),
        }
    baseline_login = login["express"]
    candidate_login = login["fastapi"]
    decrease_scaled = (
        baseline_login["successes"] * candidate_login["samples"]
        - candidate_login["successes"] * baseline_login["samples"]
    ) * 1000
    if (
        decrease_scaled
        > profile["policy"]["candidateLoginSuccessDecreasePer1000"]
        * baseline_login["samples"]
        * candidate_login["samples"]
    ):
        reasons.append("login-success-threshold-aggregate")
    metrics["loginSuccess"] = login
    return metrics, reasons


def evaluate(
    document: Any,
    profile_path: Path = DEFAULT_PROFILE,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    profile_hash = "0" * 64
    manifest_hash = "0" * 64
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "suiteId": "phase7-performance-v1",
        "status": "INCOMPLETE",
        "reasonCodes": [],
        "profileSha256": profile_hash,
        "manifestSha256": manifest_hash,
        "validatedSampleCount": 0,
        "observedSampleCount": 0,
        "observedSampleCountCapped": False,
        "metrics": {},
        "qualifyingEvidence": False,
        "overallReplacementReady": False,
    }
    try:
        profile_bytes = _read_bounded_regular(profile_path, "profile")
        # Select only the error-envelope version here, never policy authority.
        # Recognizable v2 profiles must report v2 INCOMPLETE even when unfrozen.
        try:
            header = json.loads(profile_bytes.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            header = None
        if (
            isinstance(header, dict)
            and type(header.get("schemaVersion")) is int
            and header["schemaVersion"] == 2
            and header.get("suiteId") == "phase7-performance-v2"
        ):
            result["schemaVersion"] = 2
            result["suiteId"] = "phase7-performance-v2"
        manifest_bytes = _read_bounded_regular(manifest_path, "manifest")
        profile_hash = _sha256(profile_bytes)
        manifest_hash = _sha256(manifest_bytes)
        result["profileSha256"] = profile_hash
        result["manifestSha256"] = manifest_hash
        profile = load_profile(
            profile_path,
            manifest_path,
            profile_bytes=profile_bytes,
            manifest_bytes=manifest_bytes,
        )
        result["schemaVersion"] = profile["schemaVersion"]
        result["suiteId"] = profile["suiteId"]
        evidence = _exact_object(
            document,
            {
                "schemaVersion",
                "suiteId",
                "profileSha256",
                "manifestSha256",
                "runId",
                "sourceRevision",
                "provenance",
                "epochs",
                "samples",
            },
            "evidence",
        )
        samples_value = evidence.get("samples")
        if isinstance(samples_value, list):
            result["observedSampleCount"] = min(len(samples_value), MAX_INPUT_BYTES)
            result["observedSampleCountCapped"] = len(samples_value) > MAX_INPUT_BYTES
        if (
            not _integer(evidence.get("schemaVersion"))
            or evidence.get("schemaVersion") != profile["schemaVersion"]
            or evidence.get("suiteId") != profile["suiteId"]
        ):
            raise IncompleteEvidence("evidence-version-or-suite-mismatch")
        if (
            evidence.get("profileSha256") != profile_hash
            or evidence.get("manifestSha256") != manifest_hash
        ):
            raise IncompleteEvidence("evidence-hash-binding-mismatch")
        _validate_provenance(evidence)
        reset_ids = _validate_epochs(evidence, profile)
        samples = _validate_samples(evidence, profile, reset_ids)
        result["validatedSampleCount"] = len(samples)
        metrics, reasons = _metrics(samples, profile)
        result["metrics"] = metrics
        result["reasonCodes"] = reasons
        result["status"] = "FAIL" if reasons else "PASS"
    except (IncompleteEvidence, OSError, json.JSONDecodeError) as exc:
        reason = str(exc) if isinstance(exc, IncompleteEvidence) else "unreadable-evidence"
        result["reasonCodes"] = [reason]
    return result


def _write_json(value: Any, output: Path | None) -> None:
    text = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if output is None:
        sys.stdout.write(text)
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.tmp-", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
            output_file.write(text)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.link(temporary, output)
        directory_descriptor = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate_parser = subparsers.add_parser("generate-plan")
    generate_parser.add_argument("--output", type=Path)
    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--input", type=Path, required=True)
    evaluate_parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "generate-plan":
        try:
            profile_bytes = _read_bounded_regular(args.profile, "profile")
            manifest_bytes = _read_bounded_regular(args.manifest, "manifest")
            profile = load_profile(
                args.profile,
                args.manifest,
                profile_bytes=profile_bytes,
                manifest_bytes=manifest_bytes,
            )
            _write_json(generate_plan(profile, _sha256(profile_bytes)), args.output)
            return 0
        except (IncompleteEvidence, OSError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"performance contract incomplete: {exc}\n")
            return 2
    try:
        raw_input = _read_bounded_regular(args.input, "evidence")
        document = json.loads(raw_input.decode("utf-8"))
    except (IncompleteEvidence, UnicodeDecodeError, json.JSONDecodeError):
        document = None
    result = evaluate(document, args.profile, args.manifest)
    try:
        _write_json(result, args.output)
    except OSError as exc:
        sys.stderr.write(f"performance contract output refused: {exc}\n")
        return 2
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
