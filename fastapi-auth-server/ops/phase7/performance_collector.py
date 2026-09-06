#!/usr/bin/env python3
"""Development-only open-loop Phase 7 performance collector.

The collector owns scheduling and monotonic timestamps.  Action drivers may perform
HTTP work and classify its outcome, but cannot supply timing rows.  Output remains
non-qualifying until the controlled collector and attestation chain authenticate it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast
from urllib import parse

REPO_ROOT = Path(__file__).resolve().parents[3]
PERFORMANCE_EVALUATOR = REPO_ROOT / "contracts/bin/performance.py"
RUNTIMES = ("express", "fastapi")
OUTCOMES = {
    "success",
    "expected-failure",
    "unexpected-outcome",
    "unexpected-error",
    "timeout",
}
FULL_EPOCHS = 10
FULL_WARMUPS = 20
FULL_MEASURED = 100
FULL_RATE_PER_SECOND = 20
FULL_MAX_IN_FLIGHT = 16
FULL_TIMEOUT_SECONDS = 5.0
FULL_MEASUREMENT_ROWS = 20_000
REQUIRED_REPEATS = 3
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
ORIGIN_FORM_PATH = re.compile(r"^/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$")


class CollectionError(Exception):
    """The collector could not produce structurally trustworthy development data."""


class ActionTimedOut(Exception):
    """An action reached its collector-owned timeout."""

    reason_code = "absolute-action-deadline-exceeded"


class RemoteActionDrainUnproven(CollectionError):
    """The local socket is closed, but the remote handler may still mutate state."""

    deadline_reason_code = ActionTimedOut.reason_code
    drain_reason_code = "remote-action-drain-unproven"

    def __init__(self) -> None:
        super().__init__(self.drain_reason_code)


@dataclass(frozen=True)
class ActionRequest:
    flow_id: str
    runtime: str
    epoch: int
    trial: int
    kind: str
    phase: str


class MeasuredAction(Protocol):
    def execute(self, action: ActionRequest, timeout_seconds: float) -> str: ...

    def reset(self, *, epoch: int, runtime: str, timeout_seconds: float) -> ResetProof: ...


@dataclass(frozen=True)
class ResetProof:
    reset_id: str
    state_sha256: str
    status: str = "PASS"


@dataclass(frozen=True)
class BlockSpec:
    flow_ids: tuple[str, ...]
    expected_failure_flow_ids: frozenset[str]
    warmup_trials_per_flow: int
    measured_trials_per_flow: int
    success_trials_per_flow: int
    rate_per_second: int
    max_in_flight: int
    timeout_seconds: float

    def validate(self) -> None:
        if not self.flow_ids or len(set(self.flow_ids)) != len(self.flow_ids):
            raise CollectionError("invalid-flow-set")
        if not self.expected_failure_flow_ids.issubset(self.flow_ids):
            raise CollectionError("invalid-expected-failure-flow-set")
        integers = (
            self.warmup_trials_per_flow,
            self.measured_trials_per_flow,
            self.success_trials_per_flow,
            self.rate_per_second,
            self.max_in_flight,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in integers):
            raise CollectionError("invalid-block-integer")
        if (
            self.warmup_trials_per_flow < 0
            or self.measured_trials_per_flow <= 0
            or not 0 <= self.success_trials_per_flow <= self.measured_trials_per_flow
            or self.rate_per_second <= 0
            or self.max_in_flight <= 0
            or not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise CollectionError("invalid-block-policy")


@dataclass(frozen=True)
class ProfileSpec:
    document: dict[str, Any]
    profile_sha256: str
    manifest_sha256: str

    @classmethod
    def load(cls, profile_path: Path, manifest_path: Path) -> ProfileSpec:
        evaluator = _load_evaluator()
        profile_bytes = evaluator._read_bounded_regular(profile_path, "profile")
        manifest_bytes = evaluator._read_bounded_regular(manifest_path, "manifest")
        profile = cast(
            dict[str, Any],
            evaluator.load_profile(
                profile_path,
                manifest_path,
                profile_bytes=profile_bytes,
                manifest_bytes=manifest_bytes,
            ),
        )
        if profile.get("schemaVersion") != 2 or profile.get("policyVersion") != 2:
            raise CollectionError("reviewed-profile-v2-required")
        return cls(
            profile,
            evaluator._sha256(profile_bytes),
            evaluator._sha256(manifest_bytes),
        )

    def block_spec(self) -> BlockSpec:
        load = self.document["load"]
        return BlockSpec(
            flow_ids=tuple(self.document["flowIds"]),
            expected_failure_flow_ids=frozenset(self.document["expectedFailureFlowIds"]),
            warmup_trials_per_flow=self.document["warmupTrialsPerFlowRuntimeEpoch"],
            measured_trials_per_flow=self.document["measuredTrialsPerFlowRuntimeEpoch"],
            success_trials_per_flow=self.document["successTrialsPerApplicableFlowRuntimeEpoch"],
            rate_per_second=load["ratePerSecond"],
            max_in_flight=load["maxInFlight"],
            timeout_seconds=load["timeoutMs"] / 1000,
        )

    def require_full_contract(self) -> None:
        spec = self.block_spec()
        if (
            self.document["epochs"] != FULL_EPOCHS
            or spec.warmup_trials_per_flow != FULL_WARMUPS
            or spec.measured_trials_per_flow != FULL_MEASURED
            or spec.rate_per_second != FULL_RATE_PER_SECOND
            or spec.max_in_flight != FULL_MAX_IN_FLIGHT
            or spec.timeout_seconds != FULL_TIMEOUT_SECONDS
            or len(spec.flow_ids) * len(RUNTIMES) * FULL_EPOCHS * FULL_MEASURED
            != FULL_MEASUREMENT_ROWS
        ):
            raise CollectionError("full-performance-contract-mismatch")


@dataclass(frozen=True)
class BlockCollection:
    epoch: dict[str, Any]
    samples: tuple[dict[str, Any], ...]
    maximum_in_flight: int


@dataclass(frozen=True)
class CollectedRun:
    document: dict[str, Any]
    evaluation: dict[str, Any]
    policy_version: int

    @property
    def run_id(self) -> str:
        return cast(str, self.document["runId"])


def _load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "phase7_performance_evaluator", PERFORMANCE_EVALUATOR
    )
    if spec is None or spec.loader is None:
        raise CollectionError("performance-evaluator-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _outcome(value: Any) -> str:
    if not isinstance(value, str) or value not in OUTCOMES:
        return "unexpected-error"
    return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def _expected_kind(spec: BlockSpec, flow_id: str, trial: int) -> str:
    if flow_id in spec.expected_failure_flow_ids and trial > spec.success_trials_per_flow:
        return "expected-failure"
    return "success"


def _sleep_until(
    target_ns: int,
    *,
    clock_ns: Callable[[], int],
    sleep: Callable[[float], None],
) -> None:
    while True:
        remaining_ns = target_ns - clock_ns()
        if remaining_ns <= 0:
            return
        sleep(remaining_ns / 1_000_000_000)


def _execute_measured(
    action_driver: MeasuredAction,
    action: ActionRequest,
    scheduled_ns: int,
    reset_id: str,
    deadline_ns: int,
    clock_ns: Callable[[], int],
    concurrency_lock: threading.Lock,
    concurrency: list[int],
) -> dict[str, Any]:
    with concurrency_lock:
        concurrency[0] += 1
        concurrency[1] = max(concurrency[1], concurrency[0])
    try:
        remaining_seconds = (deadline_ns - clock_ns()) / 1_000_000_000
        if remaining_seconds <= 0:
            return {
                "flowId": action.flow_id,
                "runtime": action.runtime,
                "epoch": action.epoch,
                "trial": action.trial,
                "kind": action.kind,
                "scheduledNs": scheduled_ns,
                "completedNs": clock_ns(),
                "outcome": "timeout",
                "attempt": 1,
                "retryCount": 0,
                "outlierRemoved": False,
                "resetId": reset_id,
            }
        try:
            outcome = _outcome(action_driver.execute(action, remaining_seconds))
        except ActionTimedOut as exc:
            raise RemoteActionDrainUnproven from exc
        except CollectionError:
            raise
        except Exception:
            outcome = "unexpected-error"
        completed_ns = clock_ns()
        if completed_ns > deadline_ns:
            outcome = "timeout"
    finally:
        with concurrency_lock:
            concurrency[0] -= 1
    return {
        "flowId": action.flow_id,
        "runtime": action.runtime,
        "epoch": action.epoch,
        "trial": action.trial,
        "kind": action.kind,
        "scheduledNs": scheduled_ns,
        "completedNs": completed_ns,
        "outcome": outcome,
        "attempt": 1,
        "retryCount": 0,
        "outlierRemoved": False,
        "resetId": reset_id,
    }


def collect_block(
    *,
    epoch: int,
    runtime: str,
    runtime_order: Sequence[str],
    spec: BlockSpec,
    action_driver: MeasuredAction,
    clock_ns: Callable[[], int] = time.monotonic_ns,
    sleep: Callable[[float], None] = time.sleep,
) -> BlockCollection:
    """Collect one runtime block; warmups and reset are excluded from samples."""

    spec.validate()
    if type(action_driver) is not LoopbackJsonAction:
        raise CollectionError("bounded-loopback-action-required")
    if runtime not in RUNTIMES or tuple(runtime_order) not in {
        RUNTIMES,
        tuple(reversed(RUNTIMES)),
    }:
        raise CollectionError("invalid-runtime-order")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise CollectionError("invalid-epoch")

    for flow_id in spec.flow_ids:
        for trial in range(1, spec.warmup_trials_per_flow + 1):
            action = ActionRequest(flow_id, runtime, epoch, trial, "success", "warmup")
            try:
                observed = _outcome(action_driver.execute(action, spec.timeout_seconds))
            except ActionTimedOut as exc:
                raise RemoteActionDrainUnproven from exc
            except CollectionError:
                raise
            except Exception as exc:
                raise CollectionError("warmup-action-failed") from exc
            if observed != "success":
                raise CollectionError("warmup-action-failed")

    try:
        reset = action_driver.reset(
            epoch=epoch, runtime=runtime, timeout_seconds=spec.timeout_seconds
        )
    except ActionTimedOut as exc:
        raise RemoteActionDrainUnproven from exc
    if (
        not isinstance(reset, ResetProof)
        or not isinstance(reset.reset_id, str)
        or SAFE_ID.fullmatch(reset.reset_id) is None
        or not isinstance(reset.status, str)
        or reset.status != "PASS"
        or not isinstance(reset.state_sha256, str)
        or HEX_64.fullmatch(reset.state_sha256) is None
    ):
        raise CollectionError("reset-not-proven")

    spacing_ns = 1_000_000_000 // spec.rate_per_second
    block_start_ns = clock_ns()
    futures: list[Future[dict[str, Any]]] = []
    concurrency = [0, 0]
    concurrency_lock = threading.Lock()
    executor = ThreadPoolExecutor(max_workers=spec.max_in_flight)
    capacity_exceeded = False
    action_failed = False
    observed_futures: set[Future[dict[str, Any]]] = set()
    try:
        offset = 0
        for flow_id in spec.flow_ids:
            for trial in range(1, spec.measured_trials_per_flow + 1):
                scheduled_ns = block_start_ns + offset * spacing_ns
                _sleep_until(scheduled_ns, clock_ns=clock_ns, sleep=sleep)
                for future in futures:
                    if future.done() and future not in observed_futures:
                        observed_futures.add(future)
                        if future.exception() is not None:
                            action_failed = True
                            break
                if action_failed:
                    break
                active = sum(not future.done() for future in futures)
                if active >= spec.max_in_flight:
                    capacity_exceeded = True
                    break
                kind = _expected_kind(spec, flow_id, trial)
                action = ActionRequest(flow_id, runtime, epoch, trial, kind, "measured")
                futures.append(
                    executor.submit(
                        _execute_measured,
                        action_driver,
                        action,
                        scheduled_ns,
                        reset.reset_id,
                        scheduled_ns + int(spec.timeout_seconds * 1_000_000_000),
                        clock_ns,
                        concurrency_lock,
                        concurrency,
                    )
                )
                offset += 1
            if capacity_exceeded:
                break
            if action_failed:
                break
    finally:
        executor.shutdown(wait=True, cancel_futures=False)
    for future in futures:
        exception = future.exception()
        if isinstance(exception, CollectionError):
            raise exception
        if exception is not None:
            raise CollectionError("measured-action-failed") from exception
    if capacity_exceeded:
        raise CollectionError("scheduler-capacity-exceeded")
    samples = tuple(future.result() for future in futures)

    return BlockCollection(
        epoch={
            "epoch": epoch,
            "runtimeOrder": list(runtime_order),
            "warmupCompletedPerFlowRuntime": spec.warmup_trials_per_flow,
            "warmupIncluded": False,
            "resets": [
                {
                    "runtime": runtime,
                    "resetId": reset.reset_id,
                    "stateSha256": reset.state_sha256,
                    "boundaryNs": block_start_ns,
                    "status": "PASS",
                }
            ],
        },
        samples=samples,
        maximum_in_flight=concurrency[1],
    )


def collect_full_run(
    *,
    profile_path: Path,
    manifest_path: Path,
    run_id: str,
    source_revision: str,
    provenance: Mapping[str, Any],
    action_driver: MeasuredAction,
) -> CollectedRun:
    """Execute the exact reviewed v2 profile and evaluate collector-owned rows."""

    profile = ProfileSpec.load(profile_path, manifest_path)
    profile.require_full_contract()
    spec = profile.block_spec()
    samples: list[dict[str, Any]] = []
    epochs: list[dict[str, Any]] = []
    for epoch, runtime_order in enumerate(profile.document["epochRuntimeOrder"], start=1):
        resets: list[dict[str, Any]] = []
        for runtime in runtime_order:
            block = collect_block(
                epoch=epoch,
                runtime=runtime,
                runtime_order=runtime_order,
                spec=spec,
                action_driver=action_driver,
            )
            resets.extend(block.epoch["resets"])
            samples.extend(block.samples)
        epochs.append(
            {
                "epoch": epoch,
                "runtimeOrder": list(runtime_order),
                "warmupCompletedPerFlowRuntime": spec.warmup_trials_per_flow,
                "warmupIncluded": False,
                "resets": resets,
            }
        )
    if len(samples) != FULL_MEASUREMENT_ROWS:
        raise CollectionError("full-measurement-count-mismatch")
    document: dict[str, Any] = {
        "schemaVersion": 2,
        "suiteId": profile.document["suiteId"],
        "profileSha256": profile.profile_sha256,
        "manifestSha256": profile.manifest_sha256,
        "runId": run_id,
        "sourceRevision": source_revision,
        "provenance": dict(provenance),
        "epochs": epochs,
        "samples": samples,
    }
    evaluator = _load_evaluator()
    evaluation = cast(dict[str, Any], evaluator.evaluate(document, profile_path, manifest_path))
    evaluation["qualifyingEvidence"] = False
    evaluation["overallReplacementReady"] = False
    return CollectedRun(document, evaluation, profile.document["policyVersion"])


def validate_repeat_group(
    runs: Sequence[CollectedRun], *, profile_path: Path, manifest_path: Path
) -> dict[str, Any]:
    """Require three independent, individually passing full-profile runs."""

    if len(runs) != REQUIRED_REPEATS:
        raise CollectionError("repeat-count-mismatch")
    profile = ProfileSpec.load(profile_path, manifest_path)
    profile.require_full_contract()
    evaluator = _load_evaluator()
    first = runs[0]
    binding = (
        first.document.get("schemaVersion"),
        first.document.get("suiteId"),
        first.document.get("sourceRevision"),
        first.document.get("profileSha256"),
        first.document.get("manifestSha256"),
        first.policy_version,
    )
    if (
        binding[0] != 2
        or binding[1] != "phase7-performance-v2"
        or not isinstance(binding[2], str)
        or REVISION.fullmatch(binding[2]) is None
        or not isinstance(binding[3], str)
        or HEX_64.fullmatch(binding[3]) is None
        or not isinstance(binding[4], str)
        or HEX_64.fullmatch(binding[4]) is None
        or binding[5] != 2
    ):
        raise CollectionError("invalid-repeat-binding")
    run_ids: set[str] = set()
    measurement_hashes: set[str] = set()
    provenance_hashes: set[str] = set()
    run_digests: list[dict[str, str]] = []
    for run in runs:
        current = (
            run.document.get("schemaVersion"),
            run.document.get("suiteId"),
            run.document.get("sourceRevision"),
            run.document.get("profileSha256"),
            run.document.get("manifestSha256"),
            run.policy_version,
        )
        if current != binding:
            raise CollectionError("repeat-binding-mismatch")
        if run.run_id in run_ids:
            raise CollectionError("duplicate-repeat-run-id")
        if SAFE_ID.fullmatch(run.run_id) is None:
            raise CollectionError("invalid-repeat-run-id")
        run_ids.add(run.run_id)
        if (
            run.document.get("profileSha256") != profile.profile_sha256
            or run.document.get("manifestSha256") != profile.manifest_sha256
        ):
            raise CollectionError("repeat-profile-or-manifest-mismatch")
        if (
            run.evaluation.get("qualifyingEvidence") is not False
            or run.evaluation.get("overallReplacementReady") is not False
        ):
            raise CollectionError("unauthorized-qualification-claim")
        measurement_hash = _canonical_sha256(
            {"epochs": run.document.get("epochs"), "samples": run.document.get("samples")}
        )
        provenance_hash = _canonical_sha256(run.document.get("provenance"))
        if measurement_hash in measurement_hashes:
            raise CollectionError("duplicate-repeat-measurement")
        if provenance_hash in provenance_hashes:
            raise CollectionError("duplicate-repeat-provenance")
        measurement_hashes.add(measurement_hash)
        provenance_hashes.add(provenance_hash)
        run_digests.append(
            {
                "runId": run.run_id,
                "documentSha256": _canonical_sha256(run.document),
                "measurementSha256": measurement_hash,
                "provenanceSha256": provenance_hash,
            }
        )
    for run in runs:
        fresh = cast(
            dict[str, Any],
            evaluator.evaluate(run.document, profile_path, manifest_path),
        )
        if (
            fresh.get("status") != "PASS"
            or fresh.get("validatedSampleCount") != FULL_MEASUREMENT_ROWS
            or fresh.get("profileSha256") != profile.profile_sha256
            or fresh.get("manifestSha256") != profile.manifest_sha256
        ):
            raise CollectionError("repeat-run-not-individually-passing")
        if run.evaluation != fresh:
            raise CollectionError("repeat-stored-evaluation-mismatch")
    return {
        "schemaVersion": 1,
        "status": "DEVELOPMENT_ONLY",
        "runIds": sorted(run_ids),
        "runs": run_digests,
        "sourceRevision": binding[2],
        "profileSha256": binding[3],
        "manifestSha256": binding[4],
        "policyVersion": binding[5],
        "validatedSampleCount": REQUIRED_REPEATS * FULL_MEASUREMENT_ROWS,
        "qualifyingEvidence": False,
        "overallReplacementReady": False,
    }


class LoopbackJsonAction:
    """Small loopback-only measured-action adapter for controlled launchers/tests."""

    __slots__ = ("_origins", "_path", "_reset_path")

    def __init__(
        self,
        origins: Mapping[str, str],
        path: str = "/phase7/action",
        reset_path: str = "/phase7/reset",
    ) -> None:
        if set(origins) != set(RUNTIMES):
            raise CollectionError("runtime-origin-set-mismatch")
        self._origins = MappingProxyType(
            {runtime: _loopback_origin(origin) for runtime, origin in origins.items()}
        )
        if (
            ORIGIN_FORM_PATH.fullmatch(path) is None
            or ORIGIN_FORM_PATH.fullmatch(reset_path) is None
        ):
            raise CollectionError("invalid-action-path")
        self._path = path
        self._reset_path = reset_path

    def execute(self, action: ActionRequest, timeout_seconds: float) -> str:
        payload = json.dumps(
            {
                "flowId": action.flow_id,
                "runtime": action.runtime,
                "epoch": action.epoch,
                "trial": action.trial,
                "kind": action.kind,
                "phase": action.phase,
            },
            separators=(",", ":"),
        ).encode()
        status, headers, raw = self._post(action.runtime, self._path, payload, timeout_seconds)
        if status != 200 or headers.get("content-type", "").partition(";")[0].strip().lower() != (
            "application/json"
        ):
            return "unexpected-error"
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "unexpected-error"
        if not isinstance(body, dict) or set(body) != {"outcome"}:
            return "unexpected-error"
        return _outcome(body["outcome"])

    def reset(self, *, epoch: int, runtime: str, timeout_seconds: float) -> ResetProof:
        payload = json.dumps({"epoch": epoch, "runtime": runtime}, separators=(",", ":")).encode()
        status, headers, raw = self._post(runtime, self._reset_path, payload, timeout_seconds)
        if status != 200 or headers.get("content-type", "").partition(";")[0].strip().lower() != (
            "application/json"
        ):
            raise CollectionError("reset-not-proven")
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CollectionError("reset-not-proven") from exc
        if not isinstance(body, dict) or set(body) != {"resetId", "stateSha256", "status"}:
            raise CollectionError("reset-not-proven")
        return ResetProof(
            reset_id=body["resetId"],
            state_sha256=body["stateSha256"],
            status=body["status"],
        )

    def _post(
        self, runtime: str, path: str, payload: bytes, timeout_seconds: float
    ) -> tuple[int, dict[str, str], bytes]:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise CollectionError("invalid-action-timeout")
        if ORIGIN_FORM_PATH.fullmatch(path) is None:
            raise CollectionError("invalid-action-path")
        origin = _loopback_origin(self._origins[runtime])
        parsed = parse.urlparse(origin)
        host = cast(str, parsed.hostname)
        port = cast(int, parsed.port)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        host_header = f"[{host}]:{port}" if family == socket.AF_INET6 else f"{host}:{port}"
        request_bytes = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + payload
        deadline = time.monotonic() + timeout_seconds
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(_remaining_seconds(deadline))
            connection.connect((host, port))
            connection.settimeout(_remaining_seconds(deadline))
            connection.sendall(request_bytes)
            return _read_bounded_http_response(connection, deadline)
        except ActionTimedOut:
            raise
        except TimeoutError as exc:
            raise ActionTimedOut from exc
        except OSError as exc:
            raise CollectionError("http-transport-error") from exc
        finally:
            connection.close()


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ActionTimedOut
    return remaining


def _read_bounded_http_response(
    connection: socket.socket, deadline: float
) -> tuple[int, dict[str, str], bytes]:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        if len(received) > 4096:
            raise CollectionError("http-response-headers-too-large")
        connection.settimeout(_remaining_seconds(deadline))
        chunk = connection.recv(min(4097 - len(received), 1024))
        if not chunk:
            raise CollectionError("incomplete-http-response-headers")
        received.extend(chunk)
    header_bytes, body = bytes(received).split(b"\r\n\r\n", 1)
    try:
        lines = header_bytes.decode("ascii").split("\r\n")
        protocol, status_text, _reason = lines[0].split(" ", 2)
        status = int(status_text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise CollectionError("malformed-http-status") from exc
    if protocol not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status <= 599:
        raise CollectionError("malformed-http-status")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        normalized = name.strip().lower()
        if not separator or not normalized or normalized in headers:
            raise CollectionError("malformed-http-headers")
        headers[normalized] = value.strip()
    content_length = headers.get("content-length")
    if "transfer-encoding" in headers:
        raise CollectionError("transfer-encoding-refused")
    if content_length is None or not content_length.isascii() or not content_length.isdecimal():
        raise CollectionError("content-length-required")
    length = int(content_length)
    if length > 4096 or len(body) > length:
        raise CollectionError("invalid-http-body-length")
    mutable_body = bytearray(body)
    while len(mutable_body) < length:
        connection.settimeout(_remaining_seconds(deadline))
        chunk = connection.recv(min(length - len(mutable_body), 1024))
        if not chunk:
            raise CollectionError("incomplete-http-response-body")
        mutable_body.extend(chunk)
    return status, headers, bytes(mutable_body)


def _loopback_origin(value: str) -> str:
    try:
        parsed = parse.urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise CollectionError("invalid-loopback-origin") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise CollectionError("invalid-loopback-origin")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"
