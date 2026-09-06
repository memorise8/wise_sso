from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/phase7/performance_collector.py"
SPEC = importlib.util.spec_from_file_location("phase7_performance_collector_test", MODULE)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)

REPO_ROOT = Path(__file__).resolve().parents[3]
PROFILE_V1 = REPO_ROOT / "contracts/performance/profile-v1.json"
MANIFEST = REPO_ROOT / "contracts/manifest.json"
PERFORMANCE_TEST = REPO_ROOT / "contracts/tests/test_performance.py"
PERFORMANCE_TEST_SPEC = importlib.util.spec_from_file_location(
    "phase7_performance_contract_fixtures", PERFORMANCE_TEST
)
assert PERFORMANCE_TEST_SPEC is not None and PERFORMANCE_TEST_SPEC.loader is not None
performance_fixtures = importlib.util.module_from_spec(PERFORMANCE_TEST_SPEC)
sys.modules[PERFORMANCE_TEST_SPEC.name] = performance_fixtures
PERFORMANCE_TEST_SPEC.loader.exec_module(performance_fixtures)


class _ActionHandler(BaseHTTPRequestHandler):
    delay_seconds: ClassVar[float] = 0.0
    requests: ClassVar[list[dict[str, Any]]] = []
    reset_requests: ClassVar[list[dict[str, Any]]] = []
    active: ClassVar[int] = 0
    maximum_active: ClassVar[int] = 0
    redirect_to: ClassVar[str | None] = None
    get_count: ClassVar[int] = 0
    response_mode: ClassVar[str] = "normal"
    response_status: ClassVar[int] = 200
    raw_response: ClassVar[bytes | None] = None
    reset_response_mode: ClassVar[str] = "normal"
    reset_body_override: ClassVar[dict[str, Any] | None] = None
    late_mutation: ClassVar[threading.Event] = threading.Event()
    lock: ClassVar[threading.Lock] = threading.Lock()

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))
        if self.path == "/phase7/reset":
            type(self).reset_requests.append(payload)
            reset_id = f"epoch-{payload['epoch']:02d}-{payload['runtime']}"
            reset_body = type(self).reset_body_override or {
                "resetId": reset_id,
                "stateSha256": hashlib.sha256(reset_id.encode()).hexdigest(),
                "status": "PASS",
            }
            body = json.dumps(reset_body).encode()
            if type(self).reset_response_mode in {"slow-header", "slow-body"}:
                headers = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                )
                try:
                    if type(self).reset_response_mode == "slow-header":
                        for byte in headers + body:
                            time.sleep(0.025)
                            self.connection.sendall(bytes((byte,)))
                    else:
                        self.connection.sendall(headers)
                        for byte in body:
                            time.sleep(0.025)
                            self.connection.sendall(bytes((byte,)))
                except OSError:
                    time.sleep(0.12)
                finally:
                    type(self).late_mutation.set()
                return
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass
            return
        with self.lock:
            type(self).requests.append(payload)
        redirect_to = type(self).redirect_to
        if redirect_to is not None:
            self.send_response(303)
            self.send_header("location", redirect_to)
            self.end_headers()
            return
        if type(self).response_mode in {"slow-header", "slow-body"}:
            body = b'{"outcome":"success"}'
            headers = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
            )
            try:
                if type(self).response_mode == "slow-header":
                    for byte in headers + body:
                        time.sleep(0.025)
                        self.connection.sendall(bytes((byte,)))
                else:
                    self.connection.sendall(headers)
                    for byte in body:
                        time.sleep(0.025)
                        self.connection.sendall(bytes((byte,)))
            except OSError:
                time.sleep(0.12)
            finally:
                type(self).late_mutation.set()
            return
        if type(self).raw_response is not None:
            self.connection.sendall(type(self).raw_response or b"")
            return
        with self.lock:
            type(self).active += 1
            type(self).maximum_active = max(type(self).maximum_active, type(self).active)
        try:
            time.sleep(type(self).delay_seconds)
            outcome = (
                "expected-failure"
                if payload["phase"] == "measured" and payload["kind"] == "expected-failure"
                else "success"
            )
            body = json.dumps({"outcome": outcome}).encode()
            self.send_response(type(self).response_status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass
        finally:
            with self.lock:
                type(self).active -= 1

    def do_GET(self) -> None:
        type(self).get_count += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@pytest.fixture
def action_server() -> Iterator[tuple[str, type[_ActionHandler]]]:
    _ActionHandler.delay_seconds = 0
    _ActionHandler.requests = []
    _ActionHandler.reset_requests = []
    _ActionHandler.active = 0
    _ActionHandler.maximum_active = 0
    _ActionHandler.redirect_to = None
    _ActionHandler.get_count = 0
    _ActionHandler.response_mode = "normal"
    _ActionHandler.response_status = 200
    _ActionHandler.raw_response = None
    _ActionHandler.reset_response_mode = "normal"
    _ActionHandler.reset_body_override = None
    _ActionHandler.late_mutation = threading.Event()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ActionHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = cast(tuple[str, int], server.server_address)
    try:
        yield f"http://{host}:{port}", _ActionHandler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _spec(
    *,
    flows: tuple[str, ...] = ("one", "two"),
    warmups: int = 1,
    measured: int = 3,
    successes: int = 2,
    rate: int = 20,
    maximum: int = 16,
    timeout: float = 1.0,
) -> Any:
    return collector.BlockSpec(
        flow_ids=flows,
        expected_failure_flow_ids=frozenset({flows[-1]}),
        warmup_trials_per_flow=warmups,
        measured_trials_per_flow=measured,
        success_trials_per_flow=successes,
        rate_per_second=rate,
        max_in_flight=maximum,
        timeout_seconds=timeout,
    )


def test_actual_loopback_open_loop_schedule_owns_rows_and_excludes_warmup(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})

    result = collector.collect_block(
        epoch=1,
        runtime="express",
        runtime_order=("express", "fastapi"),
        spec=_spec(),
        action_driver=action,
    )

    assert handler.reset_requests == [{"epoch": 1, "runtime": "express"}]
    assert len(result.samples) == 6
    assert len([item for item in handler.requests if item["phase"] == "warmup"]) == 2
    assert all(row["attempt"] == 1 for row in result.samples)
    assert all(row["retryCount"] == 0 for row in result.samples)
    assert all(row["outlierRemoved"] is False for row in result.samples)
    assert [
        right["scheduledNs"] - left["scheduledNs"]
        for left, right in zip(result.samples, result.samples[1:], strict=False)
    ] == [50_000_000] * 5
    assert [row["outcome"] for row in result.samples] == [
        "success",
        "success",
        "success",
        "success",
        "success",
        "expected-failure",
    ]
    assert result.epoch["warmupIncluded"] is False
    assert result.epoch["resets"][0]["boundaryNs"] == result.samples[0]["scheduledNs"]


@pytest.mark.parametrize("response_mode", ["slow-header", "slow-body"])
def test_slow_trickle_hits_absolute_deadline_and_refuses_undrained_block(
    action_server: tuple[str, type[_ActionHandler]],
    response_mode: str,
) -> None:
    origin, handler = action_server
    handler.response_mode = response_mode
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    started = time.monotonic()
    with pytest.raises(collector.RemoteActionDrainUnproven) as failure:
        collector.collect_block(
            epoch=1,
            runtime="fastapi",
            runtime_order=("express", "fastapi"),
            spec=_spec(
                flows=("slow",),
                warmups=0,
                measured=2,
                successes=2,
                rate=10,
                timeout=0.05,
            ),
            action_driver=action,
        )
    assert failure.value.deadline_reason_code == "absolute-action-deadline-exceeded"
    assert failure.value.drain_reason_code == "remote-action-drain-unproven"
    assert time.monotonic() - started < 0.25
    assert len(handler.requests) == 1
    assert handler.reset_requests == [{"epoch": 1, "runtime": "fastapi"}]
    assert handler.late_mutation.wait(1)


@pytest.mark.parametrize("response_mode", ["slow-header", "slow-body"])
def test_slow_reset_refuses_before_warmup_or_measurement(
    action_server: tuple[str, type[_ActionHandler]],
    response_mode: str,
) -> None:
    origin, handler = action_server
    handler.reset_response_mode = response_mode
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    started = time.monotonic()
    with pytest.raises(collector.RemoteActionDrainUnproven):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(
                flows=("reset",),
                warmups=0,
                measured=1,
                successes=1,
                timeout=0.05,
            ),
            action_driver=action,
        )
    assert time.monotonic() - started < 0.25
    assert handler.reset_requests == [{"epoch": 1, "runtime": "express"}]
    assert handler.requests == []
    assert handler.late_mutation.wait(1)


def test_malformed_reset_proof_is_stably_refused(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    handler.reset_body_override = {
        "resetId": None,
        "stateSha256": 7,
        "status": True,
    }
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    with pytest.raises(collector.CollectionError, match="reset-not-proven"):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(flows=("reset",), warmups=0, measured=1, successes=1),
            action_driver=action,
        )
    assert handler.requests == []


def test_slow_warmup_refuses_without_reset_or_measurement(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    handler.response_mode = "slow-body"
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    with pytest.raises(collector.RemoteActionDrainUnproven):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(
                flows=("warmup",),
                warmups=1,
                measured=1,
                successes=1,
                timeout=0.05,
            ),
            action_driver=action,
        )
    assert len(handler.requests) == 1
    assert handler.requests[0]["phase"] == "warmup"
    assert handler.reset_requests == []
    assert handler.late_mutation.wait(1)


def test_executor_enforces_configured_concurrency_cap_with_real_http(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    handler.delay_seconds = 0.05
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    with pytest.raises(collector.CollectionError, match="scheduler-capacity-exceeded"):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(
                flows=("burst",),
                warmups=0,
                measured=8,
                successes=8,
                rate=1000,
                maximum=3,
            ),
            action_driver=action,
        )
    assert handler.maximum_active == 3
    assert len(handler.requests) == 3


@pytest.fixture(scope="module")
def repeat_contract(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, list[Any]]:
    directory = tmp_path_factory.mktemp("performance-repeat")
    profile = json.loads(PROFILE_V1.read_text(encoding="utf-8"))
    profile.update(
        {
            "$schema": "profile-v2.schema.json",
            "schemaVersion": 2,
            "suiteId": "phase7-performance-v2",
            "policyVersion": 2,
        }
    )
    profile["policy"]["candidateP50MaxPercentOfBaseline"] = 101
    profile_path = directory / "profile-v2.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    evaluator = collector._load_evaluator()
    runs = []
    for index in range(1, 4):
        document = performance_fixtures.make_evidence()
        document["schemaVersion"] = 2
        document["suiteId"] = "phase7-performance-v2"
        document["profileSha256"] = hashlib.sha256(profile_path.read_bytes()).hexdigest()
        document["runId"] = f"run-{index}"
        document["provenance"]["redisNamespace"] = f"contract.performance.00{index}"
        timestamp_offset = index * 10**15
        reset_ids: dict[str, str] = {}
        for epoch in document["epochs"]:
            for reset in epoch["resets"]:
                old_reset_id = reset["resetId"]
                new_reset_id = f"{old_reset_id}-run-{index}"
                reset_ids[old_reset_id] = new_reset_id
                reset["resetId"] = new_reset_id
                reset["boundaryNs"] += timestamp_offset
        for sample in document["samples"]:
            sample["resetId"] = reset_ids[sample["resetId"]]
            sample["scheduledNs"] += timestamp_offset
            sample["completedNs"] += timestamp_offset
        evaluation = evaluator.evaluate(document, profile_path, MANIFEST)
        assert evaluation["status"] == "PASS"
        runs.append(collector.CollectedRun(document, evaluation, 2))
    return profile_path, runs


def _replace_run(
    run: Any,
    *,
    document: dict[str, Any] | None = None,
    evaluation: dict[str, Any] | None = None,
    policy_version: int | None = None,
) -> Any:
    return collector.CollectedRun(
        document if document is not None else copy.deepcopy(run.document),
        evaluation if evaluation is not None else copy.deepcopy(run.evaluation),
        policy_version if policy_version is not None else run.policy_version,
    )


def test_three_full_runs_must_pass_individually_with_same_binding(
    repeat_contract: tuple[Path, list[Any]],
) -> None:
    profile_path, runs = repeat_contract
    result = collector.validate_repeat_group(
        runs, profile_path=profile_path, manifest_path=MANIFEST
    )
    assert result["status"] == "DEVELOPMENT_ONLY"
    assert result["validatedSampleCount"] == 60_000
    assert [item["runId"] for item in result["runs"]] == ["run-1", "run-2", "run-3"]
    assert len({item["documentSha256"] for item in result["runs"]}) == 3
    assert len({item["measurementSha256"] for item in result["runs"]}) == 3
    assert len({item["provenanceSha256"] for item in result["runs"]}) == 3
    assert result["qualifyingEvidence"] is False
    assert result["overallReplacementReady"] is False

    hostile: list[tuple[str, list[Any], str]] = []
    duplicate = list(runs)
    duplicate_document = copy.deepcopy(runs[2].document)
    duplicate_document["runId"] = "run-2"
    duplicate[2] = _replace_run(runs[2], document=duplicate_document)
    hostile.append(("duplicate", duplicate, "duplicate-repeat-run-id"))
    mixed_source = list(runs)
    source_document = copy.deepcopy(runs[2].document)
    source_document["sourceRevision"] = "d" * 40
    mixed_source[2] = _replace_run(runs[2], document=source_document)
    hostile.append(("source", mixed_source, "repeat-binding-mismatch"))
    mixed_profile = list(runs)
    profile_document = copy.deepcopy(runs[2].document)
    profile_document["profileSha256"] = "d" * 64
    mixed_profile[2] = _replace_run(runs[2], document=profile_document)
    hostile.append(("profile", mixed_profile, "repeat-binding-mismatch"))
    mixed_policy = list(runs)
    mixed_policy[2] = _replace_run(runs[2], policy_version=3)
    hostile.append(("policy", mixed_policy, "repeat-binding-mismatch"))
    failed = list(runs)
    failed_evaluation = copy.deepcopy(runs[2].evaluation)
    failed_evaluation["status"] = "FAIL"
    failed[2] = _replace_run(runs[2], evaluation=failed_evaluation)
    hostile.append(("failed", failed, "repeat-stored-evaluation-mismatch"))
    missing = list(runs)
    missing_document = copy.deepcopy(runs[2].document)
    missing_document["samples"].pop()
    missing[2] = _replace_run(runs[2], document=missing_document)
    hostile.append(("missing", missing, "repeat-run-not-individually-passing"))

    for _label, candidate, reason in hostile:
        with pytest.raises(collector.CollectionError, match=reason):
            collector.validate_repeat_group(
                candidate, profile_path=profile_path, manifest_path=MANIFEST
            )

    mutated = list(runs)
    mutated_document = copy.deepcopy(runs[2].document)
    mutated_document["samples"][-1] = copy.deepcopy(mutated_document["samples"][0])
    mutated[2] = _replace_run(runs[2], document=mutated_document)
    with pytest.raises(collector.CollectionError, match="repeat-run-not-individually-passing"):
        collector.validate_repeat_group(mutated, profile_path=profile_path, manifest_path=MANIFEST)

    cloned = list(runs)
    cloned_document = copy.deepcopy(runs[1].document)
    cloned_document["runId"] = "run-3"
    cloned_evaluation = collector._load_evaluator().evaluate(
        cloned_document, profile_path, MANIFEST
    )
    cloned[2] = _replace_run(runs[2], document=cloned_document, evaluation=cloned_evaluation)
    with pytest.raises(collector.CollectionError, match="duplicate-repeat-measurement"):
        collector.validate_repeat_group(cloned, profile_path=profile_path, manifest_path=MANIFEST)


def test_loopback_adapter_rejects_external_and_credentialed_origins() -> None:
    for origin in (
        "https://127.0.0.1:8443",
        "http://example.com:80",
        "http://user@127.0.0.1:8000",
        "http://127.0.0.1:8000/path",
    ):
        with pytest.raises(collector.CollectionError, match="invalid-loopback-origin"):
            collector.LoopbackJsonAction({"express": origin, "fastapi": origin})

    for path in (
        "/x\r\nX-Injected: yes",
        "/space here",
        "/tab\there",
        "/nul\0here",
        "/back\\slash",
        "/snowman-☃",
        "/bad-percent-%",
        "/bad-percent-%ZZ",
        "/query?x=1",
        "/fragment#x",
    ):
        with pytest.raises(collector.CollectionError, match="invalid-action-path"):
            collector.LoopbackJsonAction(
                {"express": "http://127.0.0.1:8000", "fastapi": "http://127.0.0.1:8001"},
                path,
            )
    collector.LoopbackJsonAction(
        {"express": "http://127.0.0.1:8000", "fastapi": "http://127.0.0.1:8001"},
        "/safe/%2Fvalue-._~",
    )


def test_loopback_action_never_follows_redirect(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    handler.redirect_to = origin + "/egress"
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    request_action = collector.ActionRequest("flow", "express", 1, 1, "success", "measured")
    with pytest.raises(collector.CollectionError, match="content-length-required"):
        action.execute(request_action, 0.5)
    assert handler.get_count == 0


def test_http_500_is_one_unretried_unexpected_error_sample(
    action_server: tuple[str, type[_ActionHandler]],
) -> None:
    origin, handler = action_server
    handler.response_status = 500
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    result = collector.collect_block(
        epoch=1,
        runtime="express",
        runtime_order=("express", "fastapi"),
        spec=_spec(
            flows=("server-error",),
            warmups=0,
            measured=1,
            successes=1,
        ),
        action_driver=action,
    )
    assert len(handler.requests) == 1
    assert result.samples[0]["outcome"] == "unexpected-error"
    assert result.samples[0]["attempt"] == 1
    assert result.samples[0]["retryCount"] == 0


@pytest.mark.parametrize(
    ("raw_response", "reason"),
    [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "malformed-http-headers",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "transfer-encoding-refused",
        ),
        (b"NOTHTTP 200 OK\r\nContent-Length: 2\r\n\r\n{}", "malformed-http-status"),
        (b"HTTP/1.1 200 OK\r\nBroken\r\nContent-Length: 2\r\n\r\n{}", "malformed-http-headers"),
    ],
)
def test_ambiguous_or_malformed_http_framing_is_refused(
    action_server: tuple[str, type[_ActionHandler]],
    raw_response: bytes,
    reason: str,
) -> None:
    origin, handler = action_server
    handler.raw_response = raw_response
    action = collector.LoopbackJsonAction({"express": origin, "fastapi": origin})
    request_action = collector.ActionRequest("flow", "express", 1, 1, "success", "measured")
    with pytest.raises(collector.CollectionError, match=reason):
        action.execute(request_action, 0.5)


def test_nonfinite_timeout_and_untrusted_action_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(collector.CollectionError, match="invalid-block-policy"):
            _spec(timeout=value).validate()

    class HangingAction:
        called = False

        def execute(self, action: Any, timeout_seconds: float) -> str:
            del action, timeout_seconds
            self.called = True
            time.sleep(60)
            return "success"

    hanging = HangingAction()
    with pytest.raises(collector.CollectionError, match="bounded-loopback-action-required"):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(warmups=0, measured=1, successes=1),
            action_driver=hanging,
        )
    assert hanging.called is False

    def subclass_execute(self: Any, action: Any, timeout_seconds: float) -> str:
        del action, timeout_seconds
        self.called = True
        return "success"

    hanging_subclass = type(
        "HangingSubclass",
        (collector.LoopbackJsonAction,),
        {"called": False, "execute": subclass_execute},
    )
    subclass = hanging_subclass(
        {"express": "http://127.0.0.1:8000", "fastapi": "http://127.0.0.1:8001"}
    )
    with pytest.raises(collector.CollectionError, match="bounded-loopback-action-required"):
        collector.collect_block(
            epoch=1,
            runtime="express",
            runtime_order=("express", "fastapi"),
            spec=_spec(warmups=0, measured=1, successes=1),
            action_driver=subclass,
        )
    assert subclass.called is False

    exact = collector.LoopbackJsonAction(
        {"express": "http://127.0.0.1:8000", "fastapi": "http://127.0.0.1:8001"}
    )
    with pytest.raises(AttributeError):
        exact.execute = hanging.execute
    with pytest.raises(TypeError):
        cast(Any, exact._origins)["express"] = "http://203.0.113.1:80"

    socket_called = False

    def unexpected_socket(*args: Any, **kwargs: Any) -> Any:
        nonlocal socket_called
        del args, kwargs
        socket_called = True
        raise AssertionError("socket must not be created")

    monkeypatch.setattr(collector.socket, "socket", unexpected_socket)
    request_action = collector.ActionRequest("flow", "express", 1, 1, "success", "measured")
    object.__setattr__(
        exact,
        "_origins",
        {"express": "http://203.0.113.1:80", "fastapi": "http://127.0.0.1:8001"},
    )
    with pytest.raises(collector.CollectionError, match="invalid-loopback-origin"):
        exact.execute(request_action, 0.05)

    exact_path = collector.LoopbackJsonAction(
        {"express": "http://127.0.0.1:8000", "fastapi": "http://127.0.0.1:8001"}
    )
    object.__setattr__(exact_path, "_path", "/x\r\nInjected: yes")
    with pytest.raises(collector.CollectionError, match="invalid-action-path"):
        exact_path.execute(request_action, 0.05)
    assert socket_called is False


def test_repeat_validator_rejects_authorization_claims(
    repeat_contract: tuple[Path, list[Any]],
) -> None:
    profile_path, original = repeat_contract
    runs = list(original)
    changed_evaluation = copy.deepcopy(runs[2].evaluation)
    changed_evaluation["qualifyingEvidence"] = True
    runs[2] = _replace_run(runs[2], evaluation=changed_evaluation)
    with pytest.raises(collector.CollectionError, match="unauthorized-qualification-claim"):
        collector.validate_repeat_group(runs, profile_path=profile_path, manifest_path=MANIFEST)


def test_active_v1_profile_cannot_start_full_collector() -> None:
    with pytest.raises(collector.CollectionError, match="reviewed-profile-v2-required"):
        collector.ProfileSpec.load(PROFILE_V1, MANIFEST)


def test_synthetic_reviewed_v2_profile_preserves_full_collection_contract(
    tmp_path: Path,
) -> None:
    profile = json.loads(PROFILE_V1.read_text(encoding="utf-8"))
    profile.update(
        {
            "$schema": "profile-v2.schema.json",
            "schemaVersion": 2,
            "suiteId": "phase7-performance-v2",
            "policyVersion": 2,
        }
    )
    profile["policy"]["candidateP50MaxPercentOfBaseline"] = 101
    profile_path = tmp_path / "synthetic-profile-v2.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")

    loaded = collector.ProfileSpec.load(profile_path, MANIFEST)
    loaded.require_full_contract()
    spec = loaded.block_spec()
    assert spec.rate_per_second == 20
    assert spec.max_in_flight == 16
    assert spec.timeout_seconds == 5.0
    assert len(spec.flow_ids) == 10
    assert (
        len(spec.flow_ids)
        * len(collector.RUNTIMES)
        * collector.FULL_EPOCHS
        * spec.measured_trials_per_flow
        == 20_000
    )
