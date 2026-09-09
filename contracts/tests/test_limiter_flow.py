from __future__ import annotations

import http.server
import importlib.util
import json
import socket
import sys
import threading
import unittest
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "shared_state.py"
SPEC = importlib.util.spec_from_file_location("contract_limiter_flow", RUNNER)
assert SPEC is not None and SPEC.loader is not None
shared_state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shared_state
SPEC.loader.exec_module(shared_state)

INVALID_CREDENTIALS = {"error": {"code": "INVALID_CREDENTIALS"}}
RATE_LIMITED = {"error": {"code": "RATE_LIMITED"}}


def timed_result(status: int, body: Any) -> Any:
    return shared_state.HttpResult(status, body, 10, 20)


@dataclass
class SharedLimiterState:
    concurrent_after: int | None = None
    ttl: int = 60
    lock: threading.Lock = field(default_factory=threading.Lock)
    count: int = 0
    arrivals: int = 0
    in_flight: int = 0
    max_in_flight: int = 0
    entered_by_runtime: dict[str, int] = field(
        default_factory=lambda: {"express": 0, "fastapi": 0}
    )
    race_barrier: threading.Barrier | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if self.concurrent_after is not None:
            self.race_barrier = threading.Barrier(20)

    def enter(self, runtime: str) -> bool:
        with self.lock:
            self.arrivals += 1
            arrival = self.arrivals
            self.entered_by_runtime[runtime] += 1
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)
        return self.concurrent_after is not None and arrival > self.concurrent_after

    def consume(self) -> tuple[int, dict[str, Any]]:
        with self.lock:
            self.count += 1
            if self.count <= 20:
                return 401, INVALID_CREDENTIALS
            return 429, RATE_LIMITED

    def leave(self) -> None:
        with self.lock:
            self.in_flight -= 1

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"keyCount": 1, "counters": [self.count], "ttls": [self.ttl]}


class LimiterAdapter:
    def __init__(
        self,
        state: SharedLimiterState | None = None,
        snapshot: dict[str, Any] | None = None,
    ) -> None:
        self.state = state
        self.snapshot_override = snapshot

    def invoke(self, command: str, name: str) -> dict[str, Any]:
        if command == "setup" and name == "active-password-user":
            return {"email": "fixture@example.invalid", "password": "correct"}
        if command == "snapshot" and name == "shared-rate-limit":
            if self.snapshot_override is not None:
                return self.snapshot_override
            if self.state is not None:
                return self.state.snapshot()
        raise AssertionError((command, name))


class LocalThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    request_queue_size = 32

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[http.server.BaseHTTPRequestHandler],
        runtime: str,
    ) -> None:
        self.runtime = runtime
        self.request_threads: list[threading.Thread] = []
        self.request_threads_lock = threading.Lock()
        super().__init__(server_address, request_handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, client_address = super().get_request()
        connection.settimeout(15)
        return connection, client_address

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: Any,
    ) -> None:
        current = threading.current_thread()
        current.name = f"limiter-flow-request-{self.runtime}"
        with self.request_threads_lock:
            self.request_threads.append(current)
        super().process_request_thread(request, client_address)


def handler_for(
    runtime: str, state: SharedLimiterState
) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/auth/login":
                self.send_error(404)
                return
            content_length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(content_length))
            if payload != {
                "email": "fixture@example.invalid",
                "password": "ContractOnly!wrong",
            }:
                self.send_error(400)
                return

            should_race = state.enter(runtime)
            try:
                if should_race:
                    assert state.race_barrier is not None
                    state.race_barrier.wait(timeout=10)
                status, response = state.consume()
                self._json(status, response)
            finally:
                state.leave()

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    return Handler


@contextmanager
def limiter_servers(state: SharedLimiterState) -> Iterator[dict[str, str]]:
    servers: list[LocalThreadingServer] = []
    started: list[tuple[LocalThreadingServer, threading.Thread]] = []
    try:
        urls: dict[str, str] = {}
        for runtime in ("express", "fastapi"):
            server = LocalThreadingServer(
                ("127.0.0.1", 0), handler_for(runtime, state), runtime
            )
            servers.append(server)
            host, port = cast(tuple[str, int], server.server_address)
            urls[runtime] = f"http://{host}:{port}"
            thread = threading.Thread(
                target=server.serve_forever,
                name=f"limiter-flow-{runtime}",
                daemon=True,
            )
            thread.start()
            started.append((server, thread))
        yield urls
    finally:
        primary_error = sys.exception()
        cleanup_errors: list[Exception] = []
        if state.race_barrier is not None:
            state.race_barrier.abort()
        for server, _thread in started:
            try:
                server.shutdown()
            except Exception as exc:  # noqa: BLE001 - finish every cleanup path
                cleanup_errors.append(exc)
        for server in servers:
            try:
                server.server_close()
            except Exception as exc:  # noqa: BLE001 - finish every cleanup path
                cleanup_errors.append(exc)
        for _server, thread in started:
            thread.join(timeout=5)
            if thread.is_alive():
                cleanup_errors.append(
                    RuntimeError(f"server thread did not stop: {thread.name}")
                )
        for server in servers:
            with server.request_threads_lock:
                lingering = [
                    thread.name
                    for thread in server.request_threads
                    if thread.is_alive()
                ]
            if lingering:
                cleanup_errors.append(
                    RuntimeError(
                        f"request threads did not stop: {', '.join(lingering)}"
                    )
                )
        if cleanup_errors:
            if primary_error is not None:
                for cleanup_error in cleanup_errors:
                    primary_error.add_note(
                        f"limiter server cleanup failed: {cleanup_error!r}"
                    )
            else:
                raise cleanup_errors[0]


class LimiterFlowTests(unittest.TestCase):
    def test_real_alternating_http_requests_share_one_exact_live_counter(self) -> None:
        state = SharedLimiterState()
        with limiter_servers(state) as urls:
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[7],
                urls,
                LimiterAdapter(state),
                15.0,
            )

        self.assertEqual(
            evidence["actors"],
            {
                "total": 22,
                "statusByRuntime": {
                    "express": {"401": 10, "429": 1},
                    "fastapi": {"401": 10, "429": 1},
                },
            },
        )
        self.assertEqual(evidence["state"], state.snapshot())
        self.assertEqual(state.count, 22)
        self.assertEqual(state.entered_by_runtime, {"express": 11, "fastapi": 11})

    def test_real_twenty_way_http_race_has_ten_allowed_and_ten_limited(self) -> None:
        state = SharedLimiterState(concurrent_after=10)
        observed: list[list[tuple[str, Any]]] = []
        assert_overlap = shared_state.assert_request_lifetime_overlap

        def record_and_assert(results: list[tuple[str, Any]]) -> None:
            observed.append(results)
            assert_overlap(results)

        with (
            limiter_servers(state) as urls,
            mock.patch.object(
                shared_state,
                "assert_request_lifetime_overlap",
                side_effect=record_and_assert,
            ),
        ):
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[8],
                urls,
                LimiterAdapter(state),
                15.0,
            )

        self.assertEqual(evidence["allowedCount"], 10)
        self.assertEqual(evidence["limitedCount"], 10)
        self.assertEqual(evidence["state"], state.snapshot())
        self.assertTrue(evidence["mixedRuntimeRequestLifetimeOverlap"])
        self.assertEqual(state.count, 30)
        self.assertEqual(state.entered_by_runtime, {"express": 15, "fastapi": 15})
        self.assertEqual(state.max_in_flight, 20)
        self.assertEqual(len(observed), 1)
        raced = observed[0]
        self.assertEqual(sum(result.status == 401 for _runtime, result in raced), 10)
        self.assertEqual(sum(result.status == 429 for _runtime, result in raced), 10)

    def test_alternating_oracle_rejects_wrong_boundary_or_error_code(
        self,
    ) -> None:
        hostile_results = {
            "early boundary": [
                *[timed_result(401, INVALID_CREDENTIALS) for _ in range(19)],
                *[timed_result(429, RATE_LIMITED) for _ in range(3)],
            ],
            "wrong 401 code": [
                *[
                    timed_result(401, {"error": {"code": "LOGIN_FAILED"}})
                    for _ in range(20)
                ],
                *[timed_result(429, RATE_LIMITED) for _ in range(2)],
            ],
            "wrong 429 code": [
                *[timed_result(401, INVALID_CREDENTIALS) for _ in range(20)],
                *[
                    timed_result(429, {"error": {"code": "TOO_MANY_REQUESTS"}})
                    for _ in range(2)
                ],
            ],
        }
        for label, results in hostile_results.items():
            with (
                self.subTest(label=label),
                mock.patch.object(shared_state, "_login", side_effect=results),
                self.assertRaises(shared_state.ContractFailure),
            ):
                shared_state.run_schedule(
                    shared_state.EXPECTED_SCENARIO_OBJECTS[7],
                    {"express": "unused", "fastapi": "unused"},
                    LimiterAdapter(snapshot={}),
                    1.0,
                )

    def test_simultaneous_oracle_rejects_off_by_one_boundary(self) -> None:
        raced = [
            *[
                (
                    "express" if index < 5 else "fastapi",
                    timed_result(401, INVALID_CREDENTIALS),
                )
                for index in range(9)
            ],
            *[
                ("express" if index < 6 else "fastapi", timed_result(429, RATE_LIMITED))
                for index in range(11)
            ],
        ]
        with (
            mock.patch.object(
                shared_state,
                "_login",
                return_value=timed_result(401, INVALID_CREDENTIALS),
            ),
            mock.patch.object(shared_state, "_parallel", return_value=raced),
            self.assertRaisesRegex(
                shared_state.ContractFailure,
                "same boundary",
            ),
        ):
            shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[8],
                {"express": "unused", "fastapi": "unused"},
                LimiterAdapter(snapshot={}),
                1.0,
            )

    def test_alternating_oracle_rejects_count_ttl_and_split_counter_snapshots(
        self,
    ) -> None:
        hostile_snapshots = {
            "wrong count": {"keyCount": 1, "counters": [21], "ttls": [60]},
            "expired ttl": {"keyCount": 1, "counters": [22], "ttls": [0]},
            "split counters": {
                "keyCount": 2,
                "counters": [11, 11],
                "ttls": [60, 60],
            },
        }
        accepted = [
            *[timed_result(401, INVALID_CREDENTIALS) for _ in range(20)],
            *[timed_result(429, RATE_LIMITED) for _ in range(2)],
        ]
        for label, snapshot in hostile_snapshots.items():
            with (
                self.subTest(label=label),
                mock.patch.object(shared_state, "_login", side_effect=accepted),
                self.assertRaisesRegex(
                    shared_state.ContractFailure,
                    "one live exact counter",
                ),
            ):
                shared_state.run_schedule(
                    shared_state.EXPECTED_SCENARIO_OBJECTS[7],
                    {"express": "unused", "fastapi": "unused"},
                    LimiterAdapter(snapshot=snapshot),
                    1.0,
                )

    def test_both_limiter_oracles_reject_non_integer_or_non_list_state(self) -> None:
        for schedule_index, expected_count in ((7, 22), (8, 30)):
            hostile_snapshots: dict[str, dict[str, Any]] = {
                "boolean key count": {
                    "keyCount": True,
                    "counters": [expected_count],
                    "ttls": [60],
                },
                "float key count": {
                    "keyCount": 1.0,
                    "counters": [expected_count],
                    "ttls": [60],
                },
                "boolean counter": {
                    "keyCount": 1,
                    "counters": [True],
                    "ttls": [60],
                },
                "float counter": {
                    "keyCount": 1,
                    "counters": [float(expected_count)],
                    "ttls": [60],
                },
                "boolean ttl": {
                    "keyCount": 1,
                    "counters": [expected_count],
                    "ttls": [True],
                },
                "float ttl": {
                    "keyCount": 1,
                    "counters": [expected_count],
                    "ttls": [60.0],
                },
                "non-list counters": {
                    "keyCount": 1,
                    "counters": (expected_count,),
                    "ttls": [60],
                },
                "non-list ttls": {
                    "keyCount": 1,
                    "counters": [expected_count],
                    "ttls": (60,),
                },
            }
            for label, snapshot in hostile_snapshots.items():
                schedule = shared_state.EXPECTED_SCENARIO_OBJECTS[schedule_index]
                with self.subTest(schedule=schedule["id"], hostile=label):
                    patches: tuple[Any, ...]
                    if schedule_index == 7:
                        accepted = [
                            *[
                                timed_result(401, INVALID_CREDENTIALS)
                                for _ in range(20)
                            ],
                            *[timed_result(429, RATE_LIMITED) for _ in range(2)],
                        ]
                        patches = (
                            mock.patch.object(
                                shared_state, "_login", side_effect=accepted
                            ),
                        )
                    else:
                        raced = [
                            *[
                                (
                                    "express" if index < 5 else "fastapi",
                                    timed_result(401, INVALID_CREDENTIALS),
                                )
                                for index in range(10)
                            ],
                            *[
                                (
                                    "express" if index < 5 else "fastapi",
                                    timed_result(429, RATE_LIMITED),
                                )
                                for index in range(10)
                            ],
                        ]
                        patches = (
                            mock.patch.object(
                                shared_state,
                                "_login",
                                return_value=timed_result(401, INVALID_CREDENTIALS),
                            ),
                            mock.patch.object(
                                shared_state, "_parallel", return_value=raced
                            ),
                        )
                    with ExitStack() as stack:
                        for patch in patches:
                            stack.enter_context(patch)
                        with self.assertRaises(shared_state.ContractFailure):
                            shared_state.run_schedule(
                                schedule,
                                {"express": "unused", "fastapi": "unused"},
                                LimiterAdapter(snapshot=snapshot),
                                1.0,
                            )


if __name__ == "__main__":
    unittest.main()
