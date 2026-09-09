from __future__ import annotations

import hashlib
import http.server
import importlib.util
import json
import socket
import sys
import threading
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "shared_state.py"
SPEC = importlib.util.spec_from_file_location("contract_refresh_race", RUNNER)
assert SPEC is not None and SPEC.loader is not None
shared_state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shared_state
SPEC.loader.exec_module(shared_state)

URLS = {
    "express": "http://127.0.0.1:4400",
    "fastapi": "http://127.0.0.1:4401",
}
ORIGINAL_REFRESH = "old.refresh.token"
REPLACEMENT_REFRESH = "new.refresh.token"
ACCESS_TOKEN = "new.access.token"
GENERIC_REFRESH_FAILURE = {"error": {"code": "INVALID_REFRESH_TOKEN"}}


def timed_result(status: int, body: Any = None) -> Any:
    return shared_state.HttpResult(status, body, 10, 20)


def token_result(refresh_token: str = REPLACEMENT_REFRESH) -> Any:
    return timed_result(
        200,
        {"accessToken": ACCESS_TOKEN, "refreshToken": refresh_token},
    )


def generic_failure() -> Any:
    return timed_result(401, GENERIC_REFRESH_FAILURE)


class RefreshAdapter:
    def __init__(
        self,
        *,
        active_hashes: list[str] | None = None,
        revoked_hashes: list[str] | None = None,
        active_count: int = 1,
    ) -> None:
        self.active_hashes = active_hashes or [sha256(REPLACEMENT_REFRESH)]
        self.revoked_hashes = revoked_hashes or [sha256(ORIGINAL_REFRESH)]
        self.active_count = active_count

    def invoke(self, command: str, name: str) -> dict[str, Any]:
        if command == "setup":
            if name == "active-user-refresh-hs256":
                return {"refreshToken": ORIGINAL_REFRESH}
            if name == "active-password-user":
                return {"email": "fixture@example.invalid", "password": "correct"}
        if command == "snapshot" and name == "refresh-ledger":
            return {
                "activeRefreshTokens": self.active_count,
                "revokedRefreshTokens": 1,
                "activeTokenHashes": self.active_hashes,
                "revokedTokenHashes": self.revoked_hashes,
            }
        raise AssertionError((command, name))


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class ConcurrentRefreshState:
    barrier: threading.Barrier = field(default_factory=lambda: threading.Barrier(20))
    lock: threading.Lock = field(default_factory=threading.Lock)
    consumed: bool = False
    entered_by_runtime: dict[str, int] = field(
        default_factory=lambda: {"express": 0, "fastapi": 0}
    )
    in_flight: int = 0
    max_in_flight: int = 0


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
        request, client_address = super().get_request()
        request.settimeout(15)
        return request, client_address

    def process_request_thread(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: Any,
    ) -> None:
        current = threading.current_thread()
        current.name = f"refresh-race-request-{self.runtime}"
        with self.request_threads_lock:
            self.request_threads.append(current)
        super().process_request_thread(request, client_address)


def handler_for(
    runtime: str, state: ConcurrentRefreshState
) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/auth/refresh":
                self.send_error(404)
                return
            content_length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(content_length))
            if payload != {"refreshToken": ORIGINAL_REFRESH}:
                self.send_error(400)
                return
            with state.lock:
                state.entered_by_runtime[runtime] += 1
                state.in_flight += 1
                state.max_in_flight = max(state.max_in_flight, state.in_flight)
            try:
                state.barrier.wait(timeout=10)
                with state.lock:
                    winner = not state.consumed
                    state.consumed = True
                if winner:
                    self._json(
                        200,
                        {
                            "accessToken": ACCESS_TOKEN,
                            "refreshToken": REPLACEMENT_REFRESH,
                        },
                    )
                else:
                    self._json(401, GENERIC_REFRESH_FAILURE)
            finally:
                with state.lock:
                    state.in_flight -= 1

        def do_GET(self) -> None:
            if (
                self.path == "/users/me"
                and self.headers.get("authorization") == f"Bearer {ACCESS_TOKEN}"
            ):
                self._json(200, {"id": "fixture-user"})
                return
            self.send_error(401)

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
def refresh_servers(
    state: ConcurrentRefreshState,
) -> Iterator[dict[str, str]]:
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
                name=f"refresh-race-{runtime}",
                daemon=True,
            )
            thread.start()
            started.append((server, thread))
        yield urls
    finally:
        primary_error = sys.exception()
        cleanup_errors: list[Exception] = []
        state.barrier.abort()
        for server, _thread in started:
            try:
                server.shutdown()
            except Exception as exc:  # noqa: BLE001 - finish all cleanup paths
                cleanup_errors.append(exc)
        for server in servers:
            try:
                server.server_close()
            except Exception as exc:  # noqa: BLE001 - finish all cleanup paths
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
                        f"refresh server cleanup failed: {cleanup_error!r}"
                    )
            else:
                raise cleanup_errors[0]


class RefreshRaceFlowTests(unittest.TestCase):
    def test_server_setup_failure_closes_every_acquired_resource_without_hanging(
        self,
    ) -> None:
        original_start = threading.Thread.start
        original_close = LocalThreadingServer.server_close
        starts = 0
        closed: list[LocalThreadingServer] = []

        def fail_second_start(thread: threading.Thread) -> None:
            nonlocal starts
            starts += 1
            if starts == 2:
                raise RuntimeError("injected second start failure")
            original_start(thread)

        def record_close(server: LocalThreadingServer) -> None:
            original_close(server)
            closed.append(server)

        with (
            mock.patch.object(threading.Thread, "start", new=fail_second_start),
            mock.patch.object(LocalThreadingServer, "server_close", new=record_close),
            self.assertRaisesRegex(RuntimeError, "injected second start failure"),
            refresh_servers(ConcurrentRefreshState()),
        ):
            self.fail("server setup unexpectedly completed")

        self.assertEqual(len(closed), 2)
        self.assertTrue(all(server.socket.fileno() == -1 for server in closed))
        self.assertFalse(
            any(
                thread.is_alive() and thread.name.startswith("refresh-race-")
                for thread in threading.enumerate()
            )
        )

    def test_real_twenty_way_mixed_http_refresh_race_has_one_winner(self) -> None:
        state = ConcurrentRefreshState()
        observed: list[list[tuple[str, Any]]] = []
        assert_overlap = shared_state.assert_request_lifetime_overlap

        def record_and_assert(results: list[tuple[str, Any]]) -> None:
            observed.append(results)
            assert_overlap(results)

        with (
            refresh_servers(state) as urls,
            mock.patch.object(
                shared_state,
                "assert_request_lifetime_overlap",
                side_effect=record_and_assert,
            ),
        ):
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[4],
                urls,
                RefreshAdapter(),
                15.0,
            )

        self.assertEqual(evidence["winnerCount"], 1)
        self.assertEqual(evidence["stateCounts"], {"active": 1, "revoked": 1})
        self.assertTrue(evidence["activeRefreshLinked"])
        self.assertTrue(evidence["originalRefreshRevoked"])
        self.assertEqual(state.entered_by_runtime, {"express": 10, "fastapi": 10})
        self.assertEqual(state.max_in_flight, 20)
        self.assertEqual(len(observed), 1)
        results = observed[0]
        self.assertEqual(sum(result.status == 200 for _runtime, result in results), 1)
        self.assertEqual(sum(result.status == 401 for _runtime, result in results), 19)
        self.assertTrue(
            any(
                max(express.started_ns, fastapi.started_ns)
                < min(express.ended_ns, fastapi.ended_ns)
                for express_runtime, express in results
                for fastapi_runtime, fastapi in results
                if express_runtime == "express" and fastapi_runtime == "fastapi"
            )
        )
        # HTTP lifetime overlap is transport evidence, not DB critical-section ordering.
        self.assertNotIn("databaseCriticalSectionOrdering", evidence)

    def test_refresh_race_rejects_any_result_other_than_one_winner_and_19_generic_failures(
        self,
    ) -> None:
        hostile_results = {
            "no winner": [
                ("express" if index < 10 else "fastapi", generic_failure())
                for index in range(20)
            ],
            "two winners": [
                ("express", token_result()),
                ("fastapi", token_result("second.refresh.token")),
                *[
                    ("express" if index < 9 else "fastapi", generic_failure())
                    for index in range(18)
                ],
            ],
            "nongeneric loser": [
                ("express", token_result()),
                *[
                    (
                        "express" if index < 9 else "fastapi",
                        generic_failure(),
                    )
                    for index in range(18)
                ],
                ("fastapi", timed_result(401, {"error": {"code": "TOKEN_EXPIRED"}})),
            ],
        }
        for label, results in hostile_results.items():
            with (
                self.subTest(label=label),
                mock.patch.object(shared_state, "_parallel", return_value=results),
                self.assertRaisesRegex(
                    shared_state.ContractFailure,
                    "exactly one rotation winner",
                ),
            ):
                shared_state.run_schedule(
                    shared_state.EXPECTED_SCENARIO_OBJECTS[4],
                    URLS,
                    RefreshAdapter(),
                    1.0,
                )

    def test_refresh_race_rejects_unlinked_replacement_or_unrevoked_original(
        self,
    ) -> None:
        results = [("express", token_result())] + [
            ("express" if index < 9 else "fastapi", generic_failure())
            for index in range(19)
        ]
        hostile_adapters = {
            "replacement": RefreshAdapter(
                active_hashes=[sha256("other.refresh.token")]
            ),
            "original": RefreshAdapter(revoked_hashes=[sha256("other.original.token")]),
        }
        for label, adapter in hostile_adapters.items():
            with (
                self.subTest(label=label),
                mock.patch.object(shared_state, "_parallel", return_value=results),
                mock.patch.object(shared_state, "_verify_me"),
                self.assertRaises(shared_state.ContractFailure),
            ):
                shared_state.run_schedule(
                    shared_state.EXPECTED_SCENARIO_OBJECTS[4],
                    URLS,
                    adapter,
                    1.0,
                )

    def test_both_logout_refresh_schedules_accept_each_ordering_and_reject_replay(
        self,
    ) -> None:
        login = timed_result(
            200,
            {"accessToken": "old.access.token", "refreshToken": ORIGINAL_REFRESH},
        )
        logout = timed_result(204)
        replay = generic_failure()
        for schedule_index in (5, 6):
            schedule = shared_state.EXPECTED_SCENARIO_OBJECTS[schedule_index]
            for refresh_won in (False, True):
                refresh = token_result() if refresh_won else generic_failure()
                raced = (
                    [(schedule["refresh"], refresh), (schedule["logout"], logout)]
                    if refresh_won
                    else [(schedule["logout"], logout), (schedule["refresh"], refresh)]
                )
                adapter = RefreshAdapter(active_count=1 if refresh_won else 0)
                if not refresh_won:
                    adapter.active_hashes = []
                with (
                    self.subTest(schedule=schedule["id"], refresh_won=refresh_won),
                    mock.patch.object(shared_state, "_login", return_value=login),
                    mock.patch.object(shared_state, "_parallel", return_value=raced),
                    mock.patch.object(
                        shared_state, "call", return_value=replay
                    ) as call,
                    mock.patch.object(shared_state, "_verify_me") as verify_me,
                ):
                    evidence = shared_state.run_schedule(
                        schedule,
                        URLS,
                        adapter,
                        1.0,
                    )
                self.assertEqual(evidence["refreshWon"], refresh_won)
                self.assertTrue(evidence["originalRefreshRevoked"])
                self.assertTrue(evidence["originalReplayRejected"])
                self.assertEqual(evidence["stateCounts"]["active"], int(refresh_won))
                self.assertEqual(verify_me.call_count, 2 if refresh_won else 0)
                self.assertEqual(call.call_args.args[0], URLS[schedule["refresh"]])
                self.assertEqual(call.call_args.args[2], "/auth/refresh")
                self.assertEqual(
                    call.call_args.args[3], {"refreshToken": ORIGINAL_REFRESH}
                )

    def test_logout_refresh_race_fails_if_original_replay_is_not_generic(self) -> None:
        schedule = shared_state.EXPECTED_SCENARIO_OBJECTS[5]
        raced = [
            (schedule["logout"], timed_result(204)),
            (schedule["refresh"], generic_failure()),
        ]
        with (
            mock.patch.object(
                shared_state,
                "_login",
                return_value=timed_result(
                    200,
                    {
                        "accessToken": "old.access.token",
                        "refreshToken": ORIGINAL_REFRESH,
                    },
                ),
            ),
            mock.patch.object(shared_state, "_parallel", return_value=raced),
            mock.patch.object(
                shared_state,
                "call",
                return_value=timed_result(
                    401,
                    {"error": {"code": "TOKEN_ALREADY_USED"}},
                ),
            ),
            self.assertRaisesRegex(
                shared_state.ContractFailure,
                "original token replay was not rejected",
            ),
        ):
            shared_state.run_schedule(
                schedule, URLS, RefreshAdapter(active_count=0), 1.0
            )


if __name__ == "__main__":
    unittest.main()
