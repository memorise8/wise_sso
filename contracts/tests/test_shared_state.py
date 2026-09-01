from __future__ import annotations

import http.server
import importlib.util
import json
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "shared_state.py"
SPEC = importlib.util.spec_from_file_location("contract_shared_state", RUNNER)
assert SPEC is not None and SPEC.loader is not None
shared_state = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shared_state
SPEC.loader.exec_module(shared_state)

ADAPTER_PATH = Path(__file__).resolve().parents[1] / "adapters" / "express_fixture.py"
ADAPTER_SPEC = importlib.util.spec_from_file_location(
    "contract_shared_fixture", ADAPTER_PATH
)
assert ADAPTER_SPEC is not None and ADAPTER_SPEC.loader is not None
express_fixture = importlib.util.module_from_spec(ADAPTER_SPEC)
sys.modules[ADAPTER_SPEC.name] = express_fixture
ADAPTER_SPEC.loader.exec_module(express_fixture)


class FakeAdapter:
    def __init__(self, preflight_failure: Exception | None = None):
        self.calls: list[tuple[str, str]] = []
        self.preflight_failure = preflight_failure

    def invoke(self, command: str, name: str):
        self.calls.append((command, name))
        if command == "preflight" and self.preflight_failure is not None:
            raise self.preflight_failure
        if command == "snapshot" and name == "fixture-anonymous-audits":
            return {"residualCount": 0}
        return {"status": "ok"}


def timed_result(status: int, body=None, start: int = 10, end: int = 20):
    return shared_state.HttpResult(status, body, start, end)


class SharedStateContractTests(unittest.TestCase):
    def test_approved_corpus_is_exactly_ten_schedules_and_ten_trials(self) -> None:
        schedules = shared_state.load_scenarios(shared_state.DEFAULT_SCENARIOS)
        self.assertEqual(
            tuple(item["id"] for item in schedules), shared_state.EXPECTED_SCHEDULES
        )
        self.assertEqual(
            sum(sum(item.get("actors", {}).values()) for item in schedules), 100
        )

    def test_scenario_loader_rejects_every_semantic_mutation_and_extra_field(
        self,
    ) -> None:
        document = json.loads(
            shared_state.DEFAULT_SCENARIOS.read_text(encoding="utf-8")
        )
        mutations = (
            (0, "kind", "refresh-race"),
            (0, "producer", "fastapi"),
            (0, "consumer", "express"),
            (2, "actors", {"express": 19, "fastapi": 1}),
            (7, "allowedRequests", 19),
            (7, "route", "/auth/refresh"),
            (8, "prefillRequests", 20),
        )
        for index, field, value in mutations:
            mutated = json.loads(json.dumps(document))
            mutated["scenarios"][index][field] = value
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "scenarios.json"
                path.write_text(json.dumps(mutated), encoding="utf-8")
                with (
                    self.subTest(index=index, field=field),
                    self.assertRaises(shared_state.ContractFailure),
                ):
                    shared_state.load_scenarios(path)
        mutated = json.loads(json.dumps(document))
        mutated["scenarios"][0]["unexpected"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scenarios.json"
            path.write_text(json.dumps(mutated), encoding="utf-8")
            with self.assertRaises(shared_state.ContractFailure):
                shared_state.load_scenarios(path)

    def test_execute_emits_exactly_one_hundred_pass_rows_without_retries(self) -> None:
        schedules = shared_state.load_scenarios(shared_state.DEFAULT_SCENARIOS)
        adapter = FakeAdapter()
        with mock.patch.object(
            shared_state, "run_schedule", return_value={"winnerCount": 1}
        ) as run:
            records, passed = shared_state.execute(
                schedules,
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                adapter,
                1.0,
                "run-1",
                "abc123",
            )
        self.assertTrue(passed)
        self.assertEqual(len(records), 100)
        self.assertEqual(run.call_count, 100)
        self.assertTrue(
            all(row["attempt"] == 1 and row["retryCount"] == 0 for row in records)
        )
        self.assertTrue(
            all(row["fullPhase7SampleSatisfied"] is False for row in records)
        )
        self.assertTrue(all(row["overallReplacementReady"] is False for row in records))
        self.assertEqual(adapter.calls.count(("preflight", "shared-state-core-v1")), 1)
        self.assertEqual(
            sum(command == "teardown" for command, _name in adapter.calls), 100
        )

    def test_first_failure_marks_every_later_trial_not_run(self) -> None:
        schedules = shared_state.load_scenarios(shared_state.DEFAULT_SCENARIOS)
        adapter = FakeAdapter()
        with mock.patch.object(
            shared_state,
            "run_schedule",
            side_effect=shared_state.ContractFailure("contains secret value"),
        ) as run:
            records, passed = shared_state.execute(
                schedules,
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                adapter,
                1.0,
                "run-1",
                "abc123",
            )
        self.assertFalse(passed)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(records[0]["outcome"], "FAIL")
        self.assertEqual([row["outcome"] for row in records[1:]], ["NOT_RUN"] * 99)
        encoded = json.dumps(records)
        self.assertNotIn("contains secret value", encoded)
        self.assertEqual(
            sum(command == "teardown" for command, _name in adapter.calls), 1
        )

    def test_residual_fixture_audit_after_teardown_fails_closed(self) -> None:
        schedules = shared_state.load_scenarios(shared_state.DEFAULT_SCENARIOS)

        class ResidualAdapter(FakeAdapter):
            def invoke(self, command: str, name: str):
                if command == "snapshot" and name == "fixture-anonymous-audits":
                    return {"residualCount": 1}
                return super().invoke(command, name)

        adapter = ResidualAdapter()
        with mock.patch.object(
            shared_state, "run_schedule", return_value={"winnerCount": 1}
        ) as run:
            records, passed = shared_state.execute(
                schedules,
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                adapter,
                1.0,
                "run-1",
                "abc123",
            )
        self.assertFalse(passed)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(records[0]["outcome"], "FAIL")
        self.assertEqual([row["outcome"] for row in records[1:]], ["NOT_RUN"] * 99)

    def test_preflight_failure_mutates_nothing_and_marks_all_not_run(self) -> None:
        schedules = shared_state.load_scenarios(shared_state.DEFAULT_SCENARIOS)
        adapter = FakeAdapter(shared_state.ContractFailure("database password leaked"))
        records, passed = shared_state.execute(
            schedules,
            {"express": "http://127.0.0.1:4400", "fastapi": "http://127.0.0.1:4401"},
            adapter,
            1.0,
            "run-1",
            "abc123",
        )
        self.assertFalse(passed)
        self.assertEqual([row["outcome"] for row in records], ["NOT_RUN"] * 100)
        self.assertEqual(adapter.calls, [("preflight", "shared-state-core-v1")])
        self.assertNotIn("database password leaked", json.dumps(records))

    def test_parallel_uses_one_barrier_and_returns_each_actor_once(self) -> None:
        actors = [("express", lambda: timed_result(401)) for _ in range(10)]
        actors += [("fastapi", lambda: timed_result(401)) for _ in range(10)]
        results = shared_state._parallel(actors)
        self.assertEqual(len(results), 20)
        self.assertEqual(sum(runtime == "express" for runtime, _result in results), 10)
        self.assertEqual(sum(runtime == "fastapi" for runtime, _result in results), 10)

    def test_parallel_rejects_serialized_request_lifetimes(self) -> None:
        sequence = iter(((10, 20), (20, 30)))
        lock = threading.Lock()

        def serialized():
            with lock:
                start, end = next(sequence)
                return timed_result(401, start=start, end=end)

        with self.assertRaisesRegex(shared_state.ContractFailure, "did not overlap"):
            shared_state._parallel([("express", serialized), ("fastapi", serialized)])

    def test_evidence_sanitizer_rejects_secrets_and_urls(self) -> None:
        for value in (
            {"refreshToken": "opaque"},
            {"value": "user@example.invalid"},
            {"value": "http://127.0.0.1:4400"},
            {"value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"},
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(shared_state.ContractFailure),
            ):
                shared_state.assert_sanitized(value)
        shared_state.assert_sanitized({"sourceRevision": "release.1.2"})

    def test_adapter_config_requires_private_flat_string_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.json"
            path.write_text('{"CONTRACT_FIXTURE_MODE":"1"}', encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                shared_state.load_adapter_environment(path),
                {"CONTRACT_FIXTURE_MODE": "1"},
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(
                shared_state.ContractFailure, "exact mode 0600"
            ):
                shared_state.load_adapter_environment(path)
            path.chmod(0o600)
            link = Path(directory) / "linked.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(shared_state.ContractFailure, "symlink"):
                shared_state.load_adapter_environment(link)

    def test_scenario_loader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "scenarios.json"
            link.symlink_to(shared_state.DEFAULT_SCENARIOS)
            with self.assertRaisesRegex(shared_state.ContractFailure, "non-symlink"):
                shared_state.load_scenarios(link)

    def test_jsonl_is_exclusive_private_then_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.jsonl"
            records = [{"outcome": "PASS"}]
            shared_state.write_jsonl(path, records)
            self.assertEqual(path.read_text(encoding="utf-8"), '{"outcome":"PASS"}\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            with self.assertRaises(FileExistsError):
                shared_state.write_jsonl(path, records)

    def test_origins_must_be_bare_loopback_http(self) -> None:
        self.assertEqual(
            shared_state._local_http_url("http://127.0.0.1:4400", "runtime"),
            "http://127.0.0.1:4400",
        )
        for value in (
            "https://127.0.0.1",
            "http://example.com",
            "http://127.0.0.1/path",
            "http://127.0.0.1:not-a-port",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(shared_state.ContractFailure),
            ):
                shared_state._local_http_url(value, "runtime")

    def test_main_rejects_identical_normalized_runtime_origins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = [
                "--express",
                "http://127.0.0.1:4400/",
                "--fastapi",
                "http://127.0.0.1:4400",
                "--fixture-adapter",
                "/missing/adapter",
                "--fixture-config",
                "/missing/config",
                "--jsonl",
                str(Path(directory) / "results.jsonl"),
                "--run-id",
                "run-1",
                "--source-revision",
                "abc123",
            ]
            self.assertEqual(shared_state.main(args), 2)

    def test_main_rejects_linked_or_non_executable_fixture_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text('{"CONTRACT_FIXTURE_MODE":"1"}', encoding="utf-8")
            config.chmod(0o600)
            regular = root / "adapter.py"
            regular.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            linked = root / "linked-adapter.py"
            linked.symlink_to(regular)
            common = [
                "--express",
                "http://127.0.0.1:4400",
                "--fastapi",
                "http://127.0.0.1:4401",
                "--fixture-config",
                str(config),
                "--jsonl",
                str(root / "results.jsonl"),
                "--run-id",
                "run-1",
                "--source-revision",
                "abc123",
            ]
            self.assertEqual(
                shared_state.main([*common, "--fixture-adapter", str(linked)]), 2
            )
            self.assertEqual(
                shared_state.main([*common, "--fixture-adapter", str(regular)]), 2
            )

    def test_verify_me_never_forwards_authorization_across_redirect(self) -> None:
        captured: list[str | None] = []

        class Sink(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                captured.append(self.headers.get("authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header(
                    "location", f"http://127.0.0.1:{sink.server_port}/capture"
                )
                self.end_headers()

            def log_message(self, _format, *_args):
                return

        redirect = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threads = [
            threading.Thread(target=server.serve_forever) for server in (sink, redirect)
        ]
        for thread in threads:
            thread.start()
        try:
            with self.assertRaisesRegex(shared_state.ContractFailure, "not accepted"):
                shared_state._verify_me(
                    "express",
                    {"express": f"http://127.0.0.1:{redirect.server_port}"},
                    "private.access.token",
                    1.0,
                )
        finally:
            for server in (redirect, sink):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()
        self.assertEqual(captured, [])

    def test_shared_rate_limit_probe_returns_only_counts_and_ttls(self) -> None:
        redis = mock.Mock()
        redis.scan.return_value = [
            "wiseacct:rate-limit:private-client:/auth/login",
        ]
        redis.get.return_value = b"22"
        redis.ttl.return_value = 59
        with mock.patch.object(
            express_fixture.RedisRespClient, "from_url", return_value=redis
        ):
            result = express_fixture.snapshot(
                SimpleNamespace(redis_url="redis://127.0.0.1/13"), "shared-rate-limit"
            )
        self.assertEqual(result, {"keyCount": 1, "counters": [22], "ttls": [59]})
        self.assertNotIn("private-client", json.dumps(result))

    def test_failed_login_probe_returns_lock_boolean_and_counts(self) -> None:
        config = SimpleNamespace(
            database_url="postgresql://127.0.0.1/shared_contract_test"
        )
        with (
            mock.patch.object(express_fixture, "psql", return_value="20|t"),
            mock.patch.object(express_fixture, "count", return_value=0),
        ):
            result = express_fixture.snapshot(config, "failed-login-ledger")
        self.assertEqual(
            result, {"failedLoginCount": 20, "lockSet": True, "activeRefreshTokens": 0}
        )

    def test_reset_removes_only_exact_anonymous_login_rate_limit_audits(self) -> None:
        config = SimpleNamespace(
            database_url="postgresql://127.0.0.1/shared_contract_test",
            redis_url="redis://127.0.0.1/13",
            email_domain="example.invalid",
        )
        redis = mock.Mock()
        redis.scan.return_value = []
        with (
            mock.patch.object(express_fixture, "psql", return_value="") as psql,
            mock.patch.object(
                express_fixture.RedisRespClient, "from_url", return_value=redis
            ),
        ):
            express_fixture.reset(config)
        sql = psql.call_args.args[1]
        self.assertIn("\"eventType\" = 'rate_limit_exceeded'", sql)
        self.assertIn("\"reasonCode\" = 'RATE_LIMITED'", sql)
        self.assertIn("\"detailsJson\"->>'route' = '/auth/login'", sql)
        self.assertIn("\"detailsJson\"->>'method' = 'POST'", sql)
        self.assertIn('"userId" IS NULL', sql)
        self.assertIn("\"eventType\" = 'auth_handoff_exchange_failure'", sql)
        self.assertIn("\"reasonCode\" = 'INVALID_AUTH_HANDOFF_CODE'", sql)
        self.assertIn("\"eventType\" = 'refresh'", sql)
        self.assertIn("\"reasonCode\" = 'REFRESH_FAILED'", sql)
        self.assertIn("\"eventType\" = 'logout'", sql)
        self.assertIn("\"outcome\" = 'success'", sql)
        self.assertIn('"reasonCode" IS NULL', sql)
        self.assertIn('"detailsJson" IS NULL', sql)

    def test_anonymous_audit_residual_probe_uses_the_same_narrow_predicate(
        self,
    ) -> None:
        config = SimpleNamespace(
            database_url="postgresql://127.0.0.1/shared_contract_test"
        )
        with mock.patch.object(express_fixture, "count", return_value=0) as count:
            result = express_fixture.snapshot(config, "fixture-anonymous-audits")
        self.assertEqual(result, {"residualCount": 0})
        self.assertIn(
            express_fixture.FIXTURE_ANONYMOUS_AUDIT_PREDICATE, count.call_args.args[1]
        )

    def test_handoff_race_links_winner_refresh_and_checks_me_on_both_runtimes(
        self,
    ) -> None:
        access = "aaa.bbb.ccc"
        refresh = "rrr.eee.fff"
        refresh_hash = shared_state.hashlib.sha256(refresh.encode()).hexdigest()

        class Adapter:
            def invoke(self, command, name):
                if command == "setup":
                    return {"fixture": True}
                if command == "snapshot":
                    return {
                        "activeRefreshTokens": 1,
                        "authHandoffKeys": 0,
                        "activeTokenHashes": [refresh_hash],
                    }
                raise AssertionError((command, name))

        failures = [
            (
                "express" if index < 10 else "fastapi",
                timed_result(400, {"error": {"code": "INVALID_AUTH_HANDOFF_CODE"}}),
            )
            for index in range(19)
        ]
        results = [
            (
                "fastapi",
                timed_result(200, {"accessToken": access, "refreshToken": refresh}),
            ),
            *failures,
        ]
        with (
            mock.patch.object(shared_state, "_handoff", return_value="private-code"),
            mock.patch.object(shared_state, "_parallel", return_value=results),
            mock.patch.object(shared_state, "_verify_me") as verify_me,
        ):
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[2],
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                Adapter(),
                1.0,
            )
        self.assertEqual(evidence["winnerRuntime"], "fastapi")
        self.assertTrue(evidence["activeRefreshLinked"])
        self.assertTrue(evidence["mixedRuntimeRequestLifetimeOverlap"])
        self.assertEqual(
            verify_me.call_args_list,
            [
                mock.call("express", mock.ANY, access, 1.0),
                mock.call("fastapi", mock.ANY, access, 1.0),
            ],
        )
        self.assertNotIn(refresh, json.dumps(evidence))
        self.assertNotIn(refresh_hash, json.dumps(evidence))

    def test_simultaneous_limiter_requires_ten_allowed_ten_limited_and_counter_30(
        self,
    ) -> None:
        class Adapter:
            def invoke(self, command, name):
                if command == "setup":
                    return {"email": "synthetic", "password": "unused"}
                if command == "snapshot":
                    return {"keyCount": 1, "counters": [30], "ttls": [59]}
                raise AssertionError((command, name))

        invalid = timed_result(401, {"error": {"code": "INVALID_CREDENTIALS"}})
        limited = timed_result(429, {"error": {"code": "RATE_LIMITED"}})
        raced = [("express", invalid)] * 5 + [("fastapi", invalid)] * 5
        raced += [("express", limited)] * 5 + [("fastapi", limited)] * 5
        with (
            mock.patch.object(shared_state, "_login", return_value=invalid) as login,
            mock.patch.object(shared_state, "_parallel", return_value=raced),
        ):
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[8],
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                Adapter(),
                1.0,
            )
        self.assertEqual(login.call_count, 10)
        self.assertEqual((evidence["allowedCount"], evidence["limitedCount"]), (10, 10))
        self.assertEqual(evidence["state"]["counters"], [30])

    def test_logout_refresh_winner_links_ledger_checks_me_and_rejects_original(
        self,
    ) -> None:
        original = "old.ref.token"
        access = "new.acc.token"
        replacement = "new.ref.token"
        original_hash = shared_state.hashlib.sha256(original.encode()).hexdigest()
        replacement_hash = shared_state.hashlib.sha256(replacement.encode()).hexdigest()

        class Adapter:
            def invoke(self, command, name):
                if command == "setup":
                    return {"email": "synthetic", "password": "correct"}
                if command == "snapshot":
                    return {
                        "activeRefreshTokens": 1,
                        "revokedRefreshTokens": 1,
                        "activeTokenHashes": [replacement_hash],
                        "revokedTokenHashes": [original_hash],
                    }
                raise AssertionError((command, name))

        raced = [
            ("express", timed_result(204)),
            (
                "fastapi",
                timed_result(200, {"accessToken": access, "refreshToken": replacement}),
            ),
        ]
        replay = timed_result(401, {"error": {"code": "INVALID_REFRESH_TOKEN"}})
        with (
            mock.patch.object(
                shared_state,
                "_login",
                return_value=timed_result(
                    200, {"accessToken": "old.acc.token", "refreshToken": original}
                ),
            ),
            mock.patch.object(shared_state, "_parallel", return_value=raced),
            mock.patch.object(shared_state, "call", return_value=replay) as call,
            mock.patch.object(shared_state, "_verify_me") as verify_me,
        ):
            evidence = shared_state.run_schedule(
                shared_state.EXPECTED_SCENARIO_OBJECTS[5],
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                Adapter(),
                1.0,
            )
        self.assertTrue(evidence["activeRefreshLinked"])
        self.assertTrue(evidence["originalRefreshRevoked"])
        self.assertTrue(evidence["originalReplayRejected"])
        self.assertTrue(evidence["mixedRuntimeRequestLifetimeOverlap"])
        self.assertEqual(verify_me.call_count, 2)
        self.assertEqual(call.call_args.args[2], "/auth/refresh")
        self.assertNotIn(original_hash, json.dumps(evidence))
        self.assertNotIn(replacement_hash, json.dumps(evidence))

    def test_failed_login_accepts_only_locked_bounded_count(self) -> None:
        invalid = timed_result(401, {"error": {"code": "INVALID_CREDENTIALS"}})
        results = [("express", invalid)] * 10 + [("fastapi", invalid)] * 10

        class Adapter:
            def __init__(self, count):
                self.count = count

            def invoke(self, command, name):
                if command == "setup":
                    return {"email": "synthetic", "password": "unused"}
                if command == "snapshot":
                    return {
                        "failedLoginCount": self.count,
                        "lockSet": True,
                        "activeRefreshTokens": 0,
                    }
                raise AssertionError((command, name))

        with mock.patch.object(shared_state, "_parallel", return_value=results):
            for count in (5, 20):
                evidence = shared_state.run_schedule(
                    shared_state.EXPECTED_SCENARIO_OBJECTS[9],
                    {
                        "express": "http://127.0.0.1:4400",
                        "fastapi": "http://127.0.0.1:4401",
                    },
                    Adapter(count),
                    1.0,
                )
                self.assertEqual(evidence["state"]["failedLoginCount"], count)
            for count in (4, 21):
                with self.assertRaises(shared_state.ContractFailure):
                    shared_state.run_schedule(
                        shared_state.EXPECTED_SCENARIO_OBJECTS[9],
                        {
                            "express": "http://127.0.0.1:4400",
                            "fastapi": "http://127.0.0.1:4401",
                        },
                        Adapter(count),
                        1.0,
                    )


if __name__ == "__main__":
    unittest.main()
