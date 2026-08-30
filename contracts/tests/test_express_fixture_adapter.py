from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import fnmatch
import socketserver
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ADAPTER_PATH = Path(__file__).resolve().parents[1] / "adapters" / "express_fixture.py"
SPEC = importlib.util.spec_from_file_location("express_fixture_adapter", ADAPTER_PATH)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)
RUNNER_PATH = Path(__file__).resolve().parents[1] / "bin" / "differential.py"
RUNNER_SPEC = importlib.util.spec_from_file_location("fixture_contract_differential", RUNNER_PATH)
assert RUNNER_SPEC and RUNNER_SPEC.loader
differential = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = differential
RUNNER_SPEC.loader.exec_module(differential)


def environment(**overrides):
    values = {
        "CONTRACT_FIXTURE_MODE": "1",
        "CONTRACT_SERVER_MAIL_MODE": "dev",
        "CONTRACT_REDIS_ISOLATED_DB": "1",
        "CONTRACT_REFRESH_SECRET": "isolated-refresh-secret-2026",
        "CONTRACT_BASE_URL": "http://127.0.0.1:4000",
        "CONTRACT_DATABASE_URL": "postgresql://fixture:synthetic@127.0.0.1:5432/auth_contract_test",
        "CONTRACT_REDIS_URL": "redis://:synthetic@127.0.0.1:6379/9",
        "CONTRACT_FIXTURE_EMAIL_DOMAIN": "example.invalid",
    }
    values.update(overrides)
    return values


class PreflightTests(unittest.TestCase):
    def test_valid_local_test_config_passes_preflight(self):
        redis_client = mock.Mock()
        with mock.patch.dict(os.environ, environment(), clear=True), mock.patch.object(
            adapter.shutil, "which", return_value="/synthetic/tool"
        ), mock.patch.object(adapter.RedisRespClient, "from_url", return_value=redis_client), mock.patch.object(
            adapter, "psql", return_value="auth_contract_test"
        ):
            config = adapter.load_config()
            self.assertNotIn("isolated-refresh-secret-2026", repr(config))
            self.assertEqual(adapter.preflight(config), {
                "status": "ok", "database": "auth_contract_test", "redisDatabase": 9, "mailMode": "dev",
            })
        redis_client.ping.assert_called_once_with()

    def test_refuses_non_local_database(self):
        with mock.patch.dict(
            os.environ,
            environment(CONTRACT_DATABASE_URL="postgresql://fixture:synthetic@db.example.invalid:5432/auth_contract_test"),
            clear=True,
        ):
            with self.assertRaisesRegex(adapter.AdapterError, "loopback"):
                adapter.load_config()

    def test_refuses_production_shaped_database_name_and_redis_zero(self):
        with mock.patch.dict(
            os.environ,
            environment(CONTRACT_DATABASE_URL="postgresql://fixture:synthetic@127.0.0.1:5432/auth_db"),
            clear=True,
        ):
            with self.assertRaises(adapter.AdapterError):
                adapter.load_config()
        with mock.patch.dict(
            os.environ,
            environment(CONTRACT_REDIS_URL="redis://127.0.0.1:6379/0"),
            clear=True,
        ):
            with self.assertRaisesRegex(adapter.AdapterError, "database 0"):
                adapter.load_config()

    def test_requires_explicit_dev_mail_acknowledgement(self):
        with mock.patch.dict(os.environ, environment(CONTRACT_SERVER_MAIL_MODE="smtp"), clear=True):
            with self.assertRaisesRegex(adapter.AdapterError, "mail"):
                adapter.load_config()

    def test_requires_explicit_isolated_redis_acknowledgement(self):
        values = environment()
        values.pop("CONTRACT_REDIS_ISOLATED_DB")
        with mock.patch.dict(os.environ, values, clear=True):
            with self.assertRaisesRegex(adapter.AdapterError, "ISOLATED"):
                adapter.load_config()

    def test_requires_non_placeholder_refresh_secret(self):
        values = environment(CONTRACT_REFRESH_SECRET="replace-refresh-secret")
        with mock.patch.dict(os.environ, values, clear=True):
            with self.assertRaisesRegex(adapter.AdapterError, "placeholder"):
                adapter.load_config()


class FixtureTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, environment(), clear=True)
        self.addCleanup(patcher.stop)
        patcher.start()
        self.config = adapter.load_config()

    def test_hmac_tokens_use_the_configured_server_secret(self):
        for algorithm, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
            token = adapter.refresh_fixture_token(self.config, algorithm)
            signing_input, signature = token.rsplit(".", 1)
            expected = base64.urlsafe_b64encode(
                hmac.new(self.config.refresh_secret.encode(), signing_input.encode(), digest).digest()
            ).decode().rstrip("=")
            self.assertEqual(signature, expected)
        header_segment, claims_segment, _signature = token.split(".")
        decode = lambda value: json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
        self.assertEqual(decode(header_segment), {"alg": "HS512", "typ": "JWT"})
        self.assertEqual(decode(claims_segment)["sub"], adapter.ACTIVE_USER_ID)

    def test_none_token_has_no_signature(self):
        self.assertTrue(adapter.refresh_fixture_token(self.config, "none").endswith("."))

    def test_wrong_algorithm_setup_seeds_matching_refresh_ledger_hash(self):
        with mock.patch.object(adapter, "reset"), mock.patch.object(adapter, "seed"), mock.patch.object(
            adapter, "seed_refresh_token"
        ) as seed_refresh:
            fixture = adapter.setup(self.config, "active-user-refresh-hs384")
        seed_refresh.assert_called_once_with(self.config, fixture["refreshToken"], "HS384")
        self.assertNotIn(self.config.refresh_secret, json.dumps(fixture))

    def test_valid_hs256_setup_seeds_matching_refresh_ledger_hash(self):
        with mock.patch.object(adapter, "reset"), mock.patch.object(adapter, "seed"), mock.patch.object(
            adapter, "seed_refresh_token"
        ) as seed_refresh:
            fixture = adapter.setup(self.config, "active-user-refresh-hs256")
        seed_refresh.assert_called_once_with(self.config, fixture["refreshToken"], "HS256")
        self.assertEqual(fixture["userId"], adapter.ACTIVE_USER_ID)

    def test_permissive_hmac_oracles_would_be_caught_by_unchanged_ledger_contract(self):
        for algorithm, digest in (("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
            with self.subTest(algorithm=algorithm):
                token = adapter.refresh_fixture_token(self.config, algorithm)
                signing_input, signature = token.rsplit(".", 1)
                permissive_signature = base64.urlsafe_b64encode(
                    hmac.new(self.config.refresh_secret.encode(), signing_input.encode(), digest).digest()
                ).decode().rstrip("=")
                self.assertTrue(hmac.compare_digest(signature, permissive_signature), "fixture must reach a permissive verifier")
                old_hash = hashlib.sha256(token.encode()).hexdigest()
                before = {
                    "activeRefreshTokens": 1,
                    "revokedRefreshTokens": 0,
                    "activeTokenHashes": [old_hash],
                    "revokedTokenHashes": [],
                }
                after_permissive_rotation = {
                    "activeRefreshTokens": 1,
                    "revokedRefreshTokens": 1,
                    "activeTokenHashes": ["f" * 64],
                    "revokedTokenHashes": [old_hash],
                }
                with self.assertRaisesRegex(differential.ContractFailure, "state changed"):
                    differential.assert_state(before, after_permissive_rotation, [{"type": "unchanged"}])

    def test_setup_uses_only_deterministic_synthetic_values(self):
        with mock.patch.object(adapter, "reset"), mock.patch.object(adapter, "seed"):
            fixture = adapter.setup(self.config, "active-password-user")
        self.assertEqual(fixture["userId"], adapter.ACTIVE_USER_ID)
        self.assertEqual(fixture["email"], "contract-active@example.invalid")
        self.assertEqual(fixture["password"], adapter.PASSWORD)
        self.assertEqual(len(fixture["codeChallenge"]), 43)

    def test_psql_keeps_password_out_of_command_arguments(self):
        completed = mock.Mock(returncode=0, stdout="1\n", stderr="")
        with mock.patch.object(adapter.subprocess, "run", return_value=completed) as run:
            self.assertEqual(adapter.psql(self.config, "SELECT 1;"), "1")
        command = run.call_args.args[0]
        process_environment = run.call_args.kwargs["env"]
        self.assertNotIn("synthetic", command)
        self.assertEqual(process_environment["PGPASSWORD"], "synthetic")


class FakeRedisServer:
    def __init__(self):
        self.databases = {}

        owner = self

        class Handler(socketserver.StreamRequestHandler):
            database = 0

            def read_command(self):
                if self.rfile.read(1) != b"*":
                    raise ValueError("expected array")
                count = int(self.rfile.readline().strip())
                parts = []
                for _ in range(count):
                    if self.rfile.read(1) != b"$":
                        raise ValueError("expected bulk")
                    length = int(self.rfile.readline().strip())
                    value = self.rfile.read(length)
                    if self.rfile.read(2) != b"\r\n":
                        raise ValueError("missing terminator")
                    parts.append(value.decode())
                return parts

            def write_response(self, value):
                if isinstance(value, str):
                    self.wfile.write(f"+{value}\r\n".encode())
                elif isinstance(value, int):
                    self.wfile.write(f":{value}\r\n".encode())
                elif value is None:
                    self.wfile.write(b"$-1\r\n")
                elif isinstance(value, bytes):
                    self.wfile.write(f"${len(value)}\r\n".encode() + value + b"\r\n")
                elif isinstance(value, list):
                    self.wfile.write(f"*{len(value)}\r\n".encode())
                    for item in value:
                        self.write_response(item)
                self.wfile.flush()

            def handle(self):
                while True:
                    try:
                        parts = self.read_command()
                    except (EOFError, ValueError):
                        return
                    command, *arguments = parts
                    command = command.upper()
                    state = owner.databases.setdefault(self.database, {})
                    if command == "AUTH":
                        response = "OK"
                    elif command == "SELECT":
                        self.database = int(arguments[0])
                        response = "OK"
                    elif command == "PING":
                        response = "PONG"
                    elif command == "SET":
                        expires = time.time() + int(arguments[3]) if len(arguments) == 4 and arguments[2].upper() == "EX" else None
                        owner.databases.setdefault(self.database, {})[arguments[0]] = (arguments[1].encode(), expires)
                        response = "OK"
                    elif command == "GET":
                        item = state.get(arguments[0])
                        response = item[0] if item else None
                    elif command == "TTL":
                        item = state.get(arguments[0])
                        response = -2 if not item else (-1 if item[1] is None else max(0, int(item[1] - time.time())))
                    elif command == "DEL":
                        response = sum(1 for key in arguments if state.pop(key, None) is not None)
                    elif command == "SCAN":
                        pattern = arguments[arguments.index("MATCH") + 1]
                        response = [b"0", [key.encode() for key in sorted(state) if fnmatch.fnmatch(key, pattern)]]
                    else:
                        self.wfile.write(b"-ERR unsupported\r\n")
                        self.wfile.flush()
                        continue
                    self.write_response(response)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class RespClientTests(unittest.TestCase):
    def test_real_socket_auth_select_get_set_scan_ttl_delete(self):
        with FakeRedisServer() as fake:
            host, port = fake.server.server_address
            client = adapter.RedisRespClient(host, port, 9, "fixture", "synthetic")
            client.ping()
            client.set("wiseacct:auth-handoff:one", "value", ttl_seconds=60)
            client.set("unrelated", "leave")
            self.assertEqual(client.get("wiseacct:auth-handoff:one"), b"value")
            self.assertGreaterEqual(client.ttl("wiseacct:auth-handoff:one"), 0)
            self.assertEqual(client.scan("wiseacct:auth-handoff:*"), ["wiseacct:auth-handoff:one"])
            self.assertEqual(client.delete(["wiseacct:auth-handoff:one"]), 1)
            self.assertIsNone(client.get("wiseacct:auth-handoff:one"))
            self.assertEqual(client.get("unrelated"), b"leave")


if __name__ == "__main__":
    unittest.main()
