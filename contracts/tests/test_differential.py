from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


RUNNER = Path(__file__).resolve().parents[1] / "bin" / "differential.py"
SPEC = importlib.util.spec_from_file_location("contract_differential", RUNNER)
assert SPEC and SPEC.loader
differential = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = differential
SPEC.loader.exec_module(differential)


def jwt(payload: dict[str, Any]) -> str:
    def segment(value: dict[str, Any]) -> str:
        encoded = base64.urlsafe_b64encode(json.dumps(value).encode()).decode()
        return encoded.rstrip("=")
    return f"{segment({'alg': 'RS256', 'typ': 'JWT'})}.{segment(payload)}.synthetic-signature"


class StubServer:
    def __init__(self, routes: dict[str, tuple[int, dict[str, str], Any]]):
        class Handler(BaseHTTPRequestHandler):
            def handle_request(handler_self):
                status, headers, body = routes.get(
                    handler_self.path,
                    (404, {"content-type": "application/json"}, {"error": "missing"}),
                )
                raw = json.dumps(body).encode()
                handler_self.send_response(status)
                for key, value in headers.items():
                    handler_self.send_header(key, value)
                handler_self.end_headers()
                handler_self.wfile.write(raw)

            do_GET = handle_request
            do_POST = handle_request
            do_PATCH = handle_request

            def log_message(self, _format, *_args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class FakeAdapter:
    def __init__(self):
        self.teardowns = []

    def setup(self, fixture):
        header = jwt_segment({"alg": "HS384", "typ": "JWT"})
        claims = jwt_segment({
            "sub": "00000000-0000-4000-8000-000000000001",
            "type": "refresh",
            "tokenId": "synthetic-token-id",
            "audience": "synthetic-audience",
        })
        return {
            "refreshToken": f"{header}.{claims}.synthetic-signature",
            "algorithm": "HS384",
            "audience": "synthetic-audience",
        }

    def snapshot(self, probe):
        return {"activeRefreshTokens": 1, "revokedRefreshTokens": 0}

    def teardown(self, fixture):
        self.teardowns.append(fixture)


class MatcherTests(unittest.TestCase):
    def test_predicates_validate_but_preserve_different_values(self):
        expected = {
            "id": {"$predicate": "uuid"},
            "createdAt": {"$predicate": "timestamp"},
            "callback": {"$predicate": "url"},
        }
        first = differential.match(
            {"id": "00000000-0000-4000-8000-000000000001", "createdAt": 1700000000, "callback": "https://a.example.invalid/cb"},
            expected,
        )
        second = differential.match(
            {"id": "00000000-0000-4000-8000-000000000002", "createdAt": "2024-01-01T00:00:00Z", "callback": "https://b.example.invalid/cb"},
            expected,
        )
        self.assertNotEqual(first, second)

    def test_named_capture_normalizes_a_genuinely_dynamic_value(self):
        expected = {"id": {"$capture": "generated-id", "$predicate": "uuid"}}
        first = differential.match({"id": "00000000-0000-4000-8000-000000000001"}, expected)
        second = differential.match({"id": "00000000-0000-4000-8000-000000000002"}, expected)
        self.assertEqual(first, second)

    def test_url_contract_captures_only_code_and_keeps_redirect_and_state_exact(self):
        captures = {}
        normalized = differential.match(
            "http://127.0.0.1:4100/auth/callback?code=dynamic-code&state=caller-state",
            {
                "$url": {
                    "base": "http://127.0.0.1:4100/auth/callback",
                    "query": {
                        "code": {"$capture": "handoff-code", "$predicate": "nonempty-string"},
                        "state": "caller-state",
                    },
                }
            },
            captures=captures,
        )
        self.assertEqual(normalized["query"]["code"], "<capture:handoff-code>")
        self.assertEqual(
            differential.resolve_runtime({"code": {"$captureValue": "handoff-code"}}, {}, captures),
            {"code": "dynamic-code"},
        )
        with self.assertRaisesRegex(differential.ContractFailure, "URL base"):
            differential.match(
                "http://127.0.0.1:4100/wrong?code=x&state=caller-state",
                {"$url": {"base": "http://127.0.0.1:4100/auth/callback", "query": {"code": "x", "state": "caller-state"}}},
            )

    def test_jwt_claims_are_checked_without_using_a_real_secret(self):
        token = jwt({"sub": "user-a", "type": "access", "iat": 1700000000})
        normalized = differential.match(
            token,
            {
                "$predicate": "jwt",
                "header": {"alg": "RS256", "typ": "JWT"},
                "claims": {
                    "sub": {"$predicate": "nonempty-string"},
                    "type": "access",
                    "iat": {"$predicate": "timestamp"},
                },
            },
        )
        self.assertEqual(normalized["token"], token)
        self.assertEqual(normalized["claims"]["sub"], "user-a")

    def test_extra_fields_fail_unless_explicitly_allowed(self):
        with self.assertRaisesRegex(differential.ContractFailure, "unexpected fields"):
            differential.match({"status": "ok", "extra": True}, {"status": "ok"})
        self.assertEqual(
            differential.match(
                {"status": "ok", "extra": True},
                {"status": "ok", "$allowExtra": True},
            ),
            {"status": "ok"},
        )

    @unittest.skipUnless(shutil.which("openssl"), "openssl unavailable")
    def test_rs256_signature_is_verified_against_matching_jwks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "key.pem"
            signing_input = root / "input.bin"
            signature_file = root / "signature.bin"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(private_key)],
                check=True,
                capture_output=True,
            )
            modulus = subprocess.run(
                ["openssl", "rsa", "-in", str(private_key), "-noout", "-modulus"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip().split("=", 1)[1]
            header = {"alg": "RS256", "typ": "JWT", "kid": "synthetic-test-key"}
            claims = {"sub": "synthetic-user", "iss": "https://issuer.example.invalid", "type": "access"}
            compact_input = f"{jwt_segment(header)}.{jwt_segment(claims)}"
            signing_input.write_bytes(compact_input.encode("ascii"))
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_file), str(signing_input)],
                check=True,
                capture_output=True,
            )
            signature = base64.urlsafe_b64encode(signature_file.read_bytes()).decode().rstrip("=")
            token = f"{compact_input}.{signature}"
            n_bytes = bytes.fromhex(modulus)
            jwks = {"keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "synthetic-test-key",
                "n": base64.urlsafe_b64encode(n_bytes).decode().rstrip("="), "e": "AQAB",
            }]}
            differential.verify_rs256(token, jwks, claims, {})


def jwt_segment(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


class DifferentialSuiteTests(unittest.TestCase):
    def test_fixture_scenario_uses_adapter_and_proves_no_state_change(self):
        scenario = [{
            "id": "wrong-alg",
            "fixture": "active-user-refresh-hs384",
            "fixtureExpect": {
                "$allowExtra": True,
                "refreshToken": {
                    "$capture": "wrong-alg-token",
                    "$predicate": "jwt",
                    "header": {"alg": "HS384", "typ": "JWT"},
                    "claims": {
                        "sub": {"$capture": "subject", "$predicate": "uuid"},
                        "type": "refresh",
                        "tokenId": {"$capture": "token-id", "$predicate": "nonempty-string"},
                        "audience": {"$fixture": "audience"},
                    },
                },
                "algorithm": "HS384",
                "audience": {"$predicate": "nonempty-string"},
            },
            "stateProbe": "refresh-ledger",
            "request": {"method": "POST", "path": "/auth/refresh", "json": {"refreshToken": {"$fixture": "refreshToken"}}},
            "expect": {"status": 401, "json": {"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Invalid refresh token"}}},
            "stateAssertions": [{"type": "unchanged"}],
        }]
        response = {"/auth/refresh": (401, {"content-type": "application/json"}, {"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Invalid refresh token"}})}
        baseline_adapter = FakeAdapter()
        candidate_adapter = FakeAdapter()
        with StubServer(response) as baseline, StubServer(response) as candidate:
            with contextlib.redirect_stdout(io.StringIO()):
                failures = differential.run_suite(
                    baseline.url,
                    candidate.url,
                    scenario,
                    baseline_adapter=baseline_adapter,
                    candidate_adapter=candidate_adapter,
                )
        self.assertEqual(failures, [])
        self.assertEqual(baseline_adapter.teardowns, ["active-user-refresh-hs384"])
        self.assertEqual(candidate_adapter.teardowns, ["active-user-refresh-hs384"])

    def test_equivalent_dynamic_responses_pass(self):
        scenarios = [{
            "id": "dynamic",
            "request": {"method": "GET", "path": "/item"},
            "expect": {
                "status": 200,
                "headers": {"cache-control": "public, max-age=300"},
                "json": {
                    "id": {"$capture": "generated-id", "$predicate": "uuid"},
                    "issuer": "https://issuer.example.invalid",
                },
            },
        }]
        baseline_routes = {"/item": (200, {"content-type": "application/json", "cache-control": "public, max-age=300"}, {"id": "00000000-0000-4000-8000-000000000001", "issuer": "https://issuer.example.invalid"})}
        candidate_routes = {"/item": (200, {"content-type": "application/json", "cache-control": "public, max-age=300"}, {"id": "00000000-0000-4000-8000-000000000002", "issuer": "https://issuer.example.invalid"})}
        with StubServer(baseline_routes) as baseline, StubServer(candidate_routes) as candidate:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(differential.run_suite(baseline.url, candidate.url, scenarios), [])

    def test_mismatched_issuer_fails_even_when_both_are_urls(self):
        scenarios = [{
            "id": "issuer",
            "request": {"method": "GET", "path": "/discovery"},
            "expect": {"status": 200, "json": {"issuer": {"$predicate": "url"}}},
        }]
        one = {"/discovery": (200, {"content-type": "application/json"}, {"issuer": "https://one.example.invalid"})}
        two = {"/discovery": (200, {"content-type": "application/json"}, {"issuer": "https://two.example.invalid"})}
        with StubServer(one) as baseline, StubServer(two) as candidate:
            with contextlib.redirect_stderr(io.StringIO()):
                failures = differential.run_suite(baseline.url, candidate.url, scenarios)
        self.assertEqual(len(failures), 1)
        self.assertIn("normalized responses differ", failures[0])

    def test_mismatched_jwks_value_fails(self):
        scenarios = [{
            "id": "jwks",
            "request": {"method": "GET", "path": "/jwks"},
            "expect": {
                "status": 200,
                "json": {"keys": [{"kid": {"$predicate": "nonempty-string"}, "n": {"$predicate": "nonempty-string"}, "e": "AQAB"}]},
            },
        }]
        one = {"/jwks": (200, {"content-type": "application/json"}, {"keys": [{"kid": "key-a", "n": "modulus-a", "e": "AQAB"}]})}
        two = {"/jwks": (200, {"content-type": "application/json"}, {"keys": [{"kid": "key-b", "n": "modulus-b", "e": "AQAB"}]})}
        with StubServer(one) as baseline, StubServer(two) as candidate:
            with contextlib.redirect_stderr(io.StringIO()):
                failures = differential.run_suite(baseline.url, candidate.url, scenarios)
        self.assertEqual(len(failures), 1)
        self.assertIn("normalized responses differ", failures[0])

    def test_state_unchanged_assertion_rejects_a_mutation(self):
        before = {"activeRefreshTokens": 1, "hashes": ["a" * 64]}
        after = {"activeRefreshTokens": 1, "hashes": ["b" * 64]}
        with self.assertRaisesRegex(differential.ContractFailure, "state changed"):
            differential.assert_state(before, after, [{"type": "unchanged"}])

    def test_refresh_rotation_assertion_requires_old_hash_revoked_and_new_hash_active(self):
        old_hash = "a" * 64
        before = {
            "activeRefreshTokens": 1,
            "revokedRefreshTokens": 0,
            "activeTokenHashes": [old_hash],
            "revokedTokenHashes": [],
        }
        after = {
            "activeRefreshTokens": 1,
            "revokedRefreshTokens": 1,
            "activeTokenHashes": ["b" * 64],
            "revokedTokenHashes": [old_hash],
        }
        differential.assert_state(before, after, [{"type": "refresh-rotation"}])
        with self.assertRaisesRegex(differential.ContractFailure, "did not revoke"):
            differential.assert_state(before, {**after, "revokedTokenHashes": []}, [{"type": "refresh-rotation"}])

    def test_contract_violation_fails(self):
        scenarios = [{
            "id": "health",
            "request": {"method": "GET", "path": "/healthz"},
            "expect": {"status": 200, "json": {"status": "ok"}},
        }]
        good = {"/healthz": (200, {"content-type": "application/json"}, {"status": "ok"})}
        bad = {"/healthz": (200, {"content-type": "application/json"}, {"status": "degraded"})}
        with StubServer(good) as baseline, StubServer(bad) as candidate:
            with contextlib.redirect_stderr(io.StringIO()):
                failures = differential.run_suite(baseline.url, candidate.url, scenarios)
        self.assertEqual(len(failures), 1)
        self.assertIn("expected 'ok', got 'degraded'", failures[0])

    def test_unknown_scenario_selection_fails(self):
        with self.assertRaisesRegex(differential.ContractFailure, "unknown scenario"):
            differential.load_scenarios(
                Path(__file__).resolve().parents[1] / "scenarios" / "public.json",
                {"does-not-exist"},
            )

    def test_adapter_environment_requires_flat_string_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "adapter.json"
            path.write_text('{"CONTRACT_FIXTURE_MODE":"1"}', encoding="utf-8")
            self.assertEqual(differential.load_adapter_environment(path), {"CONTRACT_FIXTURE_MODE": "1"})
            path.write_text('{"CONTRACT_FIXTURE_MODE":1}', encoding="utf-8")
            with self.assertRaisesRegex(differential.ContractFailure, "string environment"):
                differential.load_adapter_environment(path)


if __name__ == "__main__":
    unittest.main()
