from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Self, cast

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "flow_driver.py"
SPEC = importlib.util.spec_from_file_location("contract_flow_driver", RUNNER)
assert SPEC and SPEC.loader
flow_driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = flow_driver
SPEC.loader.exec_module(flow_driver)

USER_ID = "00000000-0000-4000-8000-000000000001"
EMAIL = "contract-active@example.invalid"
PASSWORD = "ContractOnly!2026"
AUDIENCE = "contract-fixture"


def segment(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


class RuntimeServer:
    def __init__(
        self,
        *,
        bad_claim: bool = False,
        replay_succeeds: bool = False,
        slow: bool = False,
        malformed_login: bool = False,
        shared_state: dict[str, Any] | None = None,
        state_path: Path | None = None,
        claim_overrides: dict[str, Any] | None = None,
        header_overrides: dict[str, Any] | None = None,
        tamper_access: bool = False,
        tamper_refresh: bool = False,
    ):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        numbers = self.private_key.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "contract-key",
            "n": base64.urlsafe_b64encode(
                numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
            "e": base64.urlsafe_b64encode(
                numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
        }
        self.state = shared_state or {"activeHashes": [], "handoffs": set()}
        self.bad_claim = bad_claim
        self.replay_succeeds = replay_succeeds
        self.slow = slow
        self.malformed_login = malformed_login
        self.state_path = state_path
        self.claim_overrides = claim_overrides or {}
        self.header_overrides = header_overrides or {}
        self.tamper_access = tamper_access
        self.tamper_refresh = tamper_refresh
        self.requests: list[tuple[str, str]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def _body(handler_self) -> dict[str, Any]:
                length = int(handler_self.headers.get("content-length", "0"))
                return json.loads(handler_self.rfile.read(length)) if length else {}

            def _send(
                handler_self,
                status: int,
                body: Any,
                headers: dict[str, str] | None = None,
            ) -> None:
                raw = b"" if body is None else json.dumps(body).encode()
                handler_self.send_response(status)
                if body is not None:
                    handler_self.send_header("content-type", "application/json")
                for key, value in (headers or {}).items():
                    handler_self.send_header(key, value)
                handler_self.send_header("content-length", str(len(raw)))
                handler_self.end_headers()
                if raw:
                    try:
                        handler_self.wfile.write(raw)
                    except BrokenPipeError:
                        pass

            def do_GET(handler_self) -> None:
                owner.requests.append(("GET", handler_self.path))
                if handler_self.path == "/.well-known/jwks.json":
                    handler_self._send(200, {"keys": [owner.jwk]})
                elif handler_self.path == "/users/me":
                    handler_self._send(
                        200,
                        {
                            "id": USER_ID,
                            "email": EMAIL,
                            "name": "Contract Active",
                            "email_verified": True,
                            "roles": [{"serviceKey": "temis", "name": "user"}],
                        },
                        {"cache-control": "no-store"},
                    )
                else:
                    handler_self._send(404, {"error": {"code": "NOT_FOUND"}})

            def do_POST(handler_self) -> None:
                owner.requests.append(("POST", handler_self.path))
                if owner.slow:
                    time.sleep(0.15)
                body = handler_self._body()
                if handler_self.path == "/auth/login":
                    if owner.malformed_login:
                        raw = b"{not-json"
                        handler_self.send_response(200)
                        handler_self.send_header("content-type", "application/json")
                        handler_self.send_header("content-length", str(len(raw)))
                        handler_self.end_headers()
                        handler_self.wfile.write(raw)
                        return
                    if body.get("password") != PASSWORD:
                        handler_self._send(
                            401,
                            {
                                "error": {
                                    "code": "INVALID_CREDENTIALS",
                                    "message": "Invalid email or password",
                                }
                            },
                        )
                    elif "clientId" in body:
                        owner.handoffs.add("private-handoff-code")
                        owner.persist()
                        handler_self._send(
                            200,
                            {
                                "redirectUrl": f"{body['redirectUri']}?code=private-handoff-code&state={body['state']}"
                            },
                        )
                    else:
                        handler_self._send(200, owner.issue_pair())
                    return
                if handler_self.path == "/auth/exchange":
                    code = body.get("code")
                    if code not in owner.handoffs:
                        if owner.replay_succeeds and code == "private-handoff-code":
                            handler_self._send(200, owner.issue_pair())
                        else:
                            handler_self._send(
                                400,
                                {
                                    "error": {
                                        "code": "INVALID_AUTH_HANDOFF_CODE",
                                        "message": "Invalid authorization code",
                                    }
                                },
                            )
                    else:
                        owner.handoffs.remove(cast(str, code))
                        owner.persist()
                        handler_self._send(200, owner.issue_pair())
                    return
                if handler_self.path == "/auth/logout":
                    refresh = body.get("refreshToken")
                    if isinstance(refresh, str):
                        digest = hashlib.sha256(refresh.encode()).hexdigest()
                        if digest in owner.active_hashes:
                            owner.active_hashes.remove(digest)
                            owner.persist()
                    handler_self._send(204, None)
                    return
                handler_self._send(404, {"error": {"code": "NOT_FOUND"}})

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = cast(tuple[str, int], self.server.server_address)
        return f"http://{host}:{port}"

    def access_token(self) -> str:
        now = int(time.time())
        claims = {
            "sub": "wrong-user" if self.bad_claim else USER_ID,
            "email": EMAIL,
            "name": "Contract Active",
            "email_verified": True,
            "type": "access",
            "roles": [{"serviceKey": "temis", "name": "user"}],
            "iat": now,
            "exp": now + 900,
            "iss": "https://auth.financenow.kr",
            "aud": AUDIENCE,
        }
        claims.update(self.claim_overrides)
        header = {"alg": "RS256", "typ": "JWT", "kid": "contract-key"}
        header.update(self.header_overrides)
        signing_input = f"{segment(header)}.{segment(claims)}"
        signature = self.private_key.sign(
            signing_input.encode(), padding.PKCS1v15(), SHA256()
        )
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        if self.tamper_access:
            encoded_signature = (
                "A" if encoded_signature[0] != "A" else "B"
            ) + encoded_signature[1:]
        return f"{signing_input}.{encoded_signature}"

    def issue_pair(self) -> dict[str, str]:
        now = int(time.time())
        signing_input = (
            f"{segment({'alg': 'HS256', 'typ': 'JWT'})}."
            f"{segment({'sub': USER_ID, 'type': 'refresh', 'tokenId': 'private-token-id', 'audience': AUDIENCE, 'iat': now, 'exp': now + 3600})}"
        )
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    b"contract-refresh-secret-value",
                    signing_input.encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        if self.tamper_refresh:
            signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        refresh = f"{signing_input}.{signature}"
        self.active_hashes.append(hashlib.sha256(refresh.encode()).hexdigest())
        self.persist()
        return {"accessToken": self.access_token(), "refreshToken": refresh}

    def reset(self) -> None:
        self.active_hashes.clear()
        self.handoffs.clear()
        self.persist()

    def persist(self) -> None:
        if self.state_path is not None:
            self.state_path.write_text(
                json.dumps(
                    {
                        "activeRefreshTokens": len(self.active_hashes),
                        "authHandoffKeys": len(self.handoffs),
                        "activeTokenHashes": self.active_hashes,
                    }
                ),
                encoding="utf-8",
            )

    @property
    def active_hashes(self) -> list[str]:
        return cast(list[str], self.state["activeHashes"])

    @property
    def handoffs(self) -> set[str]:
        return cast(set[str], self.state["handoffs"])

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class FakeAdapter:
    refresh_secret = "contract-refresh-secret-value"
    isolation_identity = ("contract-database", "contract-redis")

    def __init__(self, runtime: RuntimeServer):
        self.runtime = runtime
        self.calls: list[tuple[str, str]] = []

    def invoke(self, command: str, name: str) -> Any:
        self.calls.append((command, name))
        if command == "preflight":
            return {"status": "ok"}
        if command == "setup":
            self.runtime.reset()
            return {
                "userId": USER_ID,
                "email": EMAIL,
                "password": PASSWORD,
                "name": "Contract Active",
                "roles": [{"serviceKey": "temis", "name": "user"}],
                "audience": AUDIENCE,
                "clientId": "contract-client",
                "redirectUri": "http://127.0.0.1:4101/auth/callback",
                "state": "private-caller-state",
                "codeChallenge": "private-code-challenge",
                "codeVerifier": "private-code-verifier",
            }
        if command == "snapshot":
            if name == "fixture-anonymous-audits":
                return {"residualCount": 0}
            return {
                "activeRefreshTokens": len(self.runtime.active_hashes),
                "authHandoffKeys": len(self.runtime.handoffs),
                "activeTokenHashes": list(self.runtime.active_hashes),
            }
        if command == "teardown":
            self.runtime.reset()
            return {"status": "clean"}
        raise AssertionError(command)


class FailingSetupAdapter(FakeAdapter):
    def invoke(self, command: str, name: str) -> Any:
        if command == "setup":
            self.calls.append((command, name))
            raise flow_driver.ContractFailure("fixture-setup-failure")
        return super().invoke(command, name)


class ResidualAdapter(FakeAdapter):
    def invoke(self, command: str, name: str) -> Any:
        if command == "snapshot" and name == "fixture-anonymous-audits":
            self.calls.append((command, name))
            return {"residualCount": 1}
        return super().invoke(command, name)


class TeardownFailAdapter(FakeAdapter):
    def invoke(self, command: str, name: str) -> Any:
        if command == "teardown":
            self.calls.append((command, name))
            raise flow_driver.ContractFailure("private-secret-from-adapter")
        return super().invoke(command, name)


class FlowDriverTests(unittest.TestCase):
    def test_direct_login_failure_logout_replay_and_signed_claims(self) -> None:
        with RuntimeServer() as runtime:
            adapter = FakeAdapter(runtime)
            record = flow_driver.run_trial(
                "password-direct-login-token",
                "fastapi",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": adapter, "fastapi": adapter},
                provenance={
                    "sourceRevision": "0123456789abcdef0123456789abcdef01234567"
                },
            )
        self.assertEqual(record["outcome"], "pass")
        self.assertFalse(record["qualifyingEvidence"])
        self.assertTrue(record["assertions"]["jwt"]["accessSignatureVerified"])
        self.assertTrue(record["assertions"]["state"]["sessionTokenLinked"])
        self.assertGreaterEqual(
            record["timing"]["endedNs"], record["timing"]["startedNs"]
        )
        self.assertEqual(adapter.calls[0], ("preflight", "flow-driver-v1"))
        self.assertEqual(adapter.calls[-3], ("teardown", "active-password-user"))
        self.assertEqual(adapter.calls[-2], ("snapshot", "auth-lifecycle"))
        self.assertEqual(adapter.calls[-1], ("snapshot", "fixture-anonymous-audits"))
        serialized = json.dumps(record)
        for private_value in (PASSWORD, "private-token-id", "private-signature"):
            self.assertNotIn(private_value, serialized)

    def test_handoff_cross_runtime_failure_success_and_replay(self) -> None:
        for topology in ("express-fastapi", "fastapi-express"):
            with self.subTest(topology=topology):
                shared_state: dict[str, Any] = {
                    "activeHashes": [],
                    "handoffs": set(),
                }
                with (
                    RuntimeServer(shared_state=shared_state) as express_runtime,
                    RuntimeServer(shared_state=shared_state) as fastapi_runtime,
                ):
                    express_adapter = FakeAdapter(express_runtime)
                    fastapi_adapter = FakeAdapter(fastapi_runtime)
                    runtimes = {
                        "express": express_runtime,
                        "fastapi": fastapi_runtime,
                    }
                    record = flow_driver.run_trial(
                        "password-handoff-exchange",
                        topology,
                        {
                            "express": express_runtime.url,
                            "fastapi": fastapi_runtime.url,
                        },
                        {
                            "express": express_adapter,
                            "fastapi": fastapi_adapter,
                        },
                    )
                producer, consumer = topology.split("-")
                self.assertEqual(record["outcome"], "pass")
                self.assertTrue(record["assertions"]["negative"]["invalidCodeRejected"])
                self.assertTrue(
                    record["assertions"]["negative"]["handoffReplayRejected"]
                )
                self.assertTrue(record["assertions"]["state"]["handoffConsumed"])
                self.assertNotIn("private-handoff-code", json.dumps(record))
                self.assertEqual(
                    express_adapter.calls[0], ("preflight", "flow-driver-v1")
                )
                self.assertEqual(
                    fastapi_adapter.calls[0], ("preflight", "flow-driver-v1")
                )
                self.assertIn(("POST", "/auth/login"), runtimes[producer].requests)
                self.assertIn(("POST", "/auth/exchange"), runtimes[consumer].requests)
                self.assertNotIn(
                    ("POST", "/auth/exchange"), runtimes[producer].requests
                )

    def test_claim_mismatch_is_distinct_and_still_tears_down(self) -> None:
        with RuntimeServer(bad_claim=True) as runtime:
            adapter = FakeAdapter(runtime)
            record = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": adapter, "fastapi": adapter},
            )
        self.assertEqual(record["outcome"], "fail")
        self.assertEqual(
            record["error"]["category"],
            "access-token-signature-or-claim-mismatch",
        )
        self.assertEqual(adapter.calls[-3], ("teardown", "active-password-user"))

    def test_duplicate_handoff_consume_success_fails_closed(self) -> None:
        shared_state: dict[str, Any] = {"activeHashes": [], "handoffs": set()}
        with (
            RuntimeServer(shared_state=shared_state) as express_runtime,
            RuntimeServer(
                replay_succeeds=True, shared_state=shared_state
            ) as fastapi_runtime,
        ):
            express_adapter = FakeAdapter(express_runtime)
            fastapi_adapter = FakeAdapter(fastapi_runtime)
            record = flow_driver.run_trial(
                "password-handoff-exchange",
                "express-fastapi",
                {"express": express_runtime.url, "fastapi": fastapi_runtime.url},
                {"express": express_adapter, "fastapi": fastapi_adapter},
            )
        self.assertEqual(record["outcome"], "fail")
        self.assertEqual(record["error"]["category"], "http-error-contract-mismatch")

    def test_timeout_is_distinct_and_still_tears_down(self) -> None:
        with RuntimeServer(slow=True) as runtime:
            adapter = FakeAdapter(runtime)
            record = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": adapter, "fastapi": adapter},
                timeout=0.02,
            )
            time.sleep(0.2)
            self.assertNotEqual(runtime.active_hashes, [])
        self.assertEqual(record["outcome"], "fail")
        self.assertIn(
            record["error"]["category"],
            {"http-transport-failure", "http-response-read-failure"},
        )
        self.assertEqual(adapter.calls[-3], ("teardown", "active-password-user"))
        self.assertEqual(record["cleanup"]["outcome"], "not-proven")

    def test_error_and_handoff_envelopes_reject_changed_or_extra_fields(self) -> None:
        wrong_media = flow_driver.HttpResult(
            401,
            {"content-type": "text/notjson"},
            {
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid email or password",
                }
            },
            1,
            2,
        )
        with self.assertRaisesRegex(flow_driver.ContractFailure, "error-contract"):
            flow_driver._expect_error(
                wrong_media, 401, "INVALID_CREDENTIALS", "Invalid email or password"
            )
        error_result = flow_driver.HttpResult(
            401,
            {"content-type": "application/json"},
            {
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "changed",
                    "extra": True,
                }
            },
            1,
            2,
        )
        with self.assertRaisesRegex(flow_driver.ContractFailure, "error-contract"):
            flow_driver._expect_error(
                error_result,
                401,
                "INVALID_CREDENTIALS",
                "Invalid email or password",
            )

        fixture = {
            "redirectUri": "http://127.0.0.1:4101/auth/callback",
            "state": "private-caller-state",
        }
        invalid_redirects = (
            "http://127.0.0.1:4101/auth/callback?code=value&state=private-caller-state&extra=1",
            "http://127.0.0.1:4101/auth/callback?code=value&state=private-caller-state#fragment",
        )
        for redirect in invalid_redirects:
            with (
                self.subTest(redirect=redirect),
                self.assertRaisesRegex(flow_driver.ContractFailure, "handoff-redirect"),
            ):
                flow_driver._handoff_code(
                    flow_driver.HttpResult(
                        200,
                        {"content-type": "application/json"},
                        {"redirectUrl": redirect},
                        1,
                        2,
                    ),
                    fixture,
                )
        with self.assertRaisesRegex(flow_driver.ContractFailure, "response-contract"):
            flow_driver._handoff_code(
                flow_driver.HttpResult(
                    200,
                    {"content-type": "application/json"},
                    {
                        "redirectUrl": "http://127.0.0.1:4101/auth/callback?code=value&state=private-caller-state",
                        "extra": True,
                    },
                    1,
                    2,
                ),
                fixture,
            )

    def test_malformed_http_response_is_distinct(self) -> None:
        with RuntimeServer(malformed_login=True) as runtime:
            adapter = FakeAdapter(runtime)
            record = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": adapter, "fastapi": adapter},
            )
        self.assertEqual(record["outcome"], "fail")
        self.assertEqual(record["error"]["category"], "malformed-http-response")

    def test_fixture_setup_failure_is_distinct_and_cleanup_is_attempted(self) -> None:
        with RuntimeServer() as runtime:
            adapter = FailingSetupAdapter(runtime)
            record = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": adapter, "fastapi": adapter},
            )
        self.assertEqual(record["outcome"], "fail")
        self.assertEqual(record["error"]["category"], "fixture-setup-failure")
        self.assertIn(("teardown", "active-password-user"), adapter.calls)

    def test_token_header_claim_time_and_signature_defects_fail_closed(self) -> None:
        now = int(time.time())
        cases = (
            {"claim_overrides": {"iat": now - 1000, "exp": now - 100}},
            {"claim_overrides": {"iat": now + 500, "exp": now + 900}},
            {"claim_overrides": {"iat": float("nan")}},
            {"claim_overrides": {"iss": "https://wrong.example.invalid"}},
            {"claim_overrides": {"aud": "wrong-audience"}},
            {"claim_overrides": {"type": "refresh"}},
            {"header_overrides": {"alg": "HS256"}},
            {"header_overrides": {"kid": "unknown-key"}},
            {"tamper_access": True},
            {"tamper_refresh": True},
        )
        for options in cases:
            with self.subTest(options=options), RuntimeServer(**options) as runtime:
                adapter = FakeAdapter(runtime)
                record = flow_driver.run_trial(
                    "password-direct-login-token",
                    "express",
                    {"express": runtime.url, "fastapi": runtime.url},
                    {"express": adapter, "fastapi": adapter},
                )
                self.assertEqual(record["outcome"], "fail")
                self.assertFalse(record["qualifyingEvidence"])

    def test_cleanup_failures_are_explicit_and_adapter_details_are_not_published(
        self,
    ) -> None:
        with RuntimeServer() as runtime:
            residual_adapter = ResidualAdapter(runtime)
            residual = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": residual_adapter, "fastapi": residual_adapter},
            )
            teardown_adapter = TeardownFailAdapter(runtime)
            teardown = flow_driver.run_trial(
                "password-direct-login-token",
                "express",
                {"express": runtime.url, "fastapi": runtime.url},
                {"express": teardown_adapter, "fastapi": teardown_adapter},
            )
        self.assertEqual(residual["cleanup"]["outcome"], "fail")
        self.assertEqual(
            residual["cleanup"]["category"],
            "fixture-residual-verification-failure",
        )
        self.assertEqual(teardown["cleanup"]["outcome"], "fail")
        self.assertEqual(teardown["cleanup"]["category"], "fixture-teardown-failure")
        self.assertNotIn("private-secret-from-adapter", json.dumps(teardown))

    def test_cross_runtime_boundaries_are_validated_before_preflight(self) -> None:
        with RuntimeServer() as express_runtime, RuntimeServer() as fastapi_runtime:
            express_adapter = FakeAdapter(express_runtime)
            fastapi_adapter = FakeAdapter(fastapi_runtime)
            urls = {"express": express_runtime.url, "fastapi": fastapi_runtime.url}
            adapters = {"express": express_adapter, "fastapi": fastapi_adapter}
            with self.assertRaisesRegex(flow_driver.ContractFailure, "cross-runtime"):
                flow_driver.run_trial(
                    "password-handoff-exchange",
                    "express-express",
                    urls,
                    adapters,
                )
            fastapi_adapter.isolation_identity = ("other-db", "other-redis")
            with self.assertRaisesRegex(flow_driver.ContractFailure, "shared-isolated"):
                flow_driver.run_trial(
                    "password-handoff-exchange",
                    "express-fastapi",
                    urls,
                    adapters,
                )
            self.assertEqual(express_adapter.calls, [])
            self.assertEqual(fastapi_adapter.calls, [])

        with RuntimeServer() as same_runtime:
            adapter = FakeAdapter(same_runtime)
            with self.assertRaisesRegex(
                flow_driver.ContractFailure, "distinct-runtime"
            ):
                flow_driver.run_trial(
                    "password-handoff-exchange",
                    "express-fastapi",
                    {"express": same_runtime.url, "fastapi": same_runtime.url},
                    {"express": adapter, "fastapi": adapter},
                )
            self.assertEqual(adapter.calls, [])

    def test_auth_state_rejects_boolean_negative_and_malformed_hashes(self) -> None:
        invalid_states = (
            {
                "activeRefreshTokens": False,
                "authHandoffKeys": 0,
                "activeTokenHashes": [],
            },
            {
                "activeRefreshTokens": 0,
                "authHandoffKeys": -1,
                "activeTokenHashes": [],
            },
            {
                "activeRefreshTokens": 1,
                "authHandoffKeys": 0,
                "activeTokenHashes": ["not-a-sha256"],
            },
        )

        class StaticAdapter:
            def __init__(self, state: dict[str, Any]):
                self.state = state

            def invoke(self, _command: str, _name: str) -> Any:
                return self.state

        for state in invalid_states:
            with (
                self.subTest(state=state),
                self.assertRaisesRegex(
                    flow_driver.ContractFailure, "malformed-auth-state"
                ),
            ):
                flow_driver._auth_state(StaticAdapter(state))

    def test_topology_and_provenance_are_fail_closed(self) -> None:
        with RuntimeServer() as runtime:
            adapter = FakeAdapter(runtime)
            urls = {"express": runtime.url, "fastapi": runtime.url}
            adapters = {"express": adapter, "fastapi": adapter}
            with self.assertRaisesRegex(flow_driver.ContractFailure, "single-runtime"):
                flow_driver.run_trial(
                    "password-direct-login-token", "express-fastapi", urls, adapters
                )
            with self.assertRaisesRegex(
                flow_driver.ContractFailure, "unsupported-provenance"
            ):
                flow_driver.run_trial(
                    "password-direct-login-token",
                    "express",
                    urls,
                    adapters,
                    provenance={"accessToken": "private"},
                )

    def test_cli_uses_private_subprocess_adapter_and_writes_no_replace_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.json"
            adapter_path = root / "fixture-adapter.py"
            adapter_path.write_text(
                textwrap.dedent(
                    f"""\
                    #!/usr/bin/env python3
                    import json
                    import os
                    import sys
                    from pathlib import Path

                    command, name = sys.argv[1:]
                    state = Path(os.environ["STATE_PATH"])
                    empty = {{"activeRefreshTokens": 0, "authHandoffKeys": 0, "activeTokenHashes": []}}
                    if command == "preflight":
                        result = {{"status": "ok"}}
                    elif command == "setup":
                        state.write_text(json.dumps(empty))
                        result = {{
                            "userId": {USER_ID!r}, "email": {EMAIL!r},
                            "password": {PASSWORD!r}, "name": "Contract Active",
                            "roles": [{{"serviceKey": "temis", "name": "user"}}],
                            "audience": {AUDIENCE!r},
                        }}
                    elif command == "snapshot" and name == "fixture-anonymous-audits":
                        result = {{"residualCount": 0}}
                    elif command == "snapshot":
                        result = json.loads(state.read_text())
                    elif command == "teardown":
                        state.write_text(json.dumps(empty))
                        result = {{"status": "clean"}}
                    else:
                        raise SystemExit(2)
                    print(json.dumps(result))
                    """
                ),
                encoding="utf-8",
            )
            adapter_path.chmod(0o700)
            config_path = root / "fixture.json"
            config_path.write_text(
                json.dumps(
                    {
                        "CONTRACT_FIXTURE_MODE": "1",
                        "CONTRACT_SERVER_MAIL_MODE": "dev",
                        "CONTRACT_REDIS_ISOLATED_DB": "1",
                        "CONTRACT_DATABASE_URL": "postgresql://fixture@127.0.0.1/contract_test",
                        "CONTRACT_REDIS_URL": "redis://127.0.0.1:6379/1",
                        "CONTRACT_REFRESH_SECRET": "contract-refresh-secret-value",
                        "STATE_PATH": str(state_path),
                    }
                ),
                encoding="utf-8",
            )
            config_path.chmod(0o600)
            output_path = root / "evidence.jsonl"
            with RuntimeServer(state_path=state_path) as runtime:
                exit_code = flow_driver.main(
                    [
                        "--express",
                        runtime.url,
                        "--fastapi",
                        runtime.url,
                        "--express-adapter",
                        str(adapter_path),
                        "--fastapi-adapter",
                        str(adapter_path),
                        "--express-adapter-config",
                        str(config_path),
                        "--fastapi-adapter-config",
                        str(config_path),
                        "--flow",
                        "password-direct-login-token",
                        "--topology",
                        "express",
                        "--issuer",
                        "https://auth.financenow.kr",
                        "--jsonl",
                        str(output_path),
                        "--provenance",
                        "sourceRevision=0123456789abcdef0123456789abcdef01234567",
                    ]
                )
            self.assertEqual(exit_code, 0)
            record = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(record["outcome"], "pass")
            self.assertEqual(oct(output_path.stat().st_mode & 0o777), "0o444")
            with self.assertRaises(FileExistsError):
                flow_driver.write_jsonl(output_path, [record])


if __name__ == "__main__":
    unittest.main()
