from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, Self, cast
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "contracts" / "bin" / "oauth_google_flow.py"
SPEC = importlib.util.spec_from_file_location("contract_oauth_google_flow", MODULE_PATH)
assert SPEC and SPEC.loader
oauth = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oauth
SPEC.loader.exec_module(oauth)
EXPECTED_ISSUER = "https://auth.financenow.kr"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _json_segment(value: dict[str, Any]) -> str:
    return _b64(json.dumps(value, separators=(",", ":"), sort_keys=True).encode())


class SharedState:
    user_id = "00000000-0000-4000-8000-000000000051"
    email = "google-linked@example.invalid"
    name = "Google Linked User"
    audience = "oauth-mixed-contract"
    issuer = EXPECTED_ISSUER
    client_id = "oauth-mixed-contract"
    redirect_uri = "http://127.0.0.1:4101/auth/callback"
    provider_subject = "google-subject-051"
    run_id = "google-flow-run-051"
    roles: ClassVar[list[dict[str, str]]] = [{"serviceKey": "temis", "name": "user"}]

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.reset()

    def reset(self) -> None:
        with getattr(self, "lock", threading.Lock()):
            self.oauth_states: dict[str, dict[str, str]] = {}
            self.handoffs: dict[str, dict[str, str]] = {}
            self.provider_records: list[dict[str, object]] = []
            self.linked = False
            self.refreshes = 0
            self.active_hashes: list[str] = []
            self.sequence = 0
            self.last_access_token: str | None = None

    def create_state(self, role: str, query: dict[str, str]) -> str:
        with self.lock:
            self.sequence += 1
            state = f"private-google-state-{self.sequence}"
            self.oauth_states[state] = {**query, "role": role}
            return state

    def callback(self, state: str, role: str) -> str | None:
        with self.lock:
            metadata = self.oauth_states.pop(state, None)
            if metadata is None:
                return None
            self.provider_records.extend(
                [
                    {
                        "schemaVersion": 1,
                        "runId": self.run_id,
                        "runtime": role,
                        "source": "provider-transport",
                        "provider": "google",
                        "operation": "token",
                        "sequence": 1,
                    },
                    {
                        "schemaVersion": 1,
                        "runId": self.run_id,
                        "runtime": role,
                        "source": "provider-transport",
                        "provider": "google",
                        "operation": "user-info",
                        "sequence": 2,
                    },
                ]
            )
            self.linked = True
            code = f"private-handoff-{self.sequence}"
            self.handoffs[code] = metadata
            return code

    def exchange(self, code: str, verifier: str) -> bool:
        with self.lock:
            metadata = self.handoffs.get(code)
            if metadata is None:
                return False
            expected = _b64(__import__("hashlib").sha256(verifier.encode()).digest())
            if expected != metadata["code_challenge"]:
                return False
            del self.handoffs[code]
            self.refreshes += 1
            return True

    def token(self) -> str:
        now = int(time.time())
        header = _json_segment({"alg": "RS256", "kid": "oauth-test-key", "typ": "JWT"})
        claims = _json_segment(
            {
                "sub": self.user_id,
                "email": self.email,
                "name": self.name,
                "email_verified": True,
                "roles": self.roles,
                "type": "access",
                "aud": self.audience,
                "iss": self.issuer,
                "iat": now - 1,
                "exp": now + 300,
            }
        )
        signature = self.key.sign(
            f"{header}.{claims}".encode(), padding.PKCS1v15(), SHA256()
        )
        token = f"{header}.{claims}.{_b64(signature)}"
        self.last_access_token = token
        return token

    def refresh_token(self, secret: str) -> str:
        now = int(time.time())
        header = _json_segment({"alg": "HS256", "typ": "JWT"})
        claims = _json_segment(
            {
                "sub": self.user_id,
                "audience": self.audience,
                "type": "refresh",
                "tokenId": "google-refresh-session-1",
                "iat": now - 1,
                "exp": now + 300,
            }
        )
        signature = hmac.new(
            secret.encode(), f"{header}.{claims}".encode(), hashlib.sha256
        ).digest()
        return f"{header}.{claims}.{_b64(signature)}"

    def jwks(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "oauth-test-key",
                    "alg": "RS256",
                    "use": "sig",
                    "n": _b64(
                        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                    ),
                    "e": _b64(
                        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                    ),
                }
            ]
        }


class Runtime:
    def __init__(
        self,
        role: str,
        state: SharedState,
        *,
        redirect_status: int = 302,
        jwks_status: int = 200,
    ) -> None:
        self.role, self.state = role, state
        self.redirect_status = redirect_status
        self.jwks_status = jwks_status
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def send_json(self, status: int, body: object) -> None:
                raw = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def fail(self, code: str) -> None:
                self.send_json(
                    400,
                    {"error": {"code": code, "message": oauth._ERROR_MESSAGES[code]}},
                )

            def redirect(self, location: str) -> None:
                self.send_response(owner.redirect_status)
                self.send_header("location", location)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                query_lists = urllib.parse.parse_qs(parsed.query)
                query = {
                    key: values[0]
                    for key, values in query_lists.items()
                    if len(values) == 1
                }
                if parsed.path == "/slow":
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", "4")
                    self.end_headers()
                    for part in (b"n", b"u", b"l", b"l"):
                        time.sleep(0.08)
                        try:
                            self.wfile.write(part)
                            self.wfile.flush()
                        except OSError:
                            break
                    return
                if parsed.path == "/oversized":
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(64 * 1024 + 1))
                    self.end_headers()
                    return
                if parsed.path == "/auth/google":
                    required = {
                        "client_id",
                        "redirect_uri",
                        "state",
                        "code_challenge",
                        "code_challenge_method",
                    }
                    if (
                        set(query) != required
                        or query["code_challenge_method"] != "S256"
                    ):
                        return self.send_json(
                            400,
                            {
                                "error": {
                                    "code": "INVALID_REQUEST",
                                    "message": "Invalid request",
                                }
                            },
                        )
                    state_value = owner.state.create_state(owner.role, query)
                    authorization = (
                        "https://accounts.google.com/o/oauth2/v2/auth?"
                        + urllib.parse.urlencode(
                            {
                                "response_type": "code",
                                "client_id": "google-client",
                                "redirect_uri": f"{owner.origin}/auth/google/callback",
                                "scope": "openid email profile",
                                "state": state_value,
                            }
                        )
                    )
                    return self.redirect(authorization)
                if parsed.path == "/auth/google/callback":
                    if query.get("error"):
                        if query.get("state") in owner.state.oauth_states:
                            return self.fail("INVALID_OAUTH_STATE")
                        return self.fail("OAUTH_PROVIDER_ERROR")
                    if query.get("code") != "google-code" or not query.get("state"):
                        return self.fail("INVALID_OAUTH_STATE")
                    code = owner.state.callback(query["state"], owner.role)
                    if code is None:
                        return self.fail("INVALID_OAUTH_STATE")
                    return self.redirect(
                        owner.state.redirect_uri
                        + "?"
                        + urllib.parse.urlencode(
                            {"code": code, "state": oauth.CALLER_STATE}
                        )
                    )
                if parsed.path == "/.well-known/jwks.json":
                    return self.send_json(owner.jwks_status, owner.state.jwks())
                if parsed.path == "/users/me":
                    if (
                        self.headers.get("authorization")
                        != f"Bearer {owner.state.last_access_token}"
                    ):
                        return self.send_json(
                            401,
                            {
                                "error": {
                                    "code": "UNAUTHORIZED",
                                    "message": "Authentication is required",
                                }
                            },
                        )
                    return self.send_json(
                        200,
                        {
                            "id": owner.state.user_id,
                            "email": owner.state.email,
                            "name": owner.state.name,
                            "email_verified": True,
                            "roles": owner.state.roles,
                        },
                    )
                return self.send_json(404, {})

            def do_POST(self) -> None:
                if self.path != "/auth/exchange":
                    return self.send_json(404, {})
                length = int(self.headers.get("content-length", "0"))
                body = json.loads(self.rfile.read(length))
                if set(body) != {"clientId", "redirectUri", "code", "codeVerifier"}:
                    return self.fail("INVALID_AUTH_HANDOFF_CODE")
                if (
                    body["clientId"] != owner.state.client_id
                    or body["redirectUri"] != owner.state.redirect_uri
                ):
                    return self.fail("INVALID_AUTH_HANDOFF_CODE")
                if not owner.state.exchange(body["code"], body["codeVerifier"]):
                    return self.fail("INVALID_AUTH_HANDOFF_CODE")
                return self.send_json(
                    200,
                    {
                        "accessToken": owner.state.token(),
                        "refreshToken": self.issue_refresh(),
                    },
                )

            def issue_refresh(self) -> str:
                token = owner.state.refresh_token("oauth-contract-refresh-secret")
                owner.state.active_hashes = [hashlib.sha256(token.encode()).hexdigest()]
                return token

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = cast(tuple[str, int], self.server.server_address)[1]
        self.origin = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.server.server_close()


@dataclass(frozen=True, slots=True)
class RuntimeBindingStub:
    role: str
    origin: str
    pid: int
    process_group: int


class Adapter:
    def __init__(
        self,
        state: SharedState,
        producer: str,
        *,
        tamper_channel: bool = False,
        malformed_setup: bool = False,
        noop_teardown: bool = False,
        unrelated_session: bool = False,
        runtime_origins: dict[str, str] | None = None,
    ) -> None:
        self.state, self.producer = state, producer
        self.refresh_secret = "oauth-contract-refresh-secret"
        self.tamper_channel = tamper_channel
        self.malformed_setup = malformed_setup
        self.noop_teardown = noop_teardown
        self.unrelated_session = unrelated_session
        origins = runtime_origins or {
            "express": "http://127.0.0.1:4400",
            "fastapi": "http://127.0.0.1:4401",
        }
        self.runtime_bindings = {
            "express": RuntimeBindingStub("express", origins["express"], 91001, 91001),
            "fastapi": RuntimeBindingStub("fastapi", origins["fastapi"], 91002, 91002),
        }
        self.calls: list[tuple[str, str]] = []

    def invoke(self, command: str, name: str) -> Any:
        self.calls.append((command, name))
        if command == "setup":
            self.state.reset()
            if self.malformed_setup:
                self.state.provider_records.append({"unexpected": True})
                return []
            return {
                "userId": self.state.user_id,
                "email": self.state.email,
                "name": self.state.name,
                "roles": self.state.roles,
                "audience": self.state.audience,
                "clientId": self.state.client_id,
                "redirectUri": self.state.redirect_uri,
                "provider": "google",
                "providerSubject": self.state.provider_subject,
                "runId": self.state.run_id,
            }
        if command == "teardown":
            if not self.noop_teardown:
                self.state.reset()
            return {"status": "clean"}
        if name == "oauth-google-provider-invocations":
            return {
                "source": "launcher-owned-private-provider-record-pipe-v1",
                "consumed": not self.tamper_channel,
                "records": list(self.state.provider_records),
            }
        if name == "oauth-google-state":
            return {
                "canonicalUsers": int(self.state.linked),
                "providerIdentities": int(self.state.linked),
                "provider": "google",
                "providerSubject": self.state.provider_subject,
                "linkedUserId": self.state.user_id,
                "oauthStatesRemaining": len(self.state.oauth_states),
                "handoffsRemaining": len(self.state.handoffs),
                "activeRefreshTokens": self.state.refreshes,
                "activeTokenHashes": [
                    *self.state.active_hashes,
                    *(["f" * 64] if self.unrelated_session else []),
                ],
            }
        if name == "oauth-google-residual":
            return {
                "oauthStates": len(self.state.oauth_states),
                "handoffs": len(self.state.handoffs),
                "activeRefreshTokens": self.state.refreshes,
                "activeTokenHashes": list(self.state.active_hashes),
                "providerRecords": len(self.state.provider_records),
            }
        raise AssertionError((command, name))


class GoogleOAuthFlowTests(unittest.TestCase):
    @staticmethod
    def config_document() -> dict[str, object]:
        return {
            "producerOrigin": "http://127.0.0.1:4400",
            "consumerOrigin": "http://127.0.0.1:4401",
            "producer": "express",
            "consumer": "fastapi",
            "expectedIssuer": EXPECTED_ISSUER,
            "fixtureAdapter": "/tmp/fixture-adapter",
            "fixtureEnvironment": {"CONTRACT_REFRESH_SECRET": "test-refresh-secret"},
        }

    def run_order(self, producer_role: str) -> dict[str, Any]:
        state = SharedState()
        consumer_role = "fastapi" if producer_role == "express" else "express"
        with Runtime("express", state) as express, Runtime("fastapi", state) as fastapi:
            runtimes = {"express": express, "fastapi": fastapi}
            adapter = Adapter(
                state,
                producer_role,
                runtime_origins={
                    "express": express.origin,
                    "fastapi": fastapi.origin,
                },
            )
            result = oauth.run_google_flow(
                runtimes[producer_role].origin,
                runtimes[consumer_role].origin,
                adapter,
                producer=producer_role,
                consumer=consumer_role,
                expected_issuer=EXPECTED_ISSUER,
            )
            self.assertEqual(adapter.calls[0], ("setup", "google-oauth-user"))
            self.assertEqual(
                adapter.calls[-2:],
                [
                    ("teardown", "google-oauth-user"),
                    ("snapshot", "oauth-google-residual"),
                ],
            )
            return cast(dict[str, Any], result)

    def test_express_to_fastapi_connected_flow(self) -> None:
        result = self.run_order("express")
        self.assertEqual(result["ordering"], "express-fastapi")
        self.assertTrue(all(result["assertions"].values()))
        self.assertFalse(result["qualifying"])
        self.assertEqual(result["unverified"], ["provider-error-state-lifecycle"])
        self.assertTrue(result["assertions"]["oauthSuccessStateReplayRejected"])
        self.assertNotIn("oauthStateReplayRejected", result["assertions"])

    def test_fastapi_to_express_connected_flow(self) -> None:
        result = self.run_order("fastapi")
        self.assertEqual(result["ordering"], "fastapi-express")
        self.assertTrue(result["assertions"]["realAccessJwtVerified"])

    def test_rejects_provider_records_without_consumed_private_channel(self) -> None:
        state = SharedState()
        with Runtime("express", state) as express, Runtime("fastapi", state) as fastapi:
            adapter = Adapter(
                state,
                "express",
                tamper_channel=True,
                runtime_origins={
                    "express": express.origin,
                    "fastapi": fastapi.origin,
                },
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "invocation-mismatch"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer=EXPECTED_ISSUER,
                )
            self.assertEqual(
                adapter.calls[-2:],
                [
                    ("teardown", "google-oauth-user"),
                    ("snapshot", "oauth-google-residual"),
                ],
            )

    def test_http_reader_enforces_absolute_deadline_and_body_cap(self) -> None:
        state = SharedState()
        with Runtime("express", state) as runtime:
            started = time.monotonic()
            with self.assertRaisesRegex(
                oauth.ContractFailure, "deadline-exceeded|transport-failure"
            ):
                oauth._call(runtime.origin, "GET", "/slow", timeout=0.14)
            self.assertLess(time.monotonic() - started, 0.3)
            with self.assertRaisesRegex(oauth.ContractFailure, "body-too-large"):
                oauth._call(runtime.origin, "GET", "/oversized", timeout=1)

    def test_secure_config_reads_in_bounded_loop_and_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            config_path = Path(raw_directory) / "oauth-google.json"
            config_path.write_text(json.dumps(self.config_document()), encoding="utf-8")
            config_path.chmod(0o600)
            self.assertEqual(
                oauth._secure_config(config_path)["expectedIssuer"], EXPECTED_ISSUER
            )

            original_read = oauth.os.read
            changed = False

            def mutate_mode(descriptor: int, count: int) -> bytes:
                nonlocal changed
                chunk = cast(bytes, original_read(descriptor, count))
                if not changed:
                    changed = True
                    config_path.chmod(0o640)
                return chunk

            with (
                mock.patch.object(oauth.os, "read", side_effect=mutate_mode),
                self.assertRaisesRegex(oauth.ContractFailure, "changed-during-read"),
            ):
                oauth._secure_config(config_path)

    def test_secure_config_rejects_growth_past_bound_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            config_path = Path(raw_directory) / "oauth-google.json"
            config_path.write_text(json.dumps(self.config_document()), encoding="utf-8")
            config_path.chmod(0o600)
            original_read = oauth.os.read
            grown = False

            def grow_file(descriptor: int, count: int) -> bytes:
                nonlocal grown
                chunk = cast(bytes, original_read(descriptor, count))
                if not grown:
                    grown = True
                    with config_path.open("ab") as stream:
                        stream.write(b"x" * (oauth.MAX_CONFIG_BYTES + 1))
                return chunk

            with (
                mock.patch.object(oauth.os, "read", side_effect=grow_file),
                self.assertRaisesRegex(oauth.ContractFailure, "config-too-large"),
            ):
                oauth._secure_config(config_path)

    def test_rejects_same_runtime_ordering_before_setup(self) -> None:
        state = SharedState()
        adapter = Adapter(state, "express")
        with self.assertRaisesRegex(oauth.ContractFailure, "mixed-ordering"):
            oauth.run_google_flow(
                "http://127.0.0.1:1",
                "http://127.0.0.1:1",
                adapter,
                producer="express",
                consumer="express",
                expected_issuer=EXPECTED_ISSUER,
            )
        self.assertEqual(adapter.calls, [])

    def test_rejects_distinct_roles_on_the_same_normalized_origin(self) -> None:
        state = SharedState()
        adapter = Adapter(state, "express")
        with self.assertRaisesRegex(oauth.ContractFailure, "distinct-origins"):
            oauth.run_google_flow(
                "http://127.0.0.1:4400/",
                "http://127.0.0.1:4400",
                adapter,
                producer="express",
                consumer="fastapi",
                expected_issuer=EXPECTED_ISSUER,
            )
        self.assertEqual(adapter.calls, [])

    def test_malformed_setup_preserves_primary_error_and_still_cleans(self) -> None:
        state = SharedState()
        adapter = Adapter(state, "express", malformed_setup=True, noop_teardown=True)
        with self.assertRaisesRegex(
            oauth.ContractFailure, "malformed-fixture"
        ) as captured:
            oauth.run_google_flow(
                "http://127.0.0.1:4400",
                "http://127.0.0.1:4401",
                adapter,
                producer="express",
                consumer="fastapi",
                expected_issuer=EXPECTED_ISSUER,
            )
        self.assertIn(
            "google-oauth-cleanup-failure", getattr(captured.exception, "__notes__", [])
        )
        self.assertIn(("teardown", "google-oauth-user"), adapter.calls)
        self.assertIn(("snapshot", "oauth-google-residual"), adapter.calls)

    def test_interrupt_is_not_replaced_by_fixture_cleanup_failure(self) -> None:
        for primary in (KeyboardInterrupt(), SystemExit(130)):
            with self.subTest(primary=type(primary).__name__):
                state = SharedState()
                adapter = Adapter(state, "express")

                def invoke(
                    command: str, _name: str, failure: BaseException = primary
                ) -> Any:
                    if command == "setup":
                        raise failure
                    if command == "teardown":
                        return {"status": "not-clean"}
                    raise ValueError("residual probe failed")

                with (
                    mock.patch.object(adapter, "invoke", side_effect=invoke) as called,
                    self.assertRaises(type(primary)) as captured,
                ):
                    oauth.run_google_flow(
                        "http://127.0.0.1:4400",
                        "http://127.0.0.1:4401",
                        adapter,
                        producer="express",
                        consumer="fastapi",
                        expected_issuer=EXPECTED_ISSUER,
                    )
                self.assertIs(captured.exception, primary)
                self.assertIn("google-oauth-cleanup-failure", primary.__notes__)
                self.assertIsInstance(primary.__cause__, oauth.ContractFailure)
                self.assertEqual(
                    str(primary.__cause__), "google-oauth-teardown-mismatch"
                )
                self.assertEqual(
                    called.call_args_list[-2:],
                    [
                        mock.call("teardown", "google-oauth-user"),
                        mock.call("snapshot", "oauth-google-residual"),
                    ],
                )

    def test_noop_teardown_is_rejected_by_residual_probe(self) -> None:
        state = SharedState()
        with Runtime("express", state) as express, Runtime("fastapi", state) as fastapi:
            adapter = Adapter(
                state,
                "express",
                noop_teardown=True,
                runtime_origins={"express": express.origin, "fastapi": fastapi.origin},
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "cleanup-residual"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer=EXPECTED_ISSUER,
                )

    def test_wrong_independent_issuer_is_rejected(self) -> None:
        state = SharedState()
        with Runtime("express", state) as express, Runtime("fastapi", state) as fastapi:
            adapter = Adapter(
                state,
                "express",
                runtime_origins={"express": express.origin, "fastapi": fastapi.origin},
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "jwt-claim-mismatch"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer="https://wrong-issuer.example",
                )

    def test_unrelated_active_session_is_rejected(self) -> None:
        state = SharedState()
        with Runtime("express", state) as express, Runtime("fastapi", state) as fastapi:
            adapter = Adapter(
                state,
                "express",
                unrelated_session=True,
                runtime_origins={"express": express.origin, "fastapi": fastapi.origin},
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "state-mismatch"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer=EXPECTED_ISSUER,
                )

    def test_requires_exact_302_redirect_and_200_jwks(self) -> None:
        state = SharedState()
        with (
            Runtime("express", state, redirect_status=303) as express,
            Runtime("fastapi", state) as fastapi,
        ):
            adapter = Adapter(
                state,
                "express",
                runtime_origins={"express": express.origin, "fastapi": fastapi.origin},
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "start-response"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer=EXPECTED_ISSUER,
                )
        with (
            Runtime("express", state) as express,
            Runtime("fastapi", state, jwks_status=201) as fastapi,
        ):
            adapter = Adapter(
                state,
                "express",
                runtime_origins={"express": express.origin, "fastapi": fastapi.origin},
            )
            with self.assertRaisesRegex(oauth.ContractFailure, "jwks-response"):
                oauth.run_google_flow(
                    express.origin,
                    fastapi.origin,
                    adapter,
                    producer="express",
                    consumer="fastapi",
                    expected_issuer=EXPECTED_ISSUER,
                )

    def test_rejects_non_loopback_runtime_before_setup(self) -> None:
        state = SharedState()
        adapter = Adapter(state, "express")
        with self.assertRaisesRegex(oauth.ContractFailure, "producer-origin-invalid"):
            oauth.run_google_flow(
                "https://auth.example.com",
                "http://127.0.0.1:1",
                adapter,
                producer="express",
                consumer="fastapi",
                expected_issuer=EXPECTED_ISSUER,
            )
        self.assertEqual(adapter.calls, [])

    def test_rejects_localhost_alias_and_malformed_redirect_query(self) -> None:
        state = SharedState()
        adapter = Adapter(state, "express")
        with self.assertRaisesRegex(oauth.ContractFailure, "producer-origin-invalid"):
            oauth.run_google_flow(
                "http://localhost:4400",
                "http://127.0.0.1:4401",
                adapter,
                producer="express",
                consumer="fastapi",
                expected_issuer=EXPECTED_ISSUER,
            )
        with self.assertRaisesRegex(oauth.ContractFailure, "redirect-query-mismatch"):
            oauth._one_query(
                "https://accounts.google.com/o/oauth2/v2/auth?broken",
                "https://accounts.google.com",
                "/o/oauth2/v2/auth",
            )

    def test_tampered_jwt_is_rejected_by_real_rsa_verification(self) -> None:
        state = SharedState()
        token = state.token()
        head, claims, signature = token.split(".")
        tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        tampered = f"{head}.{claims}.{tampered_signature}"
        with self.assertRaisesRegex(oauth.ContractFailure, "signature-mismatch"):
            oauth._verify_access_token(
                tampered,
                state.jwks(),
                user_id=state.user_id,
                email=state.email,
                name=state.name,
                roles=state.roles,
                audience=state.audience,
                issuer=state.issuer,
            )

    def test_tampered_refresh_jwt_is_rejected_by_real_hmac_verification(self) -> None:
        state = SharedState()
        token = state.refresh_token("oauth-contract-refresh-secret")
        head, claims, signature = token.split(".")
        tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        tampered = f"{head}.{claims}.{tampered_signature}"
        with self.assertRaisesRegex(oauth.ContractFailure, "signature-mismatch"):
            oauth._verify_refresh_token(
                tampered,
                user_id=state.user_id,
                audience=state.audience,
                secret="oauth-contract-refresh-secret",
            )


if __name__ == "__main__":
    unittest.main()
