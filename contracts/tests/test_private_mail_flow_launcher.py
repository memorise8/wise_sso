from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest import mock

BIN = Path(__file__).resolve().parents[1] / "bin"


def load(name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, BIN / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


launcher_module = load(
    "contract_private_mail_flow_launcher", "private_mail_flow_launcher.py"
)
flow_driver = load("contract_private_mail_flow_driver", "flow_driver.py")
adapter_spec = importlib.util.spec_from_file_location(
    "contract_private_mail_express_adapter",
    Path(__file__).resolve().parents[1] / "adapters" / "express_fixture.py",
)
assert adapter_spec is not None and adapter_spec.loader is not None
express_adapter = importlib.util.module_from_spec(adapter_spec)
sys.modules[adapter_spec.name] = express_adapter
adapter_spec.loader.exec_module(express_adapter)

USER_ID = "00000000-0000-4000-8000-000000000002"
EMAIL = "contract-pending@example.invalid"
ATTACH_USER_ID = "00000000-0000-4000-8000-000000000004"
ATTACH_EMAIL = "contract-target@example.invalid"
RUNTIME = r"""
import hashlib, json, os, smtplib, ssl, urllib.error, urllib.request
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

mode = os.environ["FLOW_KIND"]
email = os.environ["FLOW_EMAIL"]
state = {"unused": 0, "used": 0, "confirmed": False, "password": "ContractOnly!2026", "sequence": 0, "token": "", "expired": [], "exchanges": 0, "handoff": False}
upstream = os.environ.get("UPSTREAM")

def send_mail(recipient):
    state["sequence"] += 1
    state["token"] = "owned-private-" + mode + "-" + str(state["sequence"])
    token = state["token"]
    state["digest"] = hashlib.sha256(token.encode()).hexdigest()
    message = EmailMessage()
    message["From"] = "Contract <contract@example.invalid>"
    message["To"] = recipient
    if mode == "email-verification":
        message["Subject"] = "Verify your email"
        prefix = "Use this link to verify your email:"
        path = "verify-email"
    else:
        message["Subject"] = "Reset your password"
        prefix = "Use this link to reset your password:"
        path = "password-reset"
    message.set_content(f"{prefix} https://frontend.invalid/{path}?token={token}")
    context = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=3) as smtp:
        smtp.starttls(context=context)
        smtp.send_message(message)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def body(self):
        length = int(self.headers.get("content-length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")
    def json(self, status, value):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def proxy(self, method, body=None):
        raw = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(upstream + self.path, data=raw, headers={"content-type": "application/json"}, method=method)
        try:
            response = urllib.request.urlopen(req, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = response.read()
            self.send_response(response.status)
            if response.headers.get("content-type"):
                self.send_header("content-type", response.headers["content-type"])
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    def do_GET(self):
        if self.path == "/health":
            if os.environ.get("HEALTH_REDIRECT") == "1":
                self.send_response(302)
                self.send_header("location", "http://example.com/escaped")
                self.end_headers()
            else:
                self.json(200, {"status": "ok"})
        elif upstream:
            self.proxy("GET")
        elif self.path == "/state":
            self.json(200, {key: value for key, value in state.items() if key not in {"token", "password", "expired"}})
        else:
            self.json(404, {})
    def do_POST(self):
        body = self.body()
        if upstream:
            self.proxy("POST", body)
            return
        if self.path == "/expire":
            state["expired"].append(state["token"])
            state["unused"] = 0
            self.json(200, {"status": "expired"})
            return
        if self.path.endswith("/request"):
            send_mail(body.get("email", email))
            state["unused"] = 1
            state["used"] = 0
            state["handoff"] = bool(body.get("clientId"))
            self.json(202, {"status": "accepted"})
            return
        if self.path.endswith("/confirm"):
            if body.get("token") != state["token"] or body.get("token") in state["expired"] or state["used"]:
                code = "INVALID_VERIFICATION_TOKEN" if mode == "email-verification" else "INVALID_RESET_TOKEN"
                message = "Invalid or expired verification token" if mode == "email-verification" else "Invalid or expired reset token"
                self.json(400, {"error": {"code": code, "message": message}})
                return
            state.update(unused=0, used=1, confirmed=True)
            if mode == "password-reset":
                state["password"] = body["password"]
            if mode == "email-verification":
                response = {"status": "verified"}
                if os.environ.get("FLOW_HANDOFF") == "1" and state["handoff"]:
                    response["redirectUrl"] = "http://127.0.0.1:4101/auth/callback?code=handoff-code&state=contract-state"
                self.json(200, response)
            else:
                self.send_response(204); self.end_headers()
            return
        if self.path == "/auth/login":
            if body.get("password") == state["password"]:
                self.json(200, {"accessToken": "fake-access", "refreshToken": "fake-refresh"})
            else:
                self.json(401, {"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"}})
            return
        if self.path == "/auth/refresh":
            self.json(401, {"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Invalid refresh token"}})
            return
        if self.path == "/auth/exchange":
            state["exchanges"] += 1
            if state["exchanges"] == 1:
                self.json(200, {"accessToken": "fake-access", "refreshToken": "fake-refresh"})
            else:
                self.json(400, {"error": {"code": "INVALID_AUTH_HANDOFF_CODE", "message": "Invalid authorization code"}})
            return
        if self.path == "/auth/logout":
            self.send_response(204); self.end_headers()
            return
        self.json(404, {})

ThreadingHTTPServer(("127.0.0.1", int(os.environ["APP_PORT"])), Handler).serve_forever()
"""

ADAPTER = r"""#!/usr/bin/env python3
import json, os, sys, urllib.request
command, name = sys.argv[1:]
base = os.environ["CONTRACT_BASE_URL"]
if command == "preflight":
    result = {"status": "ready"}
elif command == "setup":
    result = {
        "userId": os.environ["FLOW_USER_ID"], "email": os.environ["FLOW_EMAIL"],
        "attachUserId": os.environ["FLOW_ATTACH_USER_ID"],
        "attachEmail": os.environ["FLOW_ATTACH_EMAIL"],
    }
elif command == "teardown":
    result = {"status": "clean"}
elif command == "expire":
    request = urllib.request.Request(base + "/expire", data=b"{}", headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=2) as response:
        result = json.load(response)
else:
    with urllib.request.urlopen(base + "/state", timeout=2) as response:
        state = json.load(response)
    if name in {"auth-lifecycle", "pending-email-auth-lifecycle"}:
        result = {"activeRefreshTokens": 0, "authHandoffKeys": 0, "activeTokenHashes": []}
    elif name == "fixture-anonymous-audits":
        result = {"residualCount": 0}
    elif name in {"email-verification-ledger", "attach-email-verification-ledger"}:
        result = {"unusedTokens": state["unused"], "digests": [state["digest"]] if state["unused"] else []}
    elif name == "email-verification-result":
        result = {
            "userId": os.environ["FLOW_USER_ID"], "email": os.environ["FLOW_EMAIL"],
            "status": "ACTIVE", "emailVerified": state["confirmed"],
            "unusedTokens": state["unused"], "usedTokens": state["used"],
            "passwordCredentials": 1,
            "duplicateUsers": 1,
            "defaultRoles": 1
        }
    elif name == "email-verification-audits":
        result = {"requests": 3, "confirmationSuccesses": 2, "confirmationFailures": 2}
    elif name == "pending-password-attach-result":
        result = {
            "userId": os.environ["FLOW_ATTACH_USER_ID"],
            "email": os.environ["FLOW_ATTACH_EMAIL"], "status": "ACTIVE",
            "passwordCredentials": 1, "pendingPasswordCredentials": 0,
            "duplicateUsers": 1,
        }
    else:
        result = {"status": "ok"}
print(json.dumps(result))
"""


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast(tuple[str, int], listener.getsockname())[1]


class HttpStateAdapter:
    refresh_secret = "private-flow-refresh-secret"
    isolation_identity = ("contract-db", "contract-redis")

    def __init__(
        self,
        base_url: str,
        kind: str,
        *,
        handoff: bool = False,
        attach: bool = False,
        runtime_identity: tuple[str, int] | None = None,
        tamper_digest: bool = False,
    ) -> None:
        self.base_url = base_url
        self.kind = kind
        self.handoff = handoff
        self.attach = attach
        self.runtime_identity = runtime_identity or ("single", 1)
        self.tamper_digest = tamper_digest
        self.refresh_ledger_calls = 0

    def invoke(self, command: str, name: str) -> Any:
        if command == "setup":
            if name == "pending-email-user":
                fixture: dict[str, Any] = {"userId": USER_ID, "email": EMAIL}
                fixture.update(
                    attachUserId=ATTACH_USER_ID,
                    attachEmail=ATTACH_EMAIL,
                )
                if self.handoff:
                    fixture.update(
                        name="Contract Pending",
                        roles=[{"serviceKey": "temis", "name": "user"}],
                        audience="contract-fixture",
                        clientId="contract-fixture",
                        redirectUri="http://127.0.0.1:4101/auth/callback",
                        state="contract-state",
                        codeChallenge="contract-challenge",
                        codeVerifier="contract-verifier",
                    )
                if self.attach:
                    fixture.update(
                        attachUserId=ATTACH_USER_ID,
                        attachEmail=ATTACH_EMAIL,
                    )
                return fixture
            return {
                "userId": USER_ID,
                "email": EMAIL,
                "password": "ContractOnly!2026",
                "name": "Contract Active",
                "roles": [{"serviceKey": "temis", "name": "user"}],
                "audience": "contract-fixture",
            }
        if command == "teardown":
            return {"status": "clean"}
        if command == "expire":
            request = urllib.request.Request(
                f"{self.base_url}/expire",
                data=b"{}",
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                return json.load(response)
        with urllib.request.urlopen(f"{self.base_url}/state", timeout=2) as response:
            state = json.load(response)
        if name in {
            "email-verification-ledger",
            "attach-email-verification-ledger",
            "password-reset-ledger",
        }:
            digests = [state["digest"]] if state["unused"] else []
            if self.tamper_digest and digests:
                digests = ["0" * 64]
            return {"unusedTokens": state["unused"], "digests": digests}
        if name == "email-verification-result":
            return {
                "userId": USER_ID,
                "email": EMAIL,
                "status": "ACTIVE",
                "emailVerified": state["confirmed"],
                "unusedTokens": state["unused"],
                "usedTokens": state["used"],
                "passwordCredentials": 1,
                "duplicateUsers": 1,
                "defaultRoles": 1,
            }
        if name == "password-reset-result":
            return {
                "userId": USER_ID,
                "unusedTokens": state["unused"],
                "usedTokens": state["used"],
                "activeRefreshTokens": 0,
            }
        if name == "refresh-ledger":
            self.refresh_ledger_calls += 1
            hashes = [
                hashlib.sha256(b"old-refresh").hexdigest(),
                hashlib.sha256(b"second-refresh").hexdigest(),
            ]
            if self.refresh_ledger_calls == 1:
                return {
                    "activeRefreshTokens": 2,
                    "revokedRefreshTokens": 0,
                    "activeTokenHashes": hashes,
                    "revokedTokenHashes": [],
                }
            return {
                "activeRefreshTokens": 0,
                "revokedRefreshTokens": 2,
                "activeTokenHashes": [],
                "revokedTokenHashes": hashes,
            }
        if name == "email-verification-audits":
            return {
                "requests": 3,
                "confirmationSuccesses": 2,
                "confirmationFailures": 2,
            }
        if name == "password-reset-audits":
            return {
                "requests": 2,
                "confirmationSuccesses": 1,
                "confirmationFailures": 2,
            }
        if name == "pending-password-attach-result":
            return {
                "userId": ATTACH_USER_ID,
                "email": ATTACH_EMAIL,
                "status": "ACTIVE",
                "passwordCredentials": 1,
                "pendingPasswordCredentials": 0,
                "duplicateUsers": 1,
            }
        raise AssertionError((command, name))


class PrivateMailFlowLauncherTests(unittest.TestCase):
    def launch(self, directory: Path, kind: str, port: int) -> Any:
        spec = launcher_module.RuntimeSpec.create(
            name="fake-runtime",
            command=(sys.executable, "-c", RUNTIME),
            cwd=Path(__file__).resolve().parents[2],
            health_url=f"http://127.0.0.1:{port}/health",
            environment={
                "APP_PORT": str(port),
                "FLOW_KIND": kind,
                "FLOW_EMAIL": EMAIL,
            },
        )
        return launcher_module.PrivateMailFlowLauncher(
            directory=directory,
            run_id=f"run-{kind}",
            recipients={USER_ID: EMAIL, ATTACH_USER_ID: ATTACH_EMAIL},
            runtimes=(spec,),
            readiness_timeout=5,
        )

    def test_verification_driver_uses_actual_owned_smtp_capture(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            with self.launch(directory, "email-verification", port) as owned:
                result = flow_driver.run_email_verification_flow(
                    url=f"http://127.0.0.1:{port}",
                    adapter=HttpStateAdapter(
                        f"http://127.0.0.1:{port}",
                        "email-verification",
                        attach=True,
                    ),
                    token_source=owned,
                )
                self.assertTrue(result["mail"]["privateCaptureConsumed"])
                self.assertTrue(result["state"]["pendingPasswordAttached"])
                self.assertFalse(result["qualifyingEvidence"])
            self.assertEqual(list(directory.iterdir()), [])

    def test_reset_driver_uses_actual_owned_smtp_capture(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            with self.launch(directory, "password-reset", port) as owned:
                with (
                    mock.patch.object(
                        flow_driver,
                        "_verify_token_pair",
                        side_effect=(
                            ("access", "old-refresh"),
                            ("access", "second-refresh"),
                            ("access", "new-refresh"),
                        ),
                    ),
                    mock.patch.object(
                        flow_driver,
                        "_auth_state",
                        side_effect=(
                            {
                                "activeRefreshTokens": 2,
                                "authHandoffKeys": 0,
                                "activeTokenHashes": [
                                    hashlib.sha256(b"old-refresh").hexdigest(),
                                    hashlib.sha256(b"second-refresh").hexdigest(),
                                ],
                            },
                            {
                                "activeRefreshTokens": 1,
                                "authHandoffKeys": 0,
                                "activeTokenHashes": [
                                    hashlib.sha256(b"new-refresh").hexdigest()
                                ],
                            },
                            {
                                "activeRefreshTokens": 0,
                                "authHandoffKeys": 0,
                                "activeTokenHashes": [],
                            },
                        ),
                    ),
                ):
                    result = flow_driver.run_password_reset_flow(
                        url=f"http://127.0.0.1:{port}",
                        adapter=HttpStateAdapter(
                            f"http://127.0.0.1:{port}", "password-reset"
                        ),
                        token_source=owned,
                    )
                self.assertTrue(result["state"]["refreshTokensRevoked"])
                self.assertFalse(result["qualifyingEvidence"])
            self.assertEqual(list(directory.iterdir()), [])

    def test_captured_digest_must_match_persisted_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            with (
                self.launch(directory, "email-verification", port) as owned,
                self.assertRaisesRegex(
                    flow_driver.ContractFailure, "digest-state-mismatch"
                ),
            ):
                flow_driver.run_email_verification_flow(
                    url=f"http://127.0.0.1:{port}",
                    adapter=HttpStateAdapter(
                        f"http://127.0.0.1:{port}",
                        "email-verification",
                        tamper_digest=True,
                    ),
                    token_source=owned,
                )
            self.assertEqual(list(directory.iterdir()), [])

    def test_verification_driver_executes_cross_origin_handoff_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            producer_port = unused_port()
            consumer_port = unused_port()
            producer = launcher_module.RuntimeSpec.create(
                name="producer-runtime",
                command=(sys.executable, "-c", RUNTIME),
                cwd=Path(__file__).resolve().parents[2],
                health_url=f"http://127.0.0.1:{producer_port}/health",
                environment={
                    "APP_PORT": str(producer_port),
                    "FLOW_KIND": "email-verification",
                    "FLOW_EMAIL": EMAIL,
                    "FLOW_HANDOFF": "1",
                },
            )
            consumer = launcher_module.RuntimeSpec.create(
                name="consumer-runtime",
                command=(sys.executable, "-c", RUNTIME),
                cwd=Path(__file__).resolve().parents[2],
                health_url=f"http://127.0.0.1:{consumer_port}/health",
                environment={
                    "APP_PORT": str(consumer_port),
                    "FLOW_KIND": "email-verification",
                    "FLOW_EMAIL": EMAIL,
                    "UPSTREAM": f"http://127.0.0.1:{producer_port}",
                },
            )
            with launcher_module.PrivateMailFlowLauncher(
                directory=directory,
                run_id="run-verification-handoff",
                recipients={USER_ID: EMAIL, ATTACH_USER_ID: ATTACH_EMAIL},
                runtimes=(producer, consumer),
                readiness_timeout=5,
            ) as owned:
                producer_binding = owned.binding("producer-runtime")
                consumer_binding = owned.binding("consumer-runtime")
                producer_adapter = HttpStateAdapter(
                    f"http://127.0.0.1:{producer_port}",
                    "email-verification-attach-handoff-exchange",
                    handoff=True,
                    runtime_identity=(
                        producer_binding.runtime_name,
                        producer_binding.process_pid,
                    ),
                )
                consumer_adapter = HttpStateAdapter(
                    f"http://127.0.0.1:{consumer_port}",
                    "email-verification",
                    handoff=True,
                    runtime_identity=(
                        consumer_binding.runtime_name,
                        consumer_binding.process_pid,
                    ),
                )
                with (
                    mock.patch.object(
                        flow_driver,
                        "_verify_token_pair",
                        return_value=("access", "refresh"),
                    ),
                    mock.patch.object(flow_driver, "_token_is_active"),
                    mock.patch.object(
                        flow_driver,
                        "_auth_state",
                        side_effect=(
                            {
                                "activeRefreshTokens": 1,
                                "authHandoffKeys": 0,
                                "activeTokenHashes": [
                                    hashlib.sha256(b"refresh").hexdigest()
                                ],
                            },
                            {
                                "activeRefreshTokens": 0,
                                "authHandoffKeys": 0,
                                "activeTokenHashes": [],
                            },
                        ),
                    ),
                ):
                    result = flow_driver.run_email_verification_flow(
                        url=f"http://127.0.0.1:{producer_port}",
                        consumer_url=f"http://127.0.0.1:{consumer_port}",
                        adapter=producer_adapter,
                        consumer_adapter=consumer_adapter,
                        token_source=owned,
                    )
                self.assertTrue(result["state"]["handoffExchanged"])

    def test_fixture_adapter_rejects_private_mode_without_owned_binding(self) -> None:
        adapter_path = (
            Path(__file__).resolve().parents[1] / "adapters" / "express_fixture.py"
        )
        environment = {
            "CONTRACT_FIXTURE_MODE": "1",
            "CONTRACT_SERVER_MAIL_MODE": "private-loopback-smtp",
            "CONTRACT_REDIS_ISOLATED_DB": "1",
            "CONTRACT_REFRESH_SECRET": "sufficiently-random-private-secret",
            "CONTRACT_DATABASE_URL": "postgresql://contract@127.0.0.1/contract_test",
            "CONTRACT_REDIS_URL": "redis://127.0.0.1/1",
        }
        with self.assertRaisesRegex(flow_driver.ContractFailure, "owned launcher"):
            flow_driver.FixtureAdapter(
                adapter_path, environment, "http://127.0.0.1:4000"
            )

    def test_secure_config_and_session_reads_reject_same_fd_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "secure.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o600)
            initial = path.stat()
            changed = os.stat_result(
                (
                    initial.st_mode,
                    initial.st_ino + 1,
                    initial.st_dev,
                    initial.st_nlink,
                    initial.st_uid,
                    initial.st_gid,
                    initial.st_size,
                    initial.st_atime,
                    initial.st_mtime,
                    initial.st_ctime,
                )
            )
            with (
                mock.patch.object(
                    flow_driver.os, "fstat", side_effect=(initial, changed)
                ),
                self.assertRaisesRegex(flow_driver.ContractFailure, "changed"),
            ):
                flow_driver.load_adapter_environment(path)
            with (
                mock.patch.object(
                    express_adapter.os, "fstat", side_effect=(initial, changed)
                ),
                self.assertRaisesRegex(express_adapter.AdapterError, "changed"),
            ):
                express_adapter._secure_read(path, "private mail session")

    def test_real_pending_fixture_exposes_account_attach_contract(self) -> None:
        config = express_adapter.Config(
            base_url="http://127.0.0.1:4000",
            database_url="postgresql://contract@127.0.0.1/contract_test",
            redis_url="redis://127.0.0.1/1",
            email_domain="example.invalid",
            audience="contract-fixture",
            client_id="contract-fixture",
            redirect_uri="http://127.0.0.1:4101/auth/callback",
            refresh_secret="private-flow-refresh-secret",
        )
        with (
            mock.patch.object(express_adapter, "reset"),
            mock.patch.object(express_adapter, "seed"),
        ):
            fixture = express_adapter.setup(config, "pending-email-user")
        self.assertEqual(fixture["attachUserId"], express_adapter.TARGET_USER_ID)
        self.assertEqual(fixture["attachEmail"], "contract-target@example.invalid")

    def test_runtime_spec_rejects_caller_mail_override(self) -> None:
        with self.assertRaisesRegex(launcher_module.LaunchError, "may not override"):
            launcher_module.RuntimeSpec.create(
                name="bad",
                command=(sys.executable, "-c", "pass"),
                cwd=Path.cwd(),
                health_url="http://127.0.0.1:1/health",
                environment={"SMTP_HOST": "127.0.0.1"},
            )

    def test_mail_flow_validation_failure_still_tears_down_fixture(self) -> None:
        calls: list[tuple[str, str]] = []

        class BrokenAdapter:
            refresh_secret = "unused"
            isolation_identity = ("db", "redis")

            def invoke(self, command: str, name: str) -> Any:
                calls.append((command, name))
                return {} if command == "setup" else {"status": "clean"}

        with self.assertRaisesRegex(flow_driver.ContractFailure, "malformed-fixture"):
            flow_driver.run_email_verification_flow(
                url="http://127.0.0.1:1",
                adapter=BrokenAdapter(),
                token_source=mock.Mock(),
            )
        self.assertEqual(
            calls,
            [
                ("setup", "pending-email-user"),
                ("teardown", "pending-email-user"),
            ],
        )

    def test_mail_trial_records_failure_and_residual_cleanup(self) -> None:
        class ResidualAdapter:
            refresh_secret = "unused"
            isolation_identity = ("db", "redis")
            runtime_identity = ("owned", 1)

            def invoke(self, command: str, name: str) -> Any:
                if command == "preflight":
                    return {"status": "ready"}
                if name in {"auth-lifecycle", "pending-email-auth-lifecycle"}:
                    return {
                        "activeRefreshTokens": 0,
                        "authHandoffKeys": 0,
                        "activeTokenHashes": [],
                    }
                if name == "fixture-anonymous-audits":
                    return {"residualCount": 0}
                raise AssertionError((command, name))

        with mock.patch.object(
            flow_driver,
            "run_email_verification_flow",
            side_effect=flow_driver.ContractFailure("malformed-fixture"),
        ):
            record = flow_driver.run_mail_trial(
                "email-verification-attach-handoff-exchange",
                "express",
                {"express": "http://127.0.0.1:4000"},
                {"express": ResidualAdapter()},
                mock.Mock(),
                1,
            )
        self.assertEqual(record["outcome"], "fail")
        self.assertEqual(record["error"], {"category": "malformed-fixture"})
        self.assertEqual(record["cleanup"], {"outcome": "pass"})

    def test_main_malformed_origin_does_not_mask_error_with_unbound_records(
        self,
    ) -> None:
        args = [
            "--express",
            "not-an-origin",
            "--express-adapter",
            "/missing/express.py",
            "--express-adapter-config",
            "/missing/express.json",
            "--fastapi",
            "http://127.0.0.1:4001",
            "--fastapi-adapter",
            "/missing/fastapi.py",
            "--fastapi-adapter-config",
            "/missing/fastapi.json",
            "--issuer",
            "https://auth.example.invalid",
            "--jsonl",
            "/missing/evidence.jsonl",
        ]
        self.assertEqual(flow_driver.main(args), 2)

    def test_health_redirect_is_not_followed_and_startup_cleans_owned_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            spec = launcher_module.RuntimeSpec.create(
                name="redirect-runtime",
                command=(sys.executable, "-c", RUNTIME),
                cwd=Path(__file__).resolve().parents[2],
                health_url=f"http://127.0.0.1:{port}/health",
                environment={
                    "APP_PORT": str(port),
                    "FLOW_KIND": "email-verification",
                    "FLOW_EMAIL": EMAIL,
                    "HEALTH_REDIRECT": "1",
                },
            )
            owned = launcher_module.PrivateMailFlowLauncher(
                directory=directory,
                run_id="redirect-refused",
                recipients={USER_ID: EMAIL},
                runtimes=(spec,),
                readiness_timeout=0.2,
            )
            with self.assertRaisesRegex(launcher_module.LaunchError, "readiness"):
                owned.start()
            with self.assertRaisesRegex(launcher_module.LaunchError, "not active"):
                owned.binding("redirect-runtime")
            with self.assertRaisesRegex(launcher_module.LaunchError, "not active"):
                owned.take(user_id=USER_ID, kind="email-verification")
            self.assertEqual(list(directory.iterdir()), [])

    def test_cleanup_failure_retains_process_and_capture_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            owned = self.launch(directory, "email-verification", port)
            owned.start()
            original = launcher_module.runtime_helpers._terminate_process_group
            calls = 0

            def fail_once(process: Any, pidfd: int, timeout: float) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise launcher_module.runtime_helpers.RuntimeRefused("injected")
                original(process, pidfd, timeout)

            with mock.patch.object(
                launcher_module.runtime_helpers,
                "_terminate_process_group",
                side_effect=fail_once,
            ):
                with self.assertRaisesRegex(
                    launcher_module.LaunchError, "process cleanup"
                ):
                    owned.close()
                self.assertEqual(len(owned._processes), 1)
                owned._server.assert_active()
                with self.assertRaisesRegex(launcher_module.LaunchError, "not active"):
                    owned.binding("fake-runtime")
                with self.assertRaisesRegex(launcher_module.LaunchError, "not active"):
                    owned.take(user_id=USER_ID, kind="email-verification")
                owned.close()
            self.assertEqual(list(directory.iterdir()), [])

    def test_pidfd_interruption_uses_preownership_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            owned = self.launch(directory, "email-verification", port)
            with (
                mock.patch.object(
                    launcher_module.os,
                    "pidfd_open",
                    side_effect=KeyboardInterrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                owned.start()
            self.assertEqual(list(directory.iterdir()), [])

    def test_pidfd_close_failure_never_retries_fd_or_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            owned = self.launch(directory, "email-verification", unused_port())
            owned.start()
            original = launcher_module.runtime_helpers._terminate_process_group
            calls = 0

            def counted_terminate(process: Any, pidfd: int, timeout: float) -> None:
                nonlocal calls
                calls += 1
                original(process, pidfd, timeout)

            with (
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_process_group",
                    side_effect=counted_terminate,
                ),
                mock.patch.object(
                    launcher_module.os,
                    "close",
                    side_effect=OSError("injected pidfd close failure"),
                ),
                self.assertRaisesRegex(launcher_module.LaunchError, "cleanup failed"),
            ):
                owned.close()
            self.assertEqual(owned._processes, [])
            owned.close()
            self.assertEqual(calls, 1)

    def test_post_reap_interrupt_never_retains_or_resignals_process(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            owned = self.launch(Path(raw), "email-verification", unused_port())
            owned.start()
            original = launcher_module.runtime_helpers._terminate_process_group
            calls = 0

            def terminate_then_interrupt(
                process: Any, pidfd: int, timeout: float
            ) -> None:
                nonlocal calls
                calls += 1
                original(process, pidfd, timeout)
                raise KeyboardInterrupt

            with (
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_process_group",
                    side_effect=terminate_then_interrupt,
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                owned.close()
            self.assertEqual(owned._processes, [])
            owned.close()
            self.assertEqual(calls, 1)

    def test_actual_pidfd_close_interrupt_never_closes_reused_fd(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            owned = self.launch(Path(raw), "email-verification", unused_port())
            owned.start()
            real_close = launcher_module.os.close
            target_pidfd = owned._processes[0][1]
            reused_fd = -1
            close_calls = 0

            def close_reuse_then_interrupt(descriptor: int) -> None:
                nonlocal close_calls, reused_fd
                if descriptor != target_pidfd or close_calls:
                    real_close(descriptor)
                    return
                close_calls += 1
                real_close(descriptor)
                reused_fd = os.open("/dev/null", os.O_RDONLY)
                raise KeyboardInterrupt

            try:
                with (
                    mock.patch.object(
                        launcher_module.os,
                        "close",
                        side_effect=close_reuse_then_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    owned._bounded_drain()
                self.assertEqual(close_calls, 1)
                self.assertGreaterEqual(reused_fd, 0)
                os.fstat(reused_fd)
                self.assertEqual(owned._processes, [])
            finally:
                if reused_fd >= 0:
                    real_close(reused_fd)

    def test_exact_auth_state_rejects_stale_handoff_and_noop_logout(self) -> None:
        active_hash = hashlib.sha256(b"refresh").hexdigest()
        with self.assertRaisesRegex(
            flow_driver.ContractFailure, "auth-state-transition-mismatch"
        ):
            flow_driver._expect_exact_auth_state(
                {
                    "activeRefreshTokens": 1,
                    "authHandoffKeys": 1,
                    "activeTokenHashes": [active_hash],
                },
                active_hashes={active_hash},
            )
        with self.assertRaisesRegex(
            flow_driver.ContractFailure, "auth-state-transition-mismatch"
        ):
            flow_driver._expect_exact_auth_state(
                {
                    "activeRefreshTokens": 1,
                    "authHandoffKeys": 0,
                    "activeTokenHashes": [active_hash],
                },
                active_hashes=set(),
            )

    def test_malformed_refresh_ledger_hashes_fail_with_contract_category(self) -> None:
        with self.assertRaisesRegex(
            flow_driver.ContractFailure,
            "password-reset-refresh-revocation-state-mismatch",
        ):
            flow_driver._digest_set(
                [{"not": "a digest"}],
                "password-reset-refresh-revocation-state-mismatch",
            )

    def test_context_exit_interrupt_drains_before_reraising(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            owned = self.launch(directory, "email-verification", unused_port())
            original = launcher_module.runtime_helpers._terminate_process_group
            calls = 0

            def interrupt_once(process: Any, pidfd: int, timeout: float) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt
                original(process, pidfd, timeout)

            with (
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_process_group",
                    side_effect=interrupt_once,
                ),
                self.assertRaises(KeyboardInterrupt),
                owned,
            ):
                pass
            self.assertEqual(calls, 2)
            self.assertEqual(list(directory.iterdir()), [])

    def test_capture_interrupt_is_retried_then_original_is_reraised(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            owned = self.launch(directory, "email-verification", unused_port())
            original = owned._server.close
            calls = 0

            def interrupt_capture_once() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt
                original()

            with (
                mock.patch.object(
                    owned._server, "close", side_effect=interrupt_capture_once
                ),
                self.assertRaises(KeyboardInterrupt),
                owned,
            ):
                pass
            self.assertEqual(calls, 2)
            self.assertTrue(owned._closed)
            self.assertEqual(list(directory.iterdir()), [])

    def test_transient_capture_error_is_retried_to_full_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            owned = self.launch(directory, "email-verification", unused_port())
            original = owned._server.close
            calls = 0

            def fail_capture_once() -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise launcher_module.capture.CaptureError("injected")
                original()

            with (
                mock.patch.object(
                    owned._server, "close", side_effect=fail_capture_once
                ),
                owned,
            ):
                pass
            self.assertEqual(calls, 2)
            self.assertTrue(owned._closed)
            self.assertEqual(list(directory.iterdir()), [])

    def test_exited_before_ready_is_detected_without_popen_poll(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            spec = launcher_module.RuntimeSpec.create(
                name="early-exit",
                command=(sys.executable, "-c", "raise SystemExit(0)"),
                cwd=Path(__file__).resolve().parents[2],
                health_url=f"http://127.0.0.1:{port}/health",
            )
            owned = launcher_module.PrivateMailFlowLauncher(
                directory=directory,
                run_id="early-exit-nonreaping",
                recipients={USER_ID: EMAIL},
                runtimes=(spec,),
                readiness_timeout=2,
            )
            with (
                mock.patch.object(
                    launcher_module.subprocess.Popen,
                    "poll",
                    side_effect=AssertionError("poll must not reap the group leader"),
                ),
                self.assertRaisesRegex(launcher_module.LaunchError, "exited"),
            ):
                owned.start()
            self.assertEqual(list(directory.iterdir()), [])

    def test_preexisting_listener_cannot_be_attributed_to_owned_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            port = unused_port()
            listener = subprocess.Popen(
                (
                    sys.executable,
                    "-c",
                    (
                        "from http.server import BaseHTTPRequestHandler,HTTPServer; "
                        "H=type('H',(BaseHTTPRequestHandler,),{'do_GET':lambda s: "
                        "(s.send_response(200),s.end_headers()),'log_message':lambda *a:None}); "
                        f"HTTPServer(('127.0.0.1',{port}),H).serve_forever()"
                    ),
                ),
                start_new_session=True,
            )
            try:
                spec = launcher_module.RuntimeSpec.create(
                    name="unrelated-listener",
                    command=(sys.executable, "-c", "import time; time.sleep(5)"),
                    cwd=Path(__file__).resolve().parents[2],
                    health_url=f"http://127.0.0.1:{port}/health",
                )
                owned = launcher_module.PrivateMailFlowLauncher(
                    directory=directory,
                    run_id="listener-attribution-negative",
                    recipients={USER_ID: EMAIL},
                    runtimes=(spec,),
                    readiness_timeout=0.5,
                )
                with self.assertRaisesRegex(
                    launcher_module.LaunchError, "listener already exists"
                ):
                    owned.start()
                self.assertEqual(list(directory.iterdir()), [])
            finally:
                listener.terminate()
                listener.wait(timeout=2)

    def test_startup_transient_cleanup_failure_is_retried_before_original_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            ports = (unused_port(), unused_port())
            specs = tuple(
                launcher_module.RuntimeSpec.create(
                    name=f"runtime-{index}",
                    command=(sys.executable, "-c", RUNTIME),
                    cwd=Path(__file__).resolve().parents[2],
                    health_url=f"http://127.0.0.1:{port}/health",
                    environment={
                        "APP_PORT": str(port),
                        "FLOW_KIND": "email-verification",
                        "FLOW_EMAIL": EMAIL,
                    },
                )
                for index, port in enumerate(ports)
            )
            owned = launcher_module.PrivateMailFlowLauncher(
                directory=directory,
                run_id="second-runtime-cleanup-failure",
                recipients={USER_ID: EMAIL},
                runtimes=specs,
                readiness_timeout=2,
            )
            real_pidfd_open = launcher_module.os.pidfd_open
            real_pre_pidfd = launcher_module.runtime_helpers._terminate_before_pidfd
            pidfd_calls = 0
            cleanup_calls = 0

            def fail_second_pidfd(pid: int, flags: int) -> int:
                nonlocal pidfd_calls
                pidfd_calls += 1
                if pidfd_calls == 2:
                    raise OSError("injected second pidfd failure")
                return cast(int, real_pidfd_open(pid, flags))

            def fail_cleanup_once(process: Any, timeout: float) -> None:
                nonlocal cleanup_calls
                cleanup_calls += 1
                if cleanup_calls == 1:
                    raise launcher_module.runtime_helpers.RuntimeRefused("injected")
                real_pre_pidfd(process, timeout)

            with (
                mock.patch.object(
                    launcher_module.os,
                    "pidfd_open",
                    side_effect=fail_second_pidfd,
                ),
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_before_pidfd",
                    side_effect=fail_cleanup_once,
                ),
                self.assertRaisesRegex(launcher_module.LaunchError, "pidfd"),
            ):
                owned.start()
            self.assertEqual(cleanup_calls, 2)
            self.assertEqual(owned._processes, [])
            self.assertEqual(list(directory.iterdir()), [])

    def test_startup_permanent_drain_failure_is_typed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            owned = self.launch(directory, "email-verification", unused_port())
            calls = 0

            def refuse_drain(process: Any, pidfd: int, timeout: float) -> None:
                nonlocal calls
                calls += 1
                raise launcher_module.runtime_helpers.RuntimeRefused("injected")

            with (
                mock.patch.object(
                    owned,
                    "_wait_until_ready",
                    side_effect=launcher_module.LaunchError("readiness primary"),
                ),
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_process_group",
                    side_effect=refuse_drain,
                ),
                self.assertRaises(launcher_module.LaunchCleanupError),
            ):
                owned.start()
            self.assertEqual(calls, 8)
            self.assertEqual(len(owned._processes), 1)
            owned.close()
            self.assertEqual(list(directory.iterdir()), [])

    def test_flow_driver_cli_owns_runtime_capture_and_verification_consumer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ports = {runtime: unused_port() for runtime in ("express", "fastapi")}
            adapter = root / "fixture-adapter.py"
            adapter.write_text(ADAPTER, encoding="utf-8")
            adapter.chmod(0o700)
            config_paths: dict[str, Path] = {}
            for runtime, port in ports.items():
                config = root / f"{runtime}.json"
                config.write_text(
                    json.dumps(
                        {
                            "CONTRACT_FIXTURE_MODE": "1",
                            "CONTRACT_SERVER_MAIL_MODE": "private-loopback-smtp",
                            "CONTRACT_REDIS_ISOLATED_DB": "1",
                            "CONTRACT_REFRESH_SECRET": "private-flow-refresh-secret",
                            "CONTRACT_DATABASE_URL": "postgresql://contract@127.0.0.1/contract_test",
                            "CONTRACT_REDIS_URL": "redis://127.0.0.1/1",
                            "FLOW_EMAIL": EMAIL,
                            "FLOW_USER_ID": USER_ID,
                            "FLOW_ATTACH_USER_ID": ATTACH_USER_ID,
                            "FLOW_ATTACH_EMAIL": ATTACH_EMAIL,
                            "FLOW_KIND": "email-verification",
                            "APP_PORT": str(port),
                        }
                    ),
                    encoding="utf-8",
                )
                config.chmod(0o600)
                config_paths[runtime] = config
            launch_config = root / "launch.json"
            launch_config.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "runId": "cli-owned-verification",
                        "recipients": {USER_ID: EMAIL, ATTACH_USER_ID: ATTACH_EMAIL},
                        "runtimes": {
                            runtime: {
                                "command": [sys.executable, "-c", RUNTIME],
                                "cwd": str(Path(__file__).resolve().parents[2]),
                                "healthUrl": f"http://127.0.0.1:{port}/health",
                            }
                            for runtime, port in ports.items()
                        },
                    }
                ),
                encoding="utf-8",
            )
            launch_config.chmod(0o600)
            output = root / "evidence.jsonl"
            args: list[str] = []
            for runtime in ("express", "fastapi"):
                args.extend(
                    (
                        f"--{runtime}",
                        f"http://127.0.0.1:{ports[runtime]}",
                        f"--{runtime}-adapter",
                        str(adapter),
                        f"--{runtime}-adapter-config",
                        str(config_paths[runtime]),
                    )
                )
            args.extend(
                (
                    "--flow",
                    "email-verification-attach-handoff-exchange",
                    "--topology",
                    "express",
                    "--timeout",
                    "5",
                    "--issuer",
                    "https://auth.example.invalid",
                    "--jsonl",
                    str(output),
                    "--private-mail-launch-config",
                    str(launch_config),
                )
            )
            real_terminate = launcher_module.runtime_helpers._terminate_process_group
            terminate_calls = 0

            def fail_first_real_terminate(
                process: Any, pidfd: int, timeout: float
            ) -> None:
                nonlocal terminate_calls
                terminate_calls += 1
                if terminate_calls == 1:
                    raise launcher_module.runtime_helpers.RuntimeRefused(
                        "injected first drain refusal"
                    )
                real_terminate(process, pidfd, timeout)

            with (
                mock.patch.object(
                    flow_driver, "_load_mail_launcher", return_value=launcher_module
                ),
                mock.patch.object(
                    launcher_module.runtime_helpers,
                    "_terminate_process_group",
                    side_effect=fail_first_real_terminate,
                ),
            ):
                self.assertEqual(flow_driver.main(args), 0)
            self.assertEqual(terminate_calls, 3)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                record["flowId"], "email-verification-attach-handoff-exchange"
            )
            self.assertEqual(record["outcome"], "pass")
            self.assertFalse(record["qualifyingEvidence"])

            cleanup_output = root / "cleanup-failure.jsonl"
            cleanup_args = list(args)
            cleanup_args[cleanup_args.index("--jsonl") + 1] = str(cleanup_output)
            original_close = launcher_module.PrivateMailFlowLauncher.close

            def fail_after_close(instance: Any) -> None:
                original_close(instance)
                raise launcher_module.LaunchCleanupError(
                    "injected launcher cleanup failure"
                )

            with (
                mock.patch.object(
                    flow_driver,
                    "_load_mail_launcher",
                    return_value=launcher_module,
                ),
                mock.patch.object(
                    launcher_module.PrivateMailFlowLauncher,
                    "close",
                    autospec=True,
                    side_effect=fail_after_close,
                ),
            ):
                self.assertEqual(flow_driver.main(cleanup_args), 2)
            cleanup_record = json.loads(cleanup_output.read_text(encoding="utf-8"))
            self.assertEqual(cleanup_record["outcome"], "fail")
            self.assertEqual(
                cleanup_record["cleanup"],
                {
                    "outcome": "fail",
                    "category": "owned-runtime-cleanup-failure",
                },
            )


if __name__ == "__main__":
    unittest.main()
