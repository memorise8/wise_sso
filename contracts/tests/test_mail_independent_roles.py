from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "contracts" / "bin" / "flow_driver.py"
RUNTIME = ROOT / "contracts" / "tests" / "mail_role_runtime.py"
USER_ID = "00000000-0000-4000-8000-000000000021"
EMAIL = "mixed-pending@example.invalid"
ATTACH_USER_ID = "00000000-0000-4000-8000-000000000022"
ATTACH_EMAIL = "mixed-attach@example.invalid"
ISSUER = "https://auth.financenow.kr"


def unused_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast(tuple[str, int], listener.getsockname())[1]


def private_key(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def write_private_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)


class CliFixture:
    def __init__(
        self,
        directory: Path,
        *,
        wrong_role: bool = False,
        wrong_secret_role: str | None = None,
        tamper_express_state: bool = False,
        bad_jwk_role: str | None = None,
        tamper_access_role: str | None = None,
        tamper_attach_result: bool = False,
        tamper_revoked_ledger: bool = False,
    ) -> None:
        self.directory = directory
        self.scratch = directory / "scratch"
        self.scratch.mkdir(mode=0o700)
        self.state = directory / "state.sqlite3"
        self.ports = {"express": unused_port(), "fastapi": unused_port()}
        keys = {
            "express": directory / "express-private.pem",
            "fastapi": directory / "fastapi-private.pem",
        }
        for path in keys.values():
            private_key(path)
        self.adapter_configs: dict[str, Path] = {}
        secrets = {
            "express": "express-refresh-secret-with-enough-entropy",
            "fastapi": "fastapi-refresh-secret-with-enough-entropy",
        }
        for role in ("express", "fastapi"):
            environment = {
                "CONTRACT_FIXTURE_MODE": "1",
                "CONTRACT_SERVER_MAIL_MODE": "private-loopback-smtp",
                "CONTRACT_REDIS_ISOLATED_DB": "1",
                "CONTRACT_REFRESH_SECRET": secrets[role],
                "CONTRACT_DATABASE_URL": "postgresql://contract@127.0.0.1/mixed_roles",
                "CONTRACT_REDIS_URL": "redis://127.0.0.1/15",
                "CONTRACT_SHARED_STATE": str(self.state),
                "CONTRACT_RUNTIME_ROLE": role,
                "CONTRACT_EXPRESS_PRIVATE_KEY": str(keys["express"]),
                "CONTRACT_FASTAPI_PRIVATE_KEY": str(keys["fastapi"]),
            }
            if role == wrong_secret_role:
                environment["RUNTIME_REFRESH_SECRET"] = "different-runtime-secret"
            if role == "express" and tamper_express_state:
                environment["CONTRACT_TAMPER_SNAPSHOT"] = "1"
            if role == bad_jwk_role:
                environment["CONTRACT_BAD_JWK"] = "1"
            if role == tamper_access_role:
                environment["CONTRACT_TAMPER_ACCESS"] = "1"
            if role == "express" and tamper_attach_result:
                environment["CONTRACT_TAMPER_ATTACH_RESULT"] = "1"
            if role == "express" and tamper_revoked_ledger:
                environment["CONTRACT_TAMPER_REVOKED_LEDGER"] = "1"
            config = directory / f"{role}-adapter.json"
            write_private_json(config, environment)
            self.adapter_configs[role] = config
        runtimes: dict[str, Any] = {}
        for role in ("express", "fastapi"):
            process_role = "express" if wrong_role and role == "fastapi" else role
            runtimes[role] = {
                "command": [
                    sys.executable,
                    str(RUNTIME),
                    "runtime",
                    "--role",
                    process_role,
                    "--port",
                    str(self.ports[role]),
                ],
                "cwd": str(ROOT),
                "healthUrl": f"http://127.0.0.1:{self.ports[role]}/health",
            }
        self.launch_config = directory / "launch.json"
        write_private_json(
            self.launch_config,
            {
                "version": 1,
                "runId": "mixed-independent-runtimes",
                "recipients": {USER_ID: EMAIL, ATTACH_USER_ID: ATTACH_EMAIL},
                "runtimes": runtimes,
            },
        )

    def run(
        self, flows: list[str], topologies: list[str]
    ) -> subprocess.CompletedProcess[str]:
        output = self.directory / "records.jsonl"
        command = [
            sys.executable,
            str(DRIVER),
            "--express",
            f"http://127.0.0.1:{self.ports['express']}",
            "--fastapi",
            f"http://127.0.0.1:{self.ports['fastapi']}",
            "--express-adapter",
            str(RUNTIME),
            "--fastapi-adapter",
            str(RUNTIME),
            "--express-adapter-config",
            str(self.adapter_configs["express"]),
            "--fastapi-adapter-config",
            str(self.adapter_configs["fastapi"]),
            "--issuer",
            ISSUER,
            "--jsonl",
            str(output),
            "--private-mail-launch-config",
            str(self.launch_config),
            "--timeout",
            "8",
        ]
        for flow in flows:
            command.extend(("--flow", flow))
        for topology in topologies:
            command.extend(("--topology", topology))
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={
                **{
                    key: value
                    for key, value in os.environ.items()
                    if key not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}
                },
                "TMPDIR": str(self.scratch),
            },
        )

    def records(self) -> list[dict[str, Any]]:
        output = self.directory / "records.jsonl"
        if not output.exists():
            return []
        return [
            json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()
        ]

    def events(self) -> list[tuple[int, str, int, str, str]]:
        with sqlite3.connect(self.state) as connection:
            return cast(
                list[tuple[int, str, int, str, str]],
                connection.execute(
                    "SELECT trial, role, pid, method, path FROM events ORDER BY sequence"
                ).fetchall(),
            )

    def assert_cleaned(self, testcase: unittest.TestCase) -> None:
        events = self.events()
        for pid in {pid for _trial, _role, pid, _method, _path in events}:
            testcase.assertFalse(Path("/proc").joinpath(str(pid)).exists())
        for port in self.ports.values():
            with testcase.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.2)
        testcase.assertEqual(list(self.scratch.iterdir()), [])


def verification_sequence(producer: str, consumer: str) -> list[tuple[str, str, str]]:
    return [
        (producer, "POST", "/auth/email-verification/request"),
        (consumer, "POST", "/auth/email-verification/confirm"),
        (producer, "POST", "/auth/email-verification/request"),
        (consumer, "POST", "/auth/email-verification/confirm"),
        (consumer, "POST", "/auth/exchange"),
        (consumer, "GET", "/.well-known/jwks.json"),
        (consumer, "GET", "/users/me"),
        (consumer, "POST", "/auth/exchange"),
        (consumer, "POST", "/auth/email-verification/confirm"),
        (consumer, "POST", "/auth/logout"),
        (producer, "POST", "/auth/email-verification/request"),
        (consumer, "POST", "/auth/email-verification/confirm"),
    ]


def reset_sequence(producer: str, consumer: str) -> list[tuple[str, str, str]]:
    return [
        (producer, "POST", "/auth/login"),
        (producer, "GET", "/.well-known/jwks.json"),
        (producer, "GET", "/users/me"),
        (consumer, "POST", "/auth/login"),
        (consumer, "GET", "/.well-known/jwks.json"),
        (consumer, "GET", "/users/me"),
        (producer, "POST", "/auth/password-reset/request"),
        (consumer, "POST", "/auth/password-reset/confirm"),
        (producer, "POST", "/auth/password-reset/request"),
        (consumer, "POST", "/auth/password-reset/confirm"),
        (consumer, "POST", "/auth/login"),
        (consumer, "POST", "/auth/refresh"),
        (producer, "POST", "/auth/refresh"),
        (consumer, "POST", "/auth/login"),
        (consumer, "GET", "/.well-known/jwks.json"),
        (consumer, "GET", "/users/me"),
        (consumer, "POST", "/auth/logout"),
        (producer, "POST", "/auth/password-reset/confirm"),
    ]


VERIFICATION_ASSERTIONS = {
    "http": {"attempted": 12, "passed": 12},
    "mail": {"mailDigestObserved": True, "privateCaptureConsumed": True},
    "negative": {
        "expiredTokenRejected": True,
        "handoffReplayRejected": True,
        "tokenReplayRejected": True,
    },
    "qualifyingEvidence": False,
    "state": {
        "credentialAttached": True,
        "handoffExchanged": True,
        "pendingPasswordAttached": True,
        "tokenConsumed": True,
        "userActivated": True,
    },
}
RESET_ASSERTIONS = {
    "http": {"attempted": 18, "passed": 18},
    "mail": {"privateCaptureConsumed": True},
    "negative": {
        "expiredTokenRejected": True,
        "oldPasswordRejected": True,
        "oldRefreshRejected": True,
        "tokenReplayRejected": True,
    },
    "qualifyingEvidence": False,
    "state": {"refreshTokensRevoked": True, "tokenConsumed": True},
}


class IndependentMailRoleTests(unittest.TestCase):
    def test_cli_executes_both_mixed_directions_with_real_crypto_and_mail(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = CliFixture(Path(raw))
            completed = fixture.run(
                [
                    "email-verification-attach-handoff-exchange",
                    "password-reset-session-revoke",
                ],
                ["express-fastapi", "fastapi-express"],
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            records = fixture.records()
            self.assertEqual(len(records), 4)
            self.assertEqual(
                {(record["flowId"], record["topology"]) for record in records},
                {
                    ("email-verification-attach-handoff-exchange", "express-fastapi"),
                    ("email-verification-attach-handoff-exchange", "fastapi-express"),
                    ("password-reset-session-revoke", "express-fastapi"),
                    ("password-reset-session-revoke", "fastapi-express"),
                },
            )
            self.assertTrue(all(record["outcome"] == "pass" for record in records))
            self.assertTrue(
                all(record["cleanup"] == {"outcome": "pass"} for record in records)
            )
            self.assertTrue(
                all(record["qualifyingEvidence"] is False for record in records)
            )
            self.assertEqual(
                [record["assertions"] for record in records],
                [
                    VERIFICATION_ASSERTIONS,
                    VERIFICATION_ASSERTIONS,
                    RESET_ASSERTIONS,
                    RESET_ASSERTIONS,
                ],
            )
            events = [event for event in fixture.events() if event[0] > 0]
            role_pids = {(role, pid) for _trial, role, pid, _method, _path in events}
            self.assertEqual({role for role, _pid in role_pids}, {"express", "fastapi"})
            self.assertEqual(len({pid for _role, pid in role_pids}), 2)
            expected_sequences = {
                1: verification_sequence("express", "fastapi"),
                2: verification_sequence("fastapi", "express"),
                3: reset_sequence("express", "fastapi"),
                4: reset_sequence("fastapi", "express"),
            }
            for trial, expected in expected_sequences.items():
                actual = [
                    (role, method, path)
                    for event_trial, role, _pid, method, path in events
                    if event_trial == trial
                ]
                self.assertEqual(actual, expected)
            fixture.assert_cleaned(self)

    def test_cli_rejects_runtime_started_under_the_wrong_role(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = CliFixture(Path(raw), wrong_role=True)
            completed = fixture.run(
                ["email-verification-attach-handoff-exchange"],
                ["express-fastapi"],
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("exited before readiness", completed.stderr)
            self.assertEqual(fixture.records(), [])
            fixture.assert_cleaned(self)

    def test_real_refresh_signature_and_shared_state_are_not_canned(self) -> None:
        cases = (
            (
                {"wrong_secret_role": "fastapi"},
                "express-fastapi",
                "refresh-token-signature-invalid",
            ),
            (
                {"wrong_secret_role": "express"},
                "fastapi-express",
                "refresh-token-signature-invalid",
            ),
            (
                {"tamper_express_state": True},
                "express-fastapi",
                "runtime-contract-failure",
            ),
            (
                {"tamper_revoked_ledger": True},
                "express-fastapi",
                "runtime-contract-failure",
            ),
        )
        for options, topology, expected_category in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as raw:
                fixture = CliFixture(Path(raw), **options)
                completed = fixture.run(
                    ["password-reset-session-revoke"],
                    [topology],
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                records = fixture.records()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["outcome"], "fail")
                self.assertEqual(records[0]["error"]["category"], expected_category)
                fixture.assert_cleaned(self)

    def test_real_jwks_access_signature_and_attach_state_cannot_be_canned(self) -> None:
        cases = (
            ({"bad_jwk_role": "fastapi"}, "access-token-signature-or-claim-mismatch"),
            (
                {"tamper_access_role": "fastapi"},
                "access-token-signature-or-claim-mismatch",
            ),
            ({"tamper_attach_result": True}, "runtime-contract-failure"),
        )
        for options, expected_category in cases:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as raw:
                fixture = CliFixture(Path(raw), **options)
                completed = fixture.run(
                    ["email-verification-attach-handoff-exchange"],
                    ["express-fastapi"],
                )
                self.assertEqual(completed.returncode, 1, completed.stderr)
                records = fixture.records()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["outcome"], "fail")
                self.assertEqual(records[0]["error"]["category"], expected_category)
                fixture.assert_cleaned(self)


if __name__ == "__main__":
    unittest.main()
