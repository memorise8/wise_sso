from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path
from typing import cast
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "private_mail_capture.py"
SPEC = importlib.util.spec_from_file_location("contract_private_mail_capture", RUNNER)
assert SPEC and SPEC.loader
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)

RUN_ID = "a01-test-run"
USER_ID = "00000000-0000-4000-8000-000000000002"
EMAIL = "contract-pending@example.invalid"


def message(*, subject: str, recipient: str, link_text: str) -> EmailMessage:
    value = EmailMessage()
    value["From"] = "Contract <contract@example.invalid>"
    value["To"] = recipient
    value["Subject"] = subject
    value.set_content(link_text)
    return value


class PrivateMailCaptureTests(unittest.TestCase):
    def test_actual_starttls_path_captures_and_destructively_consumes_both_tokens(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            with capture.PrivateMailCaptureServer(
                directory=directory,
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            ) as server:
                context = ssl.create_default_context(cafile=server.ca_path)
                with smtplib.SMTP("127.0.0.1", server.port, timeout=5) as smtp:
                    smtp.ehlo()
                    self.assertTrue(smtp.has_extn("starttls"))
                    smtp.starttls(context=context)
                    smtp.ehlo()
                    smtp.send_message(
                        message(
                            subject="Verify your email",
                            recipient=EMAIL,
                            link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=private-verify",
                        )
                    )
                    smtp.send_message(
                        message(
                            subject="Reset your password",
                            recipient=EMAIL,
                            link_text="Use this link to reset your password: https://frontend.invalid/password-reset?token=private-reset",
                        )
                    )

                summary = server.mailbox.public_summary()
                self.assertEqual(
                    summary,
                    {
                        "runId": RUN_ID,
                        "capturedCounts": {
                            "email-verification": 1,
                            "password-reset": 1,
                        },
                        "containsToken": False,
                        "containsEmail": False,
                    },
                )
                self.assertNotIn(EMAIL, json.dumps(summary))
                self.assertNotIn("private-verify", json.dumps(summary))

                verification = server.mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="email-verification",
                )
                reset = server.mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="password-reset",
                )
                self.assertEqual(verification.token, "private-verify")
                self.assertEqual(reset.token, "private-reset")
                self.assertNotIn("private-verify", repr(verification))
                self.assertNotIn("private-reset", repr(reset))
                self.assertEqual(
                    server.mailbox.public_summary()["capturedCounts"],
                    {
                        "email-verification": 0,
                        "password-reset": 0,
                    },
                )

            self.assertFalse((directory / "capture-spool.json").exists())
            self.assertEqual(list(directory.iterdir()), [])

    def test_capture_rejects_wrong_run_user_and_expired_token(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            mailbox = capture.PrivateMailbox(
                Path(raw_directory) / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
                ttl_seconds=1,
            )
            mailbox.capture_message(
                message(
                    subject="Verify your email",
                    recipient=EMAIL,
                    link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=expires",
                ).as_bytes(),
                received_at=100.0,
            )
            with self.assertRaisesRegex(
                capture.CaptureScopeError, "run does not match"
            ):
                mailbox.take(
                    run_id="wrong-run",
                    user_id=USER_ID,
                    kind="email-verification",
                    now=100.5,
                )
            with self.assertRaisesRegex(
                capture.CaptureScopeError, "outside the configured scope"
            ):
                mailbox.take(
                    run_id=RUN_ID,
                    user_id="wrong-user",
                    kind="email-verification",
                    now=100.5,
                )
            with self.assertRaisesRegex(capture.CaptureExpiredError, "expired"):
                mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="email-verification",
                    now=101.1,
                )
            with self.assertRaisesRegex(capture.CaptureScopeError, "no capture exists"):
                mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="email-verification",
                    now=101.1,
                )
            mailbox.cleanup()

    def test_exact_expiry_and_non_finite_ttl_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            with self.assertRaisesRegex(capture.CaptureScopeError, "ttl_seconds"):
                capture.PrivateMailbox(
                    directory / "nan.json",
                    run_id=RUN_ID,
                    recipients={USER_ID: EMAIL},
                    ttl_seconds=float("nan"),
                )
            mailbox = capture.PrivateMailbox(
                directory / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
                ttl_seconds=1,
            )
            with self.assertRaisesRegex(
                capture.CaptureError, "received_at must be finite"
            ):
                mailbox.capture_message(
                    message(
                        subject="Verify your email",
                        recipient=EMAIL,
                        link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=nan",
                    ).as_bytes(),
                    received_at=float("nan"),
                )
            mailbox.capture_message(
                message(
                    subject="Verify your email",
                    recipient=EMAIL,
                    link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=boundary",
                ).as_bytes(),
                received_at=100.0,
            )
            with self.assertRaisesRegex(capture.CaptureError, "now must be finite"):
                mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="email-verification",
                    now=float("nan"),
                )
            with self.assertRaises(capture.CaptureExpiredError):
                mailbox.take(
                    run_id=RUN_ID,
                    user_id=USER_ID,
                    kind="email-verification",
                    now=101.0,
                )
            mailbox.cleanup()

    def test_replaced_spool_inode_is_rejected_and_original_is_zeroed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            mailbox = capture.PrivateMailbox(
                directory / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            mailbox.capture_message(
                message(
                    subject="Reset your password",
                    recipient=EMAIL,
                    link_text="Use this link to reset your password: https://frontend.invalid/password-reset?token=must-be-zeroed",
                ).as_bytes()
            )
            original = directory / "original-spool"
            mailbox.spool_path.rename(original)
            mailbox.spool_path.write_text("replacement", encoding="utf-8")
            mailbox.spool_path.chmod(0o600)
            with self.assertRaisesRegex(capture.CaptureScopeError, "inode changed"):
                mailbox.public_summary()
            mailbox.cleanup()
            self.assertEqual(original.read_bytes(), b"")
            self.assertEqual(
                mailbox.spool_path.read_text(encoding="utf-8"), "replacement"
            )

    def test_mutation_fd_acquisition_and_cleanup_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            mailbox = capture.PrivateMailbox(
                Path(raw_directory) / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            real_dup = os.dup

            def assert_locked(descriptor: int) -> int:
                self.assertTrue(mailbox._lock.locked())
                return real_dup(descriptor)

            with patch.object(capture.os, "dup", assert_locked):
                mailbox.public_summary()

            operation_started = threading.Event()
            release_operation = threading.Event()
            cleanup_finished = threading.Event()

            def hold_mutation(document: dict[str, object]) -> None:
                operation_started.set()
                self.assertTrue(release_operation.wait(2))
                self.assertIn("messages", document)

            mutation = threading.Thread(target=lambda: mailbox._mutate(hold_mutation))
            mutation.start()
            self.assertTrue(operation_started.wait(2))

            def cleanup() -> None:
                mailbox.cleanup()
                cleanup_finished.set()

            cleanup_thread = threading.Thread(target=cleanup)
            cleanup_thread.start()
            self.assertFalse(cleanup_finished.wait(0.1))
            release_operation.set()
            mutation.join(timeout=2)
            cleanup_thread.join(timeout=2)
            self.assertFalse(mutation.is_alive())
            self.assertFalse(cleanup_thread.is_alive())
            self.assertTrue(cleanup_finished.is_set())
            self.assertFalse(mailbox.spool_path.exists())

    def test_capture_purges_expired_messages_and_rejects_total_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            mailbox = capture.PrivateMailbox(
                Path(raw_directory) / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
                ttl_seconds=10,
            )
            raw = message(
                subject="Verify your email",
                recipient=EMAIL,
                link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=bounded",
            ).as_bytes()
            mailbox.capture_message(raw, received_at=100.0)
            mailbox.capture_message(raw, received_at=111.0)
            consumed = mailbox.take(
                run_id=RUN_ID,
                user_id=USER_ID,
                kind="email-verification",
                now=111.5,
            )
            self.assertEqual(consumed.token, "bounded")
            for _ in range(capture._MAX_CAPTURED_MESSAGES):
                mailbox.capture_message(raw, received_at=200.0)
            with self.assertRaisesRegex(capture.CaptureError, "message limit"):
                mailbox.capture_message(raw, received_at=200.0)
            mailbox.cleanup()

    def test_fail_closed_recipient_link_and_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            mailbox = capture.PrivateMailbox(
                directory / "capture-spool.json",
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            self.assertEqual(mailbox.spool_path.stat().st_mode & 0o777, 0o600)
            rejected = [
                message(
                    subject="Verify your email",
                    recipient="real-user@example.com",
                    link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=secret",
                ),
                message(
                    subject="Unknown action",
                    recipient=EMAIL,
                    link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=secret",
                ),
                message(
                    subject="Reset your password",
                    recipient=EMAIL,
                    link_text="Use this link to reset your password: https://frontend.invalid/password-reset",
                ),
            ]
            for value in rejected:
                with self.assertRaises(capture.CaptureError):
                    mailbox.capture_message(value.as_bytes())
            self.assertEqual(
                sum(mailbox.public_summary()["capturedCounts"].values()), 0
            )
            mailbox.cleanup()

            os.chmod(directory, 0o755)
            with self.assertRaisesRegex(capture.CaptureScopeError, "group/world"):
                capture.PrivateMailbox(
                    directory / "unsafe.json",
                    run_id=RUN_ID,
                    recipients={USER_ID: EMAIL},
                )

    def test_runtime_environment_is_loopback_smtp_and_private_ca_only(self) -> None:
        with (
            tempfile.TemporaryDirectory() as raw_directory,
            capture.PrivateMailCaptureServer(
                directory=Path(raw_directory),
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            ) as server,
        ):
            environment = server.smtp_launcher_environment()
            self.assertEqual(environment["MAIL_PROVIDER"], "smtp")
            self.assertEqual(environment["SMTP_HOST"], "127.0.0.1")
            self.assertEqual(environment["SMTP_PORT"], str(server.port))
            self.assertEqual(environment["SSL_CERT_FILE"], str(server.ca_path))
            self.assertEqual(environment["NODE_EXTRA_CA_CERTS"], str(server.ca_path))
            self.assertEqual(environment["CONTRACT_PRIVATE_MAIL_CAPTURE"], "1")
            self.assertNotIn("CONTRACT_SERVER_MAIL_MODE", environment)
            self.assertNotIn(EMAIL, json.dumps(environment))

    def test_server_bounds_concurrent_connections(self) -> None:
        clients: list[socket.socket] = []
        with (
            tempfile.TemporaryDirectory() as raw_directory,
            capture.PrivateMailCaptureServer(
                directory=Path(raw_directory),
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            ) as server,
        ):
            try:
                for _ in range(capture._MAX_CONNECTIONS):
                    client = socket.create_connection(
                        ("127.0.0.1", server.port), timeout=2
                    )
                    client.settimeout(2)
                    self.assertTrue(client.recv(128).startswith(b"220 "))
                    clients.append(client)
                extra = socket.create_connection(("127.0.0.1", server.port), timeout=2)
                extra.settimeout(2)
                self.assertEqual(extra.recv(128), b"")
                extra.close()
            finally:
                for client in clients:
                    client.close()

    def test_init_failure_rolls_back_spool_descriptor_and_owned_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            leaked = directory / "capture-cert.pem"

            def fail_tls(_directory: Path) -> tuple[Path, Path]:
                leaked.write_text("partial", encoding="utf-8")
                raise capture.CaptureError("injected TLS failure")

            with (
                patch.object(capture, "_create_tls_material", fail_tls),
                self.assertRaisesRegex(capture.CaptureError, "injected TLS failure"),
            ):
                capture.PrivateMailCaptureServer(
                    directory=directory,
                    run_id=RUN_ID,
                    recipients={USER_ID: EMAIL},
                )
            self.assertEqual(list(directory.iterdir()), [])

    def test_thread_construction_failure_rolls_back_bound_socket_and_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            bound_ports: list[int] = []
            real_server = capture._SmtpServer

            def record_server(*args: object, **kwargs: object) -> object:
                server = real_server(*args, **kwargs)
                bound_ports.append(server.server_address[1])
                return server

            with (
                patch.object(capture, "_SmtpServer", record_server),
                patch.object(
                    capture.threading,
                    "Thread",
                    side_effect=RuntimeError("injected thread construction failure"),
                ),
                self.assertRaisesRegex(
                    RuntimeError, "injected thread construction failure"
                ),
            ):
                capture.PrivateMailCaptureServer(
                    directory=directory,
                    run_id=RUN_ID,
                    recipients={USER_ID: EMAIL},
                )
            self.assertEqual(len(bound_ports), 1)
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", bound_ports[0]), timeout=0.2)
            self.assertEqual(list(directory.iterdir()), [])

    def test_start_failure_rolls_back_bound_socket_and_sensitive_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            server = capture.PrivateMailCaptureServer(
                directory=directory,
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            port = server.port
            with (
                patch.object(
                    server._thread,
                    "start",
                    side_effect=RuntimeError("injected thread start failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "injected thread start failure"),
            ):
                server.start()
            self.assertEqual(list(directory.iterdir()), [])
            with self.assertRaises(OSError):
                socket.create_connection(("127.0.0.1", port), timeout=0.2)
            server.close()

    def test_close_retries_transient_sensitive_artifact_cleanup_failures(self) -> None:
        def exercise(target_name: str) -> None:
            with tempfile.TemporaryDirectory() as raw_directory:
                directory = Path(raw_directory)
                server = capture.PrivateMailCaptureServer(
                    directory=directory,
                    run_id=RUN_ID,
                    recipients={USER_ID: EMAIL},
                )
                original_unlink = Path.unlink
                failure_count = 0

                def fail_once(target: Path, *, missing_ok: bool = False) -> None:
                    nonlocal failure_count
                    if target.name == target_name and failure_count == 0:
                        failure_count += 1
                        raise OSError("injected transient sensitive unlink failure")
                    original_unlink(target, missing_ok=missing_ok)

                with (
                    patch.object(Path, "unlink", fail_once),
                    self.assertRaises(capture.CaptureError),
                ):
                    server.close()
                self.assertEqual(failure_count, 1)
                server.close()
                self.assertEqual(list(directory.iterdir()), [])

        for target_name in (
            "capture-spool.json",
            "capture-cert.pem",
            "capture-key.pem",
        ):
            with self.subTest(target_name=target_name):
                exercise(target_name)

    def test_close_aborts_stalled_starttls_and_data_before_spool_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            server = capture.PrivateMailCaptureServer(
                directory=directory,
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            server.start()
            stalled_tls = socket.create_connection(
                ("127.0.0.1", server.port), timeout=2
            )
            stalled_tls.settimeout(2)
            self.assertTrue(stalled_tls.recv(128).startswith(b"220 "))
            stalled_tls.sendall(b"STARTTLS\r\n")
            self.assertTrue(stalled_tls.recv(128).startswith(b"220 "))

            context = ssl.create_default_context(cafile=server.ca_path)
            stalled_data = smtplib.SMTP("127.0.0.1", server.port, timeout=2)
            stalled_data.ehlo()
            stalled_data.starttls(context=context)
            stalled_data.ehlo()
            self.assertEqual(
                stalled_data.docmd("MAIL FROM:<contract@example.invalid>")[0], 250
            )
            self.assertEqual(stalled_data.docmd(f"RCPT TO:<{EMAIL}>")[0], 250)
            self.assertEqual(stalled_data.docmd("DATA")[0], 354)
            assert stalled_data.sock is not None
            stalled_data.sock.sendall(b"Subject: Reset your password\r\n\r\npartial")

            started = time.monotonic()
            server.close()
            self.assertLess(time.monotonic() - started, 5.0)
            server.close()
            stalled_tls.close()
            stalled_data.close()
            self.assertEqual(list(server._server.handler_errors), [])
            self.assertEqual(list(directory.iterdir()), [])

    def test_close_wins_wrap_to_tracked_starttls_transition(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            server = capture.PrivateMailCaptureServer(
                directory=directory,
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            server.start()
            transition_reached = threading.Event()
            release_transition = threading.Event()
            original_replace = cast(
                Callable[[socket.socket, socket.socket], bool],
                server._server.replace_connection,
            )

            def delayed_replace(
                previous: socket.socket, replacement: socket.socket
            ) -> bool:
                transition_reached.set()
                self.assertTrue(release_transition.wait(2))
                return original_replace(previous, replacement)

            client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            client.settimeout(2)
            self.assertTrue(client.recv(128).startswith(b"220 "))
            with patch.object(server._server, "replace_connection", delayed_replace):
                client.sendall(b"STARTTLS\r\n")
                self.assertTrue(client.recv(128).startswith(b"220 "))
                self.assertTrue(transition_reached.wait(2))
                close_finished = threading.Event()

                def close_server() -> None:
                    server.close()
                    close_finished.set()

                closer = threading.Thread(target=close_server)
                closer.start()
                deadline = time.monotonic() + 2
                while (
                    not server._server._closing.is_set() and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertTrue(server._server._closing.is_set())
                release_transition.set()
                closer.join(timeout=5)
                self.assertFalse(closer.is_alive())
                self.assertTrue(close_finished.is_set())
            client.close()
            self.assertEqual(list(server._server.handler_errors), [])
            self.assertEqual(list(directory.iterdir()), [])

    def test_mailbox_oserror_outside_close_is_observable(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            server = capture.PrivateMailCaptureServer(
                directory=Path(raw_directory),
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            )
            server.start()

            def fail_capture(_raw: bytes) -> None:
                raise OSError("injected spool failure")

            context = ssl.create_default_context(cafile=server.ca_path)
            with patch.object(server.mailbox, "capture_message", fail_capture):
                smtp = smtplib.SMTP("127.0.0.1", server.port, timeout=2)
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                with self.assertRaises(smtplib.SMTPServerDisconnected):
                    smtp.send_message(
                        message(
                            subject="Verify your email",
                            recipient=EMAIL,
                            link_text="Use this link to verify your email: https://frontend.invalid/verify-email?token=unwritten",
                        )
                    )
                smtp.close()
            deadline = time.monotonic() + 2
            while not server._server.handler_errors and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(
                any(
                    "injected spool failure" in str(item)
                    for item in server._server.handler_errors
                )
            )
            server.close()

    def test_fastapi_smtp_adapter_delivers_into_actual_private_capture_path(
        self,
    ) -> None:
        from wiseacct_sso.infrastructure.mail import SmtpMailConfig, SmtpMailService

        with (
            tempfile.TemporaryDirectory() as raw_directory,
            capture.PrivateMailCaptureServer(
                directory=Path(raw_directory),
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            ) as server,
        ):
            previous = os.environ.get("SSL_CERT_FILE")
            os.environ["SSL_CERT_FILE"] = str(server.ca_path)
            try:
                mail = SmtpMailService(
                    SmtpMailConfig(
                        "Contract <contract@example.invalid>",
                        None,
                        "127.0.0.1",
                        server.port,
                        None,
                        None,
                    )
                )
                asyncio.run(
                    mail.send_email_verification(
                        to=EMAIL,
                        verification_url=(
                            "https://frontend.invalid/verify-email?token=fastapi-private-token"
                        ),
                    )
                )
            finally:
                if previous is None:
                    os.environ.pop("SSL_CERT_FILE", None)
                else:
                    os.environ["SSL_CERT_FILE"] = previous

            token = server.mailbox.take(
                run_id=RUN_ID,
                user_id=USER_ID,
                kind="email-verification",
            )
            self.assertEqual(token.token, "fastapi-private-token")

    @unittest.skipUnless(
        shutil.which("node")
        and (
            Path(__file__).resolve().parents[2] / "auth-server/node_modules/nodemailer"
        ).is_dir(),
        "locked Express Node dependencies are not installed",
    )
    def test_node_smtp_transport_delivers_into_actual_private_capture_path(
        self,
    ) -> None:
        repository = Path(__file__).resolve().parents[2]
        script = """
import { generateKeyPairSync } from 'node:crypto';
(async () => {
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048, publicExponent: 0x10001
});
const publicJwk = publicKey.export({ format: 'jwk' });
Object.assign(process.env, {
  NODE_ENV: 'test',
  DATABASE_URL: 'postgresql://contract:contract@127.0.0.1:5432/contract_test',
  JWT_ACCESS_ALGORITHM: 'RS256',
  JWT_ACCESS_PRIVATE_KEY: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
  JWT_ACCESS_PUBLIC_JWK: JSON.stringify({
    kty: 'RSA', n: publicJwk.n, e: publicJwk.e, alg: 'RS256', use: 'sig', kid: 'capture-key'
  }),
  JWT_ACCESS_KEY_ID: 'capture-key',
  JWT_REFRESH_SECRET: 'capture-only-refresh-secret',
  JWT_ISSUER: 'https://auth.example.invalid',
  JWT_AUDIENCE: 'contract-fixture',
  REDIS_URL: 'redis://127.0.0.1:6379/1',
  FRONTEND_REDIRECT_URL: 'https://frontend.invalid/auth/callback',
  OAUTH_ENABLED_PROVIDERS: '',
  GOOGLE_REDIRECT_URI: 'http://127.0.0.1:4000/auth/google/callback',
  NAVER_REDIRECT_URI: 'http://127.0.0.1:4000/auth/naver/callback',
  KAKAO_REDIRECT_URI: 'http://127.0.0.1:4000/auth/kakao/callback',
  AUTH_CLIENTS_JSON: JSON.stringify([{
    clientId: 'temis', audience: 'temis',
    allowedRedirectUris: ['https://financenow.kr/auth/callback', 'https://temis.me/auth/callback', 'https://ti.temis.me/auth/callback'],
    allowedOrigins: ['https://financenow.kr'],
    defaultRole: { serviceKey: 'temis', name: 'user' }
  }]),
  MAIL_PROVIDER: 'smtp',
  MAIL_FROM: 'Contract <contract@example.invalid>',
  SMTP_HOST: '127.0.0.1',
  SMTP_PORT: process.env.CAPTURE_PORT
});
const { createMailService } = await import('./src/services/mail.service.ts');
await createMailService().sendPasswordReset({
  to: process.env.CAPTURE_TO,
  resetUrl: 'https://frontend.invalid/password-reset?token=node-private-token'
});
})();
"""
        with (
            tempfile.TemporaryDirectory() as raw_directory,
            capture.PrivateMailCaptureServer(
                directory=Path(raw_directory),
                run_id=RUN_ID,
                recipients={USER_ID: EMAIL},
            ) as server,
        ):
            completed = subprocess.run(
                ["node_modules/.bin/tsx", "--eval", script],
                cwd=repository / "auth-server",
                env={
                    **os.environ,
                    "CAPTURE_PORT": str(server.port),
                    "CAPTURE_TO": EMAIL,
                    "NODE_EXTRA_CA_CERTS": str(server.ca_path),
                },
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            token = server.mailbox.take(
                run_id=RUN_ID,
                user_id=USER_ID,
                kind="password-reset",
            )
            self.assertEqual(token.token, "node-private-token")

    def test_cli_help_does_not_start_or_create_capture_material(self) -> None:
        started = time.monotonic()
        with self.assertRaises(SystemExit) as raised:
            capture.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertLess(time.monotonic() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
