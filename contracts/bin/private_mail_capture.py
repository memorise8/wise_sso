#!/usr/bin/env python3
"""Private loopback SMTP capture for contract verification and reset flows.

The capture spool is deliberately separate from public evidence.  It contains an
opaque token only while a test flow needs to consume it, is restricted to mode
0600, and is removed by the server context manager.
"""

from __future__ import annotations

import argparse
import collections
import email.policy
import errno
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from types import FrameType
from typing import Any, Literal, Self, TextIO, TypeVar, cast
from urllib.parse import parse_qs, urlsplit

MailKind = Literal["email-verification", "password-reset"]

_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_USER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUBJECT_KIND: dict[str, MailKind] = {
    "Verify your email": "email-verification",
    "Reset your password": "password-reset",
}
_TEXT_PREFIX: dict[MailKind, str] = {
    "email-verification": "Use this link to verify your email:",
    "password-reset": "Use this link to reset your password:",
}
_MAX_MESSAGE_BYTES = 256 * 1024
_MAX_CAPTURED_MESSAGES = 64
_MAX_TOKEN_BYTES = 8 * 1024
_MAX_TOTAL_TOKEN_BYTES = 128 * 1024
_MAX_CONNECTIONS = 8
_CONNECTION_TIMEOUT_SECONDS = 15.0
_T = TypeVar("_T")


class CaptureError(Exception):
    """Base class for fail-closed private capture errors."""


class CaptureScopeError(CaptureError):
    """The requested run or user is outside the configured capture scope."""


class CaptureExpiredError(CaptureError):
    """The matching captured token has expired and was destroyed."""


@dataclass(frozen=True, slots=True)
class CapturedToken:
    kind: MailKind
    user_id: str
    token: str
    token_sha256: str

    def __repr__(self) -> str:
        return (
            f"CapturedToken(kind={self.kind!r}, user_id={self.user_id!r}, "
            f"token='[REDACTED]', token_sha256={self.token_sha256!r})"
        )


def _validate_identifier(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value):
        raise CaptureScopeError(f"{label} has an invalid shape")
    return value


def _normalize_recipients(recipients: dict[str, str]) -> dict[str, str]:
    if not recipients:
        raise CaptureScopeError("at least one synthetic recipient is required")
    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for user_id, raw_email in recipients.items():
        _validate_identifier(user_id, _USER_ID, "user_id")
        address = raw_email.strip().lower()
        local, separator, domain = address.rpartition("@")
        if not separator or not local or not domain.endswith(".invalid"):
            raise CaptureScopeError(
                "capture recipients must use a reserved .invalid domain"
            )
        if address in seen:
            raise CaptureScopeError("capture recipient addresses must be unique")
        seen.add(address)
        normalized[address] = user_id
    return normalized


class PrivateMailbox:
    """Mode-0600 spool with scoped, destructive token consumption."""

    def __init__(
        self,
        spool_path: Path,
        *,
        run_id: str,
        recipients: dict[str, str],
        ttl_seconds: float = 300.0,
    ) -> None:
        self.spool_path = spool_path.resolve()
        self.run_id = _validate_identifier(run_id, _RUN_ID, "run_id")
        self._recipients = _normalize_recipients(recipients)
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0 or ttl_seconds > 3600:
            raise CaptureScopeError(
                "ttl_seconds must be greater than zero and at most 3600"
            )
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._accepting = True
        self._descriptor_open = False
        self._content_destroyed = False
        self._path_clean = False
        self._cleanup_complete = False
        self._create_spool()

    def _create_spool(self) -> None:
        parent_mode = self.spool_path.parent.stat().st_mode & 0o777
        if parent_mode & 0o077:
            raise CaptureScopeError(
                "capture spool parent must not be group/world accessible"
            )
        descriptor = os.open(
            self.spool_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        spool_stat = os.fstat(descriptor)
        if not stat.S_ISREG(spool_stat.st_mode):
            os.close(descriptor)
            raise CaptureScopeError("capture spool must be a regular file")
        self._spool_identity = (spool_stat.st_dev, spool_stat.st_ino)
        self._spool_descriptor = descriptor
        self._descriptor_open = True
        with os.fdopen(os.dup(descriptor), "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "runId": self.run_id, "messages": []}, stream)
            stream.flush()
            os.fsync(stream.fileno())

    def _mutate(self, operation: Callable[[dict[str, Any]], _T]) -> _T:
        with self._lock:
            if not self._accepting:
                raise CaptureError("capture mailbox is closed")
            path_stat = self.spool_path.stat(follow_symlinks=False)
            if (path_stat.st_dev, path_stat.st_ino) != self._spool_identity:
                raise CaptureScopeError("capture spool inode changed")
            descriptor = os.dup(self._spool_descriptor)
            stream = os.fdopen(descriptor, "r+", encoding="utf-8")
            return self._mutate_locked(stream, operation)

    def _mutate_locked(
        self,
        stream: TextIO,
        operation: Callable[[dict[str, Any]], _T],
    ) -> _T:
        with stream:
            spool_stat = os.fstat(stream.fileno())
            if (spool_stat.st_dev, spool_stat.st_ino) != self._spool_identity:
                raise CaptureScopeError("capture spool inode changed")
            if not stat.S_ISREG(spool_stat.st_mode) or spool_stat.st_mode & 0o077:
                raise CaptureScopeError("capture spool permissions became unsafe")
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                stream.seek(0)
                document = json.load(stream)
                if document.get("version") != 1 or document.get("runId") != self.run_id:
                    raise CaptureScopeError(
                        "capture spool scope does not match this run"
                    )
                result = operation(document)
                stream.seek(0)
                json.dump(document, stream, separators=(",", ":"), sort_keys=True)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
                return result
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def capture_message(
        self, raw_message: bytes, *, received_at: float | None = None
    ) -> None:
        if len(raw_message) > _MAX_MESSAGE_BYTES:
            raise CaptureError("mail message exceeds the private capture size limit")
        message = BytesParser(policy=email.policy.default).parsebytes(raw_message)
        typed_message = message
        kind = _SUBJECT_KIND.get(str(typed_message.get("Subject", "")))
        if kind is None:
            raise CaptureError("mail subject is not an approved contract message")
        addresses = [
            address.lower()
            for _, address in getaddresses(typed_message.get_all("To", []))
        ]
        if len(addresses) != 1 or addresses[0] not in self._recipients:
            raise CaptureScopeError(
                "mail recipient is outside the configured synthetic users"
            )
        token = _extract_token(typed_message, kind)
        if len(token.encode()) > _MAX_TOKEN_BYTES:
            raise CaptureError("captured token exceeds the private capture size limit")
        now = time.time() if received_at is None else received_at
        if not math.isfinite(now):
            raise CaptureError("capture received_at must be finite")
        record = {
            "expiresAt": now + self.ttl_seconds,
            "kind": kind,
            "receivedAt": now,
            "token": token,
            "tokenSha256": hashlib.sha256(token.encode()).hexdigest(),
            "userId": self._recipients[addresses[0]],
        }

        def append(document: dict[str, Any]) -> None:
            messages = document.get("messages")
            if not isinstance(messages, list):
                raise CaptureScopeError("capture spool messages are malformed")
            _purge_expired(messages, now=now)
            if len(messages) >= _MAX_CAPTURED_MESSAGES:
                raise CaptureError("private capture message limit reached")
            total_token_bytes = sum(
                len(item.get("token", "").encode())
                for item in messages
                if isinstance(item, dict) and isinstance(item.get("token"), str)
            )
            if total_token_bytes + len(token.encode()) > _MAX_TOTAL_TOKEN_BYTES:
                raise CaptureError("private capture token storage limit reached")
            messages.append(record)

        self._mutate(append)

    def take(
        self,
        *,
        run_id: str,
        user_id: str,
        kind: MailKind,
        now: float | None = None,
    ) -> CapturedToken:
        if run_id != self.run_id:
            raise CaptureScopeError("capture run does not match")
        if user_id not in self._recipients.values():
            raise CaptureScopeError("capture user is outside the configured scope")
        current = time.time() if now is None else now
        if not math.isfinite(current):
            raise CaptureError("capture now must be finite")

        def consume(document: dict[str, Any]) -> CapturedToken | None:
            messages = document.get("messages")
            if not isinstance(messages, list):
                raise CaptureScopeError("capture spool messages are malformed")
            matches = [
                (index, item)
                for index, item in enumerate(messages)
                if isinstance(item, dict)
                and item.get("userId") == user_id
                and item.get("kind") == kind
            ]
            if not matches:
                raise CaptureScopeError(
                    "no capture exists for the requested user and kind"
                )
            index, item = matches[-1]
            del messages[index]
            expires_at = item.get("expiresAt")
            if (
                not isinstance(expires_at, (int, float))
                or not math.isfinite(expires_at)
                or current >= expires_at
            ):
                return None
            token = item.get("token")
            token_sha256 = item.get("tokenSha256")
            if (
                not isinstance(token, str)
                or not token
                or not isinstance(token_sha256, str)
            ):
                raise CaptureScopeError("captured token record is malformed")
            if hashlib.sha256(token.encode()).hexdigest() != token_sha256:
                raise CaptureScopeError("captured token digest does not match")
            return CapturedToken(kind, user_id, token, token_sha256)

        captured = self._mutate(consume)
        if captured is None:
            raise CaptureExpiredError("captured token expired and was destroyed")
        return captured

    def public_summary(self) -> dict[str, Any]:
        def summarize(document: dict[str, Any]) -> dict[str, Any]:
            messages = document.get("messages")
            if not isinstance(messages, list):
                raise CaptureScopeError("capture spool messages are malformed")
            _purge_expired(messages, now=time.time())
            counts = {kind: 0 for kind in _SUBJECT_KIND.values()}
            for item in messages:
                if isinstance(item, dict) and item.get("kind") in counts:
                    counts[cast(MailKind, item["kind"])] += 1
            return {
                "runId": self.run_id,
                "capturedCounts": counts,
                "containsToken": False,
                "containsEmail": False,
            }

        return self._mutate(summarize)

    def cleanup(self) -> None:
        failures: list[OSError] = []
        with self._lock:
            if self._cleanup_complete:
                return
            self._accepting = False
            if self._descriptor_open and not self._content_destroyed:
                try:
                    os.lseek(self._spool_descriptor, 0, os.SEEK_SET)
                    os.ftruncate(self._spool_descriptor, 0)
                    os.fsync(self._spool_descriptor)
                    self._content_destroyed = True
                except OSError as exc:
                    failures.append(exc)
            if not self._path_clean:
                try:
                    path_stat = self.spool_path.stat(follow_symlinks=False)
                except FileNotFoundError:
                    self._path_clean = True
                except OSError as exc:
                    failures.append(exc)
                else:
                    if (
                        path_stat.st_dev,
                        path_stat.st_ino,
                    ) != self._spool_identity:
                        if self._content_destroyed:
                            self._path_clean = True
                    else:
                        try:
                            self.spool_path.unlink()
                            self._path_clean = True
                        except OSError as exc:
                            failures.append(exc)
            if self._descriptor_open and (self._content_destroyed or self._path_clean):
                try:
                    os.close(self._spool_descriptor)
                    self._descriptor_open = False
                except OSError as exc:
                    failures.append(exc)
            self._cleanup_complete = not self._descriptor_open and self._path_clean
        if failures:
            raise CaptureError(
                "could not fully remove private capture spool"
            ) from failures[0]
        if not self._cleanup_complete:
            raise CaptureError("private capture spool cleanup remains incomplete")


def _purge_expired(messages: list[Any], *, now: float) -> None:
    messages[:] = [
        item
        for item in messages
        if isinstance(item, dict)
        and isinstance(item.get("expiresAt"), (int, float))
        and math.isfinite(item["expiresAt"])
        and now < item["expiresAt"]
    ]


def _extract_token(message: EmailMessage, kind: MailKind) -> str:
    body = message.get_body(preferencelist=("plain",))
    if body is None:
        raise CaptureError("mail message must contain a plain-text body")
    content = cast(str, body.get_content())
    prefix = _TEXT_PREFIX[kind]
    candidates = [
        line.removeprefix(prefix).strip()
        for line in content.splitlines()
        if line.startswith(prefix)
    ]
    if len(candidates) != 1:
        raise CaptureError("mail message must contain exactly one approved action link")
    parsed = urlsplit(candidates[0])
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise CaptureError(
            "mail action link must be an absolute HTTP(S) URL without credentials"
        )
    tokens = parse_qs(parsed.query, keep_blank_values=True).get("token", [])
    if len(tokens) != 1 or not tokens[0]:
        raise CaptureError("mail action link must contain exactly one non-empty token")
    return tokens[0]


class _SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True

    def __init__(
        self, address: tuple[str, int], mailbox: PrivateMailbox, context: ssl.SSLContext
    ):
        self.mailbox = mailbox
        self.tls_context = context
        self._connection_slots = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        self._active_connections: set[socket.socket] = set()
        self._active_lock = threading.Lock()
        self._closing = threading.Event()
        self.handler_errors: collections.deque[BaseException] = collections.deque(
            maxlen=16
        )
        super().__init__(address, _SmtpHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self.track_connection(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.untrack_connection(request)
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.untrack_connection(request)
            self._connection_slots.release()

    def track_connection(self, connection: socket.socket) -> None:
        with self._active_lock:
            self._active_connections.add(connection)

    def replace_connection(
        self, previous: socket.socket, replacement: socket.socket
    ) -> bool:
        with self._active_lock:
            self._active_connections.discard(previous)
            if self._closing.is_set():
                return False
            self._active_connections.add(replacement)
            return True

    def untrack_connection(self, connection: socket.socket) -> None:
        with self._active_lock:
            self._active_connections.discard(connection)

    def abort_active_connections(self) -> None:
        with self._active_lock:
            connections = tuple(self._active_connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def begin_close(self) -> None:
        with self._active_lock:
            self._closing.set()

    def handle_error(self, request: Any, client_address: Any) -> None:
        failure = sys.exception()
        expected_close_errnos = {
            errno.EBADF,
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.ENOTCONN,
            errno.EPIPE,
        }
        if self._closing.is_set() and (
            isinstance(failure, (ssl.SSLError, TimeoutError))
            or (isinstance(failure, OSError) and failure.errno in expected_close_errnos)
        ):
            return
        if failure is not None:
            self.handler_errors.append(failure)


class _SmtpHandler(socketserver.StreamRequestHandler):
    server: _SmtpServer

    def _reply(self, value: bytes) -> None:
        self.wfile.write(value + b"\r\n")
        self.wfile.flush()

    def handle(self) -> None:
        self.connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
        tls_active = False
        recipients: list[str] = []
        self._reply(b"220 private-mail-capture ESMTP")
        while True:
            line = self.rfile.readline(8192)
            if not line:
                return
            command, _, argument = line.rstrip(b"\r\n").partition(b" ")
            upper = command.upper()
            if upper in {b"EHLO", b"HELO"}:
                self._reply(b"250-private-mail-capture")
                if not tls_active:
                    self._reply(b"250-STARTTLS")
                self._reply(f"250 SIZE {_MAX_MESSAGE_BYTES}".encode())
            elif upper == b"STARTTLS" and not tls_active:
                self._reply(b"220 Ready to start TLS")
                previous = self.connection
                wrapped = self.server.tls_context.wrap_socket(
                    self.connection,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
                accepted = self.server.replace_connection(previous, wrapped)
                self.connection = wrapped
                self.request = wrapped
                self.rfile.close()
                self.wfile.close()
                if not accepted:
                    wrapped.close()
                    return
                self.rfile = wrapped.makefile("rb")
                self.wfile = wrapped.makefile("wb")
                wrapped.do_handshake()
                tls_active = True
                recipients.clear()
            elif (
                upper == b"MAIL"
                and tls_active
                and argument.upper().startswith(b"FROM:")
            ):
                recipients.clear()
                self._reply(b"250 OK")
            elif (
                upper == b"RCPT" and tls_active and argument.upper().startswith(b"TO:")
            ):
                recipients.append(
                    argument[3:].strip().strip(b"<>").decode("utf-8", errors="strict")
                )
                self._reply(b"250 OK")
            elif upper == b"DATA" and tls_active and recipients:
                self._reply(b"354 End data with <CR><LF>.<CR><LF>")
                raw = bytearray()
                oversized = False
                while True:
                    data_line = self.rfile.readline(8192)
                    if not data_line or data_line == b".\r\n":
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    if not oversized:
                        raw.extend(data_line)
                        oversized = len(raw) > _MAX_MESSAGE_BYTES
                try:
                    if oversized:
                        raise CaptureError(
                            "mail message exceeds the private capture size limit"
                        )
                    self.server.mailbox.capture_message(bytes(raw))
                except (CaptureError, UnicodeError, ValueError):
                    self._reply(b"554 Message rejected by private capture policy")
                else:
                    self._reply(b"250 Captured")
                recipients.clear()
            elif upper == b"RSET":
                recipients.clear()
                self._reply(b"250 OK")
            elif upper == b"NOOP":
                self._reply(b"250 OK")
            elif upper == b"QUIT":
                self._reply(b"221 Bye")
                return
            else:
                self._reply(b"502 Command not implemented")

    def finish(self) -> None:
        connection = self.connection
        try:
            super().finish()
        finally:
            self.server.untrack_connection(connection)
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def _create_tls_material(directory: Path) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise CaptureError(
            "openssl is required to create ephemeral capture TLS material"
        )
    certificate = directory / "capture-cert.pem"
    private_key = directory / "capture-key.pem"
    command = [
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-keyout",
        str(private_key),
        "-out",
        str(certificate),
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=20, check=False
    )
    if completed.returncode != 0:
        raise CaptureError("openssl could not create ephemeral capture TLS material")
    private_key.chmod(0o600)
    certificate.chmod(0o600)
    return certificate, private_key


class PrivateMailCaptureServer:
    """Loopback-only STARTTLS SMTP service backed by a private scoped mailbox."""

    def __init__(
        self,
        *,
        directory: Path,
        run_id: str,
        recipients: dict[str, str],
        ttl_seconds: float = 300.0,
    ) -> None:
        resolved = directory.resolve()
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        if resolved.stat().st_mode & 0o077:
            raise CaptureScopeError(
                "capture directory must not be group/world accessible"
            )
        if any(resolved.iterdir()):
            raise CaptureScopeError("capture directory must be empty")
        self._directory = resolved
        self._close_lock = threading.Lock()
        self._closing = False
        self._cleanup_complete = False
        self.mailbox = PrivateMailbox(
            resolved / "capture-spool.json",
            run_id=run_id,
            recipients=recipients,
            ttl_seconds=ttl_seconds,
        )
        self.ca_path = resolved / "capture-cert.pem"
        key_path = resolved / "capture-key.pem"
        bound_server: _SmtpServer | None = None
        try:
            self.ca_path, key_path = _create_tls_material(resolved)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(self.ca_path, key_path)
            bound_server = _SmtpServer(("127.0.0.1", 0), self.mailbox, context)
            self._server = bound_server
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
            )
        except BaseException as original:
            rollback_failures: list[Exception] = []
            operations: list[Callable[[], Any]] = []
            if bound_server is not None:
                operations.extend(
                    (
                        bound_server.begin_close,
                        bound_server.abort_active_connections,
                        bound_server.server_close,
                    )
                )
            operations.extend(
                (
                    self.mailbox.cleanup,
                    lambda: self.ca_path.unlink(missing_ok=True),
                    lambda: key_path.unlink(missing_ok=True),
                )
            )
            for operation in operations:
                try:
                    operation()
                except (CaptureError, OSError, RuntimeError) as exc:
                    rollback_failures.append(exc)
            if rollback_failures:
                original.add_note(
                    f"private capture rollback also had {len(rollback_failures)} failure(s)"
                )
            raise

    @property
    def port(self) -> int:
        return cast(tuple[str, int], self._server.server_address)[1]

    def smtp_launcher_environment(self) -> dict[str, str]:
        """Return inputs for a reviewed test-only launcher, not fixture guard claims."""

        return {
            "MAIL_PROVIDER": "smtp",
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": str(self.port),
            "SMTP_USERNAME": "",
            "SMTP_PASSWORD": "",
            "SSL_CERT_FILE": str(self.ca_path),
            "NODE_EXTRA_CA_CERTS": str(self.ca_path),
            "CONTRACT_PRIVATE_MAIL_CAPTURE": "1",
        }

    def start(self) -> None:
        if self._closing:
            raise CaptureError("private capture server is closing")
        try:
            self._thread.start()
        except BaseException as original:
            try:
                self.close()
            except (CaptureError, OSError, RuntimeError) as cleanup_error:
                original.add_note(
                    f"private capture start rollback failed: {cleanup_error}"
                )
            raise

    def close(self) -> None:
        with self._close_lock:
            if self._cleanup_complete:
                return
            self._closing = True
            failures: list[tuple[str, Exception]] = []

            def attempt(label: str, operation: Callable[[], Any]) -> None:
                try:
                    operation()
                except (CaptureError, OSError, RuntimeError) as exc:
                    failures.append((label, exc))

            self._server.begin_close()
            if self._thread.is_alive():
                attempt("server shutdown", self._server.shutdown)
                self._thread.join(timeout=5)
                if self._thread.is_alive():
                    failures.append(("server thread drain", CaptureError("timed out")))
            attempt("active connection abort", self._server.abort_active_connections)
            attempt("handler drain", self._server.server_close)
            attempt("mailbox cleanup", self.mailbox.cleanup)
            attempt("certificate cleanup", lambda: self.ca_path.unlink(missing_ok=True))
            key_path = self._directory / "capture-key.pem"
            attempt("private key cleanup", lambda: key_path.unlink(missing_ok=True))
            if failures:
                labels = ", ".join(label for label, _ in failures)
                raise CaptureError(
                    f"private capture close failed: {labels}"
                ) from failures[0][1]
            self._cleanup_complete = True

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _parse_recipient(value: str) -> tuple[str, str]:
    user_id, separator, address = value.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError("recipient must use USER_ID=EMAIL")
    return user_id, address


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--recipient", action="append", required=True, type=_parse_recipient
    )
    parser.add_argument("--ttl-seconds", type=float, default=300.0)
    args = parser.parse_args(argv)
    recipients = dict(args.recipient)
    stop = threading.Event()

    def request_stop(_signum: int, _frame: FrameType | None) -> None:
        stop.set()

    previous_term = signal.signal(signal.SIGTERM, request_stop)
    previous_int = signal.signal(signal.SIGINT, request_stop)
    try:
        with PrivateMailCaptureServer(
            directory=args.directory,
            run_id=args.run_id,
            recipients=recipients,
            ttl_seconds=args.ttl_seconds,
        ) as capture:
            endpoint = {
                "host": "127.0.0.1",
                "port": capture.port,
                "caPath": str(capture.ca_path),
                "spoolPath": str(capture.mailbox.spool_path),
                "containsToken": False,
                "containsEmail": False,
            }
            print(
                json.dumps(endpoint, separators=(",", ":"), sort_keys=True), flush=True
            )
            while not stop.wait(0.25):
                pass
        return 0
    except (CaptureError, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)


if __name__ == "__main__":
    raise SystemExit(main())
