#!/usr/bin/env python3
"""Hermetic two-process auth runtime used by mail-flow driver tests only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import smtplib
import sqlite3
import ssl
import sys
import time
import urllib.parse
from collections.abc import Callable
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, TypeVar, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

USER_ID = "00000000-0000-4000-8000-000000000021"
EMAIL = "mixed-pending@example.invalid"
ATTACH_USER_ID = "00000000-0000-4000-8000-000000000022"
ATTACH_EMAIL = "mixed-attach@example.invalid"
PASSWORD = "ContractMixed!2026"
NAME = "Mixed Runtime User"
ROLES = [{"serviceKey": "temis", "name": "user"}]
AUDIENCE = "mixed-runtime-fixture"
CLIENT_ID = "mixed-runtime-fixture"
REDIRECT_URI = "http://127.0.0.1:4101/auth/callback"
CALLER_STATE = "mixed-caller-state"
CODE_VERIFIER = "mixed-code-verifier"
CODE_CHALLENGE = "mixed-code-challenge"
ISSUER = "https://auth.financenow.kr"
T = TypeVar("T")


def _segment(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        )
        .decode()
        .rstrip("=")
    )


class State:
    def __init__(self, path: Path) -> None:
        self.path = path
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), document TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, trial INTEGER NOT NULL, role TEXT NOT NULL, pid INTEGER NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), current_trial INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO metadata(id, current_trial) VALUES(1, 0) ON CONFLICT(id) DO NOTHING"
            )

    @staticmethod
    def empty() -> dict[str, Any]:
        return {
            "fixture": "none",
            "password": PASSWORD,
            "verified": False,
            "attachVerified": False,
            "sequence": 0,
            "tokens": [],
            "activeHashes": [],
            "revokedHashes": [],
            "handoffs": {},
            "verificationAudits": {"requests": 0, "success": 0, "failure": 0},
            "resetAudits": {"requests": 0, "success": 0, "failure": 0},
        }

    def reset(self, fixture: str, *, advance_trial: bool = False) -> None:
        document = self.empty()
        document["fixture"] = fixture
        document["verified"] = fixture == "active-password-user"
        with sqlite3.connect(self.path) as connection:
            if advance_trial:
                connection.execute(
                    "UPDATE metadata SET current_trial=current_trial + 1 WHERE id=1"
                )
            connection.execute(
                "INSERT INTO state(id, document) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",
                (json.dumps(document, separators=(",", ":")),),
            )

    def read(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute("SELECT document FROM state WHERE id=1").fetchone()
        return self.empty() if row is None else json.loads(row[0])

    def mutate(self, operation: Callable[[dict[str, Any]], T]) -> T:
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT document FROM state WHERE id=1").fetchone()
            document = self.empty() if row is None else json.loads(row[0])
            result = operation(document)
            connection.execute(
                "INSERT INTO state(id, document) VALUES(1, ?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",
                (json.dumps(document, separators=(",", ":")),),
            )
            return result

    def event(self, role: str, method: str, path: str) -> None:
        with sqlite3.connect(self.path, timeout=5) as connection:
            connection.execute(
                "INSERT INTO events(trial, role, pid, method, path) SELECT current_trial, ?, ?, ?, ? FROM metadata WHERE id=1",
                (role, os.getpid(), method, path),
            )


def _fixture(name: str) -> dict[str, Any]:
    common = {
        "userId": USER_ID,
        "email": EMAIL,
        "password": PASSWORD,
        "name": NAME,
        "roles": ROLES,
        "audience": AUDIENCE,
        "clientId": CLIENT_ID,
        "redirectUri": REDIRECT_URI,
        "state": CALLER_STATE,
        "codeChallenge": CODE_CHALLENGE,
        "codeVerifier": CODE_VERIFIER,
    }
    if name == "pending-email-user":
        common.update(attachUserId=ATTACH_USER_ID, attachEmail=ATTACH_EMAIL)
    return common


def _latest(document: dict[str, Any], kind: str, user_id: str) -> dict[str, Any] | None:
    tokens = cast(list[dict[str, Any]], document["tokens"])
    for token in reversed(tokens):
        if token["kind"] == kind and token["userId"] == user_id:
            return token
    return None


def adapter_main() -> int:
    command, name = sys.argv[1:]
    state = State(Path(os.environ["CONTRACT_SHARED_STATE"]))
    if command == "preflight":
        result: Any = {"status": "ready"}
    elif command == "setup":
        state.reset(name, advance_trial=True)
        result = _fixture(name)
    elif command == "teardown":
        state.reset("none")
        result = {"status": "clean"}
    elif command == "expire":
        kind = (
            "email-verification" if "email-verification" in name else "password-reset"
        )

        def expire(document: dict[str, Any]) -> None:
            candidates = [item for item in document["tokens"] if item["kind"] == kind]
            if candidates:
                candidates[-1]["status"] = "expired"

        state.mutate(expire)
        result = {"status": "expired"}
    else:
        document = state.read()
        if name in {"auth-lifecycle", "pending-email-auth-lifecycle"}:
            active_hashes = list(document["activeHashes"])
            if os.environ.get("CONTRACT_TAMPER_SNAPSHOT") == "1":
                active_hashes.append("0" * 64)
            result = {
                "activeRefreshTokens": len(active_hashes),
                "authHandoffKeys": len(document["handoffs"]),
                "activeTokenHashes": active_hashes,
            }
        elif name == "fixture-anonymous-audits":
            result = {"residualCount": 0}
        elif name in {"email-verification-ledger", "attach-email-verification-ledger"}:
            user_id = ATTACH_USER_ID if name.startswith("attach-") else USER_ID
            token = _latest(document, "email-verification", user_id)
            result = {
                "unusedTokens": int(token is not None and token["status"] == "unused"),
                "digests": [token["digest"]]
                if token is not None and token["status"] == "unused"
                else [],
            }
        elif name == "password-reset-ledger":
            token = _latest(document, "password-reset", USER_ID)
            result = {
                "unusedTokens": int(token is not None and token["status"] == "unused"),
                "digests": [token["digest"]]
                if token is not None and token["status"] == "unused"
                else [],
            }
        elif name == "email-verification-result":
            token = _latest(document, "email-verification", USER_ID)
            result = {
                "userId": USER_ID,
                "email": EMAIL,
                "status": "ACTIVE" if document["verified"] else "PENDING",
                "emailVerified": document["verified"],
                "unusedTokens": int(token is not None and token["status"] == "unused"),
                "usedTokens": int(token is not None and token["status"] == "used"),
                "passwordCredentials": 1,
                "duplicateUsers": 1,
                "defaultRoles": 1,
            }
        elif name == "pending-password-attach-result":
            result = {
                "userId": ATTACH_USER_ID,
                "email": ATTACH_EMAIL,
                "status": "ACTIVE" if document["attachVerified"] else "PENDING",
                "passwordCredentials": int(document["attachVerified"]),
                "pendingPasswordCredentials": int(not document["attachVerified"]),
                "duplicateUsers": 1,
            }
            if os.environ.get("CONTRACT_TAMPER_ATTACH_RESULT") == "1":
                result["passwordCredentials"] = 0
        elif name == "password-reset-result":
            token = _latest(document, "password-reset", USER_ID)
            result = {
                "userId": USER_ID,
                "unusedTokens": int(token is not None and token["status"] == "unused"),
                "usedTokens": int(token is not None and token["status"] == "used"),
                "activeRefreshTokens": len(document["activeHashes"]),
            }
        elif name == "refresh-ledger":
            revoked_hashes = list(document["revokedHashes"])
            if os.environ.get("CONTRACT_TAMPER_REVOKED_LEDGER") == "1":
                revoked_hashes = revoked_hashes[:1]
            result = {
                "activeRefreshTokens": len(document["activeHashes"]),
                "revokedRefreshTokens": len(revoked_hashes),
                "activeTokenHashes": document["activeHashes"],
                "revokedTokenHashes": revoked_hashes,
            }
        elif name == "email-verification-audits":
            audits = document["verificationAudits"]
            result = {
                "requests": audits["requests"],
                "confirmationSuccesses": audits["success"],
                "confirmationFailures": audits["failure"],
            }
        elif name == "password-reset-audits":
            audits = document["resetAudits"]
            result = {
                "requests": audits["requests"],
                "confirmationSuccesses": audits["success"],
                "confirmationFailures": audits["failure"],
            }
        else:
            raise RuntimeError(f"unsupported snapshot: {name}")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


class Runtime:
    def __init__(self, role: str) -> None:
        if os.environ.get("CONTRACT_RUNTIME_ROLE") != role:
            raise RuntimeError("configured runtime role does not match owned process")
        self.role = role
        self.state = State(Path(os.environ["CONTRACT_SHARED_STATE"]))
        self.secret = os.environ.get(
            "RUNTIME_REFRESH_SECRET", os.environ["CONTRACT_REFRESH_SECRET"]
        )
        key_bytes = Path(
            os.environ[f"CONTRACT_{role.upper()}_PRIVATE_KEY"]
        ).read_bytes()
        self.private_key = cast(
            rsa.RSAPrivateKey,
            serialization.load_pem_private_key(key_bytes, password=None),
        )
        public = self.private_key.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": f"{role}-key",
            "n": base64.urlsafe_b64encode(
                public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
            "e": base64.urlsafe_b64encode(
                public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")
            )
            .decode()
            .rstrip("="),
        }
        if os.environ.get("CONTRACT_BAD_JWK") == "1":
            self.jwk["n"] = "AQAB"

    def access_token(self) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": f"{self.role}-key"}
        claims = {
            "sub": USER_ID,
            "email": EMAIL,
            "name": NAME,
            "email_verified": True,
            "type": "access",
            "roles": ROLES,
            "iat": now,
            "exp": now + 900,
            "iss": ISSUER,
            "aud": AUDIENCE,
        }
        signing_input = f"{_segment(header)}.{_segment(claims)}"
        signature = self.private_key.sign(
            signing_input.encode(), padding.PKCS1v15(), SHA256()
        )
        encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        if os.environ.get("CONTRACT_TAMPER_ACCESS") == "1":
            encoded_signature = (
                "A" if encoded_signature[0] != "A" else "B"
            ) + encoded_signature[1:]
        return f"{signing_input}.{encoded_signature}"

    def refresh_token(self) -> str:
        now = int(time.time())
        header = _segment({"alg": "HS256", "typ": "JWT"})
        claims = _segment(
            {
                "sub": USER_ID,
                "type": "refresh",
                "tokenId": f"{self.role}-{time.monotonic_ns()}",
                "audience": AUDIENCE,
                "iat": now,
                "exp": now + 3600,
            }
        )
        signing_input = f"{header}.{claims}"
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    self.secret.encode(), signing_input.encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        token = f"{signing_input}.{signature}"
        digest = hashlib.sha256(token.encode()).hexdigest()
        self.state.mutate(lambda document: document["activeHashes"].append(digest))
        return token

    def pair(self) -> dict[str, str]:
        return {
            "accessToken": self.access_token(),
            "refreshToken": self.refresh_token(),
        }

    def verify_access(self, token: str) -> bool:
        try:
            encoded_header, encoded_claims, encoded_signature = token.split(".")
            signature = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
            self.private_key.public_key().verify(
                signature,
                f"{encoded_header}.{encoded_claims}".encode(),
                padding.PKCS1v15(),
                SHA256(),
            )
            claims = cast(
                dict[str, Any],
                json.loads(
                    base64.urlsafe_b64decode(
                        encoded_claims + "=" * (-len(encoded_claims) % 4)
                    )
                ),
            )
            return claims.get("sub") == USER_ID and claims.get("exp", 0) > int(
                time.time()
            )
        except (ValueError, InvalidSignature, json.JSONDecodeError):
            return False

    def verify_refresh(self, token: str) -> bool:
        try:
            signing_input, signature = token.rsplit(".", 1)
        except ValueError:
            return False
        expected = (
            base64.urlsafe_b64encode(
                hmac.new(
                    self.secret.encode(), signing_input.encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        return hmac.compare_digest(signature, expected)

    def send_mail(self, recipient: str, kind: str, token: str) -> None:
        message = EmailMessage()
        message["From"] = "Contract <contract@example.invalid>"
        message["To"] = recipient
        if kind == "email-verification":
            message["Subject"] = "Verify your email"
            message.set_content(
                f"Use this link to verify your email: https://frontend.invalid/verify-email?token={token}"
            )
        else:
            message["Subject"] = "Reset your password"
            message.set_content(
                f"Use this link to reset your password: https://frontend.invalid/password-reset?token={token}"
            )
        context = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
        with smtplib.SMTP(
            os.environ["SMTP_HOST"], int(os.environ["SMTP_PORT"]), timeout=3
        ) as smtp:
            smtp.starttls(context=context)
            smtp.send_message(message)

    def issue_mail(self, email: str, kind: str, body: dict[str, Any]) -> None:
        user_id = ATTACH_USER_ID if email == ATTACH_EMAIL else USER_ID

        def issue(document: dict[str, Any]) -> str:
            document["sequence"] += 1
            token = f"{kind}-{document['sequence']}-{hashlib.sha256((self.role + email).encode()).hexdigest()[:16]}"
            document["tokens"].append(
                {
                    "kind": kind,
                    "userId": user_id,
                    "token": token,
                    "digest": hashlib.sha256(token.encode()).hexdigest(),
                    "status": "unused",
                    "handoff": {
                        key: body[key]
                        for key in ("clientId", "redirectUri", "state", "codeChallenge")
                        if key in body
                    },
                }
            )
            audits = document[
                "verificationAudits" if kind == "email-verification" else "resetAudits"
            ]
            audits["requests"] += 1
            return token

        token = self.state.mutate(issue)
        self.send_mail(email, kind, token)


def serve(role: str, port: int) -> int:
    runtime = Runtime(role)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def body(self) -> dict[str, Any]:
            length = int(self.headers.get("content-length", "0"))
            return cast(dict[str, Any], json.loads(self.rfile.read(length) or b"{}"))

        def send_json(self, status: int, body: Any) -> None:
            raw = (
                b""
                if body is None
                else json.dumps(body, separators=(",", ":")).encode()
            )
            self.send_response(status)
            if body is not None:
                self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            if raw:
                self.wfile.write(raw)

        def error(self, status: int, code: str, message: str) -> None:
            self.send_json(status, {"error": {"code": code, "message": message}})

        def do_GET(self) -> None:
            runtime.state.event(role, "GET", self.path)
            if self.path == "/health":
                self.send_json(200, {"status": "ok", "role": role})
            elif self.path == "/.well-known/jwks.json":
                self.send_json(200, {"keys": [runtime.jwk]})
            elif self.path == "/users/me":
                authorization = self.headers.get("authorization", "")
                if not authorization.startswith("Bearer ") or not runtime.verify_access(
                    authorization[7:]
                ):
                    self.error(401, "INVALID_ACCESS_TOKEN", "Invalid access token")
                else:
                    self.send_json(
                        200,
                        {
                            "id": USER_ID,
                            "email": EMAIL,
                            "name": NAME,
                            "email_verified": True,
                            "roles": ROLES,
                        },
                    )
            else:
                self.error(404, "NOT_FOUND", "Not found")

        def do_POST(self) -> None:
            runtime.state.event(role, "POST", self.path)
            body = self.body()
            if self.path in {
                "/auth/email-verification/request",
                "/auth/password-reset/request",
            }:
                kind = (
                    "email-verification"
                    if "email-verification" in self.path
                    else "password-reset"
                )
                runtime.issue_mail(str(body.get("email")), kind, body)
                self.send_json(202, {"status": "accepted"})
                return
            if self.path in {
                "/auth/email-verification/confirm",
                "/auth/password-reset/confirm",
            }:
                kind = (
                    "email-verification"
                    if "email-verification" in self.path
                    else "password-reset"
                )

                def confirm(document: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
                    tokens = cast(list[dict[str, Any]], document["tokens"])
                    token = next(
                        (
                            item
                            for item in tokens
                            if item["token"] == body.get("token")
                            and item["kind"] == kind
                        ),
                        None,
                    )
                    audits = document[
                        "verificationAudits"
                        if kind == "email-verification"
                        else "resetAudits"
                    ]
                    if token is None or token["status"] != "unused":
                        audits["failure"] += 1
                        return False, {}
                    token["status"] = "used"
                    audits["success"] += 1
                    if kind == "password-reset":
                        document["password"] = body.get("password")
                        document["revokedHashes"].extend(document["activeHashes"])
                        document["activeHashes"] = []
                    elif token["userId"] == ATTACH_USER_ID:
                        document["attachVerified"] = True
                    else:
                        document["verified"] = True
                        if token["handoff"]:
                            code = f"handoff-{document['sequence']}"
                            document["handoffs"][code] = token["handoff"]
                    return True, token

                accepted, token = runtime.state.mutate(confirm)
                if not accepted:
                    if kind == "email-verification":
                        self.error(
                            400,
                            "INVALID_VERIFICATION_TOKEN",
                            "Invalid or expired verification token",
                        )
                    else:
                        self.error(
                            400, "INVALID_RESET_TOKEN", "Invalid or expired reset token"
                        )
                elif kind == "password-reset":
                    self.send_json(204, None)
                else:
                    response = {"status": "verified"}
                    if token["handoff"]:
                        code = f"handoff-{runtime.state.read()['sequence']}"
                        response["redirectUrl"] = (
                            f"{token['handoff']['redirectUri']}?{urllib.parse.urlencode({'code': code, 'state': token['handoff']['state']})}"
                        )
                    self.send_json(200, response)
                return
            if self.path == "/auth/login":
                document = runtime.state.read()
                if (
                    body.get("email") != EMAIL
                    or body.get("password") != document["password"]
                    or not document["verified"]
                ):
                    self.error(401, "INVALID_CREDENTIALS", "Invalid email or password")
                elif "clientId" in body:

                    def handoff(document: dict[str, Any]) -> str:
                        code = f"login-handoff-{time.monotonic_ns()}"
                        document["handoffs"][code] = body
                        return code

                    code = runtime.state.mutate(handoff)
                    self.send_json(
                        200,
                        {
                            "redirectUrl": f"{body['redirectUri']}?{urllib.parse.urlencode({'code': code, 'state': body['state']})}"
                        },
                    )
                else:
                    self.send_json(200, runtime.pair())
                return
            if self.path == "/auth/exchange":

                def exchange(document: dict[str, Any]) -> bool:
                    stored = document["handoffs"].pop(str(body.get("code")), None)
                    return (
                        stored is not None
                        and stored.get("clientId") == body.get("clientId")
                        and stored.get("redirectUri") == body.get("redirectUri")
                        and body.get("codeVerifier") == CODE_VERIFIER
                    )

                if runtime.state.mutate(exchange):
                    self.send_json(200, runtime.pair())
                else:
                    self.error(
                        400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code"
                    )
                return
            if self.path == "/auth/logout":
                digest = hashlib.sha256(
                    str(body.get("refreshToken", "")).encode()
                ).hexdigest()

                def logout(document: dict[str, Any]) -> None:
                    if digest in document["activeHashes"]:
                        document["activeHashes"].remove(digest)
                        document["revokedHashes"].append(digest)

                runtime.state.mutate(logout)
                self.send_json(204, None)
                return
            if self.path == "/auth/refresh":
                refresh_token = str(body.get("refreshToken", ""))
                digest = hashlib.sha256(refresh_token.encode()).hexdigest()
                document = runtime.state.read()
                if (
                    not runtime.verify_refresh(refresh_token)
                    or digest not in document["activeHashes"]
                ):
                    self.error(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token")
                else:
                    self.send_json(200, runtime.pair())
                return
            self.error(404, "NOT_FOUND", "Not found")

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] in {
        "preflight",
        "setup",
        "snapshot",
        "expire",
        "teardown",
    }:
        return adapter_main()
    if len(sys.argv) < 2 or sys.argv[1] != "runtime":
        raise RuntimeError("expected adapter command or runtime mode")
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", required=True, choices=("express", "fastapi"))
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args(sys.argv[2:])
    return serve(args.role, args.port)


if __name__ == "__main__":
    raise SystemExit(main())
