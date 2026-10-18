from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import importlib.util
import json
import re
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Self, cast
from unittest import mock
from urllib import parse

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

RUNNER = Path(__file__).resolve().parents[1] / "bin" / "admin_flow.py"
SPEC = importlib.util.spec_from_file_location("contract_admin_flow", RUNNER)
assert SPEC is not None and SPEC.loader is not None
admin_flow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = admin_flow
SPEC.loader.exec_module(admin_flow)

DATABASE = "postgresql://contract:secret@127.0.0.1:55432/contract_admin"
REDIS = "redis://127.0.0.1:56379/9"
ISSUER = "https://auth.example.invalid"
AUDIENCE = "contract-audience"
PASSWORD = "ContractOnly!2026"
ADMIN_EMAIL = "contract-admin@example.invalid"
TARGET_EMAIL = "contract-active@example.invalid"
ADMIN_ROLE_ID = "00000000-0000-4000-8000-000000000101"
USER_ROLE_ID = "00000000-0000-4000-8000-000000000102"
TARGET_ADMIN_ROLE_ID = "00000000-0000-4000-8000-000000000103"
CREATED_AT = "2026-09-01T00:00:00.000Z"


def role(role_id: str, name: str) -> dict[str, str]:
    return {"id": role_id, "serviceKey": "temis", "name": name}


def segment(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        )
        .decode()
        .rstrip("=")
    )


class Backend:
    """Small state/ledger adapter double; the HTTP behavior stays independently exercised."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        numbers = self.private_key.public_key().public_numbers()
        self.jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "admin-contract-key",
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
        self.sequence = 0
        self.requests: list[tuple[str, str, str]] = []
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.users: dict[str, dict[str, Any]] = {
                admin_flow.ADMIN_USER_ID: {
                    "email": ADMIN_EMAIL,
                    "name": "Contract Admin",
                    "status": "active",
                    "roles": [role(ADMIN_ROLE_ID, "admin")],
                },
                admin_flow.TARGET_USER_ID: {
                    "email": TARGET_EMAIL,
                    "name": "Contract Active",
                    "status": "active",
                    "roles": [role(USER_ROLE_ID, "user")],
                },
            }
            self.tokens: dict[str, set[str]] = {
                admin_flow.ADMIN_USER_ID: set(),
                admin_flow.TARGET_USER_ID: set(),
            }
            self.audits: list[dict[str, Any]] = []

    def audit(
        self,
        event: str,
        actor: str,
        target: str | None,
        reason: str,
        details: dict[str, Any],
        *,
        outcome: str = "success",
    ) -> None:
        with self.lock:
            number = len(self.audits) + 1
            self.audits.append(
                {
                    "id": f"00000000-0000-4000-8000-{number:012d}",
                    "eventType": event,
                    "outcome": outcome,
                    "userId": actor if target is None else target,
                    "actorUserId": actor,
                    "targetUserId": target,
                    "reasonCode": reason,
                    "detailsJson": details,
                    "createdAt": f"2026-09-01T00:00:{number:02d}.000Z",
                }
            )

    def revoke(self, user_id: str) -> int:
        with self.lock:
            count = len(self.tokens[user_id])
            self.tokens[user_id].clear()
            return count


class HttpRuntime:
    def __init__(
        self,
        runtime: str,
        backend: Backend,
        secret: str,
        *,
        fault: str | None = None,
    ) -> None:
        self.runtime = runtime
        self.backend = backend
        self.secret = secret
        self.fault = fault
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "AdminContract/1"

            def body(self) -> dict[str, Any]:
                length = int(self.headers.get("content-length", "0"))
                if not length:
                    return {}
                value = json.loads(self.rfile.read(length))
                return cast(dict[str, Any], value)

            def send_json(self, status: int, body: Any) -> None:
                raw = json.dumps(body, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json; charset=utf-8")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def bearer_subject(self) -> str | None:
                authorization = self.headers.get("authorization", "")
                if not authorization.startswith("Bearer "):
                    return None
                token = authorization[7:]
                try:
                    head, claims, signature = token.split(".")
                    owner.backend.private_key.public_key().verify(
                        base64.urlsafe_b64decode(
                            signature + "=" * (-len(signature) % 4)
                        ),
                        f"{head}.{claims}".encode(),
                        padding.PKCS1v15(),
                        SHA256(),
                    )
                    payload = json.loads(
                        base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4))
                    )
                    if (
                        payload.get("iss") != ISSUER
                        or payload.get("aud") != AUDIENCE
                        or payload.get("type") != "access"
                        or payload.get("exp", 0) <= int(time.time())
                    ):
                        return ""
                    subject = payload.get("sub")
                    return subject if isinstance(subject, str) else ""
                except (ValueError, json.JSONDecodeError):
                    return ""

            def authorize_admin(self, path: str) -> str | None:
                subject = self.bearer_subject()
                if subject is None:
                    self.send_json(
                        401,
                        {
                            "error": {
                                "code": "UNAUTHORIZED",
                                "message": "Bearer access token is required",
                            }
                        },
                    )
                    return None
                user = owner.backend.users.get(subject)
                is_admin = bool(
                    user
                    and user["status"] == "active"
                    and role(ADMIN_ROLE_ID, "admin") in user["roles"]
                )
                if not is_admin:
                    if subject in owner.backend.users:
                        owner.backend.audit(
                            "admin_authorization_failure",
                            subject,
                            None,
                            "FORBIDDEN",
                            {"route": path, "method": self.command},
                            outcome="failure",
                        )
                    self.send_json(
                        403,
                        {
                            "error": {
                                "code": "FORBIDDEN",
                                "message": "Admin role is required",
                            }
                        },
                    )
                    return None
                return subject

            def issue_pair(self, user_id: str) -> dict[str, str]:
                with owner.backend.lock:
                    owner.backend.sequence += 1
                    sequence = owner.backend.sequence
                user = owner.backend.users[user_id]
                now = int(time.time())
                claims = {
                    "sub": user_id,
                    "email": user["email"],
                    "name": user["name"],
                    "email_verified": True,
                    "type": "access",
                    "roles": [
                        {"serviceKey": item["serviceKey"], "name": item["name"]}
                        for item in user["roles"]
                    ],
                    "iat": now,
                    "exp": now + 900,
                    "iss": ISSUER,
                    "aud": AUDIENCE,
                }
                if owner.fault == "bad-access-claim":
                    claims["aud"] = "wrong-audience"
                signing_input = f"{segment({'alg': 'RS256', 'typ': 'JWT', 'kid': 'admin-contract-key'})}.{segment(claims)}"
                signature = owner.backend.private_key.sign(
                    signing_input.encode(), padding.PKCS1v15(), SHA256()
                )
                encoded_signature = (
                    base64.urlsafe_b64encode(signature).decode().rstrip("=")
                )
                if owner.fault == "bad-access-signature":
                    encoded_signature = (
                        "A" if encoded_signature[0] != "A" else "B"
                    ) + encoded_signature[1:]
                access = f"{signing_input}.{encoded_signature}"
                refresh_input = f"{segment({'alg': 'HS256', 'typ': 'JWT'})}.{segment({'sub': user_id, 'type': 'refresh', 'tokenId': f'{owner.runtime}-{sequence}', 'audience': AUDIENCE, 'iat': now, 'exp': now + 3600})}"
                refresh_signature = (
                    base64.urlsafe_b64encode(
                        hmac.new(
                            owner.secret.encode(),
                            refresh_input.encode(),
                            hashlib.sha256,
                        ).digest()
                    )
                    .decode()
                    .rstrip("=")
                )
                refresh = f"{refresh_input}.{refresh_signature}"
                owner.backend.tokens[user_id].add(
                    hashlib.sha256(refresh.encode()).hexdigest()
                )
                return {"accessToken": access, "refreshToken": refresh}

            def do_GET(self) -> None:
                parsed = parse.urlparse(self.path)
                owner.backend.requests.append((owner.runtime, "GET", self.path))
                if parsed.path == "/.well-known/jwks.json":
                    self.send_json(200, {"keys": [owner.backend.jwk]})
                    return
                if parsed.path == "/users/me":
                    subject = self.bearer_subject()
                    user = owner.backend.users.get(subject or "")
                    if not user:
                        self.send_json(
                            401,
                            {
                                "error": {
                                    "code": "UNAUTHORIZED",
                                    "message": "Unauthorized",
                                }
                            },
                        )
                        return
                    self.send_json(
                        200,
                        {
                            "id": subject,
                            "email": user["email"],
                            "name": user["name"],
                            "email_verified": True,
                            "roles": [
                                {"serviceKey": item["serviceKey"], "name": item["name"]}
                                for item in user["roles"]
                            ],
                        },
                    )
                    return
                match = re.fullmatch(
                    r"/(?:admin|manage-api)/(users|audit-logs)", parsed.path
                )
                if match:
                    if owner.fault == "broken-manage-alias" and parsed.path.startswith(
                        "/manage-api"
                    ):
                        self.send_json(
                            404,
                            {"error": {"code": "NOT_FOUND", "message": "Not found"}},
                        )
                        return
                    if self.authorize_admin(parsed.path) is None:
                        return
                    if match.group(1) == "users":
                        target = owner.backend.users[admin_flow.TARGET_USER_ID]
                        items = [
                            {
                                "id": admin_flow.TARGET_USER_ID,
                                "email": target["email"],
                                "name": target["name"],
                                "status": target["status"].upper(),
                                "createdAt": CREATED_AT,
                                "roles": [dict(item) for item in target["roles"]],
                            }
                        ]
                        if owner.fault == "directory-role-id":
                            items[0]["roles"][0]["id"] = "wrong-directory-role-id"
                    else:
                        query = parse.parse_qs(parsed.query)
                        actor = query.get("actorUserId", [None])[0]
                        items = [
                            dict(item)
                            for item in owner.backend.audits
                            if item["actorUserId"] == actor
                        ]
                        if items and owner.fault == "api-wrong-user-id":
                            items[0]["userId"] = admin_flow.ADMIN_USER_ID
                        if items and owner.fault == "api-fabricated-time":
                            items[0]["createdAt"] = "tomorrow"
                        if len(items) > 1 and owner.fault == "api-duplicate-id":
                            items[1]["id"] = items[0]["id"]
                    page: dict[str, Any] = {
                        "items": items,
                        "total": len(items),
                        "page": 1,
                        "pageSize": 25,
                    }
                    if owner.fault == "bool-pagination":
                        page["page"] = True
                    self.send_json(200, page)
                    return
                self.send_json(
                    404, {"error": {"code": "NOT_FOUND", "message": "Not found"}}
                )

            def do_POST(self) -> None:
                self.mutate("POST")

            def do_PATCH(self) -> None:
                self.mutate("PATCH")

            def do_DELETE(self) -> None:
                self.mutate("DELETE")

            def mutate(self, method: str) -> None:
                parsed = parse.urlparse(self.path)
                body = self.body()
                owner.backend.requests.append((owner.runtime, method, self.path))
                if parsed.path == "/auth/login":
                    user_id = next(
                        (
                            key
                            for key, value in owner.backend.users.items()
                            if value["email"] == body.get("email")
                        ),
                        None,
                    )
                    user = owner.backend.users.get(user_id or "")
                    if (
                        not user
                        or body.get("password") != PASSWORD
                        or user["status"] != "active"
                    ):
                        self.send_json(
                            401,
                            {
                                "error": {
                                    "code": "INVALID_CREDENTIALS",
                                    "message": "Invalid email or password",
                                }
                            },
                        )
                    else:
                        self.send_json(200, self.issue_pair(cast(str, user_id)))
                    return
                if parsed.path == "/auth/refresh":
                    token = body.get("refreshToken")
                    digest = hashlib.sha256(str(token).encode()).hexdigest()
                    active = any(
                        digest in hashes for hashes in owner.backend.tokens.values()
                    )
                    if owner.fault == "bad-refresh-envelope" and not active:
                        self.send_json(
                            401,
                            {
                                "error": {
                                    "code": "INVALID_REFRESH_TOKEN",
                                    "message": "Wrong message",
                                }
                            },
                        )
                    elif (
                        owner.fault == "revoke-ledger-stale"
                        or not active
                        and owner.fault != "accept-revoked"
                    ):
                        self.send_json(
                            401,
                            {
                                "error": {
                                    "code": "INVALID_REFRESH_TOKEN",
                                    "message": "Invalid refresh token",
                                }
                            },
                        )
                    else:
                        self.send_json(
                            200, {"accessToken": "accepted", "refreshToken": "accepted"}
                        )
                    return
                actor = self.authorize_admin(parsed.path)
                if actor is None:
                    return
                status_match = re.fullmatch(
                    r"/(?:admin|manage-api)/users/([^/]+)/status", parsed.path
                )
                assign_match = re.fullmatch(
                    r"/(?:admin|manage-api)/users/([^/]+)/roles", parsed.path
                )
                remove_match = re.fullmatch(
                    r"/(?:admin|manage-api)/users/([^/]+)/roles/([^/]+)", parsed.path
                )
                revoke_match = re.fullmatch(
                    r"/(?:admin|manage-api)/users/([^/]+)/revoke-sessions", parsed.path
                )
                if status_match and method == "PATCH":
                    target_id = status_match.group(1)
                    if target_id == actor and body.get("status") in {
                        "SUSPENDED",
                        "DELETED",
                    }:
                        self.send_json(
                            403,
                            {
                                "error": {
                                    "code": "FORBIDDEN",
                                    "message": "Admins cannot suspend or delete their own account",
                                }
                            },
                        )
                        return
                    count = owner.backend.revoke(target_id)
                    if not (
                        owner.fault == "status-ledger-stale"
                        and body.get("status") == "SUSPENDED"
                    ):
                        owner.backend.users[target_id]["status"] = str(
                            body["status"]
                        ).lower()
                    owner.backend.audit(
                        "admin_user_status_changed",
                        actor,
                        target_id,
                        body["reasonCode"],
                        {"route": "PATCH /admin/users/:id/status"},
                    )
                    response: dict[str, Any] = {
                        "statusChanged": True,
                        "revokedRefreshTokenCount": (
                            99
                            if owner.fault == "suspend-count-99"
                            and body.get("status") == "SUSPENDED"
                            else count
                        ),
                    }
                    if owner.fault == "unexpected-field":
                        response["extra"] = 1
                    self.send_json(200, response)
                    return
                if assign_match and method == "POST":
                    target_id = assign_match.group(1)
                    owner.backend.users[target_id]["roles"].append(
                        role(TARGET_ADMIN_ROLE_ID, "admin")
                    )
                    owner.backend.audit(
                        "admin_user_role_assigned",
                        actor,
                        target_id,
                        body["reasonCode"],
                        {"route": "POST /admin/users/:id/roles"},
                    )
                    self.send_json(
                        200, {"roleAssigned": True, "roleId": TARGET_ADMIN_ROLE_ID}
                    )
                    return
                if remove_match and method == "DELETE":
                    target_id, role_id = remove_match.groups()
                    if target_id == actor and role_id == ADMIN_ROLE_ID:
                        self.send_json(
                            403,
                            {
                                "error": {
                                    "code": "FORBIDDEN",
                                    "message": "Admins cannot remove their own admin role",
                                }
                            },
                        )
                        return
                    owner.backend.users[target_id]["roles"] = [
                        item
                        for item in owner.backend.users[target_id]["roles"]
                        if item["id"] != role_id
                    ]
                    count = owner.backend.revoke(target_id)
                    owner.backend.audit(
                        "admin_user_role_removed",
                        actor,
                        target_id,
                        body["reasonCode"],
                        {
                            "roleId": role_id,
                            "route": "DELETE /admin/users/:id/roles/:roleId",
                        },
                    )
                    self.send_json(
                        200,
                        {
                            "roleRemoved": True,
                            "roleId": role_id,
                            "revokedRefreshTokenCount": (
                                99 if owner.fault == "remove-count-99" else count
                            ),
                        },
                    )
                    return
                if revoke_match and method == "POST":
                    target_id = revoke_match.group(1)
                    if target_id == actor:
                        self.send_json(
                            403,
                            {
                                "error": {
                                    "code": "FORBIDDEN",
                                    "message": "Admins cannot revoke their own sessions",
                                }
                            },
                        )
                        return
                    if owner.fault == "revoke-ledger-stale":
                        count = len(owner.backend.tokens[target_id])
                    else:
                        count = owner.backend.revoke(target_id)
                    owner.backend.audit(
                        "admin_user_sessions_revoked",
                        actor,
                        target_id,
                        body["reasonCode"],
                        {"route": "POST /admin/users/:id/revoke-sessions"},
                    )
                    self.send_json(
                        200,
                        {
                            "revokedCount": (
                                True
                                if owner.fault == "bool-count"
                                else 99
                                if owner.fault == "revoke-count-99"
                                else count
                            )
                        },
                    )
                    return
                self.send_json(
                    404, {"error": {"code": "NOT_FOUND", "message": "Not found"}}
                )

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = cast(tuple[str, int], self.server.server_address)
        return f"http://{host}:{port}"

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("admin HTTP listener did not terminate")


class StateAdapter:
    isolation_identity = (DATABASE, REDIS)

    def __init__(
        self, backend: Backend, refresh_secret: str, *, fault: str | None = None
    ) -> None:
        self.backend = backend
        self.refresh_secret = refresh_secret
        self.fault = fault
        self.calls: list[tuple[str, str]] = []

    def invoke(self, command: str, name: str) -> Any:
        self.calls.append((command, name))
        if command == "preflight":
            result = {
                "status": "ok",
                "database": "contract_admin",
                "redisDatabase": 9,
                "mailMode": "dev",
                "runtime": "fastapi",
                "schema": "prisma-compatible",
            }
            if self.fault == "preflight-bool":
                result["redisDatabase"] = True
            return result
        if command == "setup":
            self.backend.reset()
            return {
                "admin": {
                    "userId": admin_flow.ADMIN_USER_ID,
                    "email": ADMIN_EMAIL,
                    "password": PASSWORD,
                    "name": "Contract Admin",
                    "roles": [{"serviceKey": "temis", "name": "admin"}],
                    "audience": AUDIENCE,
                },
                "target": {
                    "userId": admin_flow.TARGET_USER_ID,
                    "email": TARGET_EMAIL,
                    "password": PASSWORD,
                    "name": "Contract Active",
                    "roles": [{"serviceKey": "temis", "name": "user"}],
                    "audience": AUDIENCE,
                },
                "adminRoleId": ADMIN_ROLE_ID,
            }
        if command == "control":
            if self.fault == "restore-error" and name == "restore-admin":
                raise RuntimeError("private restore detail")
            self.backend.users[admin_flow.ADMIN_USER_ID]["status"] = (
                "suspended" if name == "suspend-admin" else "active"
            )
            return {"status": "controlled"}
        if command == "snapshot" and name == admin_flow.STATE:
            return self.state()
        if command == "snapshot" and name == admin_flow.RESIDUAL:
            result = {
                "users": len(self.backend.users),
                "activeRefreshTokens": sum(map(len, self.backend.tokens.values())),
                "adminAudits": len(self.backend.audits),
            }
            if self.fault == "residual-bool" and not self.backend.users:
                result["users"] = False
            return result
        if command == "teardown":
            self.backend.users.clear()
            self.backend.tokens.clear()
            self.backend.audits.clear()
            return {"users": 0, "activeRefreshTokens": 0, "adminAud": 0}
        raise AssertionError((command, name))

    def state(self) -> dict[str, Any]:
        admin = self.backend.users[admin_flow.ADMIN_USER_ID]
        target = self.backend.users[admin_flow.TARGET_USER_ID]
        result = {
            "adminStatus": admin["status"],
            "adminRoles": [dict(item) for item in admin["roles"]],
            "targetStatus": target["status"],
            "targetRoles": [dict(item) for item in target["roles"]],
            "adminActiveTokenHashes": sorted(
                self.backend.tokens[admin_flow.ADMIN_USER_ID]
            ),
            "targetActiveTokenHashes": sorted(
                self.backend.tokens[admin_flow.TARGET_USER_ID]
            ),
            "audits": [dict(item) for item in self.backend.audits],
        }
        if self.fault == "audit-mismatch" and result["audits"]:
            result["audits"][0]["reasonCode"] = "WRONG"
        if self.fault == "audit-user-id-mismatch" and result["audits"]:
            result["audits"][0]["userId"] = admin_flow.ADMIN_USER_ID
        if self.fault == "role-id-mismatch" and any(
            item["name"] == "admin" for item in result["targetRoles"]
        ):
            result["targetRoles"] = [
                ({**item, "id": "wrong-role-id"} if item["name"] == "admin" else item)
                for item in result["targetRoles"]
            ]
        return result


class Adapter:
    isolation_identity = (DATABASE, REDIS)
    refresh_secret = "contract-refresh-secret"

    def __init__(self, *, runtime: str = "fastapi") -> None:
        self.runtime = runtime
        self.calls: list[tuple[str, str]] = []
        self.teardown_error: BaseException | None = None
        self.residual_error: BaseException | None = None

    def invoke(self, command: str, name: str) -> Any:
        self.calls.append((command, name))
        if command == "preflight":
            return {
                "status": "ok",
                "database": "contract_admin",
                "redisDatabase": 9,
                "mailMode": "dev",
                "runtime": "fastapi",
                "schema": "prisma-compatible",
            }
        if command == "setup":
            return {
                "admin": {
                    "userId": admin_flow.ADMIN_USER_ID,
                    "email": "contract-admin@example.invalid",
                    "password": "ContractOnly!2026",
                    "name": "Contract Admin",
                    "roles": [{"serviceKey": "temis", "name": "admin"}],
                    "audience": "contract-audience",
                },
                "target": {
                    "userId": admin_flow.TARGET_USER_ID,
                    "email": "contract-active@example.invalid",
                    "password": "ContractOnly!2026",
                    "name": "Contract Active",
                    "roles": [{"serviceKey": "temis", "name": "user"}],
                    "audience": "contract-audience",
                },
                "adminRoleId": "role-admin",
            }
        if command == "snapshot" and name == admin_flow.STATE:
            return {
                "adminStatus": "active",
                "adminRoles": [role("role-admin", "admin")],
                "targetStatus": "active",
                "targetRoles": [role("role-user", "user")],
                "adminActiveTokenHashes": [],
                "targetActiveTokenHashes": [],
                "audits": [],
            }
        if command == "teardown":
            if self.teardown_error is not None:
                raise self.teardown_error
            return {"status": "removed"}
        if command == "snapshot" and name == admin_flow.RESIDUAL:
            if self.residual_error is not None:
                raise self.residual_error
            return {"users": 0, "activeRefreshTokens": 0, "adminAudits": 0}
        raise AssertionError((command, name))


class Result:
    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self.body = body
        self.headers = {"content-type": "application/json; charset=utf-8"}


class AdminFlowTests(unittest.TestCase):
    def assert_http_fault(
        self,
        expected: str,
        *,
        server_fault: str | None = None,
        adapter_fault: str | None = None,
    ) -> None:
        backend = Backend()
        with HttpRuntime(
            "express", backend, "express-refresh-secret", fault=server_fault
        ) as server:
            adapter = StateAdapter(
                backend, "express-refresh-secret", fault=adapter_fault
            )
            with self.assertRaisesRegex(admin_flow.ContractFailure, expected):
                admin_flow.run_admin_flow(
                    "express",
                    {"express": server.url},
                    {"express": adapter},
                    expected_issuer=ISSUER,
                )

    def test_public_driver_runs_real_http_for_all_four_topologies(self) -> None:
        for topology in admin_flow.TOPOLOGIES:
            with self.subTest(topology=topology), contextlib.ExitStack() as stack:
                backend = Backend()
                runtimes = tuple(dict.fromkeys(admin_flow._runtime_order(topology)))
                servers = {
                    runtime: stack.enter_context(
                        HttpRuntime(runtime, backend, f"{runtime}-refresh-secret")
                    )
                    for runtime in runtimes
                }
                adapters = {
                    runtime: StateAdapter(backend, f"{runtime}-refresh-secret")
                    for runtime in runtimes
                }
                receipt = admin_flow.run_admin_flow(
                    topology,
                    {runtime: server.url for runtime, server in servers.items()},
                    adapters,
                    expected_issuer=ISSUER,
                )
                self.assertEqual(
                    receipt,
                    {
                        "flow": admin_flow.FLOW,
                        "topology": topology,
                        "passed": True,
                        "qualifying": False,
                        "assertions": {
                            name: True for name in sorted(admin_flow.ASSERTIONS)
                        },
                        "unverified": list(admin_flow.UNVERIFIED),
                    },
                )
                for runtime in runtimes:
                    runtime_paths = {
                        path
                        for seen_runtime, method, path in backend.requests
                        if seen_runtime == runtime and method == "GET"
                    }
                    self.assertTrue(
                        any(path.startswith("/admin/users?") for path in runtime_paths)
                    )
                    self.assertTrue(
                        any(
                            path.startswith("/manage-api/users?")
                            for path in runtime_paths
                        )
                    )
                self.assertEqual(backend.users, {})
                self.assertEqual(backend.tokens, {})
                self.assertEqual(backend.audits, [])

    def test_http_contract_rejects_independent_response_and_ledger_faults(self) -> None:
        cases = (
            ("admin-audit-state-mismatch", None, "audit-mismatch"),
            ("admin-audit-state-mismatch", None, "audit-user-id-mismatch"),
            ("admin-assigned-role-state-mismatch", None, "role-id-mismatch"),
            ("admin-directory-projection-mismatch", "directory-role-id", None),
            ("admin-directory-contract-mismatch", "bool-pagination", None),
            ("admin-session-revocation-mismatch", "bool-count", None),
            ("admin-role-removal-mismatch", "remove-count-99", None),
            ("admin-session-revocation-mismatch", "revoke-count-99", None),
            ("admin-status-suspension-mismatch", "suspend-count-99", None),
            ("admin-status-suspension-mismatch", "unexpected-field", None),
            ("revoked-refresh-accepted", "accept-revoked", None),
            ("revoked-refresh-accepted", "bad-refresh-envelope", None),
            ("admin-state-transition-mismatch", "revoke-ledger-stale", None),
            ("admin-state-transition-mismatch", "status-ledger-stale", None),
        )
        for expected, server_fault, adapter_fault in cases:
            with self.subTest(fault=server_fault or adapter_fault):
                self.assert_http_fault(
                    expected,
                    server_fault=server_fault,
                    adapter_fault=adapter_fault,
                )

    def test_audit_api_rejects_fabricated_identity_id_and_time(self) -> None:
        cases = (
            ("admin-audit-projection-mismatch", "api-wrong-user-id"),
            ("malformed-admin-audit", "api-fabricated-time"),
            ("duplicate-admin-audit-id", "api-duplicate-id"),
        )
        for expected, fault in cases:
            with self.subTest(fault=fault):
                self.assert_http_fault(expected, server_fault=fault)

    def test_real_jwt_claim_and_signature_failures_are_detected(self) -> None:
        for fault in ("bad-access-claim", "bad-access-signature"):
            with self.subTest(fault=fault):
                self.assert_http_fault(
                    "admin-token-verification-failure", server_fault=fault
                )

    def test_mixed_topology_probes_both_aliases_on_the_opposite_origin(self) -> None:
        backend = Backend()
        with (
            HttpRuntime(
                "express",
                backend,
                "express-refresh-secret",
                fault="broken-manage-alias",
            ) as express,
            HttpRuntime(
                "fastapi", backend, "fastapi-distinct-refresh-secret"
            ) as fastapi,
        ):
            adapters = {
                "express": StateAdapter(backend, "express-refresh-secret"),
                "fastapi": StateAdapter(backend, "fastapi-distinct-refresh-secret"),
            }
            with self.assertRaisesRegex(
                admin_flow.ContractFailure, "admin-directory-contract-mismatch"
            ):
                admin_flow.run_admin_flow(
                    "express-fastapi",
                    {"express": express.url, "fastapi": fastapi.url},
                    adapters,
                    expected_issuer=ISSUER,
                )

    def test_strict_preflight_and_residual_scalars_reject_booleans(self) -> None:
        backend = Backend()
        with HttpRuntime("express", backend, "express-refresh-secret") as server:
            adapter = StateAdapter(
                backend, "express-refresh-secret", fault="preflight-bool"
            )
            with self.assertRaisesRegex(
                admin_flow.ContractFailure, "preflight-mismatch"
            ):
                admin_flow.run_admin_flow(
                    "express",
                    {"express": server.url},
                    {"express": adapter},
                    expected_issuer=ISSUER,
                )
            self.assertEqual(backend.requests, [])
            self.assertNotIn(("setup", admin_flow.FIXTURE), adapter.calls)
        self.assert_http_fault(
            "residual-state-not-empty", adapter_fault="residual-bool"
        )

    def test_stale_probe_interrupt_remains_primary_when_restore_fails(self) -> None:
        backend = Backend()
        helpers = admin_flow._flow_helpers()
        real_call = helpers.call

        def interrupt_stale(
            base_url: str,
            method: str,
            path: str,
            body: dict[str, Any] | None,
            timeout: float,
            observations: list[Any] | None = None,
            headers: dict[str, str] | None = None,
        ) -> Any:
            if (
                method == "GET"
                and path == "/manage-api/users"
                and backend.users[admin_flow.ADMIN_USER_ID]["status"] == "suspended"
            ):
                raise KeyboardInterrupt("private primary detail")
            return real_call(
                base_url, method, path, body, timeout, observations, headers
            )

        helpers.call = interrupt_stale
        with HttpRuntime("express", backend, "express-refresh-secret") as server:
            adapter = StateAdapter(
                backend, "express-refresh-secret", fault="restore-error"
            )
            with (
                mock.patch.object(admin_flow, "_flow_helpers", return_value=helpers),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                admin_flow.run_admin_flow(
                    "express",
                    {"express": server.url},
                    {"express": adapter},
                    expected_issuer=ISSUER,
                )
        notes = getattr(raised.exception, "__notes__", [])
        self.assertIn("admin restore failed: RuntimeError", notes)
        self.assertNotIn("private restore detail", " ".join(notes))

    def test_all_single_and_mixed_topologies_are_bound_before_the_trial(self) -> None:
        cases = {
            "express": ({"express": "http://127.0.0.1:4400"}, ("express", "express")),
            "fastapi": ({"fastapi": "http://127.0.0.1:4401"}, ("fastapi", "fastapi")),
            "express-fastapi": (
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                ("express", "fastapi"),
            ),
            "fastapi-express": (
                {
                    "express": "http://127.0.0.1:4400",
                    "fastapi": "http://127.0.0.1:4401",
                },
                ("fastapi", "express"),
            ),
        }
        for topology, (urls, expected_order) in cases.items():
            with self.subTest(topology=topology):
                adapters = {runtime: Adapter(runtime=runtime) for runtime in urls}
                with mock.patch.object(admin_flow, "_run_flow") as trial:
                    result = admin_flow.run_admin_flow(
                        topology,
                        urls,
                        adapters,
                        expected_issuer="https://auth.example.invalid",
                    )
                self.assertEqual(
                    trial.call_args.args[:2],
                    tuple(urls[runtime] for runtime in expected_order),
                )
                self.assertEqual(
                    set(result),
                    {
                        "flow",
                        "topology",
                        "passed",
                        "qualifying",
                        "assertions",
                        "unverified",
                    },
                )
                self.assertEqual(result["flow"], admin_flow.FLOW)
                self.assertTrue(result["passed"])
                self.assertFalse(result["qualifying"])
                self.assertEqual(
                    result["assertions"],
                    {name: True for name in sorted(admin_flow.ASSERTIONS)},
                )
                self.assertEqual(result["unverified"], list(admin_flow.UNVERIFIED))
                for adapter in adapters.values():
                    self.assertEqual(
                        adapter.calls[0], ("preflight", admin_flow.FIXTURE)
                    )
                    self.assertIn(("snapshot", admin_flow.RESIDUAL), adapter.calls)

    def test_invalid_inputs_fail_before_any_adapter_invocation(self) -> None:
        cases = [
            (
                "unknown",
                {"express": "http://127.0.0.1:4400"},
                "https://issuer.invalid",
                5,
            ),
            (
                "express",
                {"express": "https://127.0.0.1:4400"},
                "https://issuer.invalid",
                5,
            ),
            (
                "express",
                {"express": "http://127.0.0.1:4400"},
                "http://issuer.invalid",
                5,
            ),
            (
                "express",
                {"express": "http://127.0.0.1:4400"},
                "https://issuer.invalid",
                float("nan"),
            ),
        ]
        for topology, urls, issuer, timeout in cases:
            with self.subTest(topology=topology, issuer=issuer, timeout=timeout):
                adapters = {runtime: Adapter() for runtime in urls}
                with self.assertRaises(admin_flow.ContractFailure):
                    admin_flow.run_admin_flow(
                        topology,
                        urls,
                        adapters,
                        expected_issuer=issuer,
                        timeout=timeout,
                    )
                self.assertTrue(
                    all(adapter.calls == [] for adapter in adapters.values())
                )

    def test_mixed_topology_rejects_same_origin_and_store_mismatch_before_preflight(
        self,
    ) -> None:
        express = Adapter()
        fastapi = Adapter()
        urls = {"express": "http://127.0.0.1:4400", "fastapi": "http://127.0.0.1:4400"}
        with self.assertRaisesRegex(admin_flow.ContractFailure, "distinct-origins"):
            admin_flow.run_admin_flow(
                "express-fastapi",
                urls,
                {"express": express, "fastapi": fastapi},
                expected_issuer="https://issuer.invalid",
            )
        fastapi.isolation_identity = (DATABASE, "redis://127.0.0.1:56379/8")
        urls["fastapi"] = "http://127.0.0.1:4401"
        with self.assertRaisesRegex(admin_flow.ContractFailure, "shared-isolation"):
            admin_flow.run_admin_flow(
                "express-fastapi",
                urls,
                {"express": express, "fastapi": fastapi},
                expected_issuer="https://issuer.invalid",
            )
        self.assertEqual(express.calls, [])
        self.assertEqual(fastapi.calls, [])

    def test_preflight_schema_is_validated_before_setup(self) -> None:
        adapter = Adapter()
        original = adapter.invoke

        def wrong(command: str, name: str) -> Any:
            result = original(command, name)
            if command == "preflight":
                result = dict(result)
                result["schema"] = "missing"
            return result

        adapter.invoke = wrong  # type: ignore[method-assign]
        with self.assertRaisesRegex(admin_flow.ContractFailure, "preflight-mismatch"):
            admin_flow.run_admin_flow(
                "express",
                {"express": "http://127.0.0.1:4400"},
                {"express": adapter},
                expected_issuer="https://issuer.invalid",
            )
        self.assertNotIn(("setup", admin_flow.FIXTURE), adapter.calls)

    def test_primary_interrupt_survives_cleanup_failures_with_sanitized_notes(
        self,
    ) -> None:
        adapter = Adapter()
        adapter.teardown_error = RuntimeError("private teardown detail")
        adapter.residual_error = RuntimeError("private residual detail")
        with (
            mock.patch.object(
                admin_flow,
                "_run_flow",
                side_effect=KeyboardInterrupt("private primary detail"),
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            admin_flow.run_admin_flow(
                "express",
                {"express": "http://127.0.0.1:4400"},
                {"express": adapter},
                expected_issuer="https://issuer.invalid",
            )
        notes = getattr(raised.exception, "__notes__", [])
        self.assertEqual(
            notes,
            [
                "admin flow cleanup failed: RuntimeError",
                "admin flow cleanup failed: RuntimeError",
            ],
        )
        self.assertNotIn("private", " ".join(notes))

    def test_cleanup_failure_is_not_converted_to_a_passing_receipt(self) -> None:
        adapter = Adapter()
        adapter.residual_error = RuntimeError("private")
        with (
            mock.patch.object(admin_flow, "_run_flow"),
            self.assertRaisesRegex(RuntimeError, "private"),
        ):
            admin_flow.run_admin_flow(
                "fastapi",
                {"fastapi": "http://127.0.0.1:4401"},
                {"fastapi": adapter},
                expected_issuer="https://issuer.invalid",
            )

    def test_mutation_counts_require_exact_integer_one(self) -> None:
        self.assertTrue(admin_flow._strict_equal(1, 1))
        for value in (True, 0, 2, 1.0):
            with self.subTest(value=value):
                self.assertFalse(admin_flow._strict_equal(value, 1))
        with self.assertRaises(admin_flow.ContractFailure):
            admin_flow._expect_status(
                Result(200, {"statusChanged": 1}),
                200,
                {"statusChanged": True},
                "strict-body",
            )

    def test_expected_audit_content_is_independent_of_count(self) -> None:
        expected = admin_flow._audit(
            "admin_user_sessions_revoked",
            admin_flow.ADMIN_USER_ID,
            admin_flow.TARGET_USER_ID,
            "CONTRACT_SESSION_REVOKE",
            {"route": "POST /admin/users/:id/revoke-sessions"},
        )
        observed = {
            "id": "00000000-0000-4000-8000-000000000099",
            **expected,
            "createdAt": "2026-09-01T00:00:01.000Z",
        }
        admin_flow._expect_audits(
            {"audits": admin_flow._audits([observed])}, [expected]
        )
        wrong = dict(observed, reasonCode="WRONG")
        with self.assertRaisesRegex(admin_flow.ContractFailure, "audit-state-mismatch"):
            admin_flow._expect_audits(
                {"audits": admin_flow._audits([wrong])}, [expected]
            )


if __name__ == "__main__":
    unittest.main()
