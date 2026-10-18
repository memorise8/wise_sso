#!/usr/bin/env python3
"""Isolated Express fixture adapter using HTTP, psql, and stdlib RESP."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib import error, parse, request

PASSWORD = "ContractOnly!2026"
PASSWORD_HASH = "$argon2id$v=19$m=19456,t=2,p=1$Y29udHJhY3QtZml4dHVyZQ$qBKSeab/Q2pFMu2TocZA6c1w/qtUDTgvDmzv1tsEgqI"
ACTIVE_USER_ID = "00000000-0000-4000-8000-000000000001"
PENDING_USER_ID = "00000000-0000-4000-8000-000000000002"
ADMIN_USER_ID = "00000000-0000-4000-8000-000000000003"
TARGET_USER_ID = "00000000-0000-4000-8000-000000000004"
FIXTURE_IDS = (ACTIVE_USER_ID, PENDING_USER_ID, ADMIN_USER_ID, TARGET_USER_ID)
EMAIL_LOCAL_PARTS = {
    ACTIVE_USER_ID: "contract-active",
    PENDING_USER_ID: "contract-pending",
    ADMIN_USER_ID: "contract-admin",
    TARGET_USER_ID: "contract-target",
}
SAFE_DB_NAME = re.compile(r"(?:^|[_-])(test|contract|fixture)(?:$|[_-])", re.IGNORECASE)
SAFE_REDIS_KEY_PREFIXES = (
    "wiseacct:auth-handoff:",
    "wiseacct:oauth-state:",
    "wiseacct:rate-limit:",
)
FIXTURE_ANONYMOUS_AUDIT_PREDICATE = r""""userId" IS NULL
  AND "actorUserId" IS NULL
  AND "targetUserId" IS NULL
  AND (
    ("eventType" = 'rate_limit_exceeded' AND "reasonCode" = 'RATE_LIMITED'
      AND "detailsJson"->>'route' = '/auth/login' AND "detailsJson"->>'method' = 'POST')
    OR ("eventType" = 'auth_handoff_exchange_failure' AND "reasonCode" = 'INVALID_AUTH_HANDOFF_CODE'
      AND "detailsJson"->>'route' = '/auth/exchange')
    OR ("eventType" = 'refresh' AND "reasonCode" = 'REFRESH_FAILED')
    OR ("eventType" = 'logout' AND "outcome" = 'success'
      AND "reasonCode" IS NULL AND "detailsJson" IS NULL)
  )"""


class AdapterError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    base_url: str
    database_url: str
    redis_url: str
    email_domain: str
    audience: str
    client_id: str
    redirect_uri: str
    refresh_secret: str = field(repr=False)


def _local_url(value: str, schemes: set[str], label: str) -> parse.ParseResult:
    parsed = parse.urlparse(value)
    if parsed.scheme not in schemes or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise AdapterError(f"{label} must use an allowed scheme and a loopback host")
    return parsed


def load_config() -> Config:
    if os.environ.get("CONTRACT_FIXTURE_MODE") != "1":
        raise AdapterError("CONTRACT_FIXTURE_MODE=1 is required")
    mail_mode = os.environ.get("CONTRACT_SERVER_MAIL_MODE")
    if mail_mode == "private-loopback-smtp":
        _validate_private_mail_session()
    elif mail_mode != "dev":
        raise AdapterError(
            "mail isolation mode must be dev or a launcher-bound private-loopback-smtp session"
        )
    if os.environ.get("CONTRACT_REDIS_ISOLATED_DB") != "1":
        raise AdapterError("CONTRACT_REDIS_ISOLATED_DB=1 is required")
    required = {
        name: os.environ.get(name, "").strip()
        for name in (
            "CONTRACT_BASE_URL",
            "CONTRACT_DATABASE_URL",
            "CONTRACT_REDIS_URL",
            "CONTRACT_REFRESH_SECRET",
        )
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise AdapterError(f"missing environment variables: {', '.join(missing)}")
    _local_url(required["CONTRACT_BASE_URL"], {"http", "https"}, "CONTRACT_BASE_URL")
    database = _local_url(
        required["CONTRACT_DATABASE_URL"],
        {"postgres", "postgresql"},
        "CONTRACT_DATABASE_URL",
    )
    redis = _local_url(required["CONTRACT_REDIS_URL"], {"redis"}, "CONTRACT_REDIS_URL")
    database_name = database.path.lstrip("/")
    if not database_name or not SAFE_DB_NAME.search(database_name):
        raise AdapterError(
            "database name must contain a test, contract, or fixture boundary segment"
        )
    if database_name == "auth_db":
        raise AdapterError("the production-shaped auth_db database name is forbidden")
    try:
        redis_db = int(redis.path.lstrip("/") or "0")
    except ValueError as exc:
        raise AdapterError(
            "CONTRACT_REDIS_URL must contain a numeric database"
        ) from exc
    if redis_db < 1:
        raise AdapterError(
            "Redis database 0 is forbidden; use an isolated database >= 1"
        )
    refresh_secret = required["CONTRACT_REFRESH_SECRET"]
    unsafe_secrets = {
        "test-refresh-secret-long",
        "synthetic-contract-only-key",
        PASSWORD,
    }
    unsafe_markers = ("replace", "changeme", "placeholder", "example")
    if (
        len(refresh_secret) < 16
        or len(set(refresh_secret)) < 8
        or refresh_secret in unsafe_secrets
        or any(marker in refresh_secret.lower() for marker in unsafe_markers)
    ):
        raise AdapterError(
            "CONTRACT_REFRESH_SECRET must be at least 16 characters and not a known placeholder"
        )
    email_domain = (
        os.environ.get("CONTRACT_FIXTURE_EMAIL_DOMAIN", "example.invalid")
        .strip()
        .lower()
    )
    if not re.fullmatch(r"[a-z0-9.-]+", email_domain):
        raise AdapterError("CONTRACT_FIXTURE_EMAIL_DOMAIN is invalid")
    audience = os.environ.get("CONTRACT_FIXTURE_AUDIENCE", "contract-fixture")
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", audience):
        raise AdapterError("CONTRACT_FIXTURE_AUDIENCE is invalid")
    return Config(
        base_url=required["CONTRACT_BASE_URL"].rstrip("/"),
        database_url=required["CONTRACT_DATABASE_URL"],
        redis_url=required["CONTRACT_REDIS_URL"],
        email_domain=email_domain,
        audience=audience,
        client_id=os.environ.get("CONTRACT_FIXTURE_CLIENT_ID", "contract-fixture"),
        redirect_uri=os.environ.get(
            "CONTRACT_FIXTURE_REDIRECT_URI", "http://127.0.0.1:4101/auth/callback"
        ),
        refresh_secret=refresh_secret,
    )


def _validate_private_mail_session() -> None:
    session_value = os.environ.get("CONTRACT_PRIVATE_MAIL_SESSION_FILE", "")
    capability = os.environ.get("CONTRACT_PRIVATE_MAIL_SESSION_CAPABILITY", "")
    if not session_value or not capability:
        raise AdapterError("private mail mode requires a launcher-issued session")
    try:
        document = json.loads(_secure_read(Path(session_value), "private mail session"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError("private mail session could not be read") from exc
    required = {
        "version": 1,
        "launcherPid": os.getppid(),
        "smtpHost": "127.0.0.1",
        "smtpPort": os.environ.get("SMTP_PORT"),
        "caSha256": os.environ.get("CONTRACT_PRIVATE_MAIL_CA_SHA256"),
        "capability": capability,
    }
    if any(document.get(key) != value for key, value in required.items()):
        raise AdapterError("private mail session does not match its launcher binding")
    ca_path = Path(os.environ.get("SSL_CERT_FILE", ""))
    try:
        ca_digest = hashlib.sha256(_secure_read(ca_path, "private mail CA")).hexdigest()
    except OSError as exc:
        raise AdapterError("private mail CA could not be read") from exc
    if (
        os.environ.get("SMTP_HOST") != "127.0.0.1"
        or ca_digest != document.get("caSha256")
        or os.environ.get("NODE_EXTRA_CA_CERTS") != str(ca_path)
    ):
        raise AdapterError(
            "private mail transport does not match its owned loopback session"
        )


def _secure_read(path: Path, label: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise AdapterError(f"{label} secure open is unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise AdapterError(f"{label} must be a mode-0600 regular file")
        data = bytearray()
        while True:
            chunk = os.read(descriptor, min(65536, 1_048_577 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 1_048_576:
                raise AdapterError(f"{label} exceeds the bounded read limit")
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mode)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
        if before_identity != after_identity or len(data) != before.st_size:
            raise AdapterError(f"{label} changed while being read")
        return bytes(data)
    finally:
        os.close(descriptor)


def preflight(config: Config) -> dict[str, Any]:
    missing = [tool for tool in ("psql",) if not shutil.which(tool)]
    if missing:
        raise AdapterError(f"required CLI tools are missing: {', '.join(missing)}")
    _local_url(config.redirect_uri, {"http", "https"}, "CONTRACT_FIXTURE_REDIRECT_URI")
    RedisRespClient.from_url(config.redis_url).ping()
    expected_database = parse.urlparse(config.database_url).path.lstrip("/")
    actual_database = psql(config, "SELECT current_database();")
    if actual_database != expected_database:
        raise AdapterError(
            f"PostgreSQL connected to unexpected database {actual_database!r}"
        )
    return {
        "status": "ok",
        "database": actual_database,
        "redisDatabase": int(parse.urlparse(config.redis_url).path.lstrip("/")),
        "mailMode": os.environ["CONTRACT_SERVER_MAIL_MODE"],
    }


def emails(config: Config) -> dict[str, str]:
    return {
        user_id: f"{local}@{config.email_domain}"
        for user_id, local in EMAIL_LOCAL_PARTS.items()
    }


def _psql_environment(parsed: parse.ParseResult) -> dict[str, str]:
    env = {**os.environ}
    if parsed.password:
        env["PGPASSWORD"] = parse.unquote(parsed.password)
    return env


def psql(config: Config, sql: str) -> str:
    parsed = parse.urlparse(config.database_url)
    command = [
        "psql",
        "-X",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        parsed.hostname or "127.0.0.1",
        "-p",
        str(parsed.port or 5432),
        "-U",
        parse.unquote(parsed.username or "postgres"),
        "-d",
        parsed.path.lstrip("/"),
        "-c",
        sql,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=_psql_environment(parsed),
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise AdapterError(f"psql failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


class RedisRespClient:
    """Small dependency-free RESP2 client scoped to the fixture adapter."""

    def __init__(
        self,
        host: str,
        port: int,
        database: int,
        username: str | None,
        password: str | None,
    ):
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password

    @classmethod
    def from_url(cls, value: str) -> RedisRespClient:
        parsed = _local_url(value, {"redis"}, "CONTRACT_REDIS_URL")
        return cls(
            parsed.hostname or "127.0.0.1",
            parsed.port or 6379,
            int(parsed.path.lstrip("/") or "0"),
            parse.unquote(parsed.username) if parsed.username else None,
            parse.unquote(parsed.password) if parsed.password else None,
        )

    @staticmethod
    def _encode(parts: tuple[Any, ...]) -> bytes:
        encoded = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            value = str(part).encode("utf-8") if not isinstance(part, bytes) else part
            encoded.extend((f"${len(value)}\r\n".encode(), value, b"\r\n"))
        return b"".join(encoded)

    @classmethod
    def _read(cls, stream: Any) -> Any:
        marker = stream.read(1)
        if not marker:
            raise AdapterError("Redis closed the connection")
        line = stream.readline()
        if not line.endswith(b"\r\n"):
            raise AdapterError("Redis returned a malformed RESP line")
        payload = line[:-2]
        if marker == b"+":
            return payload.decode("utf-8")
        if marker == b"-":
            raise AdapterError(
                f"Redis error: {payload.decode('utf-8', errors='replace')}"
            )
        if marker == b":":
            return int(payload)
        if marker == b"$":
            length = int(payload)
            if length == -1:
                return None
            value = stream.read(length)
            if stream.read(2) != b"\r\n":
                raise AdapterError("Redis returned a malformed bulk string")
            return value
        if marker == b"*":
            length = int(payload)
            if length == -1:
                return None
            return [cls._read(stream) for _ in range(length)]
        raise AdapterError(f"Redis returned an unsupported RESP marker {marker!r}")

    def _send(self, stream: Any, *parts: Any) -> Any:
        stream.write(self._encode(parts))
        stream.flush()
        return self._read(stream)

    def command(self, *parts: Any) -> Any:
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=5
            ) as connection:
                connection.settimeout(5)
                with connection.makefile("rwb") as stream:
                    if self.password:
                        auth = (
                            ("AUTH", self.username, self.password)
                            if self.username
                            else ("AUTH", self.password)
                        )
                        if self._send(stream, *auth) != "OK":
                            raise AdapterError("Redis AUTH did not return OK")
                    if self._send(stream, "SELECT", self.database) != "OK":
                        raise AdapterError("Redis SELECT did not return OK")
                    return self._send(stream, *parts)
        except (OSError, ValueError) as exc:
            raise AdapterError(f"Redis connection failed: {exc}") from exc

    def ping(self) -> None:
        if self.command("PING") != "PONG":
            raise AdapterError("Redis PING did not return PONG")

    def get(self, key: str) -> bytes | None:
        result = self.command("GET", key)
        if result is not None and not isinstance(result, bytes):
            raise AdapterError("Redis GET returned an unexpected response")
        return result

    def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None:
        parts: tuple[Any, ...] = (
            ("SET", key, value)
            if ttl_seconds is None
            else ("SET", key, value, "EX", ttl_seconds)
        )
        if self.command(*parts) != "OK":
            raise AdapterError("Redis SET did not return OK")

    def ttl(self, key: str) -> int:
        result = self.command("TTL", key)
        if not isinstance(result, int):
            raise AdapterError("Redis TTL returned an unexpected response")
        return result

    def delete(self, keys: list[str]) -> int:
        if not keys:
            return 0
        result = self.command("DEL", *keys)
        if not isinstance(result, int):
            raise AdapterError("Redis DEL returned an unexpected response")
        return result

    def scan(self, pattern: str) -> list[str]:
        cursor = "0"
        keys: list[str] = []
        while True:
            result = self.command("SCAN", cursor, "MATCH", pattern, "COUNT", 100)
            if (
                not isinstance(result, list)
                or len(result) != 2
                or not isinstance(result[0], bytes)
                or not isinstance(result[1], list)
            ):
                raise AdapterError("Redis SCAN returned an unexpected response")
            cursor = result[0].decode("ascii")
            for key in result[1]:
                if not isinstance(key, bytes):
                    raise AdapterError("Redis SCAN returned a non-bulk key")
                keys.append(key.decode("utf-8"))
            if cursor == "0":
                return keys


def reset(config: Config) -> None:
    ids = ", ".join(f"'{item}'" for item in FIXTURE_IDS)
    fixture_emails = ", ".join(f"'{item}'" for item in emails(config).values())
    psql(
        config,
        f"""BEGIN;
DELETE FROM "AuditLog" WHERE "userId" IN ({ids}) OR "actorUserId" IN ({ids}) OR "targetUserId" IN ({ids}) OR "reasonCode" = 'CONTRACT_FIXTURE';
DELETE FROM "AuditLog"
WHERE {FIXTURE_ANONYMOUS_AUDIT_PREDICATE};
DELETE FROM "User" WHERE "id" IN ({ids}) OR "email" IN ({fixture_emails});
COMMIT;""",
    )
    redis_client = RedisRespClient.from_url(config.redis_url)
    for prefix in SAFE_REDIS_KEY_PREFIXES:
        keys = redis_client.scan(f"{prefix}*")
        for start in range(0, len(keys), 100):
            redis_client.delete(keys[start : start + 100])


def seed(config: Config) -> None:
    fixture_emails = emails(config)
    users = [
        (
            ACTIVE_USER_ID,
            fixture_emails[ACTIVE_USER_ID],
            True,
            "Contract Active",
            "ACTIVE",
        ),
        (
            PENDING_USER_ID,
            fixture_emails[PENDING_USER_ID],
            False,
            "Contract Pending",
            "PENDING_EMAIL_VERIFICATION",
        ),
        (
            ADMIN_USER_ID,
            fixture_emails[ADMIN_USER_ID],
            True,
            "Contract Admin",
            "ACTIVE",
        ),
        (
            TARGET_USER_ID,
            fixture_emails[TARGET_USER_ID],
            True,
            "Contract Target",
            "ACTIVE",
        ),
    ]
    user_values = ",\n".join(
        f"('{user_id}', '{email}', {str(verified).lower()}, '{name}', '{status}'::\"UserStatus\", CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        for user_id, email, verified, name, status in users
    )
    credential_users = (ACTIVE_USER_ID, PENDING_USER_ID, ADMIN_USER_ID)
    credential_values = ",\n".join(
        f"('10000000-0000-4000-8000-00000000000{index}', '{user_id}', '{fixture_emails[user_id]}', '{PASSWORD_HASH}', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        for index, user_id in enumerate(credential_users, start=1)
    )
    psql(
        config,
        f"""BEGIN;
INSERT INTO "User" ("id", "email", "emailVerified", "name", "status", "createdAt", "updatedAt") VALUES
{user_values};
INSERT INTO "PasswordCredential" ("id", "userId", "email", "passwordHash", "failedLoginCount", "passwordUpdatedAt", "createdAt", "updatedAt") VALUES
{credential_values};
INSERT INTO "Role" ("id", "serviceKey", "name") VALUES ('20000000-0000-4000-8000-000000000001', 'temis', 'admin')
ON CONFLICT ("serviceKey", "name") DO NOTHING;
INSERT INTO "Role" ("id", "serviceKey", "name") VALUES ('20000000-0000-4000-8000-000000000002', 'temis', 'user')
ON CONFLICT ("serviceKey", "name") DO NOTHING;
INSERT INTO "UserRole" ("id", "userId", "roleId")
SELECT '30000000-0000-4000-8000-000000000001', '{ADMIN_USER_ID}', "id" FROM "Role" WHERE "serviceKey" = 'temis' AND "name" = 'admin';
INSERT INTO "UserRole" ("id", "userId", "roleId")
SELECT '30000000-0000-4000-8000-000000000002', '{ACTIVE_USER_ID}', "id" FROM "Role" WHERE "serviceKey" = 'temis' AND "name" = 'user';
INSERT INTO "PendingPasswordCredential" ("id", "userId", "email", "passwordHash", "expiresAt", "createdAt", "updatedAt")
VALUES ('50000000-0000-4000-8000-000000000001', '{TARGET_USER_ID}', '{fixture_emails[TARGET_USER_ID]}', '{PASSWORD_HASH}', CURRENT_TIMESTAMP + INTERVAL '1 hour', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
COMMIT;""",
    )


def http_json(
    config: Config, method: str, path: str, body: dict[str, Any]
) -> tuple[int, Any]:
    req = request.Request(
        f"{config.base_url}{path}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
        method=method,
    )
    try:
        response = request.urlopen(req, timeout=10)
    except error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read()
        return response.status, json.loads(raw) if raw else None


def _segment(value: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )


def refresh_fixture_token(config: Config, algorithm: str) -> str:
    if algorithm not in {"none", "HS256", "HS384", "HS512"}:
        raise AdapterError(f"unsupported refresh fixture algorithm {algorithm!r}")
    header = _segment({"alg": algorithm, "typ": "JWT"})
    issued_at = int(time.time())
    token_id = hashlib.sha256(
        f"contract-{algorithm.lower()}-token-id".encode()
    ).hexdigest()
    claims = _segment(
        {
            "sub": ACTIVE_USER_ID,
            "type": "refresh",
            "tokenId": token_id,
            "audience": config.audience,
            "iat": issued_at,
            "exp": issued_at + 3600,
        }
    )
    if algorithm == "none":
        signature = ""
    else:
        digest = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[algorithm]
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    config.refresh_secret.encode(),
                    f"{header}.{claims}".encode(),
                    digest,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
    return f"{header}.{claims}.{signature}"


def seed_refresh_token(config: Config, token: str, algorithm: str) -> None:
    ids = {
        "none": "40000000-0000-4000-8000-000000000001",
        "HS256": "40000000-0000-4000-8000-000000000002",
        "HS384": "40000000-0000-4000-8000-000000000003",
        "HS512": "40000000-0000-4000-8000-000000000004",
    }
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    psql(
        config,
        f"""INSERT INTO "RefreshToken" ("id", "tokenHash", "userId", "audience", "expiresAt", "revokedAt", "createdAt")
VALUES ('{ids[algorithm]}', '{token_hash}', '{ACTIVE_USER_ID}', '{config.audience}', CURRENT_TIMESTAMP + INTERVAL '1 hour', NULL, CURRENT_TIMESTAMP);""",
    )


def setup(config: Config, fixture: str) -> dict[str, Any]:
    reset(config)
    seed(config)
    fixture_emails = emails(config)
    common = {"audience": config.audience}
    refresh_fixtures = {
        "active-user-refresh-none": "none",
        "active-user-refresh-hs256": "HS256",
        "active-user-refresh-hs384": "HS384",
        "active-user-refresh-hs512": "HS512",
    }
    if fixture in refresh_fixtures:
        algorithm = refresh_fixtures[fixture]
        token = refresh_fixture_token(config, algorithm)
        seed_refresh_token(config, token, algorithm)
        return {
            **common,
            "refreshToken": token,
            "algorithm": algorithm,
            "userId": ACTIVE_USER_ID,
            "email": fixture_emails[ACTIVE_USER_ID],
            "name": "Contract Active",
            "roles": [{"serviceKey": "temis", "name": "user"}],
        }
    if fixture == "active-password-user":
        verifier = "contract-pkce-verifier-AAAAAAAAAAAAAAAAAAAA"
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        return {
            **common,
            "userId": ACTIVE_USER_ID,
            "email": fixture_emails[ACTIVE_USER_ID],
            "password": PASSWORD,
            "name": "Contract Active",
            "roles": [{"serviceKey": "temis", "name": "user"}],
            "clientId": config.client_id,
            "redirectUri": config.redirect_uri,
            "state": "contract-caller-state",
            "codeChallenge": challenge,
            "codeVerifier": verifier,
        }
    if fixture == "pending-email-user":
        verifier = "contract-pkce-verifier-AAAAAAAAAAAAAAAAAAAA"
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .decode()
            .rstrip("=")
        )
        return {
            **common,
            "userId": PENDING_USER_ID,
            "email": fixture_emails[PENDING_USER_ID],
            "name": "Contract Pending",
            "roles": [{"serviceKey": "temis", "name": "user"}],
            "clientId": config.client_id,
            "redirectUri": config.redirect_uri,
            "state": "contract-verification-state",
            "codeChallenge": challenge,
            "codeVerifier": verifier,
            "attachUserId": TARGET_USER_ID,
            "attachEmail": fixture_emails[TARGET_USER_ID],
        }
    if fixture == "admin-and-active-target":
        status, tokens = http_json(
            config,
            "POST",
            "/auth/login",
            {
                "email": fixture_emails[ADMIN_USER_ID],
                "password": PASSWORD,
            },
        )
        if (
            status != 200
            or not isinstance(tokens, dict)
            or not isinstance(tokens.get("accessToken"), str)
        ):
            raise AdapterError(f"admin fixture login failed with HTTP {status}")
        return {
            **common,
            "authorization": f"Bearer {tokens['accessToken']}",
            "targetStatusPath": f"/admin/users/{TARGET_USER_ID}/status",
        }
    raise AdapterError(f"unsupported fixture {fixture!r}")


def expire(config: Config, fixture: str) -> dict[str, Any]:
    targets = {
        "latest-email-verification": ("EmailVerificationToken", PENDING_USER_ID),
        "latest-password-reset": ("PasswordResetToken", ACTIVE_USER_ID),
    }
    if fixture not in targets:
        raise AdapterError(f"unsupported expiration fixture {fixture!r}")
    table, user_id = targets[fixture]
    updated = count(
        config,
        f'''WITH target AS (
  SELECT "id" FROM "{table}" WHERE "userId" = '{user_id}' AND "usedAt" IS NULL
  ORDER BY "createdAt" DESC LIMIT 1
), updated AS (
UPDATE "{table}" SET "expiresAt" = CURRENT_TIMESTAMP - INTERVAL '1 second'
WHERE "id" IN (SELECT "id" FROM target) RETURNING 1
)
SELECT COUNT(*) FROM updated;''',
    )
    if updated != 1:
        raise AdapterError("expiration fixture did not update exactly one token")
    return {"status": "expired"}


def count(config: Config, sql: str) -> int:
    value = psql(config, sql)
    try:
        return int(value)
    except ValueError as exc:
        raise AdapterError(f"expected numeric psql result, got {value!r}") from exc


def redis_key_count(config: Config, prefix: str) -> int:
    return len(RedisRespClient.from_url(config.redis_url).scan(f"{prefix}*"))


def snapshot(config: Config, probe: str) -> Any:
    if probe == "refresh-ledger":
        active = count(
            config,
            f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL;""",
        )
        revoked = count(
            config,
            f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NOT NULL;""",
        )
        active_hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        revoked_hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NOT NULL ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {
            "activeRefreshTokens": active,
            "revokedRefreshTokens": revoked,
            "activeTokenHashes": active_hashes,
            "revokedTokenHashes": revoked_hashes,
        }
    if probe == "auth-lifecycle":
        active = count(
            config,
            f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL;""",
        )
        active_hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {
            "activeRefreshTokens": active,
            "authHandoffKeys": redis_key_count(config, "wiseacct:auth-handoff:"),
            "activeTokenHashes": active_hashes,
        }
    if probe == "pending-email-auth-lifecycle":
        active = count(
            config,
            f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{PENDING_USER_ID}' AND "revokedAt" IS NULL;""",
        )
        active_hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "RefreshToken" WHERE "userId" = '{PENDING_USER_ID}' AND "revokedAt" IS NULL ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {
            "activeRefreshTokens": active,
            "authHandoffKeys": redis_key_count(config, "wiseacct:auth-handoff:"),
            "activeTokenHashes": active_hashes,
        }
    if probe == "password-reset-ledger":
        unused = count(
            config,
            f"""SELECT COUNT(*) FROM "PasswordResetToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;""",
        )
        hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "PasswordResetToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {"unusedTokens": unused, "digests": hashes}
    if probe == "email-verification-ledger":
        unused = count(
            config,
            f"""SELECT COUNT(*) FROM "EmailVerificationToken" WHERE "userId" = '{PENDING_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;""",
        )
        hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "EmailVerificationToken" WHERE "userId" = '{PENDING_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {"unusedTokens": unused, "digests": hashes}
    if probe == "attach-email-verification-ledger":
        unused = count(
            config,
            f"""SELECT COUNT(*) FROM "EmailVerificationToken" WHERE "userId" = '{TARGET_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;""",
        )
        hashes = [
            item
            for item in psql(
                config,
                f"""SELECT "tokenHash" FROM "EmailVerificationToken" WHERE "userId" = '{TARGET_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP ORDER BY "tokenHash";""",
            ).splitlines()
            if item
        ]
        return {"unusedTokens": unused, "digests": hashes}
    if probe == "email-verification-result":
        user_row = psql(
            config,
            f"""SELECT "id"::text || '|' || "email" || '|' || "status"::text || '|' || "emailVerified"::text
FROM "User" WHERE "id" = '{PENDING_USER_ID}';""",
        ).split("|")
        if len(user_row) != 4 or user_row[3] not in {"true", "false"}:
            raise AdapterError(
                "email verification result returned an unexpected user row"
            )
        return {
            "userId": user_row[0],
            "email": user_row[1],
            "status": user_row[2],
            "emailVerified": user_row[3] == "true",
            "unusedTokens": count(
                config,
                f"""SELECT COUNT(*) FROM "EmailVerificationToken" WHERE "userId" = '{PENDING_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;""",
            ),
            "usedTokens": count(
                config,
                f"""SELECT COUNT(*) FROM "EmailVerificationToken" WHERE "userId" = '{PENDING_USER_ID}' AND "usedAt" IS NOT NULL;""",
            ),
            "passwordCredentials": count(
                config,
                f"""SELECT COUNT(*) FROM "PasswordCredential" WHERE "userId" = '{PENDING_USER_ID}';""",
            ),
            "duplicateUsers": count(
                config,
                f"""SELECT COUNT(*) FROM "User" WHERE lower("email") = lower('{emails(config)[PENDING_USER_ID]}');""",
            ),
            "defaultRoles": count(
                config,
                f"""SELECT COUNT(*) FROM "UserRole" ur JOIN "Role" r ON r."id" = ur."roleId"
WHERE ur."userId" = '{PENDING_USER_ID}' AND r."serviceKey" = 'temis' AND r."name" = 'user';""",
            ),
        }
    if probe == "password-reset-result":
        return {
            "userId": ACTIVE_USER_ID,
            "unusedTokens": count(
                config,
                f"""SELECT COUNT(*) FROM "PasswordResetToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "usedAt" IS NULL AND "expiresAt" > CURRENT_TIMESTAMP;""",
            ),
            "usedTokens": count(
                config,
                f"""SELECT COUNT(*) FROM "PasswordResetToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "usedAt" IS NOT NULL;""",
            ),
            "activeRefreshTokens": count(
                config,
                f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL;""",
            ),
        }
    if probe == "pending-password-attach-result":
        return {
            "userId": TARGET_USER_ID,
            "email": emails(config)[TARGET_USER_ID],
            "status": psql(
                config,
                f"""SELECT "status"::text FROM "User" WHERE "id" = '{TARGET_USER_ID}';""",
            ),
            "passwordCredentials": count(
                config,
                f"""SELECT COUNT(*) FROM "PasswordCredential" WHERE "userId" = '{TARGET_USER_ID}';""",
            ),
            "pendingPasswordCredentials": count(
                config,
                f"""SELECT COUNT(*) FROM "PendingPasswordCredential" WHERE "userId" = '{TARGET_USER_ID}';""",
            ),
            "duplicateUsers": count(
                config,
                f"""SELECT COUNT(*) FROM "User" WHERE lower("email") = lower('{emails(config)[TARGET_USER_ID]}');""",
            ),
        }
    if probe == "email-verification-audits":
        return {
            "requests": count(
                config,
                f"""SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'email_verification_request'
AND "userId" IN ('{PENDING_USER_ID}', '{TARGET_USER_ID}');""",
            ),
            "confirmationSuccesses": count(
                config,
                f"""SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'email_verification_confirm'
AND "outcome" = 'success' AND "userId" IN ('{PENDING_USER_ID}', '{TARGET_USER_ID}');""",
            ),
            "confirmationFailures": count(
                config,
                """SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'email_verification_confirm'
AND "outcome" = 'failure' AND "reasonCode" = 'INVALID_VERIFICATION_TOKEN';""",
            ),
        }
    if probe == "password-reset-audits":
        return {
            "requests": count(
                config,
                f"""SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'password_reset_request'
AND "userId" = '{ACTIVE_USER_ID}';""",
            ),
            "confirmationSuccesses": count(
                config,
                f"""SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'password_reset_confirm'
AND "outcome" = 'success' AND "userId" = '{ACTIVE_USER_ID}';""",
            ),
            "confirmationFailures": count(
                config,
                """SELECT COUNT(*) FROM "AuditLog" WHERE "eventType" = 'password_reset_confirm'
AND "outcome" = 'failure' AND "reasonCode" = 'INVALID_RESET_TOKEN';""",
            ),
        }
    if probe == "target-user":
        status = psql(
            config,
            f"""SELECT "status"::text FROM "User" WHERE "id" = '{TARGET_USER_ID}';""",
        )
        audits = count(
            config,
            f"""SELECT COUNT(*) FROM "AuditLog" WHERE "targetUserId" = '{TARGET_USER_ID}' AND "reasonCode" = 'CONTRACT_FIXTURE' AND "eventType" = 'admin_user_status_changed';""",
        )
        return {"status": status, "auditEvents": audits}
    if probe == "shared-rate-limit":
        redis_client = RedisRespClient.from_url(config.redis_url)
        keys = redis_client.scan("wiseacct:rate-limit:*")
        counters: list[int] = []
        ttls: list[int] = []
        for key in keys:
            raw_count = redis_client.get(key)
            try:
                counters.append(
                    int(raw_count.decode("ascii")) if raw_count is not None else -1
                )
            except (UnicodeDecodeError, ValueError) as exc:
                raise AdapterError(
                    "rate-limit counter was not a decimal integer"
                ) from exc
            ttls.append(redis_client.ttl(key))
        return {
            "keyCount": len(keys),
            "counters": sorted(counters),
            "ttls": sorted(ttls),
        }
    if probe == "failed-login-ledger":
        row = psql(
            config,
            f"""SELECT "failedLoginCount"::text || '|' || ("lockedUntil" IS NOT NULL)::text
FROM "PasswordCredential" WHERE "userId" = '{ACTIVE_USER_ID}';""",
        )
        parts = row.split("|")
        if len(parts) != 2:
            raise AdapterError("failed-login ledger returned an unexpected row")
        active = count(
            config,
            f"""SELECT COUNT(*) FROM "RefreshToken" WHERE "userId" = '{ACTIVE_USER_ID}' AND "revokedAt" IS NULL;""",
        )
        if parts[1] not in {"true", "false"}:
            raise AdapterError("failed-login ledger returned an invalid lock boolean")
        return {
            "failedLoginCount": int(parts[0]),
            "lockSet": parts[1] == "true",
            "activeRefreshTokens": active,
        }
    if probe == "fixture-anonymous-audits":
        residual = count(
            config,
            f"""SELECT COUNT(*) FROM "AuditLog"
WHERE {FIXTURE_ANONYMOUS_AUDIT_PREDICATE};""",
        )
        return {"residualCount": residual}
    raise AdapterError(f"unsupported probe {probe!r}")


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in {
            "expire",
            "preflight",
            "setup",
            "snapshot",
            "teardown",
        }:
            raise AdapterError(
                "usage: express_fixture.py {preflight|setup|expire|snapshot|teardown} <name>"
            )
        command, name = argv
        config = load_config()
        result: Any = preflight(config)
        if command == "setup":
            result = setup(config, name)
        elif command == "expire":
            result = expire(config, name)
        elif command == "snapshot":
            result = snapshot(config, name)
        elif command == "teardown":
            reset(config)
            result = {"status": "clean"}
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (
        AdapterError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
