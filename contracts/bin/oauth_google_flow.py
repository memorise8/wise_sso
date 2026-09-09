#!/usr/bin/env python3
"""Connected, non-qualifying Google OAuth mixed-runtime contract flow."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import socket
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, TypedDict, cast
from urllib import parse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

FLOW_ID: Final = "oauth-google"
GOOGLE_AUTHORIZE_ORIGIN: Final = "https://accounts.google.com"
CALLER_STATE: Final = "google-contract-caller-state"
CODE_VERIFIER: Final = (
    "google-contract-verifier-000000000000000000000000000000000000000000"
)
CODE_CHALLENGE: Final = (
    base64.urlsafe_b64encode(hashlib.sha256(CODE_VERIFIER.encode()).digest())
    .decode()
    .rstrip("=")
)
MAX_CONFIG_BYTES: Final = 64 * 1024


class ContractFailure(RuntimeError):
    """The Google flow did not prove its required contract."""


class Adapter(Protocol):
    refresh_secret: str
    runtime_bindings: Mapping[str, object]

    def invoke(self, command: str, name: str) -> Any: ...


class FlowConfig(TypedDict):
    producerOrigin: str
    consumerOrigin: str
    producer: str
    consumer: str
    expectedIssuer: str
    fixtureAdapter: str
    fixtureEnvironment: dict[str, str]


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    headers: Mapping[str, str]
    body: Any


def _loopback_origin(value: str, label: str) -> str:
    try:
        parsed = parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ContractFailure(f"google-oauth-{label}-origin-invalid") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ContractFailure(f"google-oauth-{label}-origin-invalid")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"


def _call(
    origin: str,
    method: str,
    path: str,
    body: Mapping[str, object] | None = None,
    *,
    authorization: str | None = None,
    timeout: float = 3.0,
) -> HttpResult:
    if not math.isfinite(timeout) or timeout <= 0:
        raise ContractFailure("google-oauth-http-timeout-invalid")
    parsed_origin = parse.urlsplit(origin)
    if parsed_origin.hostname is None or parsed_origin.port is None:
        raise ContractFailure("google-oauth-http-origin-invalid")
    if not path.startswith("/") or any(character in path for character in "\r\n"):
        raise ContractFailure("google-oauth-http-path-invalid")
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request_headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {parsed_origin.netloc}",
        "Connection: close",
    ]
    if encoded is not None:
        request_headers.extend(
            ["Content-Type: application/json", f"Content-Length: {len(encoded)}"]
        )
    else:
        request_headers.append("Content-Length: 0")
    if authorization is not None:
        if any(character in authorization for character in "\r\n"):
            raise ContractFailure("google-oauth-http-authorization-invalid")
        request_headers.append(f"Authorization: {authorization}")
    payload = ("\r\n".join(request_headers) + "\r\n\r\n").encode("ascii") + (
        encoded or b""
    )
    deadline = time.monotonic() + timeout
    connection: socket.socket | None = None
    try:
        connection = socket.create_connection(
            (parsed_origin.hostname, parsed_origin.port), timeout=_remaining(deadline)
        )
        connection.settimeout(_remaining(deadline))
        connection.sendall(payload)
        response_bytes = bytearray()
        while b"\r\n\r\n" not in response_bytes:
            if len(response_bytes) > 16 * 1024:
                raise ContractFailure("google-oauth-http-headers-too-large")
            connection.settimeout(_remaining(deadline))
            chunk = connection.recv(4096)
            if not chunk:
                raise ContractFailure("google-oauth-http-response-incomplete")
            response_bytes.extend(chunk)
        raw_headers, initial_body = bytes(response_bytes).split(b"\r\n\r\n", 1)
        if len(raw_headers) > 16 * 1024:
            raise ContractFailure("google-oauth-http-headers-too-large")
        status, headers = _parse_response_headers(raw_headers)
        transfer_encoding = headers.get("transfer-encoding")
        if transfer_encoding is not None:
            raise ContractFailure("google-oauth-http-framing-ambiguous")
        length_text = headers.get("content-length")
        if (
            length_text is None
            or not length_text.isascii()
            or not length_text.isdecimal()
        ):
            raise ContractFailure("google-oauth-http-content-length-invalid")
        length = int(length_text)
        if length > 64 * 1024 or len(initial_body) > length:
            raise ContractFailure("google-oauth-http-body-too-large")
        body_bytes = bytearray(initial_body)
        while len(body_bytes) < length:
            connection.settimeout(_remaining(deadline))
            chunk = connection.recv(min(4096, length - len(body_bytes)))
            if not chunk:
                raise ContractFailure("google-oauth-http-response-incomplete")
            body_bytes.extend(chunk)
    except (OSError, TimeoutError) as exc:
        raise ContractFailure("google-oauth-http-transport-failure") from exc
    finally:
        if connection is not None:
            connection.close()
    raw = bytes(body_bytes)
    content_type = headers.get("content-type", "").partition(";")[0].lower()
    try:
        decoded = (
            json.loads(raw) if raw and content_type == "application/json" else None
        )
    except json.JSONDecodeError as exc:
        raise ContractFailure("google-oauth-malformed-http-response") from exc
    return HttpResult(status, headers, decoded)


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ContractFailure("google-oauth-http-deadline-exceeded")
    return remaining


def _parse_response_headers(raw: bytes) -> tuple[int, dict[str, str]]:
    try:
        lines = raw.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ContractFailure("google-oauth-http-headers-invalid") from exc
    status_parts = lines[0].split(" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdecimal()
    ):
        raise ContractFailure("google-oauth-http-status-invalid")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            raise ContractFailure("google-oauth-http-headers-invalid")
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if not normalized or normalized in headers:
            raise ContractFailure("google-oauth-http-headers-invalid")
        headers[normalized] = value.strip()
    return int(status_parts[1]), headers


def _error(result: HttpResult, status: int, code: str) -> None:
    expected = {"error": {"code": code, "message": _ERROR_MESSAGES[code]}}
    if result.status != status or result.body != expected:
        raise ContractFailure("google-oauth-error-contract-mismatch")


_ERROR_MESSAGES: Final = {
    "INVALID_OAUTH_STATE": "Invalid OAuth state",
    "OAUTH_PROVIDER_ERROR": "OAuth provider returned an error",
    "INVALID_AUTH_HANDOFF_CODE": "Invalid authorization code",
}


def _one_query(url: str, expected_origin: str, expected_path: str) -> dict[str, str]:
    try:
        parsed = parse.urlsplit(url)
    except ValueError as exc:
        raise ContractFailure("google-oauth-redirect-boundary-mismatch") from exc
    if (
        f"{parsed.scheme}://{parsed.netloc}" != expected_origin
        or parsed.path != expected_path
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ContractFailure("google-oauth-redirect-boundary-mismatch")
    try:
        values = parse.parse_qs(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except ValueError as exc:
        raise ContractFailure("google-oauth-redirect-query-mismatch") from exc
    if any(len(items) != 1 or not items[0] for items in values.values()):
        raise ContractFailure("google-oauth-redirect-query-mismatch")
    return {key: items[0] for key, items in values.items()}


def _segment(value: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        decoded = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractFailure("google-oauth-malformed-jwt") from exc
    if not isinstance(decoded, dict):
        raise ContractFailure("google-oauth-malformed-jwt")
    return decoded


def _decode_b64url(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ContractFailure(f"google-oauth-{label}-mismatch")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ContractFailure(f"google-oauth-{label}-mismatch") from exc


def _verify_access_token(
    token: object,
    jwks: object,
    *,
    user_id: str,
    email: str,
    name: str,
    roles: object,
    audience: str,
    issuer: str,
) -> str:
    if not isinstance(token, str) or len(token.split(".")) != 3:
        raise ContractFailure("google-oauth-malformed-jwt")
    head_raw, claims_raw, signature_raw = token.split(".")
    header, claims = _segment(head_raw), _segment(claims_raw)
    if (
        set(header) != {"alg", "kid", "typ"}
        or header.get("alg") != "RS256"
        or header.get("typ") != "JWT"
        or not isinstance(header.get("kid"), str)
    ):
        raise ContractFailure("google-oauth-jwt-header-mismatch")
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ContractFailure("google-oauth-jwks-mismatch")
    keys = [
        item
        for item in jwks["keys"]
        if isinstance(item, dict) and item.get("kid") == header.get("kid")
    ]
    if len(keys) != 1:
        raise ContractFailure("google-oauth-jwks-mismatch")
    key = keys[0]
    try:
        if (
            set(key) != {"kty", "kid", "alg", "use", "n", "e"}
            or key.get("kty") != "RSA"
            or key.get("alg") != "RS256"
            or key.get("use") != "sig"
        ):
            raise ContractFailure("google-oauth-jwks-mismatch")
        modulus = int.from_bytes(_decode_b64url(key["n"], "jwks"), "big")
        exponent = int.from_bytes(_decode_b64url(key["e"], "jwks"), "big")
        signature = _decode_b64url(signature_raw, "jwt-signature")
        modulus_bytes = (modulus.bit_length() + 7) // 8
        if (
            modulus.bit_length() < 2048
            or exponent < 3
            or exponent % 2 == 0
            or len(signature) != modulus_bytes
            or int.from_bytes(signature, "big") >= modulus
        ):
            raise ContractFailure("google-oauth-jwks-mismatch")
        rsa.RSAPublicNumbers(exponent, modulus).public_key().verify(
            signature,
            f"{head_raw}.{claims_raw}".encode(),
            padding.PKCS1v15(),
            SHA256(),
        )
    except InvalidSignature as exc:
        raise ContractFailure("google-oauth-jwt-signature-mismatch") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise ContractFailure("google-oauth-jwks-mismatch") from exc
    expected = {
        "sub": user_id,
        "email": email,
        "name": name,
        "email_verified": True,
        "roles": roles,
        "type": "access",
        "aud": audience,
        "iss": issuer,
    }
    if any(claims.get(key_name) != value for key_name, value in expected.items()):
        raise ContractFailure("google-oauth-jwt-claim-mismatch")
    now = int(time.time())
    if (
        not isinstance(claims.get("iat"), int)
        or isinstance(claims.get("iat"), bool)
        or not isinstance(claims.get("exp"), int)
        or isinstance(claims.get("exp"), bool)
    ):
        raise ContractFailure("google-oauth-jwt-claim-mismatch")
    if claims["iat"] > now or claims["exp"] <= now or claims["exp"] <= claims["iat"]:
        raise ContractFailure("google-oauth-jwt-claim-mismatch")
    return token


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _verify_refresh_token(
    token: object, *, user_id: str, audience: str, secret: str
) -> None:
    if not isinstance(token, str) or len(token.split(".")) != 3 or not secret:
        raise ContractFailure("google-oauth-malformed-refresh-jwt")
    head_raw, claims_raw, signature = token.split(".")
    header, claims = _segment(head_raw), _segment(claims_raw)
    if header != {"alg": "HS256", "typ": "JWT"}:
        raise ContractFailure("google-oauth-refresh-jwt-header-mismatch")
    expected_signature = _b64url(
        hmac.new(
            secret.encode(),
            f"{head_raw}.{claims_raw}".encode(),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(signature, expected_signature):
        raise ContractFailure("google-oauth-refresh-jwt-signature-mismatch")
    expected = {"sub": user_id, "audience": audience, "type": "refresh"}
    if any(claims.get(name) != value for name, value in expected.items()):
        raise ContractFailure("google-oauth-refresh-jwt-claim-mismatch")
    if not isinstance(claims.get("tokenId"), str) or not claims["tokenId"]:
        raise ContractFailure("google-oauth-refresh-jwt-claim-mismatch")
    now = int(time.time())
    if (
        not isinstance(claims.get("iat"), int)
        or isinstance(claims.get("iat"), bool)
        or not isinstance(claims.get("exp"), int)
        or isinstance(claims.get("exp"), bool)
    ):
        raise ContractFailure("google-oauth-refresh-jwt-claim-mismatch")
    if claims["iat"] > now or claims["exp"] <= now or claims["exp"] <= claims["iat"]:
        raise ContractFailure("google-oauth-refresh-jwt-claim-mismatch")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractFailure(f"google-oauth-malformed-{label}")
    return value


def _snapshot(adapter: Adapter, name: str) -> dict[str, Any]:
    return _object(adapter.invoke("snapshot", name), name)


def _validate_runtime_bindings(
    adapter: Adapter,
    *,
    producer: str,
    consumer: str,
    producer_origin: str,
    consumer_origin: str,
) -> None:
    bindings = getattr(adapter, "runtime_bindings", None)
    if not isinstance(bindings, Mapping) or set(bindings) != {"express", "fastapi"}:
        raise ContractFailure("google-oauth-owned-runtime-bindings-required")
    identities: set[tuple[int, int]] = set()
    for role, origin in (
        (producer, producer_origin),
        (consumer, consumer_origin),
    ):
        binding = bindings[role]
        try:
            actual = (
                binding.role,
                binding.origin,
                binding.pid,
                binding.process_group,
            )
        except AttributeError as exc:
            raise ContractFailure("google-oauth-owned-runtime-binding-invalid") from exc
        if (
            actual[0] != role
            or actual[1] != origin
            or not isinstance(actual[2], int)
            or isinstance(actual[2], bool)
            or actual[2] <= 1
            or actual[3] != actual[2]
        ):
            raise ContractFailure("google-oauth-owned-runtime-binding-invalid")
        identities.add((actual[2], actual[3]))
    if len(identities) != 2:
        raise ContractFailure("google-oauth-owned-runtime-bindings-not-independent")


def _expected_issuer(value: str) -> str:
    parsed = parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ContractFailure("google-oauth-expected-issuer-invalid")
    return value


def _cleanup(adapter: Adapter, primary_error: BaseException | None) -> None:
    cleanup_error: BaseException | None = None
    try:
        teardown = adapter.invoke("teardown", "google-oauth-user")
        if teardown != {"status": "clean"}:
            raise ContractFailure("google-oauth-teardown-mismatch")
    except BaseException as exc:  # noqa: BLE001 - preserve interrupts and probe residuals
        cleanup_error = exc
    try:
        residual = _snapshot(adapter, "oauth-google-residual")
        if residual != {
            "oauthStates": 0,
            "handoffs": 0,
            "activeRefreshTokens": 0,
            "activeTokenHashes": [],
            "providerRecords": 0,
        }:
            raise ContractFailure("google-oauth-cleanup-residual")
    except BaseException as exc:  # noqa: BLE001 - cleanup must preserve the primary failure
        if cleanup_error is None:
            cleanup_error = exc
    if primary_error is None and cleanup_error is not None:
        raise cleanup_error
    if primary_error is not None and cleanup_error is not None:
        primary_error.add_note("google-oauth-cleanup-failure")
        raise primary_error from cleanup_error


def run_google_flow(
    producer_origin: str,
    consumer_origin: str,
    adapter: Adapter,
    *,
    producer: str,
    consumer: str,
    expected_issuer: str,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Run one Google OAuth producer→consumer ordering and return sanitized evidence."""

    if producer == consumer or {producer, consumer} != {"express", "fastapi"}:
        raise ContractFailure("google-oauth-mixed-ordering-required")
    producer_origin = _loopback_origin(producer_origin, "producer")
    consumer_origin = _loopback_origin(consumer_origin, "consumer")
    if producer_origin == consumer_origin:
        raise ContractFailure("google-oauth-distinct-origins-required")
    expected_issuer = _expected_issuer(expected_issuer)
    _validate_runtime_bindings(
        adapter,
        producer=producer,
        consumer=consumer,
        producer_origin=producer_origin,
        consumer_origin=consumer_origin,
    )
    primary_error: BaseException | None = None
    try:
        fixture = _object(adapter.invoke("setup", "google-oauth-user"), "fixture")
        required_fixture = {
            "userId",
            "email",
            "name",
            "roles",
            "audience",
            "clientId",
            "redirectUri",
            "provider",
            "providerSubject",
            "runId",
        }
        if set(fixture) != required_fixture or fixture.get("provider") != "google":
            raise ContractFailure("google-oauth-malformed-fixture")
        if any(
            not isinstance(fixture[name], str) or not fixture[name]
            for name in (
                "userId",
                "email",
                "name",
                "audience",
                "clientId",
                "redirectUri",
                "providerSubject",
                "runId",
            )
        ) or not isinstance(fixture["roles"], list):
            raise ContractFailure("google-oauth-malformed-fixture")
        start_path = "/auth/google?" + parse.urlencode(
            {
                "client_id": fixture["clientId"],
                "redirect_uri": fixture["redirectUri"],
                "state": CALLER_STATE,
                "code_challenge": CODE_CHALLENGE,
                "code_challenge_method": "S256",
            }
        )
        start = _call(producer_origin, "GET", start_path, timeout=timeout)
        if start.status != 302:
            raise ContractFailure("google-oauth-start-response-mismatch")
        authorization = _one_query(
            start.headers.get("location", ""),
            GOOGLE_AUTHORIZE_ORIGIN,
            "/o/oauth2/v2/auth",
        )
        if set(authorization) != {
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
        } or authorization != {
            "response_type": "code",
            "client_id": "google-client",
            "redirect_uri": f"{producer_origin}/auth/google/callback",
            "scope": "openid email profile",
            "state": authorization["state"],
        }:
            raise ContractFailure("google-oauth-authorization-contract-mismatch")
        provider_state = authorization["state"]

        wrong_state = _call(
            producer_origin,
            "GET",
            "/auth/google/callback?"
            + parse.urlencode({"code": "google-code", "state": "wrong-state"}),
            timeout=timeout,
        )
        _error(wrong_state, 400, "INVALID_OAUTH_STATE")

        provider_error = _call(
            producer_origin,
            "GET",
            "/auth/google/callback?"
            + parse.urlencode(
                {"error": "access_denied", "state": "error-response-probe-state"}
            ),
            timeout=timeout,
        )
        _error(provider_error, 400, "OAUTH_PROVIDER_ERROR")

        callback = _call(
            producer_origin,
            "GET",
            "/auth/google/callback?"
            + parse.urlencode({"code": "google-code", "state": provider_state}),
            timeout=timeout,
        )
        if callback.status != 302:
            raise ContractFailure("google-oauth-callback-response-mismatch")
        redirect_uri = parse.urlsplit(str(fixture["redirectUri"]))
        handoff = _one_query(
            callback.headers.get("location", ""),
            f"{redirect_uri.scheme}://{redirect_uri.netloc}",
            redirect_uri.path,
        )
        if set(handoff) != {"code", "state"} or handoff["state"] != CALLER_STATE:
            raise ContractFailure("google-oauth-handoff-redirect-mismatch")

        state_replay = _call(
            producer_origin,
            "GET",
            "/auth/google/callback?"
            + parse.urlencode({"code": "google-code", "state": provider_state}),
            timeout=timeout,
        )
        _error(state_replay, 400, "INVALID_OAUTH_STATE")

        bad_verifier = _call(
            consumer_origin,
            "POST",
            "/auth/exchange",
            {
                "clientId": fixture["clientId"],
                "redirectUri": fixture["redirectUri"],
                "code": handoff["code"],
                "codeVerifier": "wrong-verifier",
            },
            timeout=timeout,
        )
        _error(bad_verifier, 400, "INVALID_AUTH_HANDOFF_CODE")

        exchanged = _call(
            consumer_origin,
            "POST",
            "/auth/exchange",
            {
                "clientId": fixture["clientId"],
                "redirectUri": fixture["redirectUri"],
                "code": handoff["code"],
                "codeVerifier": CODE_VERIFIER,
            },
            timeout=timeout,
        )
        pair = _object(exchanged.body, "token-pair")
        if exchanged.status != 200 or set(pair) != {"accessToken", "refreshToken"}:
            raise ContractFailure("google-oauth-token-pair-mismatch")
        jwks_result = _call(
            consumer_origin, "GET", "/.well-known/jwks.json", timeout=timeout
        )
        if (
            jwks_result.status != 200
            or jwks_result.headers.get("content-type", "").partition(";")[0].lower()
            != "application/json"
        ):
            raise ContractFailure("google-oauth-jwks-response-mismatch")
        access = _verify_access_token(
            pair["accessToken"],
            jwks_result.body,
            user_id=str(fixture["userId"]),
            email=str(fixture["email"]),
            name=str(fixture["name"]),
            roles=fixture["roles"],
            audience=str(fixture["audience"]),
            issuer=expected_issuer,
        )
        _verify_refresh_token(
            pair["refreshToken"],
            user_id=str(fixture["userId"]),
            audience=str(fixture["audience"]),
            secret=adapter.refresh_secret,
        )
        refresh_token = cast(str, pair["refreshToken"])
        me = _call(
            consumer_origin,
            "GET",
            "/users/me",
            authorization=f"Bearer {access}",
            timeout=timeout,
        )
        if me.status != 200 or me.body != {
            "id": fixture["userId"],
            "email": fixture["email"],
            "name": fixture["name"],
            "email_verified": True,
            "roles": fixture["roles"],
        }:
            raise ContractFailure("google-oauth-current-user-mismatch")

        replay = _call(
            consumer_origin,
            "POST",
            "/auth/exchange",
            {
                "clientId": fixture["clientId"],
                "redirectUri": fixture["redirectUri"],
                "code": handoff["code"],
                "codeVerifier": CODE_VERIFIER,
            },
            timeout=timeout,
        )
        _error(replay, 400, "INVALID_AUTH_HANDOFF_CODE")

        provider_records = _snapshot(adapter, "oauth-google-provider-invocations")
        expected_records = [
            {
                "schemaVersion": 1,
                "runId": fixture["runId"],
                "runtime": producer,
                "source": "provider-transport",
                "provider": "google",
                "operation": "token",
                "sequence": 1,
            },
            {
                "schemaVersion": 1,
                "runId": fixture["runId"],
                "runtime": producer,
                "source": "provider-transport",
                "provider": "google",
                "operation": "user-info",
                "sequence": 2,
            },
        ]
        if provider_records != {
            "source": "launcher-owned-private-provider-record-pipe-v1",
            "consumed": True,
            "records": expected_records,
        }:
            raise ContractFailure("google-oauth-provider-invocation-mismatch")
        state = _snapshot(adapter, "oauth-google-state")
        expected_state = {
            "canonicalUsers": 1,
            "providerIdentities": 1,
            "provider": "google",
            "providerSubject": fixture["providerSubject"],
            "linkedUserId": fixture["userId"],
            "oauthStatesRemaining": 0,
            "handoffsRemaining": 0,
            "activeRefreshTokens": 1,
            "activeTokenHashes": [hashlib.sha256(refresh_token.encode()).hexdigest()],
        }
        if state != expected_state:
            raise ContractFailure("google-oauth-state-mismatch")
        return {
            "flow": FLOW_ID,
            "ordering": f"{producer}-{consumer}",
            "passed": True,
            "qualifying": False,
            "unverified": ["provider-error-state-lifecycle"],
            "assertions": {
                "start": True,
                "providerCalls": True,
                "providerSubjectLinked": True,
                "callerStatePreserved": True,
                "pkceRequired": True,
                "oauthSuccessStateReplayRejected": True,
                "handoffReplayRejected": True,
                "realAccessJwtVerified": True,
                "realRefreshJwtVerified": True,
                "mixedRuntimeExchange": True,
            },
        }
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        _cleanup(adapter, primary_error)


class FixtureAdapter:
    def __init__(self, executable: Path, environment: Mapping[str, str]) -> None:
        details = executable.lstat()
        if (
            executable.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or not os.access(executable, os.X_OK)
        ):
            raise ContractFailure("google-oauth-fixture-adapter-invalid")
        self.executable = executable
        self.environment = dict(environment)
        self.runtime_bindings: Mapping[str, object] = {}
        try:
            self.refresh_secret = self.environment["CONTRACT_REFRESH_SECRET"]
        except KeyError as exc:
            raise ContractFailure("google-oauth-refresh-secret-missing") from exc

    def invoke(self, command: str, name: str) -> Any:
        inherited = {
            key: value
            for key in ("LANG", "LC_ALL", "PATH")
            if (value := os.environ.get(key))
        }
        try:
            result = subprocess.run(
                [str(self.executable), command, name],
                env={**inherited, **self.environment},
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ContractFailure("google-oauth-fixture-adapter-failure") from exc
        if result.returncode != 0:
            raise ContractFailure("google-oauth-fixture-adapter-failure")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ContractFailure("google-oauth-fixture-adapter-malformed") from exc


def _secure_config(path: Path) -> FlowConfig:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ContractFailure("google-oauth-config-secure-open-unavailable")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | no_follow)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_size > MAX_CONFIG_BYTES
        ):
            raise ContractFailure("google-oauth-config-not-private")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(8192, MAX_CONFIG_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_CONFIG_BYTES:
                raise ContractFailure("google-oauth-config-too-large")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        )
        if identity_before != identity_after or size != before.st_size:
            raise ContractFailure("google-oauth-config-changed-during-read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractFailure("google-oauth-config-malformed") from exc
    fields = {
        "producerOrigin",
        "consumerOrigin",
        "producer",
        "consumer",
        "expectedIssuer",
        "fixtureAdapter",
        "fixtureEnvironment",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not isinstance(value["fixtureEnvironment"], dict)
    ):
        raise ContractFailure("google-oauth-config-malformed")
    if any(
        not isinstance(item, str)
        for key, item in value.items()
        if key != "fixtureEnvironment"
    ) or any(
        not isinstance(k, str) or not isinstance(v, str)
        for k, v in value["fixtureEnvironment"].items()
    ):
        raise ContractFailure("google-oauth-config-malformed")
    return cast(FlowConfig, value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = _secure_config(args.config)
        record = run_google_flow(
            config["producerOrigin"],
            config["consumerOrigin"],
            FixtureAdapter(
                Path(config["fixtureAdapter"]), config["fixtureEnvironment"]
            ),
            producer=config["producer"],
            consumer=config["consumer"],
            expected_issuer=config["expectedIssuer"],
        )
    except ContractFailure as exc:
        print(json.dumps({"passed": False, "qualifying": False, "error": str(exc)}))
        return 2
    except OSError:
        print(
            json.dumps(
                {
                    "passed": False,
                    "qualifying": False,
                    "error": "google-oauth-local-io-failure",
                }
            )
        )
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
