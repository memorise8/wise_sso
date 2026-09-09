#!/usr/bin/env python3
"""Execute the first password-flow qualification corpus without producing READY evidence."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import importlib.util
import io
import json
import math
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib import error, parse, request

FLOWS = (
    "password-direct-login-token",
    "password-handoff-exchange",
    "email-verification-attach-handoff-exchange",
    "password-reset-session-revoke",
)
GOOGLE_FLOW = "oauth-google"
GOOGLE_ASSERTIONS = {
    "start",
    "providerCalls",
    "providerSubjectLinked",
    "callerStatePreserved",
    "pkceRequired",
    "oauthSuccessStateReplayRejected",
    "handoffReplayRejected",
    "realAccessJwtVerified",
    "realRefreshJwtVerified",
    "mixedRuntimeExchange",
}
RUNTIMES = ("express", "fastapi")
SAFE_PROVENANCE = {"runId", "sourceRevision", "harnessRevision"}
SENSITIVE_MARKERS = (
    "accesstoken",
    "authorization",
    "code",
    "cookie",
    "password",
    "refreshtoken",
    "secret",
    "token",
    "verifier",
)
PUBLIC_FAILURE_CATEGORIES = {
    "access-token-claim-mismatch",
    "access-token-signature-or-claim-mismatch",
    "current-user-content-type-mismatch",
    "current-user-contract-mismatch",
    "fixture-setup-failure",
    "handoff-redirect-mismatch",
    "handoff-response-contract-mismatch",
    "handoff-state-mismatch",
    "http-error-contract-mismatch",
    "http-response-read-failure",
    "http-transport-failure",
    "jwks-http-failure",
    "logout-contract-mismatch",
    "logout-replay-contract-mismatch",
    "malformed-auth-state",
    "malformed-fixture",
    "malformed-http-response",
    "refresh-state-mismatch",
    "refresh-token-claim-mismatch",
    "refresh-token-header-mismatch",
    "refresh-token-signature-invalid",
    "session-state-mismatch",
    "session-token-link-mismatch",
    "token-response-contract-mismatch",
}


def _load_differential() -> Any:
    module_path = Path(__file__).with_name("differential.py")
    spec = importlib.util.spec_from_file_location(
        "flow_driver_differential", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load differential contracts from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DIFFERENTIAL = _load_differential()


def _load_mail_launcher() -> Any:
    module_path = Path(__file__).with_name("private_mail_flow_launcher.py")
    spec = importlib.util.spec_from_file_location(
        "flow_driver_private_mail", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load private mail launcher from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_oauth_launcher() -> Any:
    module_path = Path(__file__).with_name("private_oauth_flow_launcher.py")
    spec = importlib.util.spec_from_file_location(
        "flow_driver_private_oauth", module_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load private OAuth launcher from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ContractFailure(Exception):
    """The requested flow could not be proven."""


class Adapter(Protocol):
    refresh_secret: str
    isolation_identity: tuple[str, str]

    def invoke(self, command: str, name: str) -> Any: ...


class PrivateMailBinding(Protocol):
    environment: Mapping[str, str]
    runtime_name: str
    process_pid: int
    health_origin: str


class PrivateMailTokenSource(Protocol):
    def take(self, *, user_id: str, kind: str) -> Any: ...


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: Any
    started_ns: int
    ended_ns: int


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _origin(value: str, label: str) -> str:
    try:
        parsed = parse.urlparse(value)
        port = parsed.port or 80
    except ValueError as exc:
        raise ContractFailure(f"{label} has an invalid port") from exc
    if parsed.scheme != "http" or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ContractFailure(f"{label} must be a loopback HTTP origin")
    if (
        parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise ContractFailure(f"{label} must be a bare origin")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"


def _json_media_type(value: str) -> bool:
    return value.partition(";")[0].strip().lower() == "application/json"


def call(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    timeout: float,
    observations: list[HttpResult] | None = None,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers.setdefault("content-type", "application/json")
    req = request.Request(
        f"{base_url}{path}", data=encoded, headers=request_headers, method=method
    )
    opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())
    started_ns = time.monotonic_ns()
    try:
        response = opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    except (OSError, TimeoutError) as exc:
        raise ContractFailure("http-transport-failure") from exc
    try:
        with response:
            raw = response.read()
            content_type = response.headers.get("content-type", "")
            if raw and _json_media_type(content_type):
                try:
                    decoded: Any = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ContractFailure("malformed-http-response") from exc
            else:
                decoded = None if not raw else raw.decode("utf-8", errors="replace")
            result = HttpResult(
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                decoded,
                started_ns,
                time.monotonic_ns(),
            )
            if observations is not None:
                observations.append(result)
            return result
    except (OSError, TimeoutError) as exc:
        raise ContractFailure("http-response-read-failure") from exc


class FixtureAdapter:
    def __init__(
        self,
        executable: Path,
        environment: dict[str, str],
        base_url: str,
        private_mail_binding: PrivateMailBinding | None = None,
    ):
        metadata = executable.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or executable.is_symlink()
            or not os.access(executable, os.X_OK)
        ):
            raise ContractFailure("fixture adapter must be an executable regular file")
        required_guards = {
            "CONTRACT_FIXTURE_MODE": "1",
            "CONTRACT_REDIS_ISOLATED_DB": "1",
        }
        if any(environment.get(key) != value for key, value in required_guards.items()):
            raise ContractFailure("fixture config omitted required isolation guards")
        self.runtime_identity: tuple[str, object]
        mail_mode = environment.get("CONTRACT_SERVER_MAIL_MODE")
        if mail_mode == "private-loopback-smtp":
            if private_mail_binding is None:
                raise ContractFailure(
                    "private mail fixture requires an owned launcher binding"
                )
            bound_environment = dict(private_mail_binding.environment)
            protected = set(bound_environment)
            if any(
                key in environment and environment[key] != value
                for key, value in bound_environment.items()
            ):
                raise ContractFailure(
                    "fixture config conflicts with its private mail binding"
                )
            environment = {**environment, **bound_environment}
            if environment.get("CONTRACT_SERVER_MAIL_MODE") != "private-loopback-smtp":
                raise ContractFailure(
                    "private mail fixture binding has an invalid mode"
                )
            if not protected.issuperset(
                {
                    "CONTRACT_PRIVATE_MAIL_SESSION_FILE",
                    "CONTRACT_PRIVATE_MAIL_SESSION_CAPABILITY",
                    "CONTRACT_PRIVATE_MAIL_CA_SHA256",
                    "SMTP_HOST",
                    "SMTP_PORT",
                    "SSL_CERT_FILE",
                }
            ):
                raise ContractFailure("private mail fixture binding is incomplete")
            if private_mail_binding.health_origin != base_url:
                raise ContractFailure(
                    "private mail fixture binding origin does not match"
                )
            self.runtime_identity = (
                private_mail_binding.runtime_name,
                private_mail_binding.process_pid,
            )
        elif mail_mode != "dev" or private_mail_binding is not None:
            raise ContractFailure(
                "fixture config omitted a supported mail isolation mode"
            )
        else:
            self.runtime_identity = ("external-development-runtime", base_url)
        self.executable = executable
        self.environment = environment
        self.base_url = base_url
        try:
            self.refresh_secret = environment["CONTRACT_REFRESH_SECRET"]
        except KeyError as exc:
            raise ContractFailure(
                "fixture config omitted CONTRACT_REFRESH_SECRET"
            ) from exc
        try:
            self.isolation_identity = (
                environment["CONTRACT_DATABASE_URL"],
                environment["CONTRACT_REDIS_URL"],
            )
        except KeyError as exc:
            raise ContractFailure("fixture config omitted isolated store URLs") from exc

    def invoke(self, command: str, name: str) -> Any:
        inherited = {
            key: value
            for key in ("LANG", "LC_ALL", "PATH", "SYSTEMROOT")
            if (value := os.environ.get(key)) is not None
        }
        try:
            completed = subprocess.run(
                [str(self.executable), command, name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={
                    **inherited,
                    **self.environment,
                    "CONTRACT_BASE_URL": self.base_url,
                },
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ContractFailure(f"fixture-{command}-failure") from exc
        if completed.returncode != 0:
            raise ContractFailure(f"fixture-{command}-failure")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ContractFailure(f"fixture-{command}-malformed") from exc


def load_adapter_environment(path: Path) -> dict[str, str]:
    document = _read_secure_json(path, "fixture config")
    if not isinstance(document, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in document.items()
    ):
        raise ContractFailure("fixture config must contain a flat string JSON object")
    return document


def _read_secure_json(path: Path, label: str) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ContractFailure(f"{label} secure open is unavailable")
    descriptor = os.open(path, os.O_RDONLY | nofollow)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
            raise ContractFailure(
                f"{label} must be a regular file with exact mode 0600"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(65536, 1_048_577 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > 1_048_576:
                raise ContractFailure(f"{label} exceeds the bounded read limit")
        after = os.fstat(descriptor)
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mode)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mode)
        if before_identity != after_identity or size != before.st_size:
            raise ContractFailure(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    return json.loads(b"".join(chunks).decode("utf-8"))


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractFailure(f"malformed-{label}")
    return value


def _error_code(result: HttpResult) -> str | None:
    body = result.body if isinstance(result.body, dict) else {}
    envelope = body.get("error") if isinstance(body, dict) else None
    return envelope.get("code") if isinstance(envelope, dict) else None


def _expect_error(result: HttpResult, status: int, code: str, message: str) -> None:
    expected = {"error": {"code": code, "message": message}}
    if (
        result.status != status
        or result.body != expected
        or not _json_media_type(result.headers.get("content-type", ""))
    ):
        raise ContractFailure("http-error-contract-mismatch")


def _b64url_json(segment: str, label: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return _require_object(json.loads(raw), label)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractFailure(f"malformed-{label}") from exc


def _compact_token(
    value: Any, label: str
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not isinstance(value, str) or len(value.split(".")) != 3:
        raise ContractFailure(f"malformed-{label}")
    head, claims, _signature = value.split(".")
    return (
        value,
        _b64url_json(head, f"{label}-header"),
        _b64url_json(claims, f"{label}-claims"),
    )


def _expect_claims(
    actual: dict[str, Any], expected: dict[str, Any], label: str
) -> None:
    for key, value in expected.items():
        if actual.get(key) != value:
            raise ContractFailure(f"{label}-claim-mismatch")
    issued = actual.get("iat")
    expires = actual.get("exp")
    if not isinstance(issued, int) or isinstance(issued, bool):
        raise ContractFailure(f"{label}-claim-mismatch")
    now = int(time.time())
    if (
        not isinstance(expires, int)
        or isinstance(expires, bool)
        or expires <= issued
        or issued > now
        or expires <= now
    ):
        raise ContractFailure(f"{label}-claim-mismatch")


def _verify_rs256(
    token: str, jwks: dict[str, Any], claims_expected: dict[str, Any]
) -> None:
    _token, _header, claims = _compact_token(token, "access-token")
    expected = {**claims_expected, "iat": claims.get("iat"), "exp": claims.get("exp")}
    try:
        DIFFERENTIAL.verify_rs256(token, jwks, expected, {})
    except DIFFERENTIAL.ContractFailure as exc:
        raise ContractFailure("access-token-signature-or-claim-mismatch") from exc
    _expect_claims(claims, claims_expected, "access-token")


def _verify_token_pair(
    result: HttpResult,
    base_url: str,
    fixture: dict[str, Any],
    timeout: float,
    expected_issuer: str,
    refresh_secret: str,
    observations: list[HttpResult],
) -> tuple[str, str]:
    body = _require_object(result.body, "token-response")
    if result.status != 200 or set(body) != {"accessToken", "refreshToken"}:
        raise ContractFailure("token-response-contract-mismatch")
    access, _header, _claims = _compact_token(body["accessToken"], "access-token")
    refresh, refresh_header, refresh_claims = _compact_token(
        body["refreshToken"], "refresh-token"
    )
    jwks_result = call(
        base_url,
        "GET",
        "/.well-known/jwks.json",
        None,
        timeout,
        observations,
    )
    if jwks_result.status != 200:
        raise ContractFailure("jwks-http-failure")
    _verify_rs256(
        access,
        _require_object(jwks_result.body, "jwks-response"),
        {
            "sub": fixture["userId"],
            "email": fixture["email"],
            "name": fixture["name"],
            "email_verified": True,
            "type": "access",
            "roles": fixture["roles"],
            "iss": expected_issuer,
            "aud": fixture["audience"],
        },
    )
    if refresh_header.get("alg") != "HS256" or refresh_header.get("typ") != "JWT":
        raise ContractFailure("refresh-token-header-mismatch")
    signing_input, signature = refresh.rsplit(".", 1)
    expected_signature = (
        base64.urlsafe_b64encode(
            hmac.new(
                refresh_secret.encode(), signing_input.encode(), hashlib.sha256
            ).digest()
        )
        .decode()
        .rstrip("=")
    )
    if not hmac.compare_digest(signature, expected_signature):
        raise ContractFailure("refresh-token-signature-invalid")
    _expect_claims(
        refresh_claims,
        {"sub": fixture["userId"], "type": "refresh", "audience": fixture["audience"]},
        "refresh-token",
    )
    if (
        not isinstance(refresh_claims.get("tokenId"), str)
        or not refresh_claims["tokenId"]
    ):
        raise ContractFailure("refresh-token-claim-mismatch")
    me = call(
        base_url,
        "GET",
        "/users/me",
        None,
        timeout,
        observations,
        {"authorization": f"Bearer {access}"},
    )
    expected_me = {
        "id": fixture["userId"],
        "email": fixture["email"],
        "name": fixture["name"],
        "email_verified": True,
        "roles": fixture["roles"],
    }
    if me.status != 200 or me.body != expected_me:
        raise ContractFailure("current-user-contract-mismatch")
    if not _json_media_type(me.headers.get("content-type", "")):
        raise ContractFailure("current-user-content-type-mismatch")
    return access, refresh


def _auth_state(adapter: Adapter, probe: str = "auth-lifecycle") -> dict[str, Any]:
    state = _require_object(adapter.invoke("snapshot", probe), "auth-state")
    required = ("activeRefreshTokens", "authHandoffKeys", "activeTokenHashes")
    if any(key not in state for key in required):
        raise ContractFailure("malformed-auth-state")
    counts = (state["activeRefreshTokens"], state["authHandoffKeys"])
    hashes = state["activeTokenHashes"]
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        )
        or not isinstance(hashes, list)
        or any(
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in hashes
        )
        or len(hashes) != state["activeRefreshTokens"]
    ):
        raise ContractFailure("malformed-auth-state")
    return state


def _state_empty(state: dict[str, Any]) -> None:
    if (
        state["activeRefreshTokens"] != 0
        or state["authHandoffKeys"] != 0
        or state["activeTokenHashes"] != []
    ):
        raise ContractFailure("fixture-initial-state-not-empty")


def _expect_exact_auth_state(
    state: dict[str, Any], *, active_hashes: set[str], handoff_keys: int = 0
) -> None:
    if (
        state["activeRefreshTokens"] != len(active_hashes)
        or state["authHandoffKeys"] != handoff_keys
        or set(state["activeTokenHashes"]) != active_hashes
    ):
        raise ContractFailure("auth-state-transition-mismatch")


def _digest_set(value: Any, failure: str) -> set[str]:
    if (
        not isinstance(value, list)
        or any(
            not isinstance(item, str)
            or len(item) != 64
            or any(character not in "0123456789abcdef" for character in item)
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise ContractFailure(failure)
    return set(value)


def _state_delta(
    before: dict[str, Any], after: dict[str, Any], refresh: int, handoff: int
) -> None:
    if after["activeRefreshTokens"] != before["activeRefreshTokens"] + refresh:
        raise ContractFailure("refresh-state-mismatch")
    if after["authHandoffKeys"] != before["authHandoffKeys"] + handoff:
        raise ContractFailure("handoff-state-mismatch")
    hashes = after["activeTokenHashes"]
    if not isinstance(hashes, list) or len(hashes) != after["activeRefreshTokens"]:
        raise ContractFailure("session-state-mismatch")


def _token_is_active(state: dict[str, Any], refresh: str) -> None:
    digest = hashlib.sha256(refresh.encode()).hexdigest()
    if digest not in state["activeTokenHashes"]:
        raise ContractFailure("session-token-link-mismatch")


def _login(
    url: str,
    fixture: dict[str, Any],
    password: str,
    timeout: float,
    handoff: bool,
    observations: list[HttpResult],
) -> HttpResult:
    body: dict[str, Any] = {"email": fixture["email"], "password": password}
    if handoff:
        body.update(
            clientId=fixture["clientId"],
            redirectUri=fixture["redirectUri"],
            state=fixture["state"],
            codeChallenge=fixture["codeChallenge"],
            codeChallengeMethod="S256",
        )
    return call(url, "POST", "/auth/login", body, timeout, observations)


def _handoff_code(result: HttpResult, fixture: dict[str, Any]) -> str:
    body = _require_object(result.body, "handoff-response")
    redirect = body.get("redirectUrl")
    if (
        result.status != 200
        or set(body) != {"redirectUrl"}
        or not isinstance(redirect, str)
        or not _json_media_type(result.headers.get("content-type", ""))
    ):
        raise ContractFailure("handoff-response-contract-mismatch")
    actual = parse.urlparse(redirect)
    expected = parse.urlparse(fixture["redirectUri"])
    if (
        actual.scheme,
        actual.netloc,
        actual.path,
        actual.params,
        actual.fragment,
    ) != (
        expected.scheme,
        expected.netloc,
        expected.path,
        expected.params,
        expected.fragment,
    ):
        raise ContractFailure("handoff-redirect-mismatch")
    query = parse.parse_qs(actual.query, keep_blank_values=True)
    expected_query = parse.parse_qs(expected.query, keep_blank_values=True)
    if set(expected_query) & {"code", "state"}:
        raise ContractFailure("handoff-redirect-mismatch")
    if (
        set(query) != {*expected_query, "code", "state"}
        or any(query.get(key) != value for key, value in expected_query.items())
        or query.get("state") != [fixture["state"]]
        or len(query.get("code", [])) != 1
        or not query["code"][0]
    ):
        raise ContractFailure("handoff-redirect-mismatch")
    return query["code"][0]


def _exchange(
    url: str,
    fixture: dict[str, Any],
    code: str,
    timeout: float,
    observations: list[HttpResult],
) -> HttpResult:
    return call(
        url,
        "POST",
        "/auth/exchange",
        {
            "clientId": fixture["clientId"],
            "redirectUri": fixture["redirectUri"],
            "code": code,
            "codeVerifier": fixture["codeVerifier"],
        },
        timeout,
        observations,
    )


def _expect_accepted(result: HttpResult) -> None:
    if (
        result.status != 202
        or result.body != {"status": "accepted"}
        or not _json_media_type(result.headers.get("content-type", ""))
    ):
        raise ContractFailure("mail-request-contract-mismatch")


def _expect_captured_digest(captured: Any, ledger: dict[str, Any], label: str) -> None:
    digest = getattr(captured, "token_sha256", None)
    digests = ledger.get("digests")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or not isinstance(digests, list)
        or digests != [digest]
    ):
        raise ContractFailure(f"{label}-digest-state-mismatch")


def _validate_mail_topology(
    request_origin: str,
    confirm_origin: str,
    producer: Adapter,
    consumer: Adapter | None,
) -> None:
    if consumer is None:
        if request_origin != confirm_origin:
            raise ContractFailure("mail-flow-consumer-adapter-required")
        return
    if request_origin == confirm_origin:
        raise ContractFailure("mixed-topology-requires-distinct-runtime-origins")
    if producer.isolation_identity != consumer.isolation_identity:
        raise ContractFailure("mixed-topology-requires-shared-isolated-stores")
    producer_runtime = getattr(producer, "runtime_identity", None)
    consumer_runtime = getattr(consumer, "runtime_identity", None)
    if (
        not isinstance(producer_runtime, tuple)
        or not isinstance(consumer_runtime, tuple)
        or producer_runtime == consumer_runtime
    ):
        raise ContractFailure("mixed-topology-requires-distinct-owned-runtimes")


def run_email_verification_flow(
    *,
    url: str,
    adapter: Adapter,
    token_source: PrivateMailTokenSource,
    timeout: float = 5.0,
    consumer_url: str | None = None,
    consumer_adapter: Adapter | None = None,
    expected_issuer: str = "https://auth.financenow.kr",
) -> dict[str, Any]:
    """Exercise request -> private SMTP capture -> confirm -> replay over HTTP."""

    observations: list[HttpResult] = []
    fixture = _require_object(adapter.invoke("setup", "pending-email-user"), "fixture")
    try:
        handoff = consumer_url is not None or consumer_adapter is not None
        if handoff and (consumer_url is None or consumer_adapter is None):
            raise ContractFailure("verification-handoff-requires-consumer-runtime")
        required = {"userId", "email", "attachUserId", "attachEmail"}
        if handoff:
            required |= {
                "name",
                "roles",
                "audience",
                "clientId",
                "redirectUri",
                "state",
                "codeChallenge",
                "codeVerifier",
            }
        if required - fixture.keys():
            raise ContractFailure("malformed-fixture")
        request_origin = _origin(url, "verification request runtime")
        confirm_origin = _origin(
            consumer_url if consumer_url is not None else url,
            "verification confirm runtime",
        )
        _validate_mail_topology(
            request_origin, confirm_origin, adapter, consumer_adapter
        )
    except (ContractFailure, KeyError):
        adapter.invoke("teardown", "pending-email-user")
        raise
    try:
        request_body: dict[str, Any] = {"email": fixture["email"]}
        if handoff:
            request_body.update(
                clientId=fixture["clientId"],
                redirectUri=fixture["redirectUri"],
                state=fixture["state"],
                codeChallenge=fixture["codeChallenge"],
                codeChallengeMethod="S256",
            )
        requested = call(
            request_origin,
            "POST",
            "/auth/email-verification/request",
            request_body,
            timeout,
            observations,
        )
        _expect_accepted(requested)
        issued = _require_object(
            adapter.invoke("snapshot", "email-verification-ledger"),
            "email-verification-ledger",
        )
        if issued.get("unusedTokens") != 1:
            raise ContractFailure("verification-token-state-mismatch")
        expired_capture = token_source.take(
            user_id=fixture["userId"], kind="email-verification"
        )
        _expect_captured_digest(expired_capture, issued, "verification")
        expired_token = getattr(expired_capture, "token", None)
        if not isinstance(expired_token, str) or not expired_token:
            raise ContractFailure("private-mail-token-contract-mismatch")
        adapter.invoke("expire", "latest-email-verification")
        expired = call(
            confirm_origin,
            "POST",
            "/auth/email-verification/confirm",
            {"token": expired_token},
            timeout,
            observations,
        )
        _expect_error(
            expired,
            400,
            "INVALID_VERIFICATION_TOKEN",
            "Invalid or expired verification token",
        )
        requested_again = call(
            request_origin,
            "POST",
            "/auth/email-verification/request",
            request_body,
            timeout,
            observations,
        )
        _expect_accepted(requested_again)
        reissued = _require_object(
            adapter.invoke("snapshot", "email-verification-ledger"),
            "email-verification-ledger",
        )
        captured = token_source.take(
            user_id=fixture["userId"], kind="email-verification"
        )
        _expect_captured_digest(captured, reissued, "verification")
        token = getattr(captured, "token", None)
        if not isinstance(token, str) or not token:
            raise ContractFailure("private-mail-token-contract-mismatch")
        confirmed = call(
            confirm_origin,
            "POST",
            "/auth/email-verification/confirm",
            {"token": token},
            timeout,
            observations,
        )
        confirmed_body = _require_object(confirmed.body, "verification-confirm")
        if confirmed.status != 200 or confirmed_body.get("status") != "verified":
            raise ContractFailure("verification-confirm-contract-mismatch")
        refresh: str | None = None
        if handoff:
            if set(confirmed_body) != {"status", "redirectUrl"}:
                raise ContractFailure("verification-confirm-contract-mismatch")
            redirect_result = HttpResult(
                confirmed.status,
                confirmed.headers,
                {"redirectUrl": confirmed_body["redirectUrl"]},
                confirmed.started_ns,
                confirmed.ended_ns,
            )
            code = _handoff_code(redirect_result, fixture)
            assert consumer_adapter is not None
            exchanged = _exchange(confirm_origin, fixture, code, timeout, observations)
            _access, refresh = _verify_token_pair(
                exchanged,
                confirm_origin,
                fixture,
                timeout,
                expected_issuer,
                consumer_adapter.refresh_secret,
                observations,
            )
            _expect_exact_auth_state(
                _auth_state(consumer_adapter, "pending-email-auth-lifecycle"),
                active_hashes={hashlib.sha256(refresh.encode()).hexdigest()},
            )
            exchange_replay = _exchange(
                confirm_origin, fixture, code, timeout, observations
            )
            _expect_error(
                exchange_replay,
                400,
                "INVALID_AUTH_HANDOFF_CODE",
                "Invalid authorization code",
            )
        elif set(confirmed_body) != {"status"}:
            raise ContractFailure("verification-confirm-contract-mismatch")
        state = _require_object(
            adapter.invoke("snapshot", "email-verification-result"),
            "email-verification-result",
        )
        expected = {
            "userId": fixture["userId"],
            "email": fixture["email"],
            "status": "ACTIVE",
            "emailVerified": True,
            "unusedTokens": 0,
            "usedTokens": 1,
            "passwordCredentials": 1,
            "duplicateUsers": 1,
            "defaultRoles": 1,
        }
        if any(state.get(key) != value for key, value in expected.items()):
            raise ContractFailure("verification-result-state-mismatch")
        replay = call(
            confirm_origin,
            "POST",
            "/auth/email-verification/confirm",
            {"token": token},
            timeout,
            observations,
        )
        _expect_error(
            replay,
            400,
            "INVALID_VERIFICATION_TOKEN",
            "Invalid or expired verification token",
        )
        if refresh is not None:
            assert consumer_adapter is not None
            logout = call(
                confirm_origin,
                "POST",
                "/auth/logout",
                {"refreshToken": refresh},
                timeout,
                observations,
            )
            if logout.status != 204 or logout.body is not None:
                raise ContractFailure("logout-contract-mismatch")
            _expect_exact_auth_state(
                _auth_state(consumer_adapter, "pending-email-auth-lifecycle"),
                active_hashes=set(),
            )
        attach_checked = False
        attach_user = fixture.get("attachUserId")
        attach_email = fixture.get("attachEmail")
        if isinstance(attach_user, str) and isinstance(attach_email, str):
            attach_request = call(
                request_origin,
                "POST",
                "/auth/email-verification/request",
                {"email": attach_email},
                timeout,
                observations,
            )
            _expect_accepted(attach_request)
            attach_issued = _require_object(
                adapter.invoke("snapshot", "attach-email-verification-ledger"),
                "attach-email-verification-ledger",
            )
            if attach_issued.get("unusedTokens") != 1:
                raise ContractFailure("verification-attach-token-state-mismatch")
            attach_capture = token_source.take(
                user_id=attach_user, kind="email-verification"
            )
            _expect_captured_digest(
                attach_capture, attach_issued, "verification-attach"
            )
            attach_token = getattr(attach_capture, "token", None)
            if not isinstance(attach_token, str) or not attach_token:
                raise ContractFailure("private-mail-token-contract-mismatch")
            attached = call(
                confirm_origin,
                "POST",
                "/auth/email-verification/confirm",
                {"token": attach_token},
                timeout,
                observations,
            )
            if attached.status != 200 or attached.body != {"status": "verified"}:
                raise ContractFailure("verification-attach-contract-mismatch")
            attach_state = _require_object(
                adapter.invoke("snapshot", "pending-password-attach-result"),
                "pending-password-attach-result",
            )
            attach_expected = {
                "userId": attach_user,
                "email": attach_email,
                "status": "ACTIVE",
                "passwordCredentials": 1,
                "pendingPasswordCredentials": 0,
                "duplicateUsers": 1,
            }
            if any(
                attach_state.get(key) != value for key, value in attach_expected.items()
            ):
                raise ContractFailure("verification-attach-state-mismatch")
            attach_checked = True
        if not attach_checked:
            raise ContractFailure("verification-attach-fixture-mismatch")
        audits = _require_object(
            adapter.invoke("snapshot", "email-verification-audits"),
            "email-verification-audits",
        )
        expected_audits = {
            "requests": 3 if attach_checked else 2,
            "confirmationSuccesses": 2 if attach_checked else 1,
            "confirmationFailures": 2,
        }
        if any(audits.get(key) != value for key, value in expected_audits.items()):
            raise ContractFailure("verification-audit-state-mismatch")
        return {
            "http": {"attempted": len(observations), "passed": len(observations)},
            "mail": {
                "privateCaptureConsumed": True,
                "mailDigestObserved": isinstance(
                    getattr(captured, "token_sha256", None), str
                ),
            },
            "state": {
                "userActivated": True,
                "credentialAttached": True,
                "tokenConsumed": True,
                "handoffExchanged": handoff,
                "pendingPasswordAttached": attach_checked,
            },
            "negative": {
                "expiredTokenRejected": True,
                "tokenReplayRejected": True,
                "handoffReplayRejected": handoff,
            },
            "qualifyingEvidence": False,
        }
    finally:
        adapter.invoke("teardown", "pending-email-user")


def run_password_reset_flow(
    *,
    url: str,
    adapter: Adapter,
    token_source: PrivateMailTokenSource,
    timeout: float = 5.0,
    new_password: str = "ContractOnly!2026-reset",
    expected_issuer: str = "https://auth.financenow.kr",
    consumer_url: str | None = None,
    consumer_adapter: Adapter | None = None,
) -> dict[str, Any]:
    """Exercise request -> private SMTP capture -> reset -> replay over HTTP."""

    observations: list[HttpResult] = []
    fixture = _require_object(
        adapter.invoke("setup", "active-password-user"), "fixture"
    )
    try:
        if {
            "userId",
            "email",
            "password",
            "name",
            "roles",
            "audience",
        } - fixture.keys():
            raise ContractFailure("malformed-fixture")
        request_origin = _origin(url, "password reset request runtime")
        confirm_origin = _origin(
            consumer_url if consumer_url is not None else url,
            "password reset confirm runtime",
        )
        _validate_mail_topology(
            request_origin, confirm_origin, adapter, consumer_adapter
        )
    except (ContractFailure, KeyError):
        adapter.invoke("teardown", "active-password-user")
        raise
    try:
        original_login = _login(
            request_origin,
            fixture,
            fixture["password"],
            timeout,
            False,
            observations,
        )
        _original_access, original_refresh = _verify_token_pair(
            original_login,
            request_origin,
            fixture,
            timeout,
            expected_issuer,
            adapter.refresh_secret,
            observations,
        )
        second_session_origin = confirm_origin
        second_login = _login(
            second_session_origin,
            fixture,
            fixture["password"],
            timeout,
            False,
            observations,
        )
        _second_access, second_refresh = _verify_token_pair(
            second_login,
            second_session_origin,
            fixture,
            timeout,
            expected_issuer,
            (consumer_adapter or adapter).refresh_secret,
            observations,
        )
        before_reset = _auth_state(adapter)
        if before_reset["activeRefreshTokens"] != 2:
            raise ContractFailure("reset-prerequisite-session-state-mismatch")
        _token_is_active(before_reset, original_refresh)
        _token_is_active(before_reset, second_refresh)
        original_refresh_hashes = {
            hashlib.sha256(original_refresh.encode()).hexdigest(),
            hashlib.sha256(second_refresh.encode()).hexdigest(),
        }
        before_ledger = _require_object(
            adapter.invoke("snapshot", "refresh-ledger"), "refresh-ledger"
        )
        if (
            before_ledger.get("activeRefreshTokens") != 2
            or _digest_set(
                before_ledger.get("activeTokenHashes"),
                "reset-prerequisite-session-state-mismatch",
            )
            != original_refresh_hashes
            or before_ledger.get("revokedRefreshTokens") != 0
            or _digest_set(
                before_ledger.get("revokedTokenHashes"),
                "reset-prerequisite-session-state-mismatch",
            )
            != set()
        ):
            raise ContractFailure("reset-prerequisite-session-state-mismatch")
        requested = call(
            request_origin,
            "POST",
            "/auth/password-reset/request",
            {"email": fixture["email"]},
            timeout,
            observations,
        )
        _expect_accepted(requested)
        issued = _require_object(
            adapter.invoke("snapshot", "password-reset-ledger"),
            "password-reset-ledger",
        )
        if issued.get("unusedTokens") != 1:
            raise ContractFailure("reset-token-state-mismatch")
        expired_capture = token_source.take(
            user_id=fixture["userId"], kind="password-reset"
        )
        _expect_captured_digest(expired_capture, issued, "reset")
        expired_token = getattr(expired_capture, "token", None)
        if not isinstance(expired_token, str) or not expired_token:
            raise ContractFailure("private-mail-token-contract-mismatch")
        adapter.invoke("expire", "latest-password-reset")
        expired = call(
            confirm_origin,
            "POST",
            "/auth/password-reset/confirm",
            {"token": expired_token, "password": new_password},
            timeout,
            observations,
        )
        _expect_error(
            expired,
            400,
            "INVALID_RESET_TOKEN",
            "Invalid or expired reset token",
        )
        requested_again = call(
            request_origin,
            "POST",
            "/auth/password-reset/request",
            {"email": fixture["email"]},
            timeout,
            observations,
        )
        _expect_accepted(requested_again)
        reissued = _require_object(
            adapter.invoke("snapshot", "password-reset-ledger"),
            "password-reset-ledger",
        )
        captured = token_source.take(user_id=fixture["userId"], kind="password-reset")
        _expect_captured_digest(captured, reissued, "reset")
        token = getattr(captured, "token", None)
        if not isinstance(token, str) or not token:
            raise ContractFailure("private-mail-token-contract-mismatch")
        confirmed = call(
            confirm_origin,
            "POST",
            "/auth/password-reset/confirm",
            {"token": token, "password": new_password},
            timeout,
            observations,
        )
        if confirmed.status != 204 or confirmed.body is not None:
            raise ContractFailure("password-reset-confirm-contract-mismatch")
        state = _require_object(
            adapter.invoke("snapshot", "password-reset-result"),
            "password-reset-result",
        )
        expected = {
            "userId": fixture["userId"],
            "unusedTokens": 0,
            "usedTokens": 1,
            "activeRefreshTokens": 0,
        }
        if any(state.get(key) != value for key, value in expected.items()):
            raise ContractFailure("password-reset-result-state-mismatch")
        refresh_ledger = _require_object(
            adapter.invoke("snapshot", "refresh-ledger"), "refresh-ledger"
        )
        revoked_hashes = _digest_set(
            refresh_ledger.get("revokedTokenHashes"),
            "password-reset-refresh-revocation-state-mismatch",
        )
        if (
            refresh_ledger.get("activeRefreshTokens") != 0
            or _digest_set(
                refresh_ledger.get("activeTokenHashes"),
                "password-reset-refresh-revocation-state-mismatch",
            )
            != set()
            or refresh_ledger.get("revokedRefreshTokens") != 2
            or revoked_hashes != original_refresh_hashes
        ):
            raise ContractFailure("password-reset-refresh-revocation-state-mismatch")
        old_password_login = _login(
            confirm_origin,
            fixture,
            fixture["password"],
            timeout,
            False,
            observations,
        )
        _expect_error(
            old_password_login,
            401,
            "INVALID_CREDENTIALS",
            "Invalid email or password",
        )
        revoked_refresh = call(
            confirm_origin,
            "POST",
            "/auth/refresh",
            {"refreshToken": original_refresh},
            timeout,
            observations,
        )
        _expect_error(
            revoked_refresh, 401, "INVALID_REFRESH_TOKEN", "Invalid refresh token"
        )
        second_revoked_refresh = call(
            request_origin,
            "POST",
            "/auth/refresh",
            {"refreshToken": second_refresh},
            timeout,
            observations,
        )
        _expect_error(
            second_revoked_refresh,
            401,
            "INVALID_REFRESH_TOKEN",
            "Invalid refresh token",
        )
        new_login = _login(
            confirm_origin,
            fixture,
            new_password,
            timeout,
            False,
            observations,
        )
        _new_access, new_refresh = _verify_token_pair(
            new_login,
            confirm_origin,
            fixture,
            timeout,
            expected_issuer,
            (consumer_adapter or adapter).refresh_secret,
            observations,
        )
        _token_is_active(_auth_state(consumer_adapter or adapter), new_refresh)
        logout = call(
            confirm_origin,
            "POST",
            "/auth/logout",
            {"refreshToken": new_refresh},
            timeout,
            observations,
        )
        if logout.status != 204 or logout.body is not None:
            raise ContractFailure("logout-contract-mismatch")
        _state_empty(_auth_state(consumer_adapter or adapter))
        replay = call(
            _origin(url, "password reset runtime"),
            "POST",
            "/auth/password-reset/confirm",
            {"token": token, "password": new_password},
            timeout,
            observations,
        )
        _expect_error(
            replay,
            400,
            "INVALID_RESET_TOKEN",
            "Invalid or expired reset token",
        )
        audits = _require_object(
            adapter.invoke("snapshot", "password-reset-audits"),
            "password-reset-audits",
        )
        expected_audits = {
            "requests": 2,
            "confirmationSuccesses": 1,
            "confirmationFailures": 2,
        }
        if any(audits.get(key) != value for key, value in expected_audits.items()):
            raise ContractFailure("password-reset-audit-state-mismatch")
        return {
            "http": {"attempted": len(observations), "passed": len(observations)},
            "mail": {"privateCaptureConsumed": True},
            "state": {"tokenConsumed": True, "refreshTokensRevoked": True},
            "negative": {
                "oldPasswordRejected": True,
                "oldRefreshRejected": True,
                "expiredTokenRejected": True,
                "tokenReplayRejected": True,
            },
            "qualifyingEvidence": False,
        }
    finally:
        adapter.invoke("teardown", "active-password-user")


def _direct(
    url: str,
    adapter: Adapter,
    fixture: dict[str, Any],
    timeout: float,
    expected_issuer: str,
    observations: list[HttpResult],
) -> dict[str, Any]:
    before = _auth_state(adapter)
    _state_empty(before)
    success = _login(url, fixture, fixture["password"], timeout, False, observations)
    _access, refresh = _verify_token_pair(
        success,
        url,
        fixture,
        timeout,
        expected_issuer,
        adapter.refresh_secret,
        observations,
    )
    after_success = _auth_state(adapter)
    _state_delta(before, after_success, 1, 0)
    _token_is_active(after_success, refresh)

    failure = _login(url, fixture, "ContractOnly!wrong", timeout, False, observations)
    _expect_error(failure, 401, "INVALID_CREDENTIALS", "Invalid email or password")
    after_failure = _auth_state(adapter)
    _state_delta(after_success, after_failure, 0, 0)

    logout = call(
        url,
        "POST",
        "/auth/logout",
        {"refreshToken": refresh},
        timeout,
        observations,
    )
    if logout.status != 204 or logout.body is not None:
        raise ContractFailure("logout-contract-mismatch")
    after_logout = _auth_state(adapter)
    _state_delta(after_failure, after_logout, -1, 0)
    replay = call(
        url,
        "POST",
        "/auth/logout",
        {"refreshToken": refresh},
        timeout,
        observations,
    )
    if replay.status != 204 or replay.body is not None:
        raise ContractFailure("logout-replay-contract-mismatch")
    _state_delta(after_logout, _auth_state(adapter), 0, 0)
    return {
        "http": {"attempted": len(observations), "passed": len(observations)},
        "jwt": {
            "accessSignatureVerified": True,
            "accessClaimsVerified": True,
            "refreshClaimsVerified": True,
        },
        "state": {
            "sessionCreated": True,
            "sessionTokenLinked": True,
            "sessionRevoked": True,
        },
        "negative": {"invalidPasswordRejected": True, "logoutReplayIdempotent": True},
    }


def _handoff(
    producer: str,
    consumer: str,
    urls: dict[str, str],
    adapter: Adapter,
    consumer_adapter: Adapter,
    fixture: dict[str, Any],
    timeout: float,
    expected_issuer: str,
    observations: list[HttpResult],
) -> dict[str, Any]:
    before = _auth_state(adapter)
    _state_empty(before)
    invalid = _exchange(
        urls[consumer], fixture, "contract-invalid-code", timeout, observations
    )
    _expect_error(
        invalid,
        400,
        "INVALID_AUTH_HANDOFF_CODE",
        "Invalid authorization code",
    )
    _state_delta(before, _auth_state(adapter), 0, 0)

    issued = _login(
        urls[producer], fixture, fixture["password"], timeout, True, observations
    )
    code = _handoff_code(issued, fixture)
    after_issue = _auth_state(adapter)
    _state_delta(before, after_issue, 0, 1)
    consumed = _exchange(urls[consumer], fixture, code, timeout, observations)
    _access, refresh = _verify_token_pair(
        consumed,
        urls[consumer],
        fixture,
        timeout,
        expected_issuer,
        consumer_adapter.refresh_secret,
        observations,
    )
    after_consume = _auth_state(adapter)
    _state_delta(after_issue, after_consume, 1, -1)
    _token_is_active(after_consume, refresh)
    replay = _exchange(urls[consumer], fixture, code, timeout, observations)
    _expect_error(
        replay,
        400,
        "INVALID_AUTH_HANDOFF_CODE",
        "Invalid authorization code",
    )
    _state_delta(after_consume, _auth_state(adapter), 0, 0)
    return {
        "http": {"attempted": len(observations), "passed": len(observations)},
        "jwt": {
            "accessSignatureVerified": True,
            "accessClaimsVerified": True,
            "refreshClaimsVerified": True,
        },
        "state": {
            "handoffCreated": True,
            "handoffConsumed": True,
            "sessionTokenLinked": True,
        },
        "negative": {"invalidCodeRejected": True, "handoffReplayRejected": True},
    }


def run_trial(
    flow_id: str,
    topology: str,
    urls: dict[str, str],
    adapters: Mapping[str, Adapter],
    timeout: float = 5.0,
    provenance: dict[str, str] | None = None,
    expected_issuer: str = "https://auth.financenow.kr",
) -> dict[str, Any]:
    if flow_id not in FLOWS:
        raise ContractFailure("unknown-flow")
    parts = topology.split("-")
    if any(part not in RUNTIMES for part in parts):
        raise ContractFailure("unknown-topology")
    if flow_id == FLOWS[0] and len(parts) != 1:
        raise ContractFailure("direct-flow-requires-single-runtime-topology")
    if flow_id == FLOWS[1] and len(parts) != 2:
        raise ContractFailure("handoff-flow-requires-producer-consumer-topology")
    if flow_id == FLOWS[1] and parts[0] == parts[1]:
        raise ContractFailure("handoff-flow-requires-cross-runtime-topology")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ContractFailure("timeout-must-be-positive-and-finite")
    validated_provenance = validate_provenance(provenance or {})
    normalized_urls = {
        runtime: _origin(urls[runtime], runtime) for runtime in set(parts)
    }
    if len(parts) == 2 and normalized_urls[parts[0]] == normalized_urls[parts[1]]:
        raise ContractFailure("mixed-topology-requires-distinct-runtime-origins")
    if (
        not isinstance(expected_issuer, str)
        or parse.urlparse(expected_issuer).scheme != "https"
    ):
        raise ContractFailure("expected-issuer-must-be-an-HTTPS-URL")
    participating_adapters = {runtime: adapters[runtime] for runtime in set(parts)}
    if len(parts) == 2:
        identities = {
            adapter.isolation_identity for adapter in participating_adapters.values()
        }
        if len(identities) != 1:
            raise ContractFailure("mixed-topology-requires-shared-isolated-stores")
    lifecycle_runtime = parts[0]
    adapter = adapters[lifecycle_runtime]
    started = time.monotonic_ns()
    trial_id = str(uuid.uuid4())
    observations: list[HttpResult] = []
    evidence: dict[str, Any] = {}
    failure: str | None = None
    cleanup: dict[str, str] = {"outcome": "not-required"}
    setup_started = False
    try:
        for runtime in dict.fromkeys(parts):
            adapters[runtime].invoke("preflight", "flow-driver-v1")
        setup_started = True
        fixture = _require_object(
            adapter.invoke("setup", "active-password-user"), "fixture"
        )
        required = {"userId", "email", "password", "name", "roles", "audience"}
        if flow_id == FLOWS[1]:
            required |= {
                "clientId",
                "redirectUri",
                "state",
                "codeChallenge",
                "codeVerifier",
            }
        if required - fixture.keys():
            raise ContractFailure("malformed-fixture")
        evidence = (
            _direct(
                normalized_urls[parts[0]],
                adapter,
                fixture,
                timeout,
                expected_issuer,
                observations,
            )
            if flow_id == FLOWS[0]
            else _handoff(
                parts[0],
                parts[1],
                normalized_urls,
                adapter,
                adapters[parts[1]],
                fixture,
                timeout,
                expected_issuer,
                observations,
            )
        )
    except (ContractFailure, KeyError, subprocess.SubprocessError, OSError) as exc:
        candidate = str(exc) if isinstance(exc, ContractFailure) else ""
        failure = (
            candidate
            if candidate in PUBLIC_FAILURE_CATEGORIES
            else "runtime-contract-failure"
        )
    finally:
        if setup_started:
            try:
                adapter.invoke("teardown", "active-password-user")
            except (ContractFailure, subprocess.SubprocessError, OSError):
                cleanup = {"outcome": "fail", "category": "fixture-teardown-failure"}
                failure = failure or "fixture-teardown-failure"
            else:
                try:
                    _state_empty(_auth_state(adapter))
                    residual = _require_object(
                        adapter.invoke("snapshot", "fixture-anonymous-audits"),
                        "residual-audit-state",
                    )
                    if residual.get("residualCount") != 0:
                        raise ContractFailure("fixture-residual-audit-mismatch")
                except (ContractFailure, subprocess.SubprocessError, OSError):
                    cleanup = {
                        "outcome": "fail",
                        "category": "fixture-residual-verification-failure",
                    }
                    failure = failure or "fixture-residual-verification-failure"
                else:
                    cleanup = (
                        {
                            "outcome": "not-proven",
                            "category": "post-timeout-mutation-not-excluded",
                        }
                        if failure
                        in {"http-transport-failure", "http-response-read-failure"}
                        else {"outcome": "pass"}
                    )
    ended = time.monotonic_ns()
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "core-flow-trial",
        "flowId": flow_id,
        "fixtureId": "active-password-user",
        "trialId": trial_id,
        "topology": topology,
        "outcome": "pass" if failure is None else "fail",
        "timing": {
            "clock": "monotonic",
            "startedNs": started,
            "endedNs": ended,
            "durationNs": ended - started,
        },
        "attempt": 1,
        "retryCount": 0,
        "provenance": validated_provenance,
        "assertions": evidence,
        "cleanup": cleanup,
        "qualifyingEvidence": False,
    }
    if failure is not None:
        record["error"] = {"category": failure}
    assert_sanitized(record)
    return record


def validate_provenance(provenance: dict[str, str]) -> dict[str, str]:
    if any(key not in SAFE_PROVENANCE for key in provenance):
        raise ContractFailure("unsupported-provenance-key")
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(
            character
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in value
        )
        for value in provenance.values()
    ):
        raise ContractFailure("invalid-provenance-value")
    source_revision = provenance.get("sourceRevision")
    if source_revision is not None and (
        len(source_revision) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in source_revision)
    ):
        raise ContractFailure("sourceRevision-must-be-a-full-lowercase-hex-object-id")
    return dict(provenance)


def assert_sanitized(value: Any, key: str = "") -> None:
    normalized = "".join(character for character in key.lower() if character.isalnum())
    if isinstance(value, str) and any(
        marker in normalized for marker in SENSITIVE_MARKERS
    ):
        raise ContractFailure("sensitive-evidence-field")
    if isinstance(value, dict):
        for item_key, item in value.items():
            assert_sanitized(item, str(item_key))
    elif isinstance(value, list):
        for item in value:
            assert_sanitized(item, key)


def parse_provenance(items: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or []:
        key, separator, value = item.partition("=")
        if not separator or key in result:
            raise ContractFailure("invalid-provenance-argument")
        result[key] = value
    return validate_provenance(result)


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o444)
        os.link(temporary, path)
        temporary.unlink()
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for runtime in RUNTIMES:
        result.add_argument(f"--{runtime}")
        result.add_argument(f"--{runtime}-adapter", type=Path)
        result.add_argument(f"--{runtime}-adapter-config", type=Path)
    result.add_argument("--flow", action="append", choices=(*FLOWS, GOOGLE_FLOW))
    result.add_argument("--topology", action="append")
    result.add_argument("--timeout", type=float, default=5.0)
    result.add_argument("--issuer")
    result.add_argument("--jsonl", type=Path, required=True)
    result.add_argument("--provenance", action="append")
    result.add_argument(
        "--private-mail-launch-config",
        type=Path,
        help="mode-0600 owned-runtime JSON used only for verification/reset flows",
    )
    result.add_argument(
        "--oauth-google-launch-config",
        type=Path,
        help="mode-0600 config for the owned mixed-runtime Google launcher",
    )
    return result


def run_google_dispatch(config: Path) -> dict[str, Any]:
    """Run the fixed owned-runtime launcher and preserve its native result shape."""
    launcher = _load_oauth_launcher()
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        status = launcher.main(["--config", str(config)])
    if status != 0 or not output.getvalue():
        raise ContractFailure("google-owned-launcher-failure")
    lines = output.getvalue().splitlines()
    if len(lines) != 1:
        raise ContractFailure("google-owned-launcher-result-malformed")
    try:
        result = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise ContractFailure("google-owned-launcher-result-malformed") from exc
    if not isinstance(result, dict) or set(result) != {
        "flow",
        "ordering",
        "passed",
        "qualifying",
        "unverified",
        "assertions",
    }:
        raise ContractFailure("google-owned-launcher-result-malformed")
    ordering = result.get("ordering")
    assertions = result.get("assertions")
    if (
        result.get("flow") != GOOGLE_FLOW
        or not isinstance(ordering, str)
        or ordering not in {"express-fastapi", "fastapi-express"}
        or result.get("passed") is not True
        or result.get("qualifying") is not False
        or result.get("unverified") != ["provider-error-state-lifecycle"]
        or not isinstance(assertions, dict)
        or set(assertions) != GOOGLE_ASSERTIONS
        or any(value is not True for value in assertions.values())
    ):
        raise ContractFailure("google-owned-launcher-result-malformed")
    assert_sanitized(result)
    return result


def _load_private_launch_config(path: Path) -> dict[str, Any]:
    document = _read_secure_json(path, "private mail launch config")
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ContractFailure("private mail launch config is malformed")
    if (
        not isinstance(document.get("runId"), str)
        or not isinstance(document.get("recipients"), dict)
        or not isinstance(document.get("runtimes"), dict)
    ):
        raise ContractFailure("private mail launch config is malformed")
    return document


class _RuntimeDirectory:
    """Delete artifacts only after the inner owned launcher exits cleanly."""

    def __init__(self, prefix: str) -> None:
        self.path = Path(tempfile.mkdtemp(prefix=prefix))

    def __enter__(self) -> Path:
        return self.path

    def __exit__(self, exc_type: object, _value: object, _traceback: object) -> None:
        if exc_type is None or not any(self.path.iterdir()):
            shutil.rmtree(self.path)


def run_mail_trial(
    flow_id: str,
    topology: str,
    urls: Mapping[str, str],
    adapters: Mapping[str, Adapter],
    token_source: PrivateMailTokenSource,
    timeout: float,
    provenance: dict[str, str] | None = None,
    expected_issuer: str = "https://auth.financenow.kr",
) -> dict[str, Any]:
    if flow_id not in {
        "email-verification-attach-handoff-exchange",
        "password-reset-session-revoke",
    }:
        raise ContractFailure("unknown-flow")
    parts = topology.split("-")
    if len(parts) not in {1, 2} or any(part not in RUNTIMES for part in parts):
        raise ContractFailure("unknown-topology")
    if len(parts) == 2 and parts[0] == parts[1]:
        raise ContractFailure("mixed-topology-requires-cross-runtime-topology")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ContractFailure("timeout-must-be-positive-and-finite")
    if (
        not isinstance(expected_issuer, str)
        or parse.urlparse(expected_issuer).scheme != "https"
    ):
        raise ContractFailure("expected-issuer-must-be-an-HTTPS-URL")
    validated_provenance = validate_provenance(provenance or {})
    normalized_urls = {
        runtime: _origin(urls[runtime], runtime) for runtime in set(parts)
    }
    if len(parts) == 2 and normalized_urls[parts[0]] == normalized_urls[parts[1]]:
        raise ContractFailure("mixed-topology-requires-distinct-runtime-origins")
    producer = parts[0]
    consumer = parts[1] if len(parts) == 2 else None
    started_ns = time.monotonic_ns()
    assertions: dict[str, Any] = {}
    failure: str | None = None
    cleanup: dict[str, str] = {"outcome": "not-proven"}
    try:
        for runtime in dict.fromkeys(parts):
            adapters[runtime].invoke("preflight", "flow-driver-v1")
        assertions = (
            run_email_verification_flow(
                url=normalized_urls[producer],
                adapter=adapters[producer],
                token_source=token_source,
                timeout=timeout,
                expected_issuer=expected_issuer,
                consumer_url=normalized_urls[consumer] if consumer else None,
                consumer_adapter=adapters[consumer] if consumer else None,
            )
            if flow_id == "email-verification-attach-handoff-exchange"
            else run_password_reset_flow(
                url=normalized_urls[producer],
                adapter=adapters[producer],
                token_source=token_source,
                timeout=timeout,
                expected_issuer=expected_issuer,
                consumer_url=normalized_urls[consumer] if consumer else None,
                consumer_adapter=adapters[consumer] if consumer else None,
            )
        )
    except (ContractFailure, KeyError, subprocess.SubprocessError, OSError) as exc:
        candidate = str(exc) if isinstance(exc, ContractFailure) else ""
        failure = (
            candidate
            if candidate in PUBLIC_FAILURE_CATEGORIES
            else "runtime-contract-failure"
        )
    try:
        for runtime in dict.fromkeys(parts):
            lifecycle_probe = (
                "pending-email-auth-lifecycle"
                if flow_id == "email-verification-attach-handoff-exchange"
                else "auth-lifecycle"
            )
            _state_empty(_auth_state(adapters[runtime], lifecycle_probe))
            residual = _require_object(
                adapters[runtime].invoke("snapshot", "fixture-anonymous-audits"),
                "residual-audit-state",
            )
            if residual.get("residualCount") != 0:
                raise ContractFailure("fixture-residual-audit-mismatch")
    except (ContractFailure, KeyError, subprocess.SubprocessError, OSError):
        cleanup = {
            "outcome": "fail",
            "category": "fixture-residual-verification-failure",
        }
        failure = failure or "fixture-residual-verification-failure"
    else:
        cleanup = (
            {"outcome": "not-proven", "category": "post-timeout-mutation-not-excluded"}
            if failure in {"http-transport-failure", "http-response-read-failure"}
            else {"outcome": "pass"}
        )
    ended_ns = time.monotonic_ns()
    record: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "core-flow-trial",
        "flowId": flow_id,
        "fixtureId": (
            "pending-email-user"
            if flow_id == "email-verification-attach-handoff-exchange"
            else "active-password-user"
        ),
        "trialId": str(uuid.uuid4()),
        "topology": topology,
        "outcome": "pass" if failure is None else "fail",
        "timing": {
            "clock": "monotonic",
            "startedNs": started_ns,
            "endedNs": ended_ns,
            "durationNs": ended_ns - started_ns,
        },
        "attempt": 1,
        "retryCount": 0,
        "provenance": validated_provenance,
        "assertions": assertions,
        "cleanup": cleanup,
        "qualifyingEvidence": False,
    }
    if failure is not None:
        record["error"] = {"category": failure}
    assert_sanitized(record)
    return record


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    records: list[dict[str, Any]] = []
    cleanup_error_type: type[BaseException] | None = None
    try:
        selected_flows = args.flow or list(FLOWS[:2])
        if GOOGLE_FLOW in selected_flows:
            password_arguments = [
                args.express,
                args.express_adapter,
                args.express_adapter_config,
                args.fastapi,
                args.fastapi_adapter,
                args.fastapi_adapter_config,
                args.issuer,
                args.private_mail_launch_config,
            ]
            if (
                selected_flows != [GOOGLE_FLOW]
                or args.oauth_google_launch_config is None
                or args.topology is not None
                or args.provenance is not None
                or any(value is not None for value in password_arguments)
            ):
                raise ContractFailure(
                    "oauth-google requires an exclusive owned-launcher invocation"
                )
            records.append(run_google_dispatch(args.oauth_google_launch_config))
            write_jsonl(args.jsonl, records)
            print("Executed 1 owned mixed-runtime Google trial; 0 failed")
            return 0
        if args.oauth_google_launch_config is not None:
            raise ContractFailure(
                "--oauth-google-launch-config requires --flow oauth-google"
            )
        required_arguments = [
            args.express,
            args.express_adapter,
            args.express_adapter_config,
            args.fastapi,
            args.fastapi_adapter,
            args.fastapi_adapter_config,
            args.issuer,
        ]
        if any(value is None for value in required_arguments):
            raise ContractFailure(
                "password and mail flows require both runtime origins, adapters, "
                "adapter configs, and --issuer"
            )
        urls = {
            runtime: _origin(getattr(args, runtime), runtime) for runtime in RUNTIMES
        }
        adapter_environments = {
            runtime: load_adapter_environment(
                getattr(args, f"{runtime}_adapter_config")
            )
            for runtime in RUNTIMES
        }
        selected_topologies = args.topology or [
            "express",
            "fastapi",
            "express-fastapi",
            "fastapi-express",
        ]
        provenance = parse_provenance(args.provenance)
        private_flows = {
            "email-verification-attach-handoff-exchange",
            "password-reset-session-revoke",
        }
        if private_flows.intersection(selected_flows) and any(
            flow not in private_flows for flow in selected_flows
        ):
            raise ContractFailure(
                "private mail flows must run in a separate CLI invocation"
            )
        if private_flows.intersection(selected_flows):
            if args.private_mail_launch_config is None:
                raise ContractFailure("mail flows require --private-mail-launch-config")
            launch_config = _load_private_launch_config(args.private_mail_launch_config)
            launch_module = _load_mail_launcher()
            cleanup_error_type = launch_module.LaunchCleanupError
            runtime_configs = launch_config["runtimes"]
            specs = []
            protected = {
                "CONTRACT_PRIVATE_MAIL_CAPTURE",
                "CONTRACT_PRIVATE_MAIL_CA_SHA256",
                "CONTRACT_PRIVATE_MAIL_SESSION_CAPABILITY",
                "CONTRACT_PRIVATE_MAIL_SESSION_FILE",
                "CONTRACT_SERVER_MAIL_MODE",
                "MAIL_PROVIDER",
                "NODE_EXTRA_CA_CERTS",
                "SMTP_HOST",
                "SMTP_PASSWORD",
                "SMTP_PORT",
                "SMTP_USERNAME",
                "SSL_CERT_FILE",
            }
            for runtime in RUNTIMES:
                raw = runtime_configs.get(runtime)
                if not isinstance(raw, dict):
                    raise ContractFailure(
                        "private mail launch config omitted a runtime"
                    )
                command = raw.get("command")
                if not isinstance(command, list) or any(
                    not isinstance(value, str) for value in command
                ):
                    raise ContractFailure("private mail runtime command is malformed")
                base_environment = adapter_environments[runtime]
                if (
                    base_environment.get("CONTRACT_SERVER_MAIL_MODE")
                    != "private-loopback-smtp"
                ):
                    raise ContractFailure(
                        "mail flow adapter must explicitly select private-loopback-smtp"
                    )
                specs.append(
                    launch_module.RuntimeSpec.create(
                        name=runtime,
                        command=command,
                        cwd=Path(raw.get("cwd", "")),
                        health_url=raw.get("healthUrl", ""),
                        environment={
                            key: value
                            for key, value in base_environment.items()
                            if key not in protected
                        },
                    )
                )
            with (
                _RuntimeDirectory(prefix="wiseacct-private-mail-") as directory,
                launch_module.PrivateMailFlowLauncher(
                    directory=directory,
                    run_id=launch_config["runId"],
                    recipients=launch_config["recipients"],
                    runtimes=specs,
                    readiness_timeout=args.timeout,
                ) as mail,
            ):
                adapters = {
                    runtime: FixtureAdapter(
                        getattr(args, f"{runtime}_adapter"),
                        adapter_environments[runtime],
                        urls[runtime],
                        mail.binding(runtime),
                    )
                    for runtime in RUNTIMES
                }
                for flow in selected_flows:
                    if flow not in private_flows:
                        continue
                    for topology in selected_topologies:
                        parts = topology.split("-")
                        if any(part not in RUNTIMES for part in parts):
                            continue
                        if len(parts) not in {1, 2}:
                            continue
                        if len(parts) == 2 and parts[0] == parts[1]:
                            continue
                        records.append(
                            run_mail_trial(
                                flow,
                                topology,
                                urls,
                                adapters,
                                mail,
                                args.timeout,
                                provenance,
                                args.issuer,
                            )
                        )
        regular_flows = [flow for flow in selected_flows if flow not in private_flows]
        if regular_flows:
            adapters = {
                runtime: FixtureAdapter(
                    getattr(args, f"{runtime}_adapter"),
                    adapter_environments[runtime],
                    urls[runtime],
                )
                for runtime in RUNTIMES
            }
            for flow in regular_flows:
                for topology in selected_topologies:
                    applicable = (flow == FLOWS[0] and "-" not in topology) or (
                        flow == FLOWS[1] and "-" in topology
                    )
                    if not applicable:
                        continue
                    record = run_trial(
                        flow,
                        topology,
                        urls,
                        adapters,
                        args.timeout,
                        provenance,
                        args.issuer,
                    )
                    records.append(record)
                    if record["outcome"] == "fail":
                        break
                if records and records[-1]["outcome"] == "fail":
                    break
        if not records:
            raise ContractFailure("selection-produced-no-trials")
        write_jsonl(args.jsonl, records)
    except (ContractFailure, OSError, json.JSONDecodeError, RuntimeError) as exc:
        is_cleanup_error = cleanup_error_type is not None and isinstance(
            exc, cleanup_error_type
        )
        if records and is_cleanup_error and not args.jsonl.exists():
            for record in records:
                record["outcome"] = "fail"
                record["cleanup"] = {
                    "outcome": "fail",
                    "category": "owned-runtime-cleanup-failure",
                }
                record["error"] = {"category": "runtime-contract-failure"}
                assert_sanitized(record)
            try:
                write_jsonl(args.jsonl, records)
            except OSError as write_error:
                print(
                    f"ERROR cleanup evidence persistence failed: {write_error}",
                    file=sys.stderr,
                )
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    failures = sum(record["outcome"] == "fail" for record in records)
    print(f"Executed {len(records)} core-flow trial(s); {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
