#!/usr/bin/env python3
"""Execute the first password-flow qualification corpus without producing READY evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import math
import os
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib import error, parse, request

FLOWS = ("password-direct-login-token", "password-handoff-exchange")
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


class ContractFailure(Exception):
    """The requested flow could not be proven."""


class Adapter(Protocol):
    refresh_secret: str
    isolation_identity: tuple[str, str]

    def invoke(self, command: str, name: str) -> Any: ...


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
    def __init__(self, executable: Path, environment: dict[str, str], base_url: str):
        metadata = executable.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or executable.is_symlink()
            or not os.access(executable, os.X_OK)
        ):
            raise ContractFailure("fixture adapter must be an executable regular file")
        required_guards = {
            "CONTRACT_FIXTURE_MODE": "1",
            "CONTRACT_SERVER_MAIL_MODE": "dev",
            "CONTRACT_REDIS_ISOLATED_DB": "1",
        }
        if any(environment.get(key) != value for key, value in required_guards.items()):
            raise ContractFailure("fixture config omitted required isolation guards")
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
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ContractFailure(
            "fixture config must be a regular file with exact mode 0600"
        )
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in document.items()
    ):
        raise ContractFailure("fixture config must contain a flat string JSON object")
    return document


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


def _auth_state(adapter: Adapter) -> dict[str, Any]:
    state = _require_object(adapter.invoke("snapshot", "auth-lifecycle"), "auth-state")
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o444)
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for runtime in RUNTIMES:
        result.add_argument(f"--{runtime}", required=True)
        result.add_argument(f"--{runtime}-adapter", type=Path, required=True)
        result.add_argument(f"--{runtime}-adapter-config", type=Path, required=True)
    result.add_argument("--flow", action="append", choices=FLOWS)
    result.add_argument("--topology", action="append")
    result.add_argument("--timeout", type=float, default=5.0)
    result.add_argument("--issuer", required=True)
    result.add_argument("--jsonl", type=Path, required=True)
    result.add_argument("--provenance", action="append")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        urls = {
            runtime: _origin(getattr(args, runtime), runtime) for runtime in RUNTIMES
        }
        adapters = {
            runtime: FixtureAdapter(
                getattr(args, f"{runtime}_adapter"),
                load_adapter_environment(getattr(args, f"{runtime}_adapter_config")),
                urls[runtime],
            )
            for runtime in RUNTIMES
        }
        selected_flows = args.flow or list(FLOWS)
        selected_topologies = args.topology or [
            "express",
            "fastapi",
            "express-fastapi",
            "fastapi-express",
        ]
        provenance = parse_provenance(args.provenance)
        records: list[dict[str, Any]] = []
        for flow in selected_flows:
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
    except (ContractFailure, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    failures = sum(record["outcome"] == "fail" for record in records)
    print(f"Executed {len(records)} core-flow trial(s); {failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
