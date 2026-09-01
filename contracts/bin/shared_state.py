#!/usr/bin/env python3
"""Black-box shared PostgreSQL/Redis interoperability qualification runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from urllib import error, parse, request

CONTRACTS_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIOS = CONTRACTS_DIR / "scenarios" / "shared-state-core-v1.json"
EXPECTED_SCHEDULES = (
    "express-handoff-fastapi-exchange",
    "fastapi-handoff-express-exchange",
    "express-handoff-mixed-consume-race",
    "fastapi-handoff-mixed-consume-race",
    "mixed-refresh-race",
    "express-logout-fastapi-refresh-race",
    "fastapi-logout-express-refresh-race",
    "alternating-shared-rate-limit-boundary",
    "mixed-simultaneous-shared-rate-limit",
    "mixed-failed-login-race",
)
EXPECTED_SCENARIO_OBJECTS: tuple[dict[str, Any], ...] = (
    {
        "id": "express-handoff-fastapi-exchange",
        "kind": "handoff-cross-runtime",
        "producer": "express",
        "consumer": "fastapi",
    },
    {
        "id": "fastapi-handoff-express-exchange",
        "kind": "handoff-cross-runtime",
        "producer": "fastapi",
        "consumer": "express",
    },
    {
        "id": "express-handoff-mixed-consume-race",
        "kind": "handoff-consume-race",
        "producer": "express",
        "actors": {"express": 10, "fastapi": 10},
    },
    {
        "id": "fastapi-handoff-mixed-consume-race",
        "kind": "handoff-consume-race",
        "producer": "fastapi",
        "actors": {"express": 10, "fastapi": 10},
    },
    {
        "id": "mixed-refresh-race",
        "kind": "refresh-race",
        "actors": {"express": 10, "fastapi": 10},
    },
    {
        "id": "express-logout-fastapi-refresh-race",
        "kind": "logout-refresh-race",
        "producer": "express",
        "logout": "express",
        "refresh": "fastapi",
    },
    {
        "id": "fastapi-logout-express-refresh-race",
        "kind": "logout-refresh-race",
        "producer": "fastapi",
        "logout": "fastapi",
        "refresh": "express",
    },
    {
        "id": "alternating-shared-rate-limit-boundary",
        "kind": "alternating-rate-limit",
        "allowedRequests": 20,
        "limitedRequests": 2,
        "route": "/auth/login",
    },
    {
        "id": "mixed-simultaneous-shared-rate-limit",
        "kind": "simultaneous-rate-limit",
        "prefillRequests": 10,
        "actors": {"express": 10, "fastapi": 10},
        "route": "/auth/login",
    },
    {
        "id": "mixed-failed-login-race",
        "kind": "failed-login-race",
        "actors": {"express": 10, "fastapi": 10},
    },
)
SAFE_ID = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class ContractFailure(Exception):
    """The shared-state contract could not be proven."""


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: Any
    started_ns: int
    ended_ns: int


class _NoRedirectHandler(request.HTTPRedirectHandler):
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


def _local_http_url(value: str, label: str) -> str:
    try:
        parsed = parse.urlparse(value)
        port = parsed.port or 80
    except ValueError as exc:
        raise ContractFailure(f"{label} contains an invalid port") from exc
    if parsed.scheme != "http" or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ContractFailure(f"{label} must be an HTTP loopback URL")
    if (
        parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        raise ContractFailure(f"{label} must be a bare server origin")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"


def _safe_identifier(value: str, label: str) -> str:
    if (
        not value
        or len(value) > 128
        or any(character not in SAFE_ID for character in value)
    ):
        raise ContractFailure(f"{label} contains unsafe characters")
    return value


def call(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> HttpResult:
    data = (
        None
        if body is None
        else json.dumps(body, separators=(",", ":")).encode("utf-8")
    )
    request_headers = dict(headers or {})
    if body is not None:
        request_headers.setdefault("content-type", "application/json")
    req = request.Request(
        f"{base_url}{path}",
        data=data,
        headers=request_headers,
        method=method,
    )
    started_ns = time.monotonic_ns()
    try:
        response = request.build_opener(_NoRedirectHandler()).open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    except (OSError, TimeoutError) as exc:
        raise ContractFailure("HTTP transport failure") from exc
    try:
        with response:
            raw = response.read()
            content_type = response.headers.get("content-type", "")
            if raw and "json" in content_type.lower():
                try:
                    decoded: Any = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ContractFailure(
                        "HTTP response declared invalid JSON"
                    ) from exc
            else:
                decoded = None if not raw else raw.decode("utf-8", errors="replace")
            if response.status >= 500:
                raise ContractFailure("HTTP 5xx response")
            return HttpResult(response.status, decoded, started_ns, time.monotonic_ns())
    except (OSError, TimeoutError) as exc:
        raise ContractFailure("HTTP response read failure") from exc


def error_code(result: HttpResult) -> str | None:
    if not isinstance(result.body, dict):
        return None
    error_body = result.body.get("error")
    return (
        error_body.get("code")
        if isinstance(error_body, dict) and isinstance(error_body.get("code"), str)
        else None
    )


def token_pair(result: HttpResult) -> tuple[str, str]:
    if result.status != 200 or not isinstance(result.body, dict):
        raise ContractFailure("token pair request did not return HTTP 200 JSON")
    access = result.body.get("accessToken")
    refresh = result.body.get("refreshToken")
    if not isinstance(access, str) or len(access.split(".")) != 3:
        raise ContractFailure("token pair omitted a compact access token")
    if not isinstance(refresh, str) or len(refresh.split(".")) != 3:
        raise ContractFailure("token pair omitted a compact refresh token")
    return access, refresh


class FixtureAdapter:
    def __init__(self, executable: Path, environment: dict[str, str], base_url: str):
        self.executable = executable
        self.environment = environment
        self.base_url = base_url

    def invoke(self, command: str, name: str) -> Any:
        env = {**os.environ, **self.environment, "CONTRACT_BASE_URL": self.base_url}
        completed = subprocess.run(
            [str(self.executable), command, name],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise ContractFailure(f"fixture adapter {command} failed")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ContractFailure(
                f"fixture adapter {command} returned invalid JSON"
            ) from exc


def load_adapter_environment(path: Path) -> dict[str, str]:
    if path.is_symlink():
        raise ContractFailure("fixture adapter config must not be a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ContractFailure(
            "fixture adapter config must be a regular file with exact mode 0600"
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw.items()
    ):
        raise ContractFailure(
            "fixture adapter config must be a flat string environment object"
        )
    return raw


def load_scenarios(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise ContractFailure(
            "shared-state scenarios must be a regular non-symlink file"
        )
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "version",
            "suiteId",
            "trialsPerSchedule",
            "fullPhase7SampleSatisfied",
            "overallReplacementReady",
            "scenarios",
        }
        or document.get("version") != 1
    ):
        raise ContractFailure("shared-state scenario document must have version 1")
    if document.get("suiteId") != "shared-state-core-v1":
        raise ContractFailure("unexpected shared-state suite id")
    if document.get("trialsPerSchedule") != 10:
        raise ContractFailure(
            "shared-state core requires exactly 10 trials per schedule"
        )
    if (
        document.get("fullPhase7SampleSatisfied") is not False
        or document.get("overallReplacementReady") is not False
    ):
        raise ContractFailure(
            "shared-state corpus must not claim full Phase 7 or replacement readiness"
        )
    schedules = document.get("scenarios")
    if not isinstance(schedules, list) or schedules != list(EXPECTED_SCENARIO_OBJECTS):
        raise ContractFailure(
            "shared-state schedules or order differ from the approved core"
        )
    return schedules


def _require_fixture(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractFailure("fixture setup returned a non-object")
    return value


def _require_state(value: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or any(field not in value for field in fields):
        raise ContractFailure("fixture snapshot omitted required state")
    return value


def _handoff(
    runtime: str, urls: dict[str, str], fixture: dict[str, Any], timeout: float
) -> str:
    result = call(
        urls[runtime],
        "POST",
        "/auth/login",
        {
            "email": fixture["email"],
            "password": fixture["password"],
            "clientId": fixture["clientId"],
            "redirectUri": fixture["redirectUri"],
            "state": fixture["state"],
            "codeChallenge": fixture["codeChallenge"],
            "codeChallengeMethod": "S256",
        },
        timeout,
    )
    if (
        result.status != 200
        or not isinstance(result.body, dict)
        or not isinstance(result.body.get("redirectUrl"), str)
    ):
        raise ContractFailure("handoff producer did not return HTTP 200 redirectUrl")
    redirect = parse.urlparse(result.body["redirectUrl"])
    if (redirect.scheme, redirect.netloc, redirect.path) != (
        parse.urlparse(fixture["redirectUri"]).scheme,
        parse.urlparse(fixture["redirectUri"]).netloc,
        parse.urlparse(fixture["redirectUri"]).path,
    ):
        raise ContractFailure("handoff redirect target changed")
    query = parse.parse_qs(redirect.query, keep_blank_values=True)
    if (
        query.get("state") != [fixture["state"]]
        or len(query.get("code", [])) != 1
        or not query["code"][0]
    ):
        raise ContractFailure("handoff redirect omitted exact state or code")
    return query["code"][0]


def _exchange(
    runtime: str,
    urls: dict[str, str],
    fixture: dict[str, Any],
    code: str,
    timeout: float,
) -> HttpResult:
    return call(
        urls[runtime],
        "POST",
        "/auth/exchange",
        {
            "clientId": fixture["clientId"],
            "redirectUri": fixture["redirectUri"],
            "code": code,
            "codeVerifier": fixture["codeVerifier"],
        },
        timeout,
    )


def _login(
    runtime: str,
    urls: dict[str, str],
    fixture: dict[str, Any],
    password: str,
    timeout: float,
) -> HttpResult:
    return call(
        urls[runtime],
        "POST",
        "/auth/login",
        {"email": fixture["email"], "password": password},
        timeout,
    )


def _parallel(
    actors: list[tuple[str, Callable[[], HttpResult]]],
) -> list[tuple[str, HttpResult]]:
    barrier = threading.Barrier(len(actors) + 1, timeout=10)

    def invoke(
        runtime: str, operation: Callable[[], HttpResult]
    ) -> tuple[str, HttpResult]:
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:
            raise ContractFailure("concurrency barrier broke") from exc
        return runtime, operation()

    with ThreadPoolExecutor(
        max_workers=len(actors), thread_name_prefix="shared-state"
    ) as pool:
        futures = [
            pool.submit(invoke, runtime, operation) for runtime, operation in actors
        ]
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:
            raise ContractFailure("concurrency barrier broke") from exc
        results = [future.result() for future in futures]
    assert_request_lifetime_overlap(results)
    return results


def assert_request_lifetime_overlap(results: list[tuple[str, HttpResult]]) -> None:
    """Prove at least one mixed-runtime HTTP lifetime overlap, not store overlap."""
    if len(results) < 2:
        raise ContractFailure("parallel schedule requires at least two actors")
    if any(result.started_ns >= result.ended_ns for _runtime, result in results):
        raise ContractFailure("parallel actor returned an invalid monotonic interval")
    express = [result for runtime, result in results if runtime == "express"]
    fastapi = [result for runtime, result in results if runtime == "fastapi"]
    if not express or not fastapi:
        raise ContractFailure("parallel schedule omitted one runtime")
    overlaps = any(
        max(express_result.started_ns, fastapi_result.started_ns)
        < min(express_result.ended_ns, fastapi_result.ended_ns)
        for express_result in express
        for fastapi_result in fastapi
    )
    if not overlaps:
        raise ContractFailure("mixed-runtime HTTP request lifetimes did not overlap")


def _actor_summary(results: list[tuple[str, HttpResult]]) -> dict[str, Any]:
    by_runtime: dict[str, dict[str, int]] = {}
    for runtime, result in results:
        runtime_counts = by_runtime.setdefault(runtime, {})
        key = str(result.status)
        runtime_counts[key] = runtime_counts.get(key, 0) + 1
    return {"total": len(results), "statusByRuntime": by_runtime}


def _verify_me(
    runtime: str, urls: dict[str, str], access_token: str, timeout: float
) -> None:
    result = call(
        urls[runtime],
        "GET",
        "/users/me",
        None,
        timeout,
        {"authorization": f"Bearer {access_token}"},
    )
    if result.status != 200:
        raise ContractFailure("access token was not accepted by both runtimes")


def _token_ledger_link(
    state: dict[str, Any],
    refresh_token: str,
    *,
    original_token: str | None = None,
) -> None:
    refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
    if state.get("activeTokenHashes") != [refresh_hash]:
        raise ContractFailure(
            "returned refresh token is not the sole active ledger token"
        )
    if original_token is not None:
        original_hash = hashlib.sha256(original_token.encode("utf-8")).hexdigest()
        if state.get("revokedTokenHashes") != [original_hash]:
            raise ContractFailure(
                "original refresh token is not the sole revoked ledger token"
            )


def run_schedule(
    schedule: dict[str, Any],
    urls: dict[str, str],
    adapter: FixtureAdapter,
    timeout: float,
) -> dict[str, Any]:
    kind = schedule["kind"]
    if kind == "handoff-cross-runtime":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        code = _handoff(schedule["producer"], urls, fixture, timeout)
        first = _exchange(schedule["consumer"], urls, fixture, code, timeout)
        access, handoff_refresh = token_pair(first)
        replay = _exchange(schedule["producer"], urls, fixture, code, timeout)
        if replay.status != 400 or error_code(replay) != "INVALID_AUTH_HANDOFF_CODE":
            raise ContractFailure("handoff replay did not fail generically")
        _verify_me("express", urls, access, timeout)
        _verify_me("fastapi", urls, access, timeout)
        state = _require_state(
            adapter.invoke("snapshot", "auth-lifecycle"),
            ("activeRefreshTokens", "authHandoffKeys", "activeTokenHashes"),
        )
        if state["activeRefreshTokens"] != 1 or state["authHandoffKeys"] != 0:
            raise ContractFailure("cross-runtime handoff left invalid shared state")
        _token_ledger_link(state, handoff_refresh)
        return {
            "http": {"exchange200": 1, "replay400": 1, "me200": 2},
            "winnerRuntime": schedule["consumer"],
            "activeRefreshLinked": True,
            "stateCounts": {"active": 1, "handoffKeys": 0},
        }

    if kind == "handoff-consume-race":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        code = _handoff(schedule["producer"], urls, fixture, timeout)
        actors: list[tuple[str, Callable[[], HttpResult]]] = []
        for runtime, count in schedule["actors"].items():
            runtime_name = str(runtime)
            for _ in range(count):
                actors.append(
                    (
                        runtime_name,
                        partial(_exchange, runtime_name, urls, fixture, code, timeout),
                    )
                )
        results = _parallel(actors)
        successes = [
            (runtime, result) for runtime, result in results if result.status == 200
        ]
        failures = [
            result
            for _runtime, result in results
            if result.status == 400
            and error_code(result) == "INVALID_AUTH_HANDOFF_CODE"
        ]
        if len(successes) != 1 or len(failures) != 19:
            raise ContractFailure(
                "handoff race did not have exactly one winner and nineteen generic failures"
            )
        winner_runtime, winner = successes[0]
        access, winner_refresh = token_pair(winner)
        _verify_me("express", urls, access, timeout)
        _verify_me("fastapi", urls, access, timeout)
        state = _require_state(
            adapter.invoke("snapshot", "auth-lifecycle"),
            ("activeRefreshTokens", "authHandoffKeys", "activeTokenHashes"),
        )
        if state["activeRefreshTokens"] != 1 or state["authHandoffKeys"] != 0:
            raise ContractFailure("handoff race left invalid shared state")
        _token_ledger_link(state, winner_refresh)
        return {
            "actors": _actor_summary(results),
            "winnerCount": 1,
            "winnerRuntime": winner_runtime,
            "activeRefreshLinked": True,
            "mixedRuntimeRequestLifetimeOverlap": True,
            "stateCounts": {"active": 1, "handoffKeys": 0},
        }

    if kind == "refresh-race":
        fixture = _require_fixture(adapter.invoke("setup", "active-user-refresh-hs256"))
        refresh_token = fixture.get("refreshToken")
        if not isinstance(refresh_token, str):
            raise ContractFailure("refresh fixture omitted token")
        actors = []
        for runtime, count in schedule["actors"].items():
            runtime_name = str(runtime)
            for _ in range(count):
                actors.append(
                    (
                        runtime_name,
                        partial(
                            call,
                            urls[runtime_name],
                            "POST",
                            "/auth/refresh",
                            {"refreshToken": refresh_token},
                            timeout,
                        ),
                    )
                )
        results = _parallel(actors)
        successes = [
            (runtime, result) for runtime, result in results if result.status == 200
        ]
        failures = [
            result
            for _runtime, result in results
            if result.status == 401 and error_code(result) == "INVALID_REFRESH_TOKEN"
        ]
        if len(successes) != 1 or len(failures) != 19:
            raise ContractFailure(
                "refresh race did not have exactly one rotation winner"
            )
        winner_runtime, winner = successes[0]
        access, rotated_refresh = token_pair(winner)
        _verify_me("express", urls, access, timeout)
        _verify_me("fastapi", urls, access, timeout)
        state = _require_state(
            adapter.invoke("snapshot", "refresh-ledger"),
            (
                "activeRefreshTokens",
                "revokedRefreshTokens",
                "activeTokenHashes",
                "revokedTokenHashes",
            ),
        )
        if state["activeRefreshTokens"] != 1 or state["revokedRefreshTokens"] != 1:
            raise ContractFailure(
                "refresh race ledger did not contain one revoked original and one replacement"
            )
        _token_ledger_link(state, rotated_refresh, original_token=refresh_token)
        return {
            "actors": _actor_summary(results),
            "stateCounts": {"active": 1, "revoked": 1},
            "winnerCount": 1,
            "winnerRuntime": winner_runtime,
            "activeRefreshLinked": True,
            "originalRefreshRevoked": True,
            "mixedRuntimeRequestLifetimeOverlap": True,
        }

    if kind == "logout-refresh-race":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        _access, refresh_token = token_pair(
            _login(schedule["producer"], urls, fixture, fixture["password"], timeout)
        )
        results = _parallel(
            [
                (
                    schedule["logout"],
                    lambda: call(
                        urls[schedule["logout"]],
                        "POST",
                        "/auth/logout",
                        {"refreshToken": refresh_token},
                        timeout,
                    ),
                ),
                (
                    schedule["refresh"],
                    lambda: call(
                        urls[schedule["refresh"]],
                        "POST",
                        "/auth/refresh",
                        {"refreshToken": refresh_token},
                        timeout,
                    ),
                ),
            ]
        )
        by_runtime = {runtime: result for runtime, result in results}
        logout_result = by_runtime[schedule["logout"]]
        refresh_result = by_runtime[schedule["refresh"]]
        if logout_result.status != 204 or refresh_result.status not in {200, 401}:
            raise ContractFailure("logout/refresh race returned an unsupported outcome")
        if (
            refresh_result.status == 401
            and error_code(refresh_result) != "INVALID_REFRESH_TOKEN"
        ):
            raise ContractFailure(
                "logout/refresh loser did not return the generic refresh error"
            )
        logout_replacement: str | None = None
        if refresh_result.status == 200:
            access, logout_replacement = token_pair(refresh_result)
            _verify_me("express", urls, access, timeout)
            _verify_me("fastapi", urls, access, timeout)
        replay = call(
            urls[schedule["refresh"]],
            "POST",
            "/auth/refresh",
            {"refreshToken": refresh_token},
            timeout,
        )
        if replay.status != 401 or error_code(replay) != "INVALID_REFRESH_TOKEN":
            raise ContractFailure(
                "logout/refresh original token replay was not rejected"
            )
        state = _require_state(
            adapter.invoke("snapshot", "refresh-ledger"),
            (
                "activeRefreshTokens",
                "revokedRefreshTokens",
                "activeTokenHashes",
                "revokedTokenHashes",
            ),
        )
        expected_active = 1 if refresh_result.status == 200 else 0
        if (
            state["activeRefreshTokens"] != expected_active
            or state["revokedRefreshTokens"] != 1
        ):
            raise ContractFailure("logout/refresh race left extra or missing tokens")
        original_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        if state["revokedTokenHashes"] != [original_hash]:
            raise ContractFailure(
                "logout/refresh original token is not the sole revoked token"
            )
        if logout_replacement is not None:
            _token_ledger_link(state, logout_replacement, original_token=refresh_token)
        elif state["activeTokenHashes"] != []:
            raise ContractFailure(
                "logout-winning race retained an active refresh token"
            )
        return {
            "actors": _actor_summary(results),
            "refreshWon": refresh_result.status == 200,
            "stateCounts": {"active": expected_active, "revoked": 1},
            "activeRefreshLinked": refresh_result.status == 200,
            "originalRefreshRevoked": True,
            "originalReplayRejected": True,
            "mixedRuntimeRequestLifetimeOverlap": True,
        }

    if kind == "alternating-rate-limit":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        invalid_password = "ContractOnly!wrong"
        statuses: list[tuple[str, HttpResult]] = []
        total = schedule["allowedRequests"] + schedule["limitedRequests"]
        for index in range(total):
            runtime = "express" if index % 2 == 0 else "fastapi"
            statuses.append(
                (runtime, _login(runtime, urls, fixture, invalid_password, timeout))
            )
        if [result.status for _runtime, result in statuses[:20]] != [401] * 20:
            raise ContractFailure(
                "alternating rate limit blocked before the approved boundary"
            )
        if any(
            result.status != 429 or error_code(result) != "RATE_LIMITED"
            for _runtime, result in statuses[20:]
        ):
            raise ContractFailure(
                "alternating rate limit did not block both runtimes after the boundary"
            )
        state = _require_state(
            adapter.invoke("snapshot", "shared-rate-limit"),
            ("keyCount", "counters", "ttls"),
        )
        if (
            state["keyCount"] != 1
            or state["counters"] != [22]
            or len(state["ttls"]) != 1
            or state["ttls"][0] <= 0
        ):
            raise ContractFailure(
                "alternating rate limit did not share one live exact counter"
            )
        return {"actors": _actor_summary(statuses), "state": state}

    if kind == "simultaneous-rate-limit":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        invalid_password = "ContractOnly!wrong"
        prefill = [
            (
                "express" if index % 2 == 0 else "fastapi",
                _login(
                    "express" if index % 2 == 0 else "fastapi",
                    urls,
                    fixture,
                    invalid_password,
                    timeout,
                ),
            )
            for index in range(schedule["prefillRequests"])
        ]
        if any(
            result.status != 401 or error_code(result) != "INVALID_CREDENTIALS"
            for _runtime, result in prefill
        ):
            raise ContractFailure(
                "simultaneous limiter prefill did not reach the exact boundary"
            )
        actors = []
        for runtime, count in schedule["actors"].items():
            runtime_name = str(runtime)
            for _ in range(count):
                actors.append(
                    (
                        runtime_name,
                        partial(
                            _login,
                            runtime_name,
                            urls,
                            fixture,
                            invalid_password,
                            timeout,
                        ),
                    )
                )
        raced = _parallel(actors)
        allowed = [
            result
            for _runtime, result in raced
            if result.status == 401 and error_code(result) == "INVALID_CREDENTIALS"
        ]
        limited = [
            result
            for _runtime, result in raced
            if result.status == 429 and error_code(result) == "RATE_LIMITED"
        ]
        if len(allowed) != 10 or len(limited) != 10:
            raise ContractFailure(
                "simultaneous limiter did not apply the same boundary to both runtimes"
            )
        state = _require_state(
            adapter.invoke("snapshot", "shared-rate-limit"),
            ("keyCount", "counters", "ttls"),
        )
        if (
            state["keyCount"] != 1
            or state["counters"] != [30]
            or len(state["ttls"]) != 1
            or state["ttls"][0] <= 0
        ):
            raise ContractFailure(
                "simultaneous limiter did not preserve one exact shared counter"
            )
        return {
            "prefill": _actor_summary(prefill),
            "actors": _actor_summary(raced),
            "state": state,
            "allowedCount": 10,
            "limitedCount": 10,
            "mixedRuntimeRequestLifetimeOverlap": True,
        }

    if kind == "failed-login-race":
        fixture = _require_fixture(adapter.invoke("setup", "active-password-user"))
        actors = []
        for runtime, count in schedule["actors"].items():
            runtime_name = str(runtime)
            for _ in range(count):
                actors.append(
                    (
                        runtime_name,
                        partial(
                            _login,
                            runtime_name,
                            urls,
                            fixture,
                            "ContractOnly!wrong",
                            timeout,
                        ),
                    )
                )
        results = _parallel(actors)
        if any(
            result.status != 401 or error_code(result) != "INVALID_CREDENTIALS"
            for _runtime, result in results
        ):
            raise ContractFailure(
                "failed-login race did not return twenty generic credential failures"
            )
        state = _require_state(
            adapter.invoke("snapshot", "failed-login-ledger"),
            ("failedLoginCount", "lockSet", "activeRefreshTokens"),
        )
        failed_count = state["failedLoginCount"]
        if (
            not isinstance(failed_count, int)
            or isinstance(failed_count, bool)
            or not 5 <= failed_count <= 20
            or state["lockSet"] is not True
            or state["activeRefreshTokens"] != 0
        ):
            raise ContractFailure(
                "failed-login ingress smoke did not reach a valid locked credential state"
            )
        return {
            "actors": _actor_summary(results),
            "state": state,
            "mixedRuntimeRequestLifetimeOverlap": True,
            "allRequestsObservedPreLock": False,
        }

    raise ContractFailure("unknown shared-state schedule kind")


def _error_evidence(exc: Exception) -> dict[str, str]:
    message = str(exc)
    return {
        "kind": "contract-failure",
        "sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
    }


def assert_sanitized(value: Any, path: str = "$") -> None:
    """Reject accidental credential, token, URL, or email material in evidence."""
    forbidden_keys = {
        "accessToken",
        "refreshToken",
        "authorization",
        "code",
        "codeVerifier",
        "email",
        "password",
        "redirectUrl",
        "secret",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if key in forbidden_keys:
                raise ContractFailure(
                    f"evidence contains forbidden field at {path}.{key}"
                )
            assert_sanitized(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            assert_sanitized(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        if "@" in value or value.startswith(("http://", "https://", "Bearer ")):
            raise ContractFailure(f"evidence contains sensitive-shaped text at {path}")
        segments = value.split(".")
        if (
            len(segments) == 3
            and len(segments[0]) >= 8
            and len(segments[1]) >= 8
            and len(segments[2]) >= 8
        ):
            raise ContractFailure(f"evidence contains token-shaped text at {path}")


def execute(
    schedules: list[dict[str, Any]],
    urls: dict[str, str],
    adapter: FixtureAdapter,
    timeout: float,
    run_id: str,
    source_revision: str,
) -> tuple[list[dict[str, Any]], bool]:
    records: list[dict[str, Any]] = []
    halted = False
    try:
        adapter.invoke("preflight", "shared-state-core-v1")
        preflight_failure: Exception | None = None
    except Exception as exc:  # noqa: BLE001 - evidence must fail closed for any adapter defect
        preflight_failure = exc
        halted = True
    for schedule in schedules:
        for trial in range(1, 11):
            record: dict[str, Any] = {
                "schemaVersion": 1,
                "kind": "shared-state-trial",
                "suiteId": "shared-state-core-v1",
                "scheduleId": schedule["id"],
                "trial": trial,
                "attempt": 1,
                "retryCount": 0,
                "runId": run_id,
                "sourceRevision": source_revision,
                "fullPhase7SampleSatisfied": False,
                "overallReplacementReady": False,
            }
            if halted:
                record["outcome"] = "NOT_RUN"
                if preflight_failure is not None:
                    record["notRunReason"] = "preflight-failed"
                    record["error"] = _error_evidence(preflight_failure)
                    preflight_failure = None
                else:
                    record["notRunReason"] = "fail-fast"
                records.append(record)
                continue
            try:
                evidence = run_schedule(schedule, urls, adapter, timeout)
                record["outcome"] = "PASS"
                record["evidence"] = evidence
            except Exception as exc:  # noqa: BLE001 - any schedule defect is a contract failure
                record["outcome"] = "FAIL"
                record["error"] = _error_evidence(exc)
                halted = True
            finally:
                try:
                    adapter.invoke("teardown", schedule["id"])
                    residual = _require_state(
                        adapter.invoke("snapshot", "fixture-anonymous-audits"),
                        ("residualCount",),
                    )
                    if residual["residualCount"] != 0:
                        raise ContractFailure(
                            "fixture-owned anonymous audit rows remained after teardown"
                        )
                except Exception as exc:  # noqa: BLE001 - teardown defects fail the gate closed
                    if record.get("outcome") == "PASS":
                        record.pop("evidence", None)
                        record["outcome"] = "FAIL"
                        record["error"] = _error_evidence(exc)
                    halted = True
            records.append(record)
    passed = (
        not halted
        and len(records) == 100
        and all(record["outcome"] == "PASS" for record in records)
    )
    assert_sanitized(records)
    return records, passed


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True))
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
    result.add_argument("--express", required=True, help="isolated Express origin")
    result.add_argument("--fastapi", required=True, help="isolated FastAPI origin")
    result.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS)
    result.add_argument("--fixture-adapter", type=Path, required=True)
    result.add_argument("--fixture-config", type=Path, required=True)
    result.add_argument("--jsonl", type=Path, required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--timeout", type=float, default=10.0)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.timeout <= 0 or args.timeout > 60:
            raise ContractFailure(
                "timeout must be greater than zero and at most 60 seconds"
            )
        run_id = _safe_identifier(args.run_id, "run id")
        source_revision = _safe_identifier(args.source_revision, "source revision")
        urls = {
            "express": _local_http_url(args.express, "--express"),
            "fastapi": _local_http_url(args.fastapi, "--fastapi"),
        }
        if urls["express"] == urls["fastapi"]:
            raise ContractFailure("Express and FastAPI origins must be distinct")
        scenarios = load_scenarios(args.scenarios)
        environment = load_adapter_environment(args.fixture_config)
        if (
            args.fixture_adapter.is_symlink()
            or not args.fixture_adapter.is_file()
            or not os.access(args.fixture_adapter, os.X_OK)
        ):
            raise ContractFailure(
                "fixture adapter must be an executable regular non-symlink file"
            )
        adapter = FixtureAdapter(
            args.fixture_adapter.resolve(), environment, urls["express"]
        )
        records, passed = execute(
            scenarios, urls, adapter, args.timeout, run_id, source_revision
        )
        write_jsonl(args.jsonl, records)
    except (
        ContractFailure,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    summary = {
        "suiteId": "shared-state-core-v1",
        "status": "PASS" if passed else "FAIL",
        "plannedTrials": 100,
        "passedTrials": sum(record["outcome"] == "PASS" for record in records),
        "failedTrials": sum(record["outcome"] == "FAIL" for record in records),
        "notRunTrials": sum(record["outcome"] == "NOT_RUN" for record in records),
        "fullPhase7SampleSatisfied": False,
        "overallReplacementReady": False,
    }
    print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
