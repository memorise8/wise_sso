#!/usr/bin/env python3
"""Black-box HTTP contract comparison for the SSO migration."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib import error, parse, request

CONTRACTS_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIOS = CONTRACTS_DIR / "scenarios" / "public.json"
PREDICATE_KEY = "$predicate"
ALLOW_EXTRA_KEY = "$allowExtra"
SAFE_PROVENANCE_KEYS = {
    "baselineImageDigest",
    "baselineRuntime",
    "candidateImageDigest",
    "candidateRuntime",
    "corpusHash",
    "harnessRevision",
    "runId",
    "scenarioHash",
    "schedule",
    "seed",
    "sourceRevision",
    "startedAt",
    "topology",
}


class ContractFailure(Exception):
    """A response did not satisfy its declared contract."""


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: Any


class _NoRedirectHandler(request.HTTPRedirectHandler):
    """Return redirects to the caller instead of following them."""

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


def _decode_json(raw: bytes, content_type: str) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8")
    if "json" in content_type.lower():
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ContractFailure(f"response declared JSON but could not be decoded: {exc}") from exc
    return text


def call(base_url: str, request_spec: dict[str, Any], timeout: float) -> HttpResult:
    method = request_spec.get("method", "GET").upper()
    path = request_spec["path"]
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    headers = {str(key): str(value) for key, value in request_spec.get("headers", {}).items()}
    data = None
    if "json" in request_spec:
        data = json.dumps(request_spec["json"], separators=(",", ":")).encode("utf-8")
        headers.setdefault("content-type", "application/json")

    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        if request_spec.get("followRedirects", True):
            response = request.urlopen(req, timeout=timeout)
        else:
            response = request.build_opener(_NoRedirectHandler()).open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc
    except TimeoutError as exc:
        raise ContractFailure("HTTP request timed out") from exc
    except OSError as exc:
        raise ContractFailure("HTTP request failed") from exc

    try:
        with response:
            raw = response.read()
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            body = _decode_json(raw, response_headers.get("content-type", ""))
            return HttpResult(status=response.status, headers=response_headers, body=body)
    except TimeoutError as exc:
        raise ContractFailure("HTTP response read timed out") from exc
    except OSError as exc:
        raise ContractFailure("HTTP response read failed") from exc


def _base64url_json(segment: str, path: str) -> Any:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractFailure(f"{path}: invalid JWT segment") from exc


def _predicate(value: Any, spec: dict[str, Any], path: str, captures: dict[str, Any]) -> Any:
    name = spec[PREDICATE_KEY]
    if name == "any":
        return value
    if name == "nonempty-string":
        if not isinstance(value, str) or not value:
            raise ContractFailure(f"{path}: expected a non-empty string")
        return value
    if name == "uuid":
        try:
            uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ContractFailure(f"{path}: expected a UUID") from exc
        return value
    if name == "timestamp":
        valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        if isinstance(value, str):
            try:
                dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
                valid = True
            except ValueError:
                valid = False
        if not valid:
            raise ContractFailure(f"{path}: expected a numeric or ISO-8601 timestamp")
        return value
    if name == "url":
        parsed = parse.urlparse(value) if isinstance(value, str) else None
        if not parsed or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ContractFailure(f"{path}: expected an absolute HTTP(S) URL")
        return value
    if name == "jwt":
        if not isinstance(value, str) or len(value.split(".")) != 3:
            raise ContractFailure(f"{path}: expected a compact JWT")
        header_segment, claims_segment, _signature = value.split(".")
        header = _base64url_json(header_segment, f"{path}.header")
        claims = _base64url_json(claims_segment, f"{path}.claims")
        normalized: dict[str, Any] = {"token": "<jwt>"}
        if "header" in spec:
            normalized["header"] = match(header, spec["header"], f"{path}.header", captures)
        if "claims" in spec:
            normalized["claims"] = match(claims, spec["claims"], f"{path}.claims", captures)
        normalized["token"] = value
        return normalized
    raise ContractFailure(f"{path}: unknown predicate {name!r}")


def match(value: Any, expected: Any, path: str = "$", captures: dict[str, Any] | None = None) -> Any:
    """Validate a value and return its deterministic comparison form."""
    captures = captures if captures is not None else {}
    if isinstance(expected, dict) and "$url" in expected:
        spec = expected["$url"]
        actual_url = parse.urlparse(value) if isinstance(value, str) else None
        expected_url = parse.urlparse(spec["base"])
        if not actual_url or (actual_url.scheme, actual_url.netloc, actual_url.path, actual_url.params, actual_url.fragment) != (
            expected_url.scheme, expected_url.netloc, expected_url.path, expected_url.params, expected_url.fragment
        ):
            raise ContractFailure(f"{path}: URL base does not match {spec['base']!r}")
        actual_query = parse.parse_qs(actual_url.query, keep_blank_values=True)
        flattened_query = {
            key: values[0] if len(values) == 1 else values
            for key, values in actual_query.items()
        }
        return {
            "base": spec["base"],
            "query": match(flattened_query, spec.get("query", {}), f"{path}.query", captures),
        }
    if isinstance(expected, dict) and "$equalsCapture" in expected:
        name = expected["$equalsCapture"]
        if name not in captures:
            raise ContractFailure(f"{path}: capture {name!r} has not been defined")
        if value != captures[name]:
            raise ContractFailure(f"{path}: value does not equal capture {name!r}")
        return f"<capture:{name}>"
    if isinstance(expected, dict) and "$capture" in expected:
        name = expected["$capture"]
        validation = {key: item for key, item in expected.items() if key != "$capture"}
        if validation:
            if PREDICATE_KEY in validation:
                _predicate(value, validation, path, captures)
            else:
                match(value, validation, path, captures)
        if name in captures and captures[name] != value:
            raise ContractFailure(f"{path}: repeated capture {name!r} changed")
        captures[name] = value
        return f"<capture:{name}>"
    if isinstance(expected, dict) and PREDICATE_KEY in expected:
        return _predicate(value, expected, path, captures)

    if isinstance(expected, dict):
        if not isinstance(value, dict):
            raise ContractFailure(f"{path}: expected an object")
        expected_keys = {key for key in expected if key != ALLOW_EXTRA_KEY}
        missing = expected_keys - value.keys()
        if missing:
            raise ContractFailure(f"{path}: missing fields {sorted(missing)}")
        if not expected.get(ALLOW_EXTRA_KEY, False):
            extra = value.keys() - expected_keys
            if extra:
                raise ContractFailure(f"{path}: unexpected fields {sorted(extra)}")
        return {
            key: match(value[key], expected[key], f"{path}.{key}", captures)
            for key in sorted(expected_keys)
        }

    if isinstance(expected, list):
        if not isinstance(value, list):
            raise ContractFailure(f"{path}: expected an array")
        if len(value) != len(expected):
            raise ContractFailure(f"{path}: expected {len(expected)} items, got {len(value)}")
        return [match(item, item_expected, f"{path}[{index}]", captures) for index, (item, item_expected) in enumerate(zip(value, expected))]

    if value != expected or type(value) is not type(expected):
        raise ContractFailure(f"{path}: expected {expected!r}, got {value!r}")
    return value


def normalize_response(result: HttpResult, expect: dict[str, Any], captures: dict[str, Any] | None = None) -> dict[str, Any]:
    captures = captures if captures is not None else {}
    if result.status != expect["status"]:
        raise ContractFailure(f"$.status: expected {expect['status']}, got {result.status}")
    normalized: dict[str, Any] = {"status": result.status}
    if "headers" in expect:
        normalized["headers"] = match(result.headers, {**expect["headers"], ALLOW_EXTRA_KEY: True}, "$.headers", captures)
    if "json" in expect:
        normalized["json"] = match(result.body, expect["json"], "$.json", captures)
    elif "body" in expect:
        normalized["body"] = match(result.body, expect["body"], "$.body", captures)
    return normalized


def resolve_fixture(value: Any, fixture: dict[str, Any]) -> Any:
    if isinstance(value, dict) and set(value) == {"$fixture"}:
        key = value["$fixture"]
        if key not in fixture:
            raise ContractFailure(f"fixture did not provide {key!r}")
        return fixture[key]
    if isinstance(value, dict):
        return {key: resolve_fixture(item, fixture) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_fixture(item, fixture) for item in value]
    return value


def resolve_runtime(value: Any, fixture: dict[str, Any], captures: dict[str, Any]) -> Any:
    value = resolve_fixture(value, fixture)
    if isinstance(value, dict) and set(value) == {"$captureValue"}:
        capture_name = value["$captureValue"]
        if capture_name not in captures:
            raise ContractFailure(f"capture {capture_name!r} is unavailable")
        return captures[capture_name]
    if isinstance(value, dict) and set(value) == {"$captureQuery"}:
        spec = value["$captureQuery"]
        capture_name = spec["capture"]
        if capture_name not in captures or not isinstance(captures[capture_name], str):
            raise ContractFailure(f"URL capture {capture_name!r} is unavailable")
        query_values = parse.parse_qs(parse.urlparse(captures[capture_name]).query, keep_blank_values=True)
        values = query_values.get(spec["name"], [])
        if len(values) != 1 or not values[0]:
            raise ContractFailure(f"capture {capture_name!r} does not have one non-empty {spec['name']!r} query value")
        return values[0]
    if isinstance(value, dict):
        return {key: resolve_runtime(item, fixture, captures) for key, item in value.items()}
    if isinstance(value, list):
        return [resolve_runtime(item, fixture, captures) for item in value]
    return value


class FixtureAdapter:
    """Language-neutral subprocess adapter; stdout is one JSON value per invocation."""

    def __init__(self, executable: Path, base_url: str, environment: dict[str, str] | None = None):
        self.executable = executable
        self.base_url = base_url
        self.environment = environment or {}

    def invoke(self, command: str, name: str) -> Any:
        env = {**os.environ, **self.environment, "CONTRACT_BASE_URL": self.base_url}
        try:
            completed = subprocess.run(
                [str(self.executable), command, name],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ContractFailure(f"adapter {command} timed out") from exc
        except (subprocess.SubprocessError, OSError) as exc:
            raise ContractFailure(f"adapter {command} invocation failed") from exc
        if completed.returncode != 0:
            raise ContractFailure(f"adapter {command} failed with exit code {completed.returncode}")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ContractFailure(f"adapter {command} {name!r} returned invalid JSON") from exc

    def setup(self, fixture: str) -> dict[str, Any]:
        result = self.invoke("setup", fixture)
        if not isinstance(result, dict):
            raise ContractFailure("adapter setup must return a JSON object")
        return result

    def preflight(self, fixture: str) -> None:
        self.invoke("preflight", fixture)

    def snapshot(self, probe: str) -> Any:
        return self.invoke("snapshot", probe)

    def teardown(self, fixture: str) -> None:
        self.invoke("teardown", fixture)


def _json_path(value: Any, path: str) -> Any:
    if not path.startswith("$."):
        raise ContractFailure(f"unsupported JSON path {path!r}")
    current = value
    for part in path[2:].split("."):
        if not isinstance(current, dict) or part not in current:
            raise ContractFailure(f"JSON path {path!r} was not found")
        current = current[part]
    return current


def assert_state(before: Any, after: Any, assertions: list[dict[str, Any]]) -> None:
    for assertion in assertions:
        kind = assertion["type"]
        if kind == "unchanged":
            if before != after:
                raise ContractFailure("state changed but the scenario requires no mutation")
        elif kind == "numeric-delta":
            prior = _json_path(before, assertion["path"])
            current = _json_path(after, assertion["path"])
            if not isinstance(prior, (int, float)) or isinstance(prior, bool) or current != prior + assertion["by"]:
                raise ContractFailure(f"state {assertion['path']} did not change by {assertion['by']}")
        elif kind == "transition":
            prior = _json_path(before, assertion["path"])
            current = _json_path(after, assertion["path"])
            if prior != assertion["from"] or current != assertion["to"]:
                raise ContractFailure(
                    f"state {assertion['path']} expected {assertion['from']!r} -> {assertion['to']!r}, got {prior!r} -> {current!r}"
                )
        elif kind == "refresh-rotation":
            expected_before = {
                "activeRefreshTokens": 1,
                "revokedRefreshTokens": 0,
                "revokedTokenHashes": [],
            }
            if any(before.get(key) != value for key, value in expected_before.items()) or len(before.get("activeTokenHashes", [])) != 1:
                raise ContractFailure("refresh rotation requires exactly one seeded active token and no revoked tokens")
            old_hash = before["activeTokenHashes"][0]
            active_after = after.get("activeTokenHashes", [])
            if (
                after.get("activeRefreshTokens") != 1
                or after.get("revokedRefreshTokens") != 1
                or len(active_after) != 1
                or active_after[0] == old_hash
                or after.get("revokedTokenHashes") != [old_hash]
            ):
                raise ContractFailure("refresh rotation did not revoke the seeded hash and create exactly one new active hash")
        else:
            raise ContractFailure(f"unknown state assertion {kind!r}")


def verify_rs256(token: str, jwks: dict[str, Any], expected_claims: dict[str, Any], captures: dict[str, Any]) -> None:
    parts = token.split(".")
    if len(parts) != 3:
        raise ContractFailure("JWT verification expected a compact token")
    header = _base64url_json(parts[0], "$.jwt.header")
    claims = _base64url_json(parts[1], "$.jwt.claims")
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ContractFailure("JWT header must use RS256 and a string kid")
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    key = next((item for item in keys or [] if item.get("kid") == header["kid"]), None)
    if not key:
        raise ContractFailure("JWT kid was not present in JWKS")
    if key.get("kty") != "RSA" or key.get("use") != "sig" or key.get("alg") != "RS256":
        raise ContractFailure("JWT JWK must be an RSA RS256 signing key")
    try:
        n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4)), "big")
        e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=" * (-len(key["e"]) % 4)), "big")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
    except (KeyError, TypeError, ValueError) as exc:
        raise ContractFailure("JWKS RSA values or JWT signature were invalid") from exc
    size = (n.bit_length() + 7) // 8
    encoded = pow(int.from_bytes(signature, "big"), e, n).to_bytes(size, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(
        f"{parts[0]}.{parts[1]}".encode("ascii")
    ).digest()
    padding_length = size - len(digest_info) - 3
    expected = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    if padding_length < 8 or not hmac.compare_digest(encoded, expected):
        raise ContractFailure("JWT RS256 signature did not verify against JWKS")
    match(claims, expected_claims, "$.jwt.claims", captures)


def assert_response(base_url: str, result: HttpResult, assertions: list[dict[str, Any]], fixture: dict[str, Any], captures: dict[str, Any], timeout: float) -> None:
    envelope = {"status": result.status, "headers": result.headers, "json": result.body}
    for raw_assertion in assertions:
        assertion = resolve_fixture(raw_assertion, fixture)
        if assertion["type"] != "jwt-rs256-jwks":
            raise ContractFailure(f"unknown response assertion {assertion['type']!r}")
        token = _json_path(envelope, assertion["tokenPath"])
        jwks = call(base_url, {"method": "GET", "path": assertion["jwksPath"]}, timeout).body
        verify_rs256(token, jwks, assertion["claims"], captures)


def load_scenarios(path: Path, selected: set[str] | None = None) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("version") != 1 or not isinstance(document.get("scenarios"), list):
        raise ContractFailure(f"{path}: unsupported or invalid scenario document")
    if any(not isinstance(scenario, dict) for scenario in document["scenarios"]):
        raise ContractFailure(f"{path}: every scenario must be a JSON object")
    scenarios = cast(list[dict[str, Any]], document["scenarios"])
    ids = [scenario.get("id") for scenario in scenarios]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ContractFailure(f"{path}: scenario ids must be unique non-empty strings")
    if selected:
        unknown = selected - set(ids)
        if unknown:
            raise ContractFailure(f"unknown scenario ids: {sorted(unknown)}")
        scenarios = [scenario for scenario in scenarios if scenario["id"] in selected]
    return scenarios


def load_adapter_environment(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in document.items()):
        raise ContractFailure(f"{path}: adapter config must be a JSON object of string environment values")
    return document


def _evidence_value(value: Any, key: str | None = None) -> Any:
    """Return a stable evidence value without persisting bearer material."""
    sensitive_keys = {
        "authorizationcode",
        "authorization",
        "clientsecret",
        "code",
        "codeverifier",
        "cookie",
        "idtoken",
        "oauthcode",
        "oauthstate",
        "password",
        "privatekey",
        "secret",
        "setcookie",
        "state",
        "token",
        "accesstoken",
        "refreshtoken",
        "verifier",
    }
    normalized_key = "".join(character for character in (key or "").lower() if character.isalnum())
    contains_sensitive_marker = any(
        marker in normalized_key for marker in ("password", "secret", "privatekey")
    )
    if (normalized_key in sensitive_keys or contains_sensitive_marker) and isinstance(value, str):
        if value.startswith("<sha256:") and value.endswith(">"):
            digest = value[len("<sha256:"):-1]
            if len(digest) == 64 and all(character in "0123456789abcdef" for character in digest):
                return value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        return f"<sha256:{digest}>"
    if isinstance(value, dict):
        return {item_key: _evidence_value(item, item_key) for item_key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_evidence_value(item) for item in value]
    return value


def canonical_record(record: dict[str, Any]) -> dict[str, Any]:
    """Create a recursively ordered, JSON-serializable evidence record."""
    return cast(dict[str, Any], _evidence_value(record))


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write deterministic one-record-per-line evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(canonical_record(record), sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )
    path.write_text(payload, encoding="utf-8")


def validate_provenance(provenance: dict[str, str]) -> dict[str, str]:
    for key, value in provenance.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or not value:
            raise ContractFailure("provenance fields must be non-empty strings")
        lowered_key = key.lower()
        if any(marker in lowered_key for marker in ("password", "secret", "credential", "token", "cookie", "authorization")):
            raise ContractFailure(f"provenance key {key!r} is secret-shaped and is not allowed")
        if key not in SAFE_PROVENANCE_KEYS:
            raise ContractFailure(f"unknown provenance key {key!r}")
    return dict(provenance)


def parse_provenance(items: list[str] | None) -> dict[str, str]:
    provenance: dict[str, str] = {}
    for item in items or []:
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise ContractFailure("--provenance must use a non-empty KEY=VALUE")
        if key in provenance:
            raise ContractFailure(f"duplicate provenance key {key!r}")
        provenance[key] = value
    return validate_provenance(provenance)


def _value_digest(value: Any) -> str:
    payload = json.dumps(
        _evidence_value(value), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _runtime_evidence(scenario: dict[str, Any], steps: list[dict[str, Any]]) -> dict[str, Any]:
    state_count = len(scenario.get("stateAssertions", [])) + sum(
        len(step.get("stateAssertions", [])) for step in steps
    )
    jwt_count = sum(
        1
        for step in steps
        for assertion in step.get("assertions", [])
        if assertion.get("type") == "jwt-rs256-jwks"
    )
    return {
        "http": {"attemptedStepCount": 0, "contractPassed": None},
        "state": {"assertionCount": state_count, "assertionsPassed": None, "snapshotDigests": []},
        "jwt": {"assertionCount": jwt_count, "assertionsPassed": None},
    }


def _run_runtime(
    runtime: str,
    base_url: str,
    scenario: dict[str, Any],
    timeout: float,
    adapter: FixtureAdapter | None,
    preflight_name: str | None,
) -> tuple[dict[str, Any], list[str]]:
    fixture_name = scenario.get("fixture")
    steps = scenario.get("steps") or [{
        "request": scenario["request"],
        "expect": scenario["expect"],
        "assertions": scenario.get("assertions", []),
    }]
    fixture: dict[str, Any] = {}
    captures: dict[str, Any] = {}
    responses: list[dict[str, Any]] = []
    lifecycle: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    failure_messages: list[str] = []
    evidence = _runtime_evidence(scenario, steps)
    phase = "initialization"
    preflight_passed = preflight_name is None
    setup_started = False

    def event(name: str, outcome: str, **details: Any) -> None:
        lifecycle.append({"phase": name, "outcome": outcome, **details})

    def fail(failure_phase: str, exc: ContractFailure) -> None:
        message = str(exc)
        errors.append({
            "kind": "contract-failure",
            "phase": failure_phase,
            "sha256": hashlib.sha256(message.encode("utf-8")).hexdigest(),
        })
        failure_messages.append(f"{runtime}: {message}")

    try:
        if fixture_name:
            if adapter is None:
                raise ContractFailure("fixture scenario requires a runtime adapter")
            if preflight_name is not None:
                phase = "preflight"
                adapter.preflight(preflight_name)
                preflight_passed = True
                event(phase, "pass")
            phase = "setup"
            setup_started = True
            fixture = adapter.setup(fixture_name)
            event(phase, "pass")
            if "fixtureExpect" in scenario:
                phase = "fixture-assertion"
                match(fixture, resolve_fixture(scenario["fixtureExpect"], fixture), f"$.{runtime}Fixture")
                event(phase, "pass")

        before_probe = scenario.get("stateProbe")
        runtime_before = None
        if before_probe:
            phase = "scenario-snapshot-before"
            if adapter is None:
                raise ContractFailure("state probe requires a runtime adapter")
            runtime_before = adapter.snapshot(before_probe)
            evidence["state"]["snapshotDigests"].append({
                "position": "scenario-before", "sha256": _value_digest(runtime_before)
            })
            event(phase, "pass", probe=before_probe)

        for step_index, step in enumerate(steps):
            step_number = step_index + 1
            step_probe = step.get("stateProbe")
            step_before = None
            if step_probe:
                phase = "step-snapshot-before"
                if adapter is None:
                    raise ContractFailure("step state probe requires a runtime adapter")
                step_before = adapter.snapshot(step_probe)
                evidence["state"]["snapshotDigests"].append({
                    "position": f"step-{step_number}-before", "sha256": _value_digest(step_before)
                })
                event(phase, "pass", probe=step_probe, step=step_number)

            phase = "http-request"
            runtime_request = resolve_runtime(step["request"], fixture, captures)
            evidence["http"]["attemptedStepCount"] += 1
            result = call(base_url, runtime_request, timeout)
            phase = "http-contract"
            runtime_expect = resolve_runtime(step["expect"], fixture, captures)
            responses.append(normalize_response(result, runtime_expect, captures))
            phase = "response-assertion"
            assert_response(base_url, result, step.get("assertions", []), fixture, captures, timeout)
            event("step", "pass", step=step_number)

            if step_probe:
                phase = "step-snapshot-after"
                step_after = adapter.snapshot(step_probe) if adapter else None
                evidence["state"]["snapshotDigests"].append({
                    "position": f"step-{step_number}-after", "sha256": _value_digest(step_after)
                })
                event(phase, "pass", probe=step_probe, step=step_number)
                phase = "step-state-assertion"
                assert_state(step_before, step_after, step.get("stateAssertions", []))
                event(phase, "pass", step=step_number)

        if before_probe:
            phase = "scenario-snapshot-after"
            runtime_after = adapter.snapshot(before_probe) if adapter else None
            evidence["state"]["snapshotDigests"].append({
                "position": "scenario-after", "sha256": _value_digest(runtime_after)
            })
            event(phase, "pass", probe=before_probe)
            phase = "scenario-state-assertion"
            assert_state(runtime_before, runtime_after, scenario.get("stateAssertions", []))
            event(phase, "pass")

        evidence["http"]["contractPassed"] = True
        if evidence["state"]["assertionCount"]:
            evidence["state"]["assertionsPassed"] = True
        if evidence["jwt"]["assertionCount"]:
            evidence["jwt"]["assertionsPassed"] = True
    except ContractFailure as exc:
        event(phase, "fail")
        fail(phase, exc)
        if phase in {"http-request", "http-contract", "response-assertion"}:
            evidence["http"]["contractPassed"] = False
        if "state-assertion" in phase and evidence["state"]["assertionCount"]:
            evidence["state"]["assertionsPassed"] = False
        if phase == "response-assertion" and evidence["jwt"]["assertionCount"]:
            evidence["jwt"]["assertionsPassed"] = False
    except subprocess.SubprocessError:
        event(phase, "fail")
        fail(phase, ContractFailure(f"adapter operation failed during {phase}"))
    except OSError:
        event(phase, "fail")
        fail(phase, ContractFailure(f"runtime operation failed during {phase}"))
    finally:
        if fixture_name and adapter is not None and preflight_passed and setup_started:
            try:
                adapter.teardown(fixture_name)
                event("teardown", "pass")
            except ContractFailure as exc:
                event("teardown", "fail")
                fail("teardown", exc)
            except subprocess.SubprocessError:
                event("teardown", "fail")
                fail("teardown", ContractFailure("adapter operation failed during teardown"))
            except OSError:
                event("teardown", "fail")
                fail("teardown", ContractFailure("runtime operation failed during teardown"))

    record = {
        "attempt": 1,
        "retryCount": 0,
        "outcome": "pass" if not errors else "fail",
        "plannedStepCount": len(steps),
        "completedStepCount": len(responses),
        "normalizedResponses": responses,
        "fixtureLifecycle": lifecycle,
        "evidence": evidence,
    }
    if errors:
        record["errors"] = errors
    return record, failure_messages


def run_suite(
    baseline_url: str,
    candidate_url: str,
    scenarios: list[dict[str, Any]],
    timeout: float = 5.0,
    baseline_adapter: FixtureAdapter | None = None,
    candidate_adapter: FixtureAdapter | None = None,
    records: list[dict[str, Any]] | None = None,
    provenance: dict[str, str] | None = None,
    baseline_preflight: str | None = None,
    candidate_preflight: str | None = None,
) -> list[str]:
    provenance = validate_provenance(provenance or {})
    failures: list[str] = []
    for scenario in scenarios:
        failures_before_scenario = len(failures)
        scenario_id = scenario["id"]
        scenario_error: str | None = None
        comparison_equal: bool | None = None
        baseline_record, baseline_failures = _run_runtime(
            "baseline", baseline_url, scenario, timeout, baseline_adapter, baseline_preflight
        )
        candidate_record, candidate_failures = _run_runtime(
            "candidate", candidate_url, scenario, timeout, candidate_adapter, candidate_preflight
        )
        for runtime_failure in [*baseline_failures, *candidate_failures]:
            failures.append(f"{scenario_id}: {runtime_failure}")
            print(f"FAIL {scenario_id}: {runtime_failure}", file=sys.stderr)

        baseline_passed = baseline_record["outcome"] == "pass"
        candidate_passed = candidate_record["outcome"] == "pass"
        if baseline_passed and candidate_passed:
            comparison_equal = baseline_record["normalizedResponses"] == candidate_record["normalizedResponses"]
            comparison_category = "equivalent" if comparison_equal else "http-response-mismatch"
            if not comparison_equal:
                scenario_error = "normalized responses differ"
                failure = (
                    f"{scenario_id}: normalized responses differ\n"
                    f"  baseline: {json.dumps(baseline_record['normalizedResponses'], sort_keys=True)}\n"
                    f"  candidate: {json.dumps(candidate_record['normalizedResponses'], sort_keys=True)}"
                )
                failures.append(failure)
                print(f"FAIL {failure}", file=sys.stderr)
        elif not baseline_passed and not candidate_passed:
            comparison_category = "both-runtime-failure"
        elif not baseline_passed:
            comparison_category = "baseline-runtime-failure"
        else:
            comparison_category = "candidate-runtime-failure"
        if baseline_failures or candidate_failures:
            scenario_error = "runtime contract failure"

        if records is not None:
            record: dict[str, Any] = {
                "schemaVersion": 1,
                "kind": "differential-scenario",
                "scenarioId": scenario_id,
                "outcome": "pass" if scenario_error is None else "fail",
                "provenance": provenance or {},
                "attempt": 1,
                "retryCount": 0,
                "plannedStepCount": baseline_record["plannedStepCount"],
                "baseline": baseline_record,
                "candidate": candidate_record,
                "comparison": {"equal": comparison_equal},
                "comparisonCategory": comparison_category,
                "comparisonEvidence": {
                    "httpCompared": baseline_passed and candidate_passed,
                    "stateAssertionsPlanned": bool(
                        baseline_record["evidence"]["state"]["assertionCount"]
                        and candidate_record["evidence"]["state"]["assertionCount"]
                    ),
                    "stateAssertedIndependently": (
                        baseline_record["evidence"]["state"]["assertionsPassed"] is True
                        and candidate_record["evidence"]["state"]["assertionsPassed"] is True
                    ),
                    "jwtAssertionsPlanned": bool(
                        baseline_record["evidence"]["jwt"]["assertionCount"]
                        and candidate_record["evidence"]["jwt"]["assertionCount"]
                    ),
                    "jwtAssertedIndependently": (
                        baseline_record["evidence"]["jwt"]["assertionsPassed"] is True
                        and candidate_record["evidence"]["jwt"]["assertionsPassed"] is True
                    ),
                },
            }
            if scenario_error is not None:
                error_kind = "normalized-responses-differ" if comparison_category == "http-response-mismatch" else "runtime-failure"
                record["error"] = {
                    "kind": error_kind,
                    "sha256": hashlib.sha256(scenario_error.encode("utf-8")).hexdigest(),
                }
            records.append(record)
        if len(failures) == failures_before_scenario:
            print(f"PASS {scenario_id}")
    return failures


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline", required=True, help="baseline server base URL")
    result.add_argument("--candidate", required=True, help="candidate server base URL")
    result.add_argument("--scenarios", type=Path, default=DEFAULT_SCENARIOS, help="scenario JSON file")
    result.add_argument("--scenario", action="append", dest="selected", help="scenario id (repeatable)")
    result.add_argument("--timeout", type=float, default=5.0, help="per-request timeout in seconds")
    result.add_argument("--baseline-adapter", type=Path, help="fixture adapter executable for baseline state")
    result.add_argument("--candidate-adapter", type=Path, help="fixture adapter executable for candidate state")
    result.add_argument("--baseline-adapter-config", type=Path, help="untracked JSON environment for the baseline adapter")
    result.add_argument("--candidate-adapter-config", type=Path, help="untracked JSON environment for the candidate adapter")
    result.add_argument("--baseline-adapter-preflight", metavar="NAME", help="opt in to one baseline adapter preflight command before fixture setup")
    result.add_argument("--candidate-adapter-preflight", metavar="NAME", help="opt in to one candidate adapter preflight command before fixture setup")
    result.add_argument("--jsonl", type=Path, help="optional machine-readable scenario result output")
    result.add_argument(
        "--provenance",
        action="append",
        metavar="KEY=VALUE",
        help="result provenance field (repeatable; for example runId or sourceRevision)",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        scenarios = load_scenarios(args.scenarios, set(args.selected) if args.selected else None)
        baseline_adapter = FixtureAdapter(
            args.baseline_adapter,
            args.baseline,
            load_adapter_environment(args.baseline_adapter_config),
        ) if args.baseline_adapter else None
        candidate_adapter = FixtureAdapter(
            args.candidate_adapter,
            args.candidate,
            load_adapter_environment(args.candidate_adapter_config),
        ) if args.candidate_adapter else None
        records: list[dict[str, Any]] | None = [] if args.jsonl else None
        failures = run_suite(
            args.baseline,
            args.candidate,
            scenarios,
            args.timeout,
            baseline_adapter,
            candidate_adapter,
            records,
            parse_provenance(args.provenance),
            args.baseline_adapter_preflight,
            args.candidate_adapter_preflight,
        )
        if args.jsonl:
            write_jsonl(args.jsonl, records or [])
    except (ContractFailure, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    if failures:
        print(f"{len(failures)} contract scenario(s) failed", file=sys.stderr)
        return 1
    print(f"All {len(scenarios)} contract scenario(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
