"""Fail-closed, test-only HTTP transport for OAuth provider contract flows."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, cast
from urllib.parse import parse_qs, urlsplit

import httpx

Provider = Literal["google", "naver", "kakao"]
Outcome = Literal["success", "timeout", "malformed-json", "redirect", "invalid-payload"]

MAX_REQUEST_BYTES: Final = 8 * 1024
MAX_RESPONSE_BYTES: Final = 64 * 1024
MAX_CONFIG_BYTES: Final = 64 * 1024


@dataclass(frozen=True, slots=True)
class ProviderEndpoints:
    issuer: str
    token: str
    user_info: str


ENDPOINTS: Final[dict[Provider, ProviderEndpoints]] = {
    "google": ProviderEndpoints(
        "https://accounts.google.com",
        "https://oauth2.googleapis.com/token",
        "https://openidconnect.googleapis.com/v1/userinfo",
    ),
    "naver": ProviderEndpoints(
        "https://nid.naver.com",
        "https://nid.naver.com/oauth2.0/token",
        "https://openapi.naver.com/v1/nid/me",
    ),
    "kakao": ProviderEndpoints(
        "https://kauth.kakao.com",
        "https://kauth.kakao.com/oauth/token",
        "https://kapi.kakao.com/v2/user/me",
    ),
}


class ProviderTransportError(httpx.TransportError):
    """A request escaped the exact test-only provider contract."""


class ProviderTransportConfigurationError(ValueError):
    """The private test-only provider configuration failed closed."""


@dataclass(frozen=True, slots=True)
class ProviderScenario:
    provider: Provider
    issuer: str
    code: str
    access_token: str
    profile: object
    client_id: str
    client_secret: str
    redirect_uri: str
    token_outcome: Outcome = "success"
    user_outcome: Outcome = "success"

    def __post_init__(self) -> None:
        endpoints = ENDPOINTS[self.provider]
        if self.issuer != endpoints.issuer:
            raise ValueError(
                "provider issuer does not match the fixed provider identity"
            )
        for name, value in (
            ("code", self.code),
            ("access_token", self.access_token),
            ("client_id", self.client_id),
            ("client_secret", self.client_secret),
            ("redirect_uri", self.redirect_uri),
        ):
            if not value or len(value.encode()) > MAX_REQUEST_BYTES:
                raise ValueError(f"{name} is empty or too large")


@dataclass(slots=True)
class ProviderRequestRecord:
    provider: Provider
    operation: Literal["token", "user-info"]
    method: str
    url: str


@dataclass(slots=True)
class TestOnlyProviderTransport(httpx.AsyncBaseTransport):
    """Intercept only the six fixed provider requests and never fall back to the network."""

    scenarios: tuple[ProviderScenario, ...]
    records: list[ProviderRequestRecord] = field(default_factory=list, init=False)
    _by_url: dict[str, tuple[ProviderScenario, Literal["token", "user-info"]]] = field(
        default_factory=dict, init=False
    )

    def __post_init__(self) -> None:
        if not self.scenarios:
            raise ValueError("at least one provider scenario is required")
        providers: set[Provider] = set()
        for scenario in self.scenarios:
            if scenario.provider in providers:
                raise ValueError("provider scenarios must be unique")
            providers.add(scenario.provider)
            endpoints = ENDPOINTS[scenario.provider]
            self._by_url[endpoints.token] = (scenario, "token")
            self._by_url[endpoints.user_info] = (scenario, "user-info")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        route = self._by_url.get(url)
        if route is None:
            raise ProviderTransportError(
                "provider request is outside the fixed allowlist", request=request
            )
        scenario, operation = route
        expected_method = "POST" if operation == "token" else "GET"
        if request.method != expected_method:
            raise ProviderTransportError(
                "provider request method is not allowed", request=request
            )
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ProviderTransportError(
                "provider URL decorations are not allowed", request=request
            )
        body_parts: list[bytes] = []
        body_size = 0
        stream = cast(httpx.AsyncByteStream, request.stream)
        async for part in stream:
            body_size += len(part)
            if body_size > MAX_REQUEST_BYTES:
                raise ProviderTransportError(
                    "provider request body is too large", request=request
                )
            body_parts.append(part)
        body = b"".join(body_parts)
        if operation == "token":
            self._validate_token_request(request, body, scenario)
            outcome = scenario.token_outcome
            payload: object = {"access_token": scenario.access_token}
        else:
            self._validate_user_request(request, body, scenario)
            outcome = scenario.user_outcome
            payload = scenario.profile
        self.records.append(
            ProviderRequestRecord(scenario.provider, operation, request.method, url)
        )
        return self._response(request, outcome, payload)

    @staticmethod
    def _validate_token_request(
        request: httpx.Request, body: bytes, scenario: ProviderScenario
    ) -> None:
        content_type = (
            request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        )
        if content_type != "application/x-www-form-urlencoded":
            raise ProviderTransportError(
                "provider token content type is not allowed", request=request
            )
        try:
            form = parse_qs(
                body.decode("utf-8"), keep_blank_values=True, strict_parsing=True
            )
        except (UnicodeDecodeError, ValueError) as error:
            raise ProviderTransportError(
                "provider token form is malformed", request=request
            ) from error
        required = {"grant_type", "client_id", "client_secret", "redirect_uri", "code"}
        if set(form) != required or any(len(values) != 1 for values in form.values()):
            raise ProviderTransportError(
                "provider token form fields are not exact", request=request
            )
        expected = {
            "grant_type": "authorization_code",
            "code": scenario.code,
            "client_id": scenario.client_id,
            "client_secret": scenario.client_secret,
            "redirect_uri": scenario.redirect_uri,
        }
        for name, value in expected.items():
            if form[name][0] != value:
                raise ProviderTransportError(
                    f"provider token {name} does not match", request=request
                )

    @staticmethod
    def _validate_user_request(
        request: httpx.Request, body: bytes, scenario: ProviderScenario
    ) -> None:
        if body:
            raise ProviderTransportError(
                "provider user-info request body is not allowed", request=request
            )
        if request.headers.get("authorization") != f"Bearer {scenario.access_token}":
            raise ProviderTransportError(
                "provider bearer token does not match", request=request
            )

    @staticmethod
    def _response(
        request: httpx.Request, outcome: Outcome, payload: object
    ) -> httpx.Response:
        if outcome == "timeout":
            raise httpx.ReadTimeout("synthetic provider timeout", request=request)
        if outcome == "redirect":
            raise ProviderTransportError(
                "provider redirects are not allowed", request=request
            )
        if outcome == "malformed-json":
            return httpx.Response(
                200,
                content=b"{",
                headers={"content-type": "application/json"},
                request=request,
            )
        if outcome == "invalid-payload":
            payload = {"unexpected": True}
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode()
        if len(encoded) > MAX_RESPONSE_BYTES:
            raise ProviderTransportError(
                "provider response body is too large", request=request
            )
        return httpx.Response(
            200,
            content=encoded,
            headers={"content-type": "application/json"},
            request=request,
        )


def load_scenarios(path: Path) -> tuple[ProviderScenario, ...]:
    """Load exact scenarios through one owned, private, no-follow descriptor."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ProviderTransportConfigurationError(
            "provider config requires no-follow descriptor support"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC | no_follow
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProviderTransportConfigurationError(
            "provider config could not be opened"
        ) from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size > MAX_CONFIG_BYTES
        ):
            raise ProviderTransportConfigurationError(
                "provider config must be an owned, private, bounded regular file"
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(8192, MAX_CONFIG_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_CONFIG_BYTES:
                raise ProviderTransportConfigurationError(
                    "provider config is too large"
                )
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProviderTransportConfigurationError(
            "provider config is not valid JSON"
        ) from error
    return _parse_scenarios(value)


def _parse_scenarios(value: object) -> tuple[ProviderScenario, ...]:
    if not isinstance(value, Mapping) or set(value) != {"scenarios"}:
        raise ProviderTransportConfigurationError(
            "provider config fields are not exact"
        )
    raw_scenarios = value["scenarios"]
    if not isinstance(raw_scenarios, list) or not 1 <= len(raw_scenarios) <= 3:
        raise ProviderTransportConfigurationError(
            "provider scenarios must contain one to three entries"
        )
    fields = {
        "provider",
        "issuer",
        "code",
        "accessToken",
        "profile",
        "clientId",
        "clientSecret",
        "redirectUri",
        "tokenOutcome",
        "userOutcome",
    }
    scenarios: list[ProviderScenario] = []
    for raw in raw_scenarios:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise ProviderTransportConfigurationError(
                "provider scenario fields are not exact"
            )
        provider = raw["provider"]
        token_outcome = raw["tokenOutcome"]
        user_outcome = raw["userOutcome"]
        if provider not in ENDPOINTS:
            raise ProviderTransportConfigurationError("provider is not supported")
        outcomes = {
            "success",
            "timeout",
            "malformed-json",
            "redirect",
            "invalid-payload",
        }
        if token_outcome not in outcomes or user_outcome not in outcomes:
            raise ProviderTransportConfigurationError("provider outcome is invalid")
        string_fields = (
            "issuer",
            "code",
            "accessToken",
            "clientId",
            "clientSecret",
            "redirectUri",
        )
        if any(not isinstance(raw[name], str) for name in string_fields):
            raise ProviderTransportConfigurationError(
                "provider string fields are invalid"
            )
        try:
            scenarios.append(
                ProviderScenario(
                    provider=cast(Provider, provider),
                    issuer=cast(str, raw["issuer"]),
                    code=cast(str, raw["code"]),
                    access_token=cast(str, raw["accessToken"]),
                    profile=raw["profile"],
                    client_id=cast(str, raw["clientId"]),
                    client_secret=cast(str, raw["clientSecret"]),
                    redirect_uri=cast(str, raw["redirectUri"]),
                    token_outcome=cast(Outcome, token_outcome),
                    user_outcome=cast(Outcome, user_outcome),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProviderTransportConfigurationError(
                "provider scenario is invalid"
            ) from error
    try:
        TestOnlyProviderTransport(tuple(scenarios))
    except ValueError as error:
        raise ProviderTransportConfigurationError(
            "provider scenarios are invalid"
        ) from error
    return tuple(scenarios)
