#!/usr/bin/env python3
"""Pre-spawn policy for the connected OAuth provider contract runtimes.

This module deliberately recognizes only two repository-owned command forms:

* Express: ``node --import <provider preload entry> <loopback wrapper>
  <built Express server>``.
* FastAPI: the repository virtualenv's ``uvicorn`` executable, the fixed
  ``provider_transport_fastapi_bootstrap:create_test_app`` factory, an exact
  adapter app-dir, a literal loopback host, and one worker with no reload.

The checks prevent an accidentally production-connected runtime from being
spawned.  They are a bounded misconfiguration guard, not containment for a
malicious child process and not cryptographic proof of runtime isolation.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast
from urllib.parse import SplitResult, urlsplit

ROOT = Path(__file__).resolve().parents[2]
ADAPTERS = ROOT / "contracts" / "adapters"
PRELOAD_ENTRY = ADAPTERS / "provider_transport_preload_entry.mjs"
FASTAPI_BOOTSTRAP = ADAPTERS / "provider_transport_fastapi_bootstrap.py"
EXPRESS_LOOPBACK = (
    ROOT / "fastapi-auth-server" / "ops" / "phase7" / "runtime_express_loopback.mjs"
)
EXPRESS_SERVER = ROOT / "auth-server" / "dist" / "src" / "server.js"
EXPRESS_CWD = ROOT / "auth-server"
FASTAPI_CWD = ROOT / "fastapi-auth-server"
FASTAPI_SRC = FASTAPI_CWD / "src"
UVICORN = FASTAPI_CWD / ".venv" / "bin" / "uvicorn"
GOOGLE_FIXTURE = ADAPTERS / "google_oauth_fixture.py"

_SUPPORTED_PROVIDERS = frozenset({"google", "naver", "kakao"})
_PROVIDER_ENV_PREFIX = {
    "google": "GOOGLE",
    "naver": "NAVER",
    "kakao": "KAKAO",
}
_EXPECTED_SCENARIO_CLIENT_ID = {
    "google": "google-client",
    "naver": "naver-client",
    "kakao": "kakao-client",
}
_EXPECTED_SCENARIO_CODE = {
    "google": "google-code",
    "naver": "naver-code",
    "kakao": "kakao-code",
}

_SAFE_DATABASE_SEGMENT = re.compile(
    r"(?:^|[_-])(test|contract|fixture)(?:$|[_-])", re.IGNORECASE
)

_BLOCKED_ENVIRONMENT = {
    "DOTENV_CONFIG_PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
}


class _ProviderTransport(Protocol):
    ProviderTransportConfigurationError: type[Exception]

    def load_scenarios(self, path: Path) -> Sequence[Any]: ...


def _load_provider_transport() -> _ProviderTransport:
    path = ROOT / "contracts" / "bin" / "provider_transport.py"
    spec = importlib.util.spec_from_file_location("oauth_launch_policy_transport", path)
    if spec is None or spec.loader is None:
        raise ValueError("oauth launch policy dependency is unavailable")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_ProviderTransport, module)


def _mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(message)
    return cast(Mapping[str, Any], value)


def _strings(value: object, message: str) -> list[str]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError(message)
    return list(cast(Sequence[str], value))


def _exact_path(value: str, expected: Path, message: str) -> None:
    candidate = Path(value)
    if not candidate.is_absolute() or candidate != expected or candidate.is_symlink():
        raise ValueError(message)
    try:
        details = candidate.stat()
    except OSError as exc:
        raise ValueError(message) from exc
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(message)


def _runtime(config: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    value = _mapping(config.get(role), "oauth runtime config is invalid")
    if set(value) != {"command", "cwd", "healthUrl", "environment"}:
        raise ValueError("oauth runtime config fields are not exact")
    if not isinstance(value["cwd"], str) or not isinstance(value["healthUrl"], str):
        raise ValueError("oauth runtime config is invalid")  # noqa: TRY004
    _strings(value["command"], "oauth runtime command is invalid")
    environment = _mapping(value["environment"], "oauth runtime environment is invalid")
    if any(not isinstance(item, str) for item in environment.values()):
        raise ValueError("oauth runtime environment is invalid")
    return value


def _endpoint(value: str, message: str) -> SplitResult:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(message) from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None
        or port == 0
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(message)
    return parsed


def _origin(parsed: SplitResult) -> str:
    assert parsed.hostname is not None and parsed.port is not None
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{parsed.port}"


def _normalized_database_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("oauth runtime database binding is invalid") from exc
    scheme = "postgresql" if parsed.scheme == "postgresql+asyncpg" else parsed.scheme
    if (
        scheme not in {"postgres", "postgresql"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or not parsed.path.lstrip("/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("oauth runtime database binding is invalid")
    database = parsed.path.lstrip("/")
    lowered = database.lower()
    if _SAFE_DATABASE_SEGMENT.search(lowered) is None or lowered == "auth_db":
        raise ValueError("oauth runtime database is not disposable")
    return parsed._replace(scheme="postgresql").geturl()


def _normalized_redis_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        database = int(parsed.path.lstrip("/") or "0")
    except (TypeError, ValueError) as exc:
        raise ValueError("oauth runtime Redis binding is invalid") from exc
    if (
        parsed.scheme != "redis"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or port is None
        or database < 1
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("oauth runtime Redis binding is invalid")
    return parsed.geturl()


def _validate_common_environment(
    runtime: Mapping[str, Any],
    fixture: Mapping[str, Any],
    expected_issuer: str,
    provider_config: Path,
    provider: str,
) -> tuple[Mapping[str, Any], SplitResult]:
    environment = _mapping(
        runtime["environment"], "oauth runtime environment is invalid"
    )
    if _BLOCKED_ENVIRONMENT.intersection(environment):
        raise ValueError("oauth runtime environment contains a blocked override")
    if any(name.startswith("UVICORN_") for name in environment):
        raise ValueError("oauth runtime environment contains a blocked override")
    if environment.get("WISEACCT_TEST_PROVIDER_CONFIG") != str(provider_config):
        raise ValueError("oauth runtime provider config binding does not match")
    if environment.get("NODE_ENV") != "test":
        raise ValueError("oauth runtime must use test mode")
    if environment.get("OAUTH_ENABLED_PROVIDERS") != provider:
        raise ValueError("oauth runtime provider allowlist is not exact")
    if environment.get("JWT_ISSUER") != expected_issuer:
        raise ValueError("oauth runtime issuer binding does not match")
    if environment.get("JWT_REFRESH_SECRET") != fixture.get("CONTRACT_REFRESH_SECRET"):
        raise ValueError("oauth runtime refresh binding does not match")
    if environment.get("JWT_AUDIENCE") != fixture.get("CONTRACT_FIXTURE_AUDIENCE"):
        raise ValueError("oauth runtime audience binding does not match")
    database = environment.get("DATABASE_URL")
    redis = environment.get("REDIS_URL")
    if not isinstance(database, str) or not isinstance(redis, str):
        raise ValueError("oauth runtime state binding is missing")  # noqa: TRY004
    fixture_database = fixture.get("CONTRACT_DATABASE_URL")
    fixture_redis = fixture.get("CONTRACT_REDIS_URL")
    if not isinstance(fixture_database, str) or not isinstance(fixture_redis, str):
        raise ValueError("oauth fixture state binding is missing")  # noqa: TRY004
    if _normalized_database_url(database) != _normalized_database_url(fixture_database):
        raise ValueError("oauth runtime database binding does not match")
    if _normalized_redis_url(redis) != _normalized_redis_url(fixture_redis):
        raise ValueError("oauth runtime Redis binding does not match")
    health = _endpoint(
        cast(str, runtime["healthUrl"]), "oauth runtime health URL is invalid"
    )
    if environment.get("PORT") != str(health.port):
        raise ValueError("oauth runtime port binding does not match")
    cwd = Path(cast(str, runtime["cwd"]))
    if (cwd / ".env").exists():
        raise ValueError("oauth runtime cwd contains an ambient dotenv file")
    return environment, health


def _validate_express(runtime: Mapping[str, Any], health: SplitResult) -> None:
    command = _strings(runtime["command"], "oauth Express command is invalid")
    node = shutil.which("node")
    if node is None or Path(command[0]).resolve() != Path(node).resolve():
        raise ValueError("oauth Express executable is not the recognized Node runtime")
    if len(command) != 5 or command[1] != "--import":
        raise ValueError("oauth Express command does not use the recognized bootstrap")
    _exact_path(command[2], PRELOAD_ENTRY, "oauth Express preload is not recognized")
    _exact_path(
        command[3], EXPRESS_LOOPBACK, "oauth Express loopback wrapper is not recognized"
    )
    _exact_path(
        command[4], EXPRESS_SERVER, "oauth Express server artifact is not recognized"
    )
    if Path(cast(str, runtime["cwd"])) != EXPRESS_CWD:
        raise ValueError("oauth Express cwd is not recognized")
    environment = cast(Mapping[str, Any], runtime["environment"])
    if environment.get("WISEACCT_PHASE7_EXPRESS_LOOPBACK") != "1":
        raise ValueError("oauth Express loopback acknowledgement is missing")
    if health.path not in {"", "/", "/healthz"}:
        raise ValueError("oauth Express health path is not recognized")


def _validate_fastapi(runtime: Mapping[str, Any], health: SplitResult) -> None:
    command = _strings(runtime["command"], "oauth FastAPI command is invalid")
    _exact_path(command[0], UVICORN, "oauth FastAPI executable is not recognized")
    expected = [
        str(UVICORN),
        "provider_transport_fastapi_bootstrap:create_test_app",
        "--factory",
        "--app-dir",
        str(ADAPTERS),
        "--host",
        cast(str, health.hostname),
        "--port",
        str(health.port),
        "--no-proxy-headers",
        "--no-server-header",
        "--no-access-log",
    ]
    if command != expected:
        raise ValueError("oauth FastAPI command does not use the recognized bootstrap")
    _exact_path(
        str(FASTAPI_BOOTSTRAP),
        FASTAPI_BOOTSTRAP,
        "oauth FastAPI bootstrap is unavailable",
    )
    if Path(cast(str, runtime["cwd"])) != FASTAPI_CWD:
        raise ValueError("oauth FastAPI cwd is not recognized")
    environment = cast(Mapping[str, Any], runtime["environment"])
    if environment.get("PYTHONPATH") != str(FASTAPI_SRC):
        raise ValueError("oauth FastAPI import path is not exact")
    if health.path not in {"", "/", "/healthz"}:
        raise ValueError("oauth FastAPI health path is not recognized")


def validate_launch_config(config: dict[str, Any], *, provider: str = "google") -> None:
    """Reject unsafe connected-flow configuration before either child is spawned."""

    if not isinstance(provider, str) or provider not in _SUPPORTED_PROVIDERS:
        raise ValueError("oauth launch provider is invalid")

    producer_role = config.get("producerRole")
    consumer_role = config.get("consumerRole")
    if not isinstance(producer_role, str) or producer_role not in {
        "express",
        "fastapi",
    }:
        raise ValueError("oauth launch producer role is invalid")
    if not isinstance(consumer_role, str) or consumer_role not in {
        "express",
        "fastapi",
    }:
        raise ValueError("oauth launch consumer role is invalid")
    if producer_role == consumer_role:
        raise ValueError("oauth launch runtime roles are not distinct")
    expected_issuer = config.get("expectedIssuer")
    if not isinstance(expected_issuer, str) or not expected_issuer:
        raise ValueError("oauth launch expected issuer is invalid")
    fixture = _mapping(
        config.get("fixtureEnvironment"), "oauth fixture environment is invalid"
    )
    if any(not isinstance(value, str) for value in fixture.values()):
        raise ValueError("oauth fixture environment is invalid")
    if fixture.get("CONTRACT_OAUTH_PROVIDER", "google") != provider:
        raise ValueError("oauth fixture provider binding does not match")
    if (
        _BLOCKED_ENVIRONMENT.intersection(fixture)
        or "PATH" in fixture
        or any(name.startswith(("PYTHON", "LD_", "DYLD_")) for name in fixture)
    ):
        raise ValueError("oauth fixture environment contains a blocked override")
    if (
        fixture.get("CONTRACT_FIXTURE_MODE") != "1"
        or fixture.get("CONTRACT_REDIS_ISOLATED_DB") != "1"
        or fixture.get("CONTRACT_FASTAPI_RUNTIME") != "1"
    ):
        raise ValueError("oauth fixture isolation acknowledgement is missing")
    fixture_adapter = config.get("fixtureAdapter")
    if not isinstance(fixture_adapter, str):
        raise ValueError("oauth fixture adapter is invalid")  # noqa: TRY004
    _exact_path(
        fixture_adapter,
        GOOGLE_FIXTURE,
        "oauth fixture adapter is not the recognized Google adapter",
    )
    provider_values: list[Path] = []
    runtimes: dict[str, Mapping[str, Any]] = {}
    health: dict[str, SplitResult] = {}
    environments: dict[str, Mapping[str, Any]] = {}
    for slot, role in (
        ("producer", producer_role),
        ("consumer", consumer_role),
    ):
        runtime = _runtime(config, slot)
        environment = _mapping(
            runtime["environment"], "oauth runtime environment is invalid"
        )
        provider_value = environment.get("WISEACCT_TEST_PROVIDER_CONFIG")
        if not isinstance(provider_value, str) or not provider_value:
            raise ValueError("oauth runtime provider config binding is missing")
        provider_values.append(Path(provider_value))
        runtimes[role] = runtime
    if provider_values[0] != provider_values[1] or not provider_values[0].is_absolute():
        raise ValueError("oauth runtime provider config bindings are not identical")
    provider_config = provider_values[0]
    transport = _load_provider_transport()
    try:
        scenarios = transport.load_scenarios(provider_config)
    except (transport.ProviderTransportConfigurationError, OSError) as exc:
        raise ValueError("oauth provider config was refused") from exc
    if len(scenarios) != 1 or scenarios[0].provider != provider:
        if provider == "google":
            raise ValueError("oauth provider config must contain only Google")
        raise ValueError(f"oauth provider config must contain only {provider.title()}")
    scenario = scenarios[0]
    if scenario.client_id != _EXPECTED_SCENARIO_CLIENT_ID[provider]:
        raise ValueError("oauth provider scenario client ID is not recognized")
    if scenario.code != _EXPECTED_SCENARIO_CODE[provider]:
        raise ValueError("oauth provider scenario code is not recognized")
    for role in ("express", "fastapi"):
        environments[role], health[role] = _validate_common_environment(
            runtimes[role], fixture, expected_issuer, provider_config, provider
        )
    if _origin(health["express"]) == _origin(health["fastapi"]):
        raise ValueError("oauth runtime origins are not distinct")
    fixture_base_url = fixture.get("CONTRACT_BASE_URL")
    if not isinstance(fixture_base_url, str):
        raise ValueError("oauth fixture base URL is missing")  # noqa: TRY004
    fixture_endpoint = _endpoint(fixture_base_url, "oauth fixture base URL is invalid")
    if fixture_endpoint.path not in {"", "/"} or _origin(fixture_endpoint) not in {
        _origin(health["express"]),
        _origin(health["fastapi"]),
    }:
        raise ValueError("oauth fixture base URL is not an owned runtime")
    _validate_express(runtimes["express"], health["express"])
    _validate_fastapi(runtimes["fastapi"], health["fastapi"])
    producer = producer_role
    producer_environment = environments[producer]
    prefix = _PROVIDER_ENV_PREFIX[provider]
    client_id_name = f"{prefix}_CLIENT_ID"
    client_secret_name = f"{prefix}_CLIENT_SECRET"
    redirect_uri_name = f"{prefix}_REDIRECT_URI"
    if (
        producer_environment.get(client_id_name) != scenario.client_id
        or producer_environment.get(client_secret_name) != scenario.client_secret
        or producer_environment.get(redirect_uri_name) != scenario.redirect_uri
    ):
        raise ValueError(
            f"oauth producer {provider.title()} scenario binding does not match"
        )
    callback = _endpoint(
        scenario.redirect_uri,
        f"oauth producer {provider.title()} callback is invalid",
    )
    if (
        _origin(callback) != _origin(health[producer])
        or callback.path != f"/auth/{provider}/callback"
    ):
        raise ValueError(
            f"oauth producer {provider.title()} callback binding does not match"
        )
    for environment in environments.values():
        if (
            environment.get(client_id_name) != scenario.client_id
            or environment.get(client_secret_name) != scenario.client_secret
            or environment.get(redirect_uri_name) != scenario.redirect_uri
        ):
            raise ValueError(
                f"oauth runtime {provider.title()} scenario binding does not match"
            )
