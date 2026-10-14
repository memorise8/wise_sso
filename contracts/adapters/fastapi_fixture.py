#!/usr/bin/env python3
"""Fail-closed fixture adapter for an isolated FastAPI SSO runtime."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast


class FixtureConfig(Protocol):
    base_url: str
    database_url: str
    redis_url: str
    email_domain: str
    audience: str
    client_id: str
    redirect_uri: str
    refresh_secret: str


class _SharedAdapter(Protocol):
    AdapterError: type[Exception]
    Config: type[Any]
    RedisRespClient: type[Any]
    ACTIVE_USER_ID: str
    PENDING_USER_ID: str
    ADMIN_USER_ID: str
    TARGET_USER_ID: str
    PASSWORD: str
    emails: Callable[[FixtureConfig], dict[str, str]]
    psql: Callable[[FixtureConfig, str], str]
    reset: Callable[[FixtureConfig], None]
    seed: Callable[[FixtureConfig], None]
    refresh_fixture_token: Callable[[FixtureConfig, str], str]
    seed_refresh_token: Callable[[FixtureConfig, str, str], None]
    setup: Callable[[FixtureConfig, str], dict[str, Any]]
    snapshot: Callable[[FixtureConfig, str], Any]
    load_config: Callable[[], FixtureConfig]
    preflight: Callable[[FixtureConfig], dict[str, Any]]


def _load_shared_adapter() -> _SharedAdapter:
    path = Path(__file__).with_name("express_fixture.py")
    spec = importlib.util.spec_from_file_location(
        "wiseacct_contract_fixture_shared", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load shared fixture adapter from {path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_SharedAdapter, module)


_shared = _load_shared_adapter()

AdapterError = _shared.AdapterError
Config = _shared.Config
RedisRespClient = _shared.RedisRespClient

# FastAPI deliberately persists into the existing Prisma-owned schema. Sharing
# these operations keeps fixtures and canonical probes identical across runtimes.
ACTIVE_USER_ID = _shared.ACTIVE_USER_ID
PENDING_USER_ID = _shared.PENDING_USER_ID
ADMIN_USER_ID = _shared.ADMIN_USER_ID
TARGET_USER_ID = _shared.TARGET_USER_ID
PASSWORD = _shared.PASSWORD
emails = _shared.emails
psql = _shared.psql
reset = _shared.reset
seed = _shared.seed
refresh_fixture_token = _shared.refresh_fixture_token
seed_refresh_token = _shared.seed_refresh_token
setup = _shared.setup
snapshot = _shared.snapshot

_REQUIRED_SCHEMA_QUERY = r"""
SELECT CASE WHEN
  to_regclass('"User"') IS NOT NULL AND
  to_regclass('"PasswordCredential"') IS NOT NULL AND
  to_regclass('"RefreshToken"') IS NOT NULL AND
  to_regclass('"EmailVerificationToken"') IS NOT NULL AND
  to_regclass('"PasswordResetToken"') IS NOT NULL AND
  to_regclass('"AuditLog"') IS NOT NULL AND
  to_regclass('"Role"') IS NOT NULL AND
  to_regclass('"UserRole"') IS NOT NULL
THEN 'prisma-compatible' ELSE 'missing' END;
"""


def load_config() -> FixtureConfig:
    """Load shared isolated-target config with an explicit FastAPI opt-in."""

    if os.environ.get("CONTRACT_FASTAPI_RUNTIME") != "1":
        raise AdapterError("CONTRACT_FASTAPI_RUNTIME=1 is required")
    return _shared.load_config()


def preflight(config: FixtureConfig) -> dict[str, Any]:
    """Prove isolation and the Prisma-compatible schema before mutation."""

    result = _shared.preflight(config)
    schema = psql(config, _REQUIRED_SCHEMA_QUERY)
    if schema != "prisma-compatible":
        raise AdapterError(
            "FastAPI fixture database is missing the required Prisma-compatible schema"
        )
    return {**result, "runtime": "fastapi", "schema": schema}


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in {
            "preflight",
            "setup",
            "snapshot",
            "teardown",
        }:
            raise AdapterError(
                "usage: fastapi_fixture.py {preflight|setup|snapshot|teardown} <name>"
            )
        command, name = argv
        config = load_config()
        result: Any = preflight(config)
        if command == "setup":
            result = setup(config, name)
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
