#!/usr/bin/env python3
"""Disposable Prisma-schema fixture adapter for private OAuth provider flows."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast


class _FixtureModule(Protocol):
    AdapterError: type[Exception]
    ACTIVE_USER_ID: str

    def load_config(self) -> Any: ...
    def preflight(self, config: Any) -> dict[str, Any]: ...
    def reset(self, config: Any) -> None: ...
    def seed(self, config: Any) -> None: ...
    def emails(self, config: Any) -> dict[str, str]: ...
    def psql(self, config: Any, sql: str) -> str: ...
    def redis_key_count(self, config: Any, prefix: str) -> int: ...


def _load(name: str) -> _FixtureModule:
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(f"google_oauth_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load fixture adapter from {path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_FixtureModule, module)


shared = _load("express_fixture.py")
fastapi = _load("fastapi_fixture.py")
AdapterError = shared.AdapterError
DEFAULT_PROVIDER = "google"
GOOGLE_PROVIDER = DEFAULT_PROVIDER
OAUTH_PROVIDERS = ("google", "naver", "kakao")
SAFE_VALUE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_IDENTITY_SCHEMA_TEMPLATE = r"""
SELECT CASE WHEN
  to_regclass('"SocialAccount"') IS NOT NULL AND
  (SELECT COUNT(*) FROM information_schema.columns
   WHERE table_schema = current_schema() AND table_name = 'SocialAccount'
     AND column_name IN ('provider', 'providerUserId', 'userId')) = 3
THEN 'prisma-{provider}-compatible' ELSE 'missing' END;
"""


def load_config() -> Any:
    return (
        fastapi.load_config()
        if os.environ.get("CONTRACT_FASTAPI_RUNTIME") == "1"
        else shared.load_config()
    )


def preflight(config: Any) -> dict[str, Any]:
    provider = _provider()
    _provider_subject(provider)
    provider_name = provider.capitalize()
    result = (
        fastapi.preflight(config)
        if os.environ.get("CONTRACT_FASTAPI_RUNTIME") == "1"
        else shared.preflight(config)
    )
    expected = f"prisma-{provider}-compatible"
    schema = shared.psql(config, _IDENTITY_SCHEMA_TEMPLATE.format(provider=provider))
    if schema != expected:
        raise AdapterError(
            f"fixture database is missing the {provider_name} identity schema"
        )
    return {**result, f"{provider}IdentitySchema": schema}


def _provider() -> str:
    provider = os.environ.get("CONTRACT_OAUTH_PROVIDER", DEFAULT_PROVIDER)
    if provider not in OAUTH_PROVIDERS:
        raise AdapterError(f"unsupported OAuth provider {provider!r}")
    return provider


def _fixture_binding() -> tuple[str, str, str]:
    provider = _provider()
    run_id = os.environ.get("CONTRACT_OAUTH_RUN_ID", "")
    provider_subject = _provider_subject(provider)
    if not SAFE_VALUE.fullmatch(run_id):
        raise AdapterError("CONTRACT_OAUTH_RUN_ID must be a safe non-empty value")
    return provider, run_id, provider_subject


def _provider_subject(provider: str) -> str:
    subject_name = f"CONTRACT_{provider.upper()}_PROVIDER_SUBJECT"
    provider_subject = os.environ.get(subject_name, "")
    if not SAFE_VALUE.fullmatch(provider_subject):
        raise AdapterError(f"{subject_name} must be a safe non-empty value")
    return provider_subject


def _require_identifier(value: str, expected: str, kind: str) -> None:
    if value != expected:
        raise AdapterError(f"unsupported {kind} {value!r}")


def setup(config: Any, fixture: str) -> dict[str, Any]:
    provider, run_id, provider_subject = _fixture_binding()
    _require_identifier(fixture, f"{provider}-oauth-user", "fixture")
    shared.reset(config)
    shared.seed(config)
    return {
        "userId": shared.ACTIVE_USER_ID,
        "email": shared.emails(config)[shared.ACTIVE_USER_ID],
        "name": "Contract Active",
        "roles": [{"serviceKey": "temis", "name": "user"}],
        "audience": config.audience,
        "clientId": config.client_id,
        "redirectUri": config.redirect_uri,
        "provider": provider,
        "providerSubject": provider_subject,
        "runId": run_id,
    }


def _rows(config: Any, sql: str) -> list[str]:
    value = shared.psql(config, sql)
    return [row for row in value.splitlines() if row]


def snapshot(config: Any, probe: str) -> dict[str, Any]:
    provider, _run_id, provider_subject = _fixture_binding()
    user_id = shared.ACTIVE_USER_ID
    if probe == f"oauth-{provider}-state":
        provider_name = provider.capitalize()
        identity_rows = _rows(
            config,
            f"""SELECT "provider" || '|' || "providerUserId" || '|' || "userId"::text
FROM "SocialAccount"
WHERE "provider" = '{provider}' AND "providerUserId" = '{provider_subject}';""",
        )
        if len(identity_rows) != 1:
            raise AdapterError(
                f"{provider_name} provider identity projection was malformed"
            )
        identity = identity_rows[0].split("|")
        if len(identity) != 3:
            raise AdapterError(
                f"{provider_name} provider identity projection was malformed"
            )
        hashes = _rows(
            config,
            f"""SELECT "tokenHash" FROM "RefreshToken"
WHERE "userId" = '{user_id}' AND "revokedAt" IS NULL ORDER BY "tokenHash";""",
        )
        return {
            "canonicalUsers": int(
                shared.psql(
                    config,
                    f"""SELECT COUNT(*) FROM "User" WHERE "id" = '{user_id}';""",
                )
            ),
            "providerIdentities": 1,
            "provider": identity[0],
            "providerSubject": identity[1],
            "linkedUserId": identity[2],
            "oauthStatesRemaining": shared.redis_key_count(
                config, "wiseacct:oauth-state:"
            ),
            "handoffsRemaining": shared.redis_key_count(
                config, "wiseacct:auth-handoff:"
            ),
            "activeRefreshTokens": len(hashes),
            "activeTokenHashes": hashes,
        }
    if probe == f"oauth-{provider}-residual":
        hashes = _rows(
            config,
            f"""SELECT "tokenHash" FROM "RefreshToken"
WHERE "userId" = '{user_id}' AND "revokedAt" IS NULL ORDER BY "tokenHash";""",
        )
        return {
            "oauthStates": shared.redis_key_count(config, "wiseacct:oauth-state:"),
            "handoffs": shared.redis_key_count(config, "wiseacct:auth-handoff:"),
            "activeRefreshTokens": len(hashes),
            "activeTokenHashes": hashes,
            "providerRecords": int(
                shared.psql(
                    config,
                    f"""SELECT COUNT(*) FROM "SocialAccount"
WHERE "provider" = '{provider}' AND "providerUserId" = '{provider_subject}';""",
                )
            ),
        }
    if probe == f"oauth-{provider}-provider-invocations":
        raise AdapterError("provider invocation evidence requires the owned launcher")
    raise AdapterError(f"unsupported snapshot probe {probe!r}")


def teardown(config: Any, fixture: str) -> dict[str, str]:
    provider, _run_id, _provider_subject = _fixture_binding()
    _require_identifier(fixture, f"{provider}-oauth-user", "fixture")
    shared.reset(config)
    expected = {
        "oauthStates": 0,
        "handoffs": 0,
        "activeRefreshTokens": 0,
        "activeTokenHashes": [],
        "providerRecords": 0,
    }
    if snapshot(config, f"oauth-{provider}-residual") != expected:
        raise AdapterError(
            f"{provider.capitalize()} OAuth fixture teardown left residual state"
        )
    return {"status": "clean"}


def main(argv: list[str]) -> int:
    try:
        if len(argv) != 2 or argv[0] not in {
            "preflight",
            "setup",
            "snapshot",
            "teardown",
        }:
            raise AdapterError(
                "usage: google_oauth_fixture.py {preflight|setup|snapshot|teardown} <name>"
            )
        command, name = argv
        config = load_config()
        result: Any = preflight(config)
        if command == "setup":
            result = setup(config, name)
        elif command == "snapshot":
            result = snapshot(config, name)
        elif command == "teardown":
            result = teardown(config, name)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (AdapterError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
