#!/usr/bin/env python3
"""Validate and snapshot the Phase 7 shared-state topology."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from validate_inputs import (
    UnsafeTarget,
    _endpoint,
    snapshot_config,
    validate_config,
    validate_http,
    validate_postgres,
    validate_redis,
)


def required_environment(name: str) -> str:
    import os

    value = os.environ.get(name, "")
    if not value:
        raise UnsafeTarget(f"missing required sensitive environment input {name}")
    return value


def credentials(raw: str) -> tuple[str, str]:
    parsed = urlsplit(raw)
    return unquote(parsed.username or ""), unquote(parsed.password or "")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--express", required=True)
    result.add_argument("--fastapi", required=True)
    result.add_argument("--express-config", required=True)
    result.add_argument("--fastapi-config", required=True)
    result.add_argument("--snapshot-dir", type=Path, required=True)
    result.add_argument("--repo", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        express = validate_http(args.express, label="Express URL")
        fastapi = validate_http(args.fastapi, label="FastAPI URL")
        if express["port"] == fastapi["port"]:
            raise UnsafeTarget("Express and FastAPI must use distinct loopback origins")

        express_database_url = required_environment("WISEACCT_PHASE7_EXPRESS_DATABASE_URL")
        fastapi_database_url = required_environment("WISEACCT_PHASE7_FASTAPI_DATABASE_URL")
        fastapi_node_url = required_environment("WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL")
        express_redis_url = required_environment("WISEACCT_PHASE7_EXPRESS_REDIS_URL")
        fastapi_redis_url = required_environment("WISEACCT_PHASE7_FASTAPI_REDIS_URL")
        express_database = validate_postgres(express_database_url, label="Express database URL")
        fastapi_database = validate_postgres(
            fastapi_database_url, label="FastAPI Python database URL", python_url=True
        )
        fastapi_node_database = validate_postgres(
            fastapi_node_url, label="FastAPI Node database URL"
        )
        if _endpoint(express_database) != _endpoint(fastapi_database):
            raise UnsafeTarget("both runtimes must use the same test PostgreSQL endpoint")
        if _endpoint(fastapi_database) != _endpoint(fastapi_node_database):
            raise UnsafeTarget("FastAPI Python and Node URLs must use the same test database")
        express_credential = credentials(express_database_url)
        fastapi_credential = credentials(fastapi_node_url)
        if credentials(fastapi_database_url) != fastapi_credential:
            raise UnsafeTarget("FastAPI Python and Node URLs must use the same runtime credential")
        if express_credential[0] == fastapi_credential[0]:
            raise UnsafeTarget("shared-state runtime roles must be distinct")
        if express_credential[1] == fastapi_credential[1]:
            raise UnsafeTarget("shared-state runtime passwords must be distinct")

        express_redis = validate_redis(express_redis_url, label="Express Redis URL")
        fastapi_redis = validate_redis(fastapi_redis_url, label="FastAPI Redis URL")
        if _endpoint(express_redis) != _endpoint(fastapi_redis):
            raise UnsafeTarget("both runtimes must use the same isolated Redis tuple")
        if express_redis["database"] != 13:
            raise UnsafeTarget("shared-state gate is restricted to Redis database 13")

        if (
            not args.snapshot_dir.is_dir()
            or args.snapshot_dir.is_symlink()
            or (args.snapshot_dir.stat().st_mode & 0o777) != 0o700
        ):
            raise UnsafeTarget("private snapshot directory must have exact mode 0700")
        express_config = snapshot_config(
            args.express_config,
            label="Express",
            repo=args.repo,
            evidence=args.evidence,
            target=args.snapshot_dir / "express.json",
        )
        fastapi_config = snapshot_config(
            args.fastapi_config,
            label="FastAPI",
            repo=args.repo,
            evidence=args.evidence,
            target=args.snapshot_dir / "fastapi.json",
        )
        validate_config(
            express_config,
            label="Express",
            expected_database=express_database_url,
            expected_redis=express_redis_url,
            expected_base=args.express,
            fastapi=False,
        )
        validate_config(
            fastapi_config,
            label="FastAPI",
            expected_database=fastapi_node_url,
            expected_redis=fastapi_redis_url,
            expected_base=args.fastapi,
            fastapi=True,
        )
        policy_keys = {
            "CONTRACT_REFRESH_SECRET",
            "CONTRACT_FIXTURE_AUDIENCE",
            "CONTRACT_FIXTURE_CLIENT_ID",
            "CONTRACT_FIXTURE_REDIRECT_URI",
        }
        if any(express_config.get(key) != fastapi_config.get(key) for key in policy_keys):
            raise UnsafeTarget("both runtimes must use the same signer and client policy")
        topology = {
            "express": express,
            "fastapi": fastapi,
            "postgres": {"shared": express_database, "distinctRuntimeRoles": True},
            "redis": {"shared": express_redis},
            "adapterConfigs": "private-snapshots-not-persisted",
        }
    except (OSError, UnsafeTarget, ValueError) as exc:
        print(f"Phase 7 shared-state input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(topology, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
