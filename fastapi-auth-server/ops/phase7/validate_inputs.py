#!/usr/bin/env python3
"""Validate and snapshot isolated Phase 7 inputs without echoing credentials."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
TEST_DATABASE = re.compile(r"(?:^|_)(?:test|contract|fixture)(?:_|$)", re.IGNORECASE)
COMMON_CONFIG_KEYS = {
    "CONTRACT_FIXTURE_MODE",
    "CONTRACT_SERVER_MAIL_MODE",
    "CONTRACT_REDIS_ISOLATED_DB",
    "CONTRACT_REFRESH_SECRET",
    "CONTRACT_BASE_URL",
    "CONTRACT_DATABASE_URL",
    "CONTRACT_REDIS_URL",
    "CONTRACT_FIXTURE_EMAIL_DOMAIN",
    "CONTRACT_FIXTURE_AUDIENCE",
    "CONTRACT_FIXTURE_CLIENT_ID",
    "CONTRACT_FIXTURE_REDIRECT_URI",
}


class UnsafeTarget(ValueError):
    """A qualification target could escape the local synthetic boundary."""


def _parsed_url(raw: str, *, label: str, schemes: set[str]) -> SplitResult:
    parsed = urlsplit(raw)
    if parsed.scheme not in schemes:
        raise UnsafeTarget(f"{label} must use an approved scheme")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise UnsafeTarget(f"{label} must target loopback only")
    if parsed.port is None:
        raise UnsafeTarget(f"{label} must use an explicit port")
    if parsed.query or parsed.fragment:
        raise UnsafeTarget(f"{label} must not contain a query or fragment")
    return parsed


def validate_http(raw: str, *, label: str) -> dict[str, object]:
    parsed = _parsed_url(raw, label=label, schemes={"http", "https"})
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTarget(f"{label} must not contain credentials")
    if parsed.path not in {"", "/"}:
        raise UnsafeTarget(f"{label} must be an origin without a path")
    return {"host": parsed.hostname, "port": parsed.port, "scheme": parsed.scheme}


def validate_postgres(raw: str, *, label: str, python_url: bool = False) -> dict[str, object]:
    parsed = _parsed_url(
        raw,
        label=label,
        schemes={"postgresql+asyncpg"} if python_url else {"postgres", "postgresql"},
    )
    database = unquote(parsed.path.removeprefix("/"))
    if parsed.port == 5432:
        raise UnsafeTarget(f"{label} must not use the default PostgreSQL port")
    if not database or "/" in database or TEST_DATABASE.search(database) is None:
        raise UnsafeTarget(f"{label} database name must contain a distinct test segment")
    if parsed.username is None or parsed.password is None:
        raise UnsafeTarget(f"{label} must use an explicit synthetic runtime credential")
    return {"database": database, "host": parsed.hostname, "port": parsed.port}


def validate_redis(raw: str, *, label: str) -> dict[str, object]:
    parsed = _parsed_url(raw, label=label, schemes={"redis", "rediss"})
    if parsed.port == 6379:
        raise UnsafeTarget(f"{label} must not use the default Redis port")
    database_text = parsed.path.removeprefix("/")
    if not database_text.isdigit():
        raise UnsafeTarget(f"{label} must use one numeric database")
    database = int(database_text)
    if not 1 <= database <= 15:
        raise UnsafeTarget(f"{label} database must be from 1 through 15")
    return {"database": database, "host": parsed.hostname, "port": parsed.port}


def _endpoint(value: dict[str, object]) -> tuple[object, object, object]:
    host = "loopback" if value["host"] in LOOPBACK_HOSTS else value["host"]
    return host, value["port"], value["database"]


def snapshot_config(
    raw_path: str, *, label: str, repo: Path, evidence: Path, target: Path
) -> dict[str, str]:
    path = Path(raw_path)
    if not path.is_absolute():
        raise UnsafeTarget(f"{label} adapter config path must be absolute")
    resolved = path.resolve()
    if resolved.is_relative_to(repo.resolve()) or resolved.is_relative_to(evidence.resolve()):
        raise UnsafeTarget(f"{label} adapter config must be outside the repository and evidence")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise UnsafeTarget(
            f"{label} adapter config must be an existing regular non-link file"
        ) from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise UnsafeTarget(f"{label} adapter config must be a regular file")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise UnsafeTarget(f"{label} adapter config must have permission mode 0600")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            payload = source.read()
    finally:
        os.close(descriptor)
    try:
        document: Any = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsafeTarget(f"{label} adapter config must contain valid JSON") from exc
    if not isinstance(document, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in document.items()
    ):
        raise UnsafeTarget(f"{label} adapter config must be a string environment object")
    target.write_bytes(payload)
    target.chmod(0o600)
    return document


def validate_config(
    document: dict[str, str],
    *,
    label: str,
    expected_database: str,
    expected_redis: str,
    expected_base: str,
    fastapi: bool,
) -> None:
    allowed = COMMON_CONFIG_KEYS | ({"CONTRACT_FASTAPI_RUNTIME"} if fastapi else set())
    unknown = set(document) - allowed
    if unknown:
        raise UnsafeTarget(f"{label} adapter config contains unapproved environment keys")
    required = {
        "CONTRACT_FIXTURE_MODE": "1",
        "CONTRACT_SERVER_MAIL_MODE": "dev",
        "CONTRACT_REDIS_ISOLATED_DB": "1",
        "CONTRACT_DATABASE_URL": expected_database,
        "CONTRACT_REDIS_URL": expected_redis,
    }
    if fastapi:
        required["CONTRACT_FASTAPI_RUNTIME"] = "1"
    if any(document.get(key) != value for key, value in required.items()):
        raise UnsafeTarget(f"{label} adapter config is missing required isolated values")
    if document.get("CONTRACT_BASE_URL", expected_base) != expected_base:
        raise UnsafeTarget(f"{label} adapter config origin does not match its runtime")
    if len(document.get("CONTRACT_REFRESH_SECRET", "")) < 16:
        raise UnsafeTarget(f"{label} adapter config requires a non-placeholder refresh secret")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline", required=True)
    result.add_argument("--candidate", required=True)
    result.add_argument("--express-config", required=True)
    result.add_argument("--fastapi-config", required=True)
    result.add_argument("--snapshot-dir", type=Path, required=True)
    result.add_argument("--repo", type=Path, required=True)
    result.add_argument("--evidence", type=Path, required=True)
    return result


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise UnsafeTarget(f"missing required sensitive environment input {name}")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        baseline = validate_http(args.baseline, label="baseline URL")
        candidate = validate_http(args.candidate, label="candidate URL")
        if baseline["port"] == candidate["port"]:
            raise UnsafeTarget("baseline and candidate must use distinct loopback origins")
        express_url = required_environment("WISEACCT_PHASE7_EXPRESS_DATABASE_URL")
        fastapi_url = required_environment("WISEACCT_PHASE7_FASTAPI_DATABASE_URL")
        fastapi_node_url = required_environment("WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL")
        express_redis_url = required_environment("WISEACCT_PHASE7_EXPRESS_REDIS_URL")
        fastapi_redis_url = required_environment("WISEACCT_PHASE7_FASTAPI_REDIS_URL")
        express_database = validate_postgres(express_url, label="Express database URL")
        fastapi_database = validate_postgres(
            fastapi_url, label="FastAPI Python database URL", python_url=True
        )
        fastapi_node_database = validate_postgres(
            fastapi_node_url, label="FastAPI Node database URL"
        )
        if _endpoint(express_database) == _endpoint(fastapi_database):
            raise UnsafeTarget("Express and FastAPI must use separate test PostgreSQL endpoints")
        if _endpoint(fastapi_database) != _endpoint(fastapi_node_database):
            raise UnsafeTarget("FastAPI Python and Node URLs must use the same test database")
        express_redis = validate_redis(express_redis_url, label="Express Redis URL")
        fastapi_redis = validate_redis(fastapi_redis_url, label="FastAPI Redis URL")
        if _endpoint(express_redis) == _endpoint(fastapi_redis):
            raise UnsafeTarget("Express and FastAPI must use distinct isolated Redis tuples")
        if (
            not args.snapshot_dir.is_dir()
            or stat.S_IMODE(args.snapshot_dir.stat().st_mode) != 0o700
        ):
            raise UnsafeTarget("private snapshot directory must exist with permission mode 0700")
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
            expected_database=express_url,
            expected_redis=express_redis_url,
            expected_base=args.baseline,
            fastapi=False,
        )
        validate_config(
            fastapi_config,
            label="FastAPI",
            expected_database=fastapi_node_url,
            expected_redis=fastapi_redis_url,
            expected_base=args.candidate,
            fastapi=True,
        )
        topology = {
            "baseline": baseline,
            "candidate": candidate,
            "postgres": {"express": express_database, "fastapi": fastapi_database},
            "redis": {"express": express_redis, "fastapi": fastapi_redis},
            "adapterConfigs": "private-snapshots-not-persisted",
        }
    except (UnsafeTarget, ValueError) as exc:
        print(f"Phase 7 input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(topology, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
