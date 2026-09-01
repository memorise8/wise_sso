#!/usr/bin/env python3
"""Validate that Phase 7 qualification targets only isolated loopback resources."""

from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import SplitResult, unquote, urlsplit

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
TEST_DATABASE = re.compile(r"(?:^|_)test(?:_|$)", re.IGNORECASE)


class UnsafeTarget(ValueError):
    """A qualification target could escape the local synthetic boundary."""


def _parsed_url(raw: str, *, label: str, schemes: set[str]) -> SplitResult:
    parsed = urlsplit(raw)
    if parsed.scheme not in schemes:
        raise UnsafeTarget(f"{label} must use one of {sorted(schemes)}")
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


def validate_postgres(raw: str, *, label: str) -> dict[str, object]:
    parsed = _parsed_url(
        raw,
        label=label,
        schemes={"postgresql", "postgresql+asyncpg"},
    )
    database = unquote(parsed.path.removeprefix("/"))
    if parsed.port == 5432:
        raise UnsafeTarget(f"{label} must not use the default PostgreSQL port")
    if not database or "/" in database or TEST_DATABASE.search(database) is None:
        raise UnsafeTarget(f"{label} database name must contain a distinct 'test' segment")
    if parsed.username is None or parsed.password is None:
        raise UnsafeTarget(f"{label} must use an explicit synthetic runtime credential")
    return {
        "database": database,
        "host": parsed.hostname,
        "port": parsed.port,
        "scheme": parsed.scheme,
    }


def validate_redis(raw: str) -> dict[str, object]:
    parsed = _parsed_url(raw, label="Redis URL", schemes={"redis", "rediss"})
    if parsed.port == 6379:
        raise UnsafeTarget("Redis URL must not use the default Redis port")
    database_text = parsed.path.removeprefix("/")
    if not database_text.isdigit():
        raise UnsafeTarget("Redis URL must select one explicit numeric database")
    database = int(database_text)
    if not 1 <= database <= 15:
        raise UnsafeTarget("Redis URL must select an isolated database from 1 through 15")
    return {
        "database": database,
        "host": parsed.hostname,
        "port": parsed.port,
        "scheme": parsed.scheme,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--baseline", required=True)
    result.add_argument("--candidate", required=True)
    result.add_argument("--database", required=True)
    result.add_argument("--node-database", required=True)
    result.add_argument("--redis", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        baseline = validate_http(args.baseline, label="baseline URL")
        candidate = validate_http(args.candidate, label="candidate URL")
        database = validate_postgres(args.database, label="Python database URL")
        node_database = validate_postgres(
            args.node_database,
            label="Node database URL",
        )
        redis = validate_redis(args.redis)
        if baseline["port"] == candidate["port"]:
            raise UnsafeTarget("baseline and candidate must use distinct loopback ports")
        database_endpoint = (database["host"], database["port"], database["database"])
        node_database_endpoint = (
            node_database["host"],
            node_database["port"],
            node_database["database"],
        )
        if database_endpoint != node_database_endpoint:
            raise UnsafeTarget(
                "Python and Node database URLs must select the same host, port, and test database"
            )
        topology = {
            "baseline": baseline,
            "candidate": candidate,
            "database": database,
            "nodeDatabase": node_database,
            "redis": redis,
        }
    except (UnsafeTarget, ValueError) as exc:
        print(f"Phase 7 input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(topology, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
