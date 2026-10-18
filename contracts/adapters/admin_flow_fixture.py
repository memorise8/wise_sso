#!/usr/bin/env python3
"""Fail-closed fixture adapter for the mixed-runtime admin contract flow."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast


class _FixtureModule(Protocol):
    AdapterError: type[Exception]
    ACTIVE_USER_ID: str
    ADMIN_USER_ID: str
    FIXTURE_IDS: tuple[str, ...]
    PASSWORD: str

    def load_config(self) -> Any: ...
    def preflight(self, config: Any) -> dict[str, Any]: ...
    def reset(self, config: Any) -> None: ...
    def seed(self, config: Any) -> None: ...
    def emails(self, config: Any) -> dict[str, str]: ...
    def psql(self, config: Any, sql: str) -> str: ...


def _load(name: str) -> _FixtureModule:
    path = Path(__file__).with_name(name)
    spec = importlib.util.spec_from_file_location(f"admin_flow_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load fixture adapter from {path}")
    module: ModuleType = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_FixtureModule, module)


shared = _load("express_fixture.py")
fastapi = _load("fastapi_fixture.py")
AdapterError = shared.AdapterError

FIXTURE_NAME = "admin-flow-users"
STATE_PROBE = "admin-flow-state"
RESIDUAL_PROBE = "admin-flow-residual"
CONTROL_STATUSES = {"suspend-admin": "SUSPENDED", "restore-admin": "ACTIVE"}
_FIXTURE_IDS = (shared.ADMIN_USER_ID, shared.ACTIVE_USER_ID)
_ALL_FIXTURE_IDS_SQL = ", ".join(f"'{user_id}'" for user_id in shared.FIXTURE_IDS)
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_TOKEN_HASH = re.compile(r"[0-9a-f]{64}\Z", re.IGNORECASE)
_UTC_MILLISECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")
_SENSITIVE_KEY = re.compile(
    r"(?:password|token|secret|authorization|cookie|email|phone|address|name)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:token|password|secret|Bearer\s+|oauth-code|handoff-code)", re.IGNORECASE
)
_EMAIL_VALUE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def _require_name(value: str, expected: str, kind: str) -> None:
    if value != expected:
        raise AdapterError(f"unsupported {kind} {value!r}")


def load_config() -> Any:
    if os.environ.get("CONTRACT_FASTAPI_RUNTIME") != "1":
        raise AdapterError("CONTRACT_FASTAPI_RUNTIME=1 is required")
    return fastapi.load_config()


def preflight(config: Any, fixture: str) -> dict[str, Any]:
    _require_name(fixture, FIXTURE_NAME, "fixture")
    return fastapi.preflight(config)


def _rows(config: Any, sql: str) -> list[str]:
    return [row for row in shared.psql(config, sql).splitlines() if row]


def _role_rows(config: Any) -> dict[str, list[dict[str, str]]]:
    rows = _rows(
        config,
        f"""SELECT ur."userId"::text || '|' || r."id"::text || '|' || r."serviceKey" || '|' || r."name"
FROM "UserRole" ur
JOIN "Role" r ON r."id" = ur."roleId"
WHERE ur."userId" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}')
ORDER BY ur."userId", r."serviceKey", r."name", r."id";""",
    )
    result: dict[str, list[dict[str, str]]] = {user_id: [] for user_id in _FIXTURE_IDS}
    for row in rows:
        parts = row.split("|")
        if len(parts) != 4 or parts[0] not in result or not _UUID.fullmatch(parts[1]):
            raise AdapterError("admin role projection was malformed")
        result[parts[0]].append(
            {"id": parts[1], "serviceKey": parts[2], "name": parts[3]}
        )
    return result


def _admin_role_id(config: Any) -> str:
    rows = _rows(
        config,
        f"""SELECT r."id"::text
FROM "UserRole" ur
JOIN "Role" r ON r."id" = ur."roleId"
WHERE ur."userId" = '{shared.ADMIN_USER_ID}'
  AND r."serviceKey" = 'temis' AND r."name" = 'admin'
ORDER BY r."id";""",
    )
    if len(rows) != 1 or not _UUID.fullmatch(rows[0]):
        raise AdapterError("admin role projection was malformed")
    return rows[0]


def setup(config: Any, fixture: str) -> dict[str, Any]:
    _require_name(fixture, FIXTURE_NAME, "fixture")
    shared.reset(config)
    shared.seed(config)
    fixture_emails = shared.emails(config)
    admin_role_id = _admin_role_id(config)
    return {
        "admin": {
            "userId": shared.ADMIN_USER_ID,
            "email": fixture_emails[shared.ADMIN_USER_ID],
            "password": shared.PASSWORD,
            "name": "Contract Admin",
            "roles": [{"serviceKey": "temis", "name": "admin"}],
            "audience": config.audience,
        },
        "target": {
            "userId": shared.ACTIVE_USER_ID,
            "email": fixture_emails[shared.ACTIVE_USER_ID],
            "password": shared.PASSWORD,
            "name": "Contract Active",
            "roles": [{"serviceKey": "temis", "name": "user"}],
            "audience": config.audience,
        },
        "adminRoleId": admin_role_id,
    }


def _statuses(config: Any) -> tuple[str, str]:
    rows = _rows(
        config,
        f"""SELECT "id"::text || '|' || lower("status"::text)
FROM "User"
WHERE "id" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}')
ORDER BY "id";""",
    )
    statuses: dict[str, str] = {}
    for row in rows:
        parts = row.split("|")
        if (
            len(parts) != 2
            or parts[0] not in _FIXTURE_IDS
            or parts[1]
            not in {
                "active",
                "suspended",
                "pending_email_verification",
                "deleted",
            }
        ):
            raise AdapterError("admin status projection was malformed")
        statuses[parts[0]] = parts[1]
    if set(statuses) != set(_FIXTURE_IDS):
        raise AdapterError("admin status projection was malformed")
    return statuses[shared.ADMIN_USER_ID], statuses[shared.ACTIVE_USER_ID]


def _active_token_hashes(config: Any) -> dict[str, list[str]]:
    rows = _rows(
        config,
        f"""SELECT "userId"::text || '|' || "tokenHash"
FROM "RefreshToken"
WHERE "userId" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}')
  AND "revokedAt" IS NULL
ORDER BY "userId", "tokenHash";""",
    )
    hashes: dict[str, list[str]] = {user_id: [] for user_id in _FIXTURE_IDS}
    for row in rows:
        parts = row.split("|")
        if (
            len(parts) != 2
            or parts[0] not in hashes
            or not _TOKEN_HASH.fullmatch(parts[1])
        ):
            raise AdapterError("active refresh token projection was malformed")
        hashes[parts[0]].append(parts[1])
    return hashes


def _sanitize_details(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    result: dict[str, object] = {}
    for raw_key, item in value.items():
        key = str(raw_key)
        if _SENSITIVE_KEY.search(key) or (
            isinstance(item, str)
            and (_SENSITIVE_VALUE.search(item) or _EMAIL_VALUE.search(item))
        ):
            result[key] = "[REDACTED]"
        elif item is None or isinstance(item, (str, int, float, bool)):
            result[key] = item
        else:
            result[key] = "[REDACTED]"
    return result


def _audits(config: Any) -> list[dict[str, object]]:
    rows = _rows(
        config,
        f"""SELECT json_build_object(
  'id', "id",
  'eventType', "eventType",
  'outcome', "outcome",
  'userId', "userId",
  'actorUserId', "actorUserId",
  'targetUserId', "targetUserId",
  'reasonCode', "reasonCode",
  'detailsJson', "detailsJson",
  'createdAt', to_char("createdAt", 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
)::text
FROM "AuditLog"
WHERE "eventType" LIKE 'admin\\_%' ESCAPE '\\'
  AND (
    "userId" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}') OR
    "actorUserId" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}') OR
    "targetUserId" IN ('{shared.ADMIN_USER_ID}', '{shared.ACTIVE_USER_ID}')
  )
ORDER BY "createdAt", "id";""",
    )
    result: list[dict[str, object]] = []
    expected = {
        "id",
        "eventType",
        "outcome",
        "userId",
        "actorUserId",
        "targetUserId",
        "reasonCode",
        "detailsJson",
        "createdAt",
    }
    for row in rows:
        try:
            projection = json.loads(row)
        except json.JSONDecodeError as exc:
            raise AdapterError("admin audit projection was malformed") from exc
        if not isinstance(projection, dict) or set(projection) != expected:
            raise AdapterError("admin audit projection was malformed")
        event_type = projection["eventType"]
        if not isinstance(event_type, str) or not event_type.startswith("admin_"):
            raise AdapterError("admin audit projection was malformed")
        if not isinstance(projection["outcome"], str) or (
            projection["reasonCode"] is not None
            and not isinstance(projection["reasonCode"], str)
        ):
            raise AdapterError("admin audit projection was malformed")
        if not isinstance(projection["id"], str) or not _UUID.fullmatch(
            projection["id"]
        ):
            raise AdapterError("admin audit projection was malformed")
        for key in ("userId", "actorUserId", "targetUserId"):
            if projection[key] is not None and projection[key] not in _FIXTURE_IDS:
                raise AdapterError("admin audit projection was malformed")
        if not isinstance(
            projection["createdAt"], str
        ) or not _UTC_MILLISECONDS.fullmatch(projection["createdAt"]):
            raise AdapterError("admin audit projection was malformed")
        projection["detailsJson"] = _sanitize_details(projection["detailsJson"])
        result.append(cast(dict[str, object], projection))
    return result


def snapshot(config: Any, probe: str) -> dict[str, Any]:
    if probe == STATE_PROBE:
        admin_status, target_status = _statuses(config)
        roles = _role_rows(config)
        hashes = _active_token_hashes(config)
        return {
            "adminStatus": admin_status,
            "adminRoles": roles[shared.ADMIN_USER_ID],
            "targetStatus": target_status,
            "targetRoles": roles[shared.ACTIVE_USER_ID],
            "adminActiveTokenHashes": hashes[shared.ADMIN_USER_ID],
            "targetActiveTokenHashes": hashes[shared.ACTIVE_USER_ID],
            "audits": _audits(config),
        }
    if probe == RESIDUAL_PROBE:
        return _residual(config)
    raise AdapterError(f"unsupported snapshot probe {probe!r}")


def control(config: Any, operation: str) -> dict[str, str]:
    if operation not in CONTROL_STATUSES:
        raise AdapterError(f"unsupported control operation {operation!r}")
    expected = CONTROL_STATUSES[operation]
    rows = _rows(
        config,
        f"""UPDATE "User"
SET "status" = '{expected}'::"UserStatus", "updatedAt" = CURRENT_TIMESTAMP
WHERE "id" = '{shared.ADMIN_USER_ID}'
RETURNING lower("status"::text);""",
    )
    if rows != [expected.lower()]:
        raise AdapterError("admin control did not update exactly one user")
    return {"status": "controlled"}


def _residual(config: Any) -> dict[str, int]:
    rows = _rows(
        config,
        f"""SELECT
  (SELECT COUNT(*) FROM "User"
   WHERE "id" IN ({_ALL_FIXTURE_IDS_SQL}))::text || '|' ||
  (SELECT COUNT(*) FROM "RefreshToken"
   WHERE "userId" IN ({_ALL_FIXTURE_IDS_SQL})
     AND "revokedAt" IS NULL)::text || '|' ||
  (SELECT COUNT(*) FROM "AuditLog"
   WHERE "eventType" LIKE 'admin\\_%' ESCAPE '\\'
     AND (
       "userId" IN ({_ALL_FIXTURE_IDS_SQL}) OR
       "actorUserId" IN ({_ALL_FIXTURE_IDS_SQL}) OR
       "targetUserId" IN ({_ALL_FIXTURE_IDS_SQL})
     ))::text;""",
    )
    if len(rows) != 1:
        raise AdapterError("admin residual projection was malformed")
    parts = rows[0].split("|")
    try:
        counts = [int(part) for part in parts]
    except ValueError as exc:
        raise AdapterError("admin residual projection was malformed") from exc
    if len(counts) != 3 or any(count < 0 for count in counts):
        raise AdapterError("admin residual projection was malformed")
    return {
        "users": counts[0],
        "activeRefreshTokens": counts[1],
        "adminAudits": counts[2],
    }


def teardown(config: Any, fixture: str) -> dict[str, int]:
    _require_name(fixture, FIXTURE_NAME, "fixture")
    shared.reset(config)
    residual = _residual(config)
    expected = {"users": 0, "activeRefreshTokens": 0, "adminAudits": 0}
    if residual != expected:
        raise AdapterError("admin flow fixture teardown left residual state")
    return residual


def _validate_command(argv: list[str]) -> tuple[str, str]:
    if len(argv) != 2:
        raise AdapterError(
            "usage: admin_flow_fixture.py {preflight|setup|snapshot|control|teardown} <name>"
        )
    command, name = argv
    expected_names = {
        "preflight": {FIXTURE_NAME},
        "setup": {FIXTURE_NAME},
        "snapshot": {STATE_PROBE, RESIDUAL_PROBE},
        "control": set(CONTROL_STATUSES),
        "teardown": {FIXTURE_NAME},
    }
    if command not in expected_names or name not in expected_names[command]:
        raise AdapterError(f"unsupported command binding {command!r} {name!r}")
    return command, name


def main(argv: list[str]) -> int:
    try:
        command, name = _validate_command(argv)
        config = load_config()
        result: Any = preflight(config, FIXTURE_NAME)
        if command == "setup":
            result = setup(config, name)
        elif command == "snapshot":
            result = snapshot(config, name)
        elif command == "control":
            result = control(config, name)
        elif command == "teardown":
            result = teardown(config, name)
        print(json.dumps(result, separators=(",", ":"), sort_keys=True))
        return 0
    except (AdapterError, OSError, ValueError) as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
