#!/usr/bin/env python3
"""Run the non-qualifying administrator compatibility development flow."""

from __future__ import annotations

import hashlib
import importlib.util
import math
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, cast
from urllib import parse

FLOW = "admin-status-role-session-audit"
RUNTIMES = ("express", "fastapi")
TOPOLOGIES = ("express", "fastapi", "express-fastapi", "fastapi-express")
ADMIN_USER_ID = "00000000-0000-4000-8000-000000000003"
TARGET_USER_ID = "00000000-0000-4000-8000-000000000001"
ASSERTIONS = frozenset(
    {
        "fixturePreflight",
        "adminAccessJwtVerified",
        "aliasParity",
        "filteredDirectory",
        "auditProjection",
        "missingBearerDenied",
        "nonAdminDenied",
        "roleAssigned",
        "roleRemoved",
        "targetSessionsRevoked",
        "oldRefreshRejected",
        "targetSuspended",
        "suspendedLoginRejected",
        "targetReactivated",
        "selfProtection",
        "staleAdminBearerRejected",
        "databaseStateMatched",
        "cleanupVerified",
    }
)
UNVERIFIED = (
    "real-engine-admin-corpus",
    "sample-size-one-per-topology",
    "cross-runtime-admin-audit-transaction-atomicity",
    "authenticated-collection",
    "global-role-cleanup",
)
FIXTURE = "admin-flow-users"
STATE = "admin-flow-state"
RESIDUAL = "admin-flow-residual"
ROLE = {"serviceKey": "temis", "name": "admin"}
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_UTC_MILLISECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")


class ContractFailure(Exception):
    """The administrator flow did not prove its development assertions."""


class Adapter(Protocol):
    isolation_identity: tuple[str, str]
    refresh_secret: str

    def invoke(self, command: str, name: str) -> Any: ...


def _flow_helpers() -> Any:
    path = Path(__file__).with_name("flow_driver.py")
    spec = importlib.util.spec_from_file_location("admin_flow_helpers", path)
    if spec is None or spec.loader is None:
        raise ContractFailure("helper-load-failure")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _object(value: Any, failure: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractFailure(failure)
    return value


def _origin(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ContractFailure(f"invalid-{label}-origin")
    try:
        parsed = parse.urlparse(value)
        port = parsed.port
    except ValueError as exc:
        raise ContractFailure(f"invalid-{label}-origin") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or port is None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ContractFailure(f"invalid-{label}-origin")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"http://{host}:{port}"


def _runtime_order(topology: str) -> tuple[str, str]:
    if topology == "express":
        return ("express", "express")
    if topology == "fastapi":
        return ("fastapi", "fastapi")
    if topology == "express-fastapi":
        return ("express", "fastapi")
    if topology == "fastapi-express":
        return ("fastapi", "express")
    raise ContractFailure("unsupported-admin-topology")


def _validate_inputs(
    topology: str,
    urls: dict[str, str],
    adapters: Mapping[str, Adapter],
    expected_issuer: str,
    timeout: float,
) -> tuple[str, str, dict[str, str], tuple[Adapter, ...]]:
    actor_runtime, target_runtime = _runtime_order(topology)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ContractFailure("invalid-admin-timeout")
    if not isinstance(expected_issuer, str):
        raise ContractFailure("invalid-admin-issuer")
    try:
        issuer = parse.urlparse(expected_issuer)
        issuer_port = issuer.port
    except ValueError as exc:
        raise ContractFailure("invalid-admin-issuer") from exc
    if (
        issuer.scheme != "https"
        or issuer.hostname is None
        or issuer.path
        or issuer.params
        or issuer.query
        or issuer.fragment
        or issuer.username
        or issuer.password
    ):
        raise ContractFailure("invalid-admin-issuer")
    issuer_host = f"[{issuer.hostname}]" if ":" in issuer.hostname else issuer.hostname
    canonical_issuer = (
        f"https://{issuer_host}:{issuer_port}"
        if issuer_port is not None
        else f"https://{issuer_host}"
    )
    if expected_issuer != canonical_issuer:
        raise ContractFailure("invalid-admin-issuer")
    required = tuple(dict.fromkeys((actor_runtime, target_runtime)))
    if set(urls) != set(required) or set(adapters) != set(required):
        raise ContractFailure("admin-topology-binding-mismatch")
    normalized = {runtime: _origin(urls[runtime], runtime) for runtime in required}
    if len(required) == 2 and len(set(normalized.values())) != 2:
        raise ContractFailure("mixed-admin-topology-requires-distinct-origins")
    participants = tuple(adapters[runtime] for runtime in required)
    identities = [
        getattr(adapter, "isolation_identity", None) for adapter in participants
    ]
    if any(
        not isinstance(identity, tuple)
        or len(identity) != 2
        or any(not isinstance(item, str) or not item for item in identity)
        for identity in identities
    ):
        raise ContractFailure("invalid-admin-isolation-identity")
    if len(set(identities)) != 1:
        raise ContractFailure("mixed-admin-topology-requires-shared-isolation")
    if any(
        not isinstance(getattr(adapter, "refresh_secret", None), str)
        or not adapter.refresh_secret
        for adapter in participants
    ):
        raise ContractFailure("invalid-admin-refresh-secret")
    return actor_runtime, target_runtime, normalized, participants


def _preflight(adapter: Adapter, runtime: str) -> None:
    del runtime
    result = _object(adapter.invoke("preflight", FIXTURE), "malformed-admin-preflight")
    identity = adapter.isolation_identity
    database = parse.urlparse(identity[0]).path.lstrip("/")
    redis_path = parse.urlparse(identity[1]).path.lstrip("/")
    if not database or not redis_path.isdigit():
        raise ContractFailure("invalid-admin-isolation-identity")
    expected: dict[str, Any] = {
        "status": "ok",
        "database": database,
        "redisDatabase": int(redis_path),
        "mailMode": "dev",
        "runtime": "fastapi",
        "schema": "prisma-compatible",
    }
    if not _strict_equal(result, expected):
        raise ContractFailure("admin-preflight-mismatch")


def _fixture_user(value: Any, expected_id: str, label: str) -> dict[str, Any]:
    user = _object(value, f"malformed-{label}-fixture")
    if set(user) != {"userId", "email", "password", "name", "roles", "audience"}:
        raise ContractFailure(f"malformed-{label}-fixture")
    if user["userId"] != expected_id:
        raise ContractFailure(f"wrong-{label}-fixture-identity")
    if any(
        not isinstance(user[key], str) or not user[key]
        for key in ("email", "password", "name", "audience")
    ):
        raise ContractFailure(f"malformed-{label}-fixture")
    _fixture_roles(user["roles"])
    return user


def _fixture_roles(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ContractFailure("malformed-admin-fixture-roles")
    roles: list[dict[str, str]] = []
    for raw in value:
        role = _object(raw, "malformed-admin-fixture-role")
        if set(role) != {"serviceKey", "name"} or any(
            not isinstance(role[key], str) or not role[key]
            for key in ("serviceKey", "name")
        ):
            raise ContractFailure("malformed-admin-fixture-role")
        roles.append(dict(role))
    if len({(role["serviceKey"], role["name"]) for role in roles}) != len(roles):
        raise ContractFailure("duplicate-admin-fixture-role")
    return sorted(roles, key=lambda item: (item["serviceKey"], item["name"]))


def _roles(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ContractFailure("malformed-admin-roles")
    roles: list[dict[str, str]] = []
    for raw in value:
        role = _object(raw, "malformed-admin-role")
        if set(role) != {"id", "serviceKey", "name"} or any(
            not isinstance(role[key], str) or not role[key]
            for key in ("id", "serviceKey", "name")
        ):
            raise ContractFailure("malformed-admin-role")
        roles.append({key: role[key] for key in ("id", "serviceKey", "name")})
    if len({role["id"] for role in roles}) != len(roles):
        raise ContractFailure("duplicate-admin-role")
    return sorted(
        roles, key=lambda item: (item["serviceKey"], item["name"], item["id"])
    )


def _setup(adapter: Adapter) -> tuple[dict[str, Any], dict[str, Any], str]:
    setup = _object(adapter.invoke("setup", FIXTURE), "malformed-admin-fixture")
    if set(setup) != {"admin", "target", "adminRoleId"}:
        raise ContractFailure("malformed-admin-fixture")
    admin = _fixture_user(setup["admin"], ADMIN_USER_ID, "admin")
    target = _fixture_user(setup["target"], TARGET_USER_ID, "target")
    role_id = setup["adminRoleId"]
    if not isinstance(role_id, str) or not role_id:
        raise ContractFailure("malformed-admin-role-id")
    if ROLE not in _fixture_roles(admin["roles"]):
        raise ContractFailure("admin-role-fixture-mismatch")
    if admin["email"] == target["email"]:
        raise ContractFailure("admin-fixture-email-collision")
    return admin, target, role_id


def _hashes(value: Any) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str)
        or len(item) != 64
        or any(character not in "0123456789abcdef" for character in item)
        for item in value
    ):
        raise ContractFailure("malformed-admin-token-hashes")
    if len(value) != len(set(value)):
        raise ContractFailure("duplicate-admin-token-hashes")
    return sorted(value)


def _audits(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ContractFailure("malformed-admin-audits")
    result: list[dict[str, Any]] = []
    keys = {
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
    for raw in value:
        item = _object(raw, "malformed-admin-audit")
        if (
            set(item) != keys
            or not isinstance(item["eventType"], str)
            or not item["eventType"].startswith("admin_")
        ):
            raise ContractFailure("malformed-admin-audit")
        if item["outcome"] not in {"success", "failure"}:
            raise ContractFailure("malformed-admin-audit")
        if item["actorUserId"] not in {ADMIN_USER_ID, TARGET_USER_ID}:
            raise ContractFailure("admin-audit-identity-mismatch")
        if item["userId"] not in {ADMIN_USER_ID, TARGET_USER_ID} or item[
            "targetUserId"
        ] not in {None, ADMIN_USER_ID, TARGET_USER_ID}:
            raise ContractFailure("admin-audit-identity-mismatch")
        if (
            not isinstance(item["id"], str)
            or _UUID.fullmatch(item["id"]) is None
            or not isinstance(item["createdAt"], str)
            or _UTC_MILLISECONDS.fullmatch(item["createdAt"]) is None
            or not isinstance(item["reasonCode"], str)
            or not item["reasonCode"]
            or not isinstance(item["detailsJson"], dict)
        ):
            raise ContractFailure("malformed-admin-audit")
        result.append(dict(item))
    if len({item["id"] for item in result}) != len(result):
        raise ContractFailure("duplicate-admin-audit-id")
    return sorted(result, key=lambda item: (item["createdAt"], item["id"]))


def _state(adapter: Adapter) -> dict[str, Any]:
    state = _object(adapter.invoke("snapshot", STATE), "malformed-admin-state")
    keys = {
        "adminStatus",
        "adminRoles",
        "targetStatus",
        "targetRoles",
        "adminActiveTokenHashes",
        "targetActiveTokenHashes",
        "audits",
    }
    if (
        set(state) != keys
        or state["adminStatus"] not in {"active", "suspended", "deleted"}
        or state["targetStatus"] not in {"active", "suspended", "deleted"}
    ):
        raise ContractFailure("malformed-admin-state")
    return {
        "adminStatus": state["adminStatus"],
        "adminRoles": _roles(state["adminRoles"]),
        "targetStatus": state["targetStatus"],
        "targetRoles": _roles(state["targetRoles"]),
        "adminActiveTokenHashes": _hashes(state["adminActiveTokenHashes"]),
        "targetActiveTokenHashes": _hashes(state["targetActiveTokenHashes"]),
        "audits": _audits(state["audits"]),
    }


def _strict_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _strict_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _strict_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _expect_status(result: Any, status: int, body: Any, failure: str) -> None:
    if result.status != status or not _strict_equal(result.body, body):
        raise ContractFailure(failure)
    media = result.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media != "application/json":
        raise ContractFailure(failure)


def _json_body(result: Any, failure: str) -> dict[str, Any]:
    media = result.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media != "application/json":
        raise ContractFailure(failure)
    return _object(result.body, failure)


def _login(
    helpers: Any,
    url: str,
    fixture: dict[str, Any],
    timeout: float,
    issuer: str,
    secret: str,
    observations: list[Any],
) -> tuple[str, str]:
    result = helpers.call(
        url,
        "POST",
        "/auth/login",
        {"email": fixture["email"], "password": fixture["password"]},
        timeout,
        observations,
    )
    try:
        return cast(
            tuple[str, str],
            helpers._verify_token_pair(
                result, url, fixture, timeout, issuer, secret, observations
            ),
        )
    except Exception as exc:
        raise ContractFailure("admin-token-verification-failure") from exc


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message}}


def _audit(
    event: str,
    actor: str,
    target: str | None,
    reason: str,
    details: dict[str, Any],
    *,
    outcome: str = "success",
) -> dict[str, Any]:
    return {
        "eventType": event,
        "outcome": outcome,
        "userId": actor if target is None else target,
        "actorUserId": actor,
        "targetUserId": target,
        "reasonCode": reason,
        "detailsJson": details,
    }


def _expect_audits(actual: dict[str, Any], expected: list[dict[str, Any]]) -> None:
    semantic_keys = {
        "eventType",
        "outcome",
        "userId",
        "actorUserId",
        "targetUserId",
        "reasonCode",
        "detailsJson",
    }
    projected = [{key: item[key] for key in semantic_keys} for item in actual["audits"]]
    if not _strict_equal(projected, expected):
        raise ContractFailure("admin-audit-state-mismatch")


def _page_items(result: Any, failure: str) -> list[dict[str, Any]]:
    body = _object(result.body, failure)
    if (
        result.status != 200
        or set(body) != {"items", "total", "page", "pageSize"}
        or not isinstance(body["items"], list)
        or not isinstance(body["total"], int)
        or isinstance(body["total"], bool)
        or not isinstance(body["page"], int)
        or isinstance(body["page"], bool)
        or not isinstance(body["pageSize"], int)
        or isinstance(body["pageSize"], bool)
        or body["total"] != len(body["items"])
    ):
        raise ContractFailure(failure)
    if body["page"] != 1 or body["pageSize"] != 25:
        raise ContractFailure(failure)
    return [_object(item, failure) for item in body["items"]]


def _refresh_rejected(
    helpers: Any, url: str, refresh: str, timeout: float, observations: list[Any]
) -> None:
    result = helpers.call(
        url, "POST", "/auth/refresh", {"refreshToken": refresh}, timeout, observations
    )
    _expect_status(
        result,
        401,
        _error("INVALID_REFRESH_TOKEN", "Invalid refresh token"),
        "revoked-refresh-accepted",
    )


def _assert_state(
    actual: dict[str, Any],
    *,
    admin: dict[str, Any],
    target: dict[str, Any],
    admin_hashes: set[str],
    target_hashes: set[str],
    target_status: str,
    target_admin: bool,
    minimum_audits: int,
) -> None:
    expected_target_roles = _fixture_roles(target["roles"])
    actual_target_roles = [
        {"serviceKey": role["serviceKey"], "name": role["name"]}
        for role in actual["targetRoles"]
    ]
    actual_admin_roles = [
        {"serviceKey": role["serviceKey"], "name": role["name"]}
        for role in actual["adminRoles"]
    ]
    has_target_admin = any(
        role["serviceKey"] == "temis" and role["name"] == "admin"
        for role in actual["targetRoles"]
    )
    if (
        actual["adminStatus"] != "active"
        or actual_admin_roles != _fixture_roles(admin["roles"])
        or actual["targetStatus"] != target_status
        or (not target_admin and actual_target_roles != expected_target_roles)
        or has_target_admin != target_admin
        or set(actual["adminActiveTokenHashes"]) != admin_hashes
        or set(actual["targetActiveTokenHashes"]) != target_hashes
        or len(actual["audits"]) < minimum_audits
    ):
        raise ContractFailure("admin-state-transition-mismatch")


def _run_flow(
    actor_url: str,
    target_url: str,
    adapter: Adapter,
    admin: dict[str, Any],
    target: dict[str, Any],
    admin_role_id: str,
    expected_issuer: str,
    timeout: float,
    actor_refresh_secret: str,
    target_refresh_secret: str,
) -> None:
    helpers = _flow_helpers()
    observations: list[Any] = []
    admin_access, admin_refresh = _login(
        helpers,
        actor_url,
        admin,
        timeout,
        expected_issuer,
        actor_refresh_secret,
        observations,
    )
    target_access, target_refresh = _login(
        helpers,
        target_url,
        target,
        timeout,
        expected_issuer,
        target_refresh_secret,
        observations,
    )
    admin_hashes = {hashlib.sha256(admin_refresh.encode()).hexdigest()}
    target_hashes = {hashlib.sha256(target_refresh.encode()).hexdigest()}
    initial = _state(adapter)
    _assert_state(
        initial,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=target_hashes,
        target_status="active",
        target_admin=False,
        minimum_audits=0,
    )
    if not any(role == {"id": admin_role_id, **ROLE} for role in initial["adminRoles"]):
        raise ContractFailure("admin-role-state-mismatch")
    auth = {"authorization": f"Bearer {admin_access}"}

    directory_projections: list[list[dict[str, Any]]] = []
    audit_projections: list[list[dict[str, Any]]] = []
    origins = tuple(dict.fromkeys((actor_url, target_url)))
    for url in origins:
        for alias in ("/admin", "/manage-api"):
            directory = helpers.call(
                url,
                "GET",
                f"{alias}/users?email={parse.quote(target['email'], safe='')}",
                None,
                timeout,
                observations,
                auth,
            )
            users = _page_items(directory, "admin-directory-contract-mismatch")
            if len(users) != 1:
                raise ContractFailure("admin-directory-projection-mismatch")
            user = users[0]
            if (
                set(user) != {"id", "email", "name", "status", "createdAt", "roles"}
                or user["id"] != TARGET_USER_ID
                or user["email"] != target["email"]
                or user["name"] != target["name"]
                or user["status"] != "ACTIVE"
                or not isinstance(user["createdAt"], str)
                or not user["createdAt"]
                or _roles(user["roles"]) != initial["targetRoles"]
            ):
                raise ContractFailure("admin-directory-projection-mismatch")
            directory_projections.append(users)
            audit_page = helpers.call(
                url,
                "GET",
                f"{alias}/audit-logs?actorUserId={ADMIN_USER_ID}",
                None,
                timeout,
                observations,
                auth,
            )
            audit_projections.append(
                _page_items(audit_page, "admin-audit-contract-mismatch")
            )
    if any(
        not _strict_equal(projection, directory_projections[0])
        for projection in directory_projections[1:]
    ):
        raise ContractFailure("admin-alias-projection-mismatch")
    if any(projection != [] for projection in audit_projections):
        raise ContractFailure("admin-audit-initial-state-mismatch")

    missing = helpers.call(
        target_url, "GET", "/manage-api/users", None, timeout, observations
    )
    _expect_status(
        missing,
        401,
        _error("UNAUTHORIZED", "Bearer access token is required"),
        "missing-admin-bearer-accepted",
    )
    denied = helpers.call(
        actor_url,
        "GET",
        "/admin/users",
        None,
        timeout,
        observations,
        {"authorization": f"Bearer {target_access}"},
    )
    _expect_status(
        denied,
        403,
        _error("FORBIDDEN", "Admin role is required"),
        "non-admin-bearer-accepted",
    )
    expected_audits = [
        _audit(
            "admin_authorization_failure",
            TARGET_USER_ID,
            None,
            "FORBIDDEN",
            {"route": "/admin/users", "method": "GET"},
            outcome="failure",
        )
    ]

    assigned = helpers.call(
        target_url,
        "POST",
        f"/manage-api/users/{TARGET_USER_ID}/roles",
        {**ROLE, "reasonCode": "CONTRACT_ROLE_ASSIGN"},
        timeout,
        observations,
        auth,
    )
    assigned_body = _json_body(assigned, "admin-role-assignment-mismatch")
    role_id = assigned_body.get("roleId")
    if (
        assigned.status != 200
        or set(assigned_body) != {"roleAssigned", "roleId"}
        or assigned_body.get("roleAssigned") is not True
        or not isinstance(role_id, str)
        or not role_id
    ):
        raise ContractFailure("admin-role-assignment-mismatch")
    after_assign = _state(adapter)
    _assert_state(
        after_assign,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=target_hashes,
        target_status="active",
        target_admin=True,
        minimum_audits=2,
    )
    assigned_role_names = [
        {"serviceKey": role["serviceKey"], "name": role["name"]}
        for role in after_assign["targetRoles"]
    ]
    if assigned_role_names != sorted(
        [*_fixture_roles(target["roles"]), ROLE],
        key=lambda item: (item["serviceKey"], item["name"]),
    ) or not any(
        role == {"id": role_id, **ROLE} for role in after_assign["targetRoles"]
    ):
        raise ContractFailure("admin-assigned-role-state-mismatch")
    expected_audits.append(
        _audit(
            "admin_user_role_assigned",
            ADMIN_USER_ID,
            TARGET_USER_ID,
            "CONTRACT_ROLE_ASSIGN",
            {"route": "POST /admin/users/:id/roles"},
        )
    )
    _expect_audits(after_assign, expected_audits)

    removed = helpers.call(
        actor_url,
        "DELETE",
        f"/admin/users/{TARGET_USER_ID}/roles/{parse.quote(role_id, safe='')}",
        {"reasonCode": "CONTRACT_ROLE_REMOVE"},
        timeout,
        observations,
        auth,
    )
    removed_body = _json_body(removed, "admin-role-removal-mismatch")
    if (
        removed.status != 200
        or set(removed_body) != {"roleRemoved", "roleId", "revokedRefreshTokenCount"}
        or removed_body.get("roleRemoved") is not True
        or removed_body.get("roleId") != role_id
        or not _strict_equal(removed_body.get("revokedRefreshTokenCount"), 1)
    ):
        raise ContractFailure("admin-role-removal-mismatch")
    target_hashes.clear()
    _refresh_rejected(helpers, target_url, target_refresh, timeout, observations)
    after_remove = _state(adapter)
    _assert_state(
        after_remove,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=target_hashes,
        target_status="active",
        target_admin=False,
        minimum_audits=3,
    )
    expected_audits.append(
        _audit(
            "admin_user_role_removed",
            ADMIN_USER_ID,
            TARGET_USER_ID,
            "CONTRACT_ROLE_REMOVE",
            {
                "roleId": role_id,
                "route": "DELETE /admin/users/:id/roles/:roleId",
            },
        )
    )
    _expect_audits(after_remove, expected_audits)

    _target_access, target_refresh = _login(
        helpers,
        target_url,
        target,
        timeout,
        expected_issuer,
        target_refresh_secret,
        observations,
    )
    target_hashes = {hashlib.sha256(target_refresh.encode()).hexdigest()}
    revoked = helpers.call(
        target_url,
        "POST",
        f"/manage-api/users/{TARGET_USER_ID}/revoke-sessions",
        {"reasonCode": "CONTRACT_SESSION_REVOKE"},
        timeout,
        observations,
        auth,
    )
    revoked_body = _json_body(revoked, "admin-session-revocation-mismatch")
    if (
        revoked.status != 200
        or set(revoked_body) != {"revokedCount"}
        or not _strict_equal(revoked_body.get("revokedCount"), 1)
    ):
        raise ContractFailure("admin-session-revocation-mismatch")
    expected_audits.append(
        _audit(
            "admin_user_sessions_revoked",
            ADMIN_USER_ID,
            TARGET_USER_ID,
            "CONTRACT_SESSION_REVOKE",
            {"route": "POST /admin/users/:id/revoke-sessions"},
        )
    )
    target_hashes.clear()
    _refresh_rejected(helpers, target_url, target_refresh, timeout, observations)
    after_revoke = _state(adapter)
    _assert_state(
        after_revoke,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=set(),
        target_status="active",
        target_admin=False,
        minimum_audits=4,
    )
    _expect_audits(after_revoke, expected_audits)

    _target_access, target_refresh = _login(
        helpers,
        actor_url,
        target,
        timeout,
        expected_issuer,
        actor_refresh_secret,
        observations,
    )
    target_hashes = {hashlib.sha256(target_refresh.encode()).hexdigest()}
    suspended = helpers.call(
        actor_url,
        "PATCH",
        f"/admin/users/{TARGET_USER_ID}/status",
        {"status": "SUSPENDED", "reasonCode": "CONTRACT_SUSPEND"},
        timeout,
        observations,
        auth,
    )
    suspended_body = _json_body(suspended, "admin-status-suspension-mismatch")
    if (
        suspended.status != 200
        or set(suspended_body) != {"statusChanged", "revokedRefreshTokenCount"}
        or suspended_body.get("statusChanged") is not True
        or not _strict_equal(suspended_body.get("revokedRefreshTokenCount"), 1)
    ):
        raise ContractFailure("admin-status-suspension-mismatch")
    expected_audits.append(
        _audit(
            "admin_user_status_changed",
            ADMIN_USER_ID,
            TARGET_USER_ID,
            "CONTRACT_SUSPEND",
            {"route": "PATCH /admin/users/:id/status"},
        )
    )
    target_hashes.clear()
    after_suspend = _state(adapter)
    _assert_state(
        after_suspend,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=set(),
        target_status="suspended",
        target_admin=False,
        minimum_audits=5,
    )
    _expect_audits(after_suspend, expected_audits)
    suspended_login = helpers.call(
        target_url,
        "POST",
        "/auth/login",
        {"email": target["email"], "password": target["password"]},
        timeout,
        observations,
    )
    _expect_status(
        suspended_login,
        401,
        _error("INVALID_CREDENTIALS", "Invalid email or password"),
        "suspended-admin-target-login-accepted",
    )
    reactivated = helpers.call(
        target_url,
        "PATCH",
        f"/manage-api/users/{TARGET_USER_ID}/status",
        {"status": "ACTIVE", "reasonCode": "CONTRACT_REACTIVATE"},
        timeout,
        observations,
        auth,
    )
    reactivated_body = _json_body(reactivated, "admin-status-reactivation-mismatch")
    if (
        reactivated.status != 200
        or set(reactivated_body) != {"statusChanged", "revokedRefreshTokenCount"}
        or reactivated_body["statusChanged"] is not True
        or not isinstance(reactivated_body["revokedRefreshTokenCount"], int)
        or isinstance(reactivated_body["revokedRefreshTokenCount"], bool)
        or reactivated_body["revokedRefreshTokenCount"] != 0
    ):
        raise ContractFailure("admin-status-reactivation-mismatch")
    expected_audits.append(
        _audit(
            "admin_user_status_changed",
            ADMIN_USER_ID,
            TARGET_USER_ID,
            "CONTRACT_REACTIVATE",
            {"route": "PATCH /admin/users/:id/status"},
        )
    )

    for status in ("SUSPENDED", "DELETED"):
        result = helpers.call(
            actor_url,
            "PATCH",
            f"/admin/users/{ADMIN_USER_ID}/status",
            {"status": status, "reasonCode": "CONTRACT_SELF_STATUS"},
            timeout,
            observations,
            auth,
        )
        _expect_status(
            result,
            403,
            _error("FORBIDDEN", "Admins cannot suspend or delete their own account"),
            "admin-self-status-protection-mismatch",
        )
    own_role = helpers.call(
        target_url,
        "DELETE",
        f"/manage-api/users/{ADMIN_USER_ID}/roles/{parse.quote(admin_role_id, safe='')}",
        {"reasonCode": "CONTRACT_SELF_ROLE"},
        timeout,
        observations,
        auth,
    )
    _expect_status(
        own_role,
        403,
        _error("FORBIDDEN", "Admins cannot remove their own admin role"),
        "admin-self-role-protection-mismatch",
    )
    own_sessions = helpers.call(
        actor_url,
        "POST",
        f"/admin/users/{ADMIN_USER_ID}/revoke-sessions",
        {"reasonCode": "CONTRACT_SELF_SESSION"},
        timeout,
        observations,
        auth,
    )
    _expect_status(
        own_sessions,
        403,
        _error("FORBIDDEN", "Admins cannot revoke their own sessions"),
        "admin-self-session-protection-mismatch",
    )

    control = _object(
        adapter.invoke("control", "suspend-admin"), "admin-control-mismatch"
    )
    if not _strict_equal(control, {"status": "controlled"}):
        raise ContractFailure("admin-control-mismatch")
    stale_error: BaseException | None = None
    try:
        stale = helpers.call(
            target_url, "GET", "/manage-api/users", None, timeout, observations, auth
        )
        _expect_status(
            stale,
            403,
            _error("FORBIDDEN", "Admin role is required"),
            "stale-admin-bearer-accepted",
        )
        expected_audits.append(
            _audit(
                "admin_authorization_failure",
                ADMIN_USER_ID,
                None,
                "FORBIDDEN",
                {"route": "/manage-api/users", "method": "GET"},
                outcome="failure",
            )
        )
    except BaseException as exc:
        stale_error = exc
        raise
    finally:
        try:
            restored = _object(
                adapter.invoke("control", "restore-admin"), "admin-control-mismatch"
            )
            if not _strict_equal(restored, {"status": "controlled"}):
                raise ContractFailure("admin-control-mismatch")
        except BaseException as restore_error:
            if stale_error is not None:
                stale_error.add_note(
                    f"admin restore failed: {type(restore_error).__name__}"
                )
            else:
                raise
    final_state = _state(adapter)
    _assert_state(
        final_state,
        admin=admin,
        target=target,
        admin_hashes=admin_hashes,
        target_hashes=set(),
        target_status="active",
        target_admin=False,
        minimum_audits=7,
    )
    _expect_audits(final_state, expected_audits)

    snapshot_admin_audits = [
        item for item in final_state["audits"] if item["actorUserId"] == ADMIN_USER_ID
    ]
    alias_audits: list[list[dict[str, Any]]] = []
    full_audit_keys = {
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
    for url in origins:
        for alias in ("/admin", "/manage-api"):
            audit_page = helpers.call(
                url,
                "GET",
                f"{alias}/audit-logs?actorUserId={ADMIN_USER_ID}",
                None,
                timeout,
                observations,
                auth,
            )
            api_audits = _page_items(audit_page, "admin-audit-contract-mismatch")
            if any(set(item) != full_audit_keys for item in api_audits):
                raise ContractFailure("admin-audit-contract-mismatch")
            alias_audits.append(api_audits)
    if any(not _strict_equal(page, alias_audits[0]) for page in alias_audits[1:]):
        raise ContractFailure("admin-alias-projection-mismatch")
    if not _strict_equal(_audits(alias_audits[0]), _audits(snapshot_admin_audits)):
        raise ContractFailure("admin-audit-projection-mismatch")


def run_admin_flow(
    topology: str,
    urls: dict[str, str],
    adapters: Mapping[str, Adapter],
    *,
    expected_issuer: str,
    timeout: float = 5,
) -> dict[str, Any]:
    """Execute a bounded nonqualifying A09 flow and return sanitized evidence."""

    actor_runtime, target_runtime, normalized, participants = _validate_inputs(
        topology, urls, adapters, expected_issuer, timeout
    )
    runtime_adapters = {
        runtime: adapters[runtime]
        for runtime in dict.fromkeys((actor_runtime, target_runtime))
    }
    for runtime, adapter in runtime_adapters.items():
        _preflight(adapter, runtime)

    owner = adapters[actor_runtime]
    setup_attempted = False
    primary_error: BaseException | None = None
    try:
        setup_attempted = True
        admin, target, admin_role_id = _setup(owner)
        empty = _state(owner)
        _assert_state(
            empty,
            admin=admin,
            target=target,
            admin_hashes=set(),
            target_hashes=set(),
            target_status="active",
            target_admin=False,
            minimum_audits=0,
        )
        if empty["audits"]:
            raise ContractFailure("admin-fixture-initial-audit-not-empty")
        _run_flow(
            normalized[actor_runtime],
            normalized[target_runtime],
            owner,
            admin,
            target,
            admin_role_id,
            expected_issuer,
            float(timeout),
            adapters[actor_runtime].refresh_secret,
            adapters[target_runtime].refresh_secret,
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if setup_attempted:
            try:
                owner.invoke("teardown", FIXTURE)
            except BaseException as exc:  # noqa: BLE001 - cleanup must survive interrupts
                cleanup_errors.append(exc)
            for adapter in participants:
                try:
                    residual = _object(
                        adapter.invoke("snapshot", RESIDUAL), "malformed-admin-residual"
                    )
                    if not _strict_equal(
                        residual,
                        {"users": 0, "activeRefreshTokens": 0, "adminAudits": 0},
                    ):
                        raise ContractFailure("admin-residual-state-not-empty")
                except BaseException as exc:  # noqa: BLE001 - inspect every participant
                    cleanup_errors.append(exc)
        if cleanup_errors:
            if primary_error is not None:
                for cleanup_error in cleanup_errors:
                    primary_error.add_note(
                        f"admin flow cleanup failed: {type(cleanup_error).__name__}"
                    )
            else:
                raise cleanup_errors[0]

    return {
        "flow": FLOW,
        "topology": topology,
        "passed": True,
        "qualifying": False,
        "assertions": {name: True for name in sorted(ASSERTIONS)},
        "unverified": list(UNVERIFIED),
    }
