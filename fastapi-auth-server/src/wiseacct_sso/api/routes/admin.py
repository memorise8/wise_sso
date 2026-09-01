"""Express-compatible administrator and audit HTTP routes."""

from __future__ import annotations

import math
import re
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Annotated, Literal, Never

from fastapi import APIRouter, Body, Depends, Header, Query, Request
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from wiseacct_sso.api.dependencies import InjectedPhase6Services
from wiseacct_sso.api.errors import ExpressJsonResponse, PublicHttpError
from wiseacct_sso.domain.admin import (
    AdminAuditLogPage,
    AdminUserListInput,
    AdminUserPage,
    AuditLogListInput,
    assert_self_admin_role_removal_allowed,
    assert_self_session_revoke_allowed,
    assert_self_status_change_allowed,
)
from wiseacct_sso.domain.users import DomainError, UserStatus

UserStatusValue = Literal[
    "PENDING_EMAIL_VERIFICATION",
    "ACTIVE",
    "SUSPENDED",
    "DELETED",
]
AuditOutcome = Literal["request", "success", "failure"]


def _strip(value: object) -> object:
    return value.strip() if isinstance(value, str) else value


TrimmedNonEmpty = Annotated[str, BeforeValidator(_strip), Field(min_length=1)]

_JS_DECIMAL_NUMBER = re.compile(r"^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$")
_JS_ISO_DATE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"(?:(?P<separator>[Tt ])(?P<hour>\d{2}):(?P<minute>\d{2})"
    r"(?::(?P<second>\d{2})(?:\.(?P<fraction>\d+))?)?"
    r"(?P<offset>[Zz]|[+-]\d{2}:?\d{2})?)?$"
)
_JS_LEGACY_YMD = re.compile(
    r"^(?P<year>\d{4})(?P<separator>[/.-])(?P<month>\d{1,2})(?P=separator)(?P<day>\d{1,2})$"
)
_JS_LEGACY_MDY = re.compile(r"^(?P<month>\d{1,2})-(?P<day>\d{1,2})-(?P<year>\d{2})$")
_JS_SLASH_MDY = re.compile(r"^(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year>\d{4})$")
_JS_MONTH_YEAR = re.compile(r"^(?P<year>\d{4})-(?P<month>\d{2})$")
_JS_YEAR = re.compile(r"^(?P<year>\d{4})$")
_JS_DAY_MONTH_NAME = re.compile(r"^(?P<day>\d{1,2}) (?P<month>[A-Za-z]{3}) (?P<year>\d{4})$")
_JS_MONTH_NAME_DAY = re.compile(r"^(?P<month>[A-Za-z]{3}) (?P<day>\d{1,2}) (?P<year>\d{4})$")
_JS_MONTHS = {
    name: index
    for index, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"),
        start=1,
    )
}


def _coerce_js_integer(value: object) -> object:
    """Bounded JavaScript Number coercion used by Express Zod query schemas."""

    if not isinstance(value, str):
        return value
    normalized = value.strip()
    if not normalized:
        return 0
    unsigned = normalized.lower()
    try:
        if unsigned.startswith(("0x", "0b", "0o")):
            numeric = float(int(unsigned, 0))
            if not math.isfinite(numeric):
                raise ValueError("not a finite integer")
            parsed = int(numeric)
        elif _JS_DECIMAL_NUMBER.fullmatch(normalized):
            numeric = float(normalized)
            if not math.isfinite(numeric) or not numeric.is_integer():
                raise ValueError("not a finite integer")
            parsed = int(numeric)
        else:
            raise ValueError("not a JavaScript number")
    except (OverflowError, ValueError) as error:
        raise ValueError("invalid coerced integer") from error
    return parsed


CoercedInteger = Annotated[int, BeforeValidator(_coerce_js_integer)]


class _QueryModel(BaseModel):
    model_config = ConfigDict(extra="ignore")

    page: CoercedInteger = Field(default=1, ge=1)
    page_size: CoercedInteger = Field(default=25, ge=1, le=100, alias="pageSize")


class UserListQuery(_QueryModel):
    status: UserStatusValue | None = None
    email: TrimmedNonEmpty | None = None
    role: TrimmedNonEmpty | None = None


class AuditLogQuery(_QueryModel):
    created_at_from: TrimmedNonEmpty | None = Field(default=None, alias="createdAtFrom")
    created_at_to: TrimmedNonEmpty | None = Field(default=None, alias="createdAtTo")
    event_type: TrimmedNonEmpty | None = Field(default=None, alias="eventType")
    outcome: AuditOutcome | None = None
    user_id: TrimmedNonEmpty | None = Field(default=None, alias="userId")
    actor_user_id: TrimmedNonEmpty | None = Field(default=None, alias="actorUserId")
    target_user_id: TrimmedNonEmpty | None = Field(default=None, alias="targetUserId")
    reason_code: TrimmedNonEmpty | None = Field(default=None, alias="reasonCode")


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: UserStatusValue
    reason_code: TrimmedNonEmpty = Field(default="ADMIN_STATUS_CHANGE", alias="reasonCode")


class RoleBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    service_key: TrimmedNonEmpty = Field(alias="serviceKey")
    name: TrimmedNonEmpty
    reason_code: TrimmedNonEmpty = Field(default="ADMIN_ROLE_ASSIGN", alias="reasonCode")


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="ignore")

    reason_code: TrimmedNonEmpty = Field(alias="reasonCode")


def _raise_public(error: DomainError) -> Never:
    raise PublicHttpError(error.status_code, error.code, error.message) from None


def _bearer(authorization: str | None) -> str:
    parts = authorization.split(" ") if authorization is not None else []
    if len(parts) < 2 or parts[0] != "Bearer" or not parts[1]:
        raise PublicHttpError(401, "UNAUTHORIZED", "Bearer access token is required")
    return parts[1]


async def _admin_actor(
    request: Request,
    services: InjectedPhase6Services,
    authorization: str | None = Header(default=None),
) -> str:
    original_path = getattr(request.state, "express_original_decoded_path", None)
    audit_route = original_path if isinstance(original_path, str) else request.url.path
    try:
        return await services.authenticate_admin(
            _bearer(authorization),
            route=audit_route,
            method=request.method,
        )
    except DomainError as error:
        _raise_public(error)


AdminActor = Annotated[str, Depends(_admin_actor)]


def _admin_path_parameter(request: Request, name: str, fallback: str) -> str:
    parameters = getattr(request.state, "express_admin_path_params", None)
    if not isinstance(parameters, dict):
        return fallback
    value = parameters.get(name)
    return value if isinstance(value, str) else fallback


def _js_iso_date(value: str) -> datetime | None:
    match = _JS_ISO_DATE.fullmatch(value)
    if match is None:
        return None
    year = int(match["year"])
    month = int(match["month"])
    day = int(match["day"])
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        raise ValueError("invalid JavaScript ISO date")
    hour = int(match["hour"] or 0)
    minute = int(match["minute"] or 0)
    second = int(match["second"] or 0)
    fraction = match["fraction"] or ""
    milliseconds = int((fraction + "000")[:3])
    if minute > 59 or second > 59 or hour > 24:
        raise ValueError("invalid JavaScript ISO time")
    if hour == 24 and (minute != 0 or second != 0 or milliseconds != 0):
        raise ValueError("invalid JavaScript end-of-day time")
    if year == 0:
        if month == 1 and day == 1 and match["separator"] is None and match["offset"] is None:
            # Python datetime/PostgreSQL AD timestamps cannot represent ECMAScript year 0000.
            # Clamping this lower-bound instant to their minimum preserves all application rows.
            return datetime.min.replace(tzinfo=UTC)
        raise ValueError("JavaScript year zero is outside the persistence range")
    parsed = datetime(year, month, 1) + timedelta(
        days=day - 1,
        hours=hour,
        minutes=minute,
        seconds=second,
        milliseconds=milliseconds,
    )
    offset = match["offset"]
    if offset is not None:
        if offset.lower() == "z":
            parsed = parsed.replace(tzinfo=UTC)
        else:
            offset_hour = int(offset[1:3])
            offset_minute = int(offset[-2:])
            if offset_hour > 23 or offset_minute > 59:
                raise ValueError("invalid JavaScript timezone offset")
            direction = 1 if offset[0] == "+" else -1
            parsed = parsed.replace(
                tzinfo=timezone(direction * timedelta(hours=offset_hour, minutes=offset_minute))
            )
    elif match["separator"] is None:
        # ECMAScript date-only strings are UTC, unlike offsetless date-time strings.
        parsed = parsed.replace(tzinfo=UTC)
    else:
        # Node interprets an offsetless date-time in the process-local timezone.
        parsed = parsed.astimezone()
    return parsed.astimezone(UTC)


def _legacy_local_date(*, year: int, month: int, day: int) -> datetime:
    if not 1 <= month <= 12 or not 1 <= day <= 31:
        raise ValueError("invalid JavaScript legacy date")
    return (datetime(year, month, 1) + timedelta(days=day - 1)).astimezone(UTC)


def _js_legacy_date(value: str) -> datetime | None:
    match = _JS_LEGACY_YMD.fullmatch(value)
    if match is not None:
        return _legacy_local_date(
            year=int(match["year"]), month=int(match["month"]), day=int(match["day"])
        )
    match = _JS_SLASH_MDY.fullmatch(value)
    if match is not None:
        return _legacy_local_date(
            year=int(match["year"]), month=int(match["month"]), day=int(match["day"])
        )
    match = _JS_LEGACY_MDY.fullmatch(value)
    if match is not None:
        short_year = int(match["year"])
        year = 2000 + short_year if short_year <= 49 else 1900 + short_year
        return _legacy_local_date(year=year, month=int(match["month"]), day=int(match["day"]))
    match = _JS_MONTH_YEAR.fullmatch(value)
    if match is not None:
        return datetime(int(match["year"]), int(match["month"]), 1, tzinfo=UTC)
    match = _JS_YEAR.fullmatch(value)
    if match is not None:
        return datetime(int(match["year"]), 1, 1, tzinfo=UTC)
    for pattern in (_JS_DAY_MONTH_NAME, _JS_MONTH_NAME_DAY):
        match = pattern.fullmatch(value)
        if match is None:
            continue
        month = _JS_MONTHS.get(match["month"].lower())
        if month is None:
            raise ValueError("invalid JavaScript month name")
        return _legacy_local_date(year=int(match["year"]), month=month, day=int(match["day"]))
    return None


def _parse_date(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = _js_iso_date(value)
        if parsed is not None:
            return parsed
        parsed = _js_legacy_date(value)
        if parsed is not None:
            return parsed
        parsed = parsedate_to_datetime(value)
        if parsed is None:
            raise ValueError("invalid RFC-2822 date")
        if parsed.tzinfo is None:
            parsed = parsed.astimezone()
        return parsed.astimezone(UTC)
    except (OverflowError, TypeError, ValueError):
        raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request") from None


def _reject_repeated_query(request: Request, names: tuple[str, ...]) -> None:
    if any(len(request.query_params.getlist(name)) > 1 for name in names):
        raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request")


def _iso(value: datetime) -> str:
    aware = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return aware.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _user_page(page: AdminUserPage) -> ExpressJsonResponse:
    return ExpressJsonResponse(
        content={
            "items": [
                {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "status": user.status.value,
                    "createdAt": _iso(user.created_at),
                    "roles": [
                        {
                            "id": role.id,
                            "serviceKey": role.service_key,
                            "name": role.name,
                        }
                        for role in user.roles
                    ],
                }
                for user in page.items
            ],
            "total": page.total,
            "page": page.page,
            "pageSize": page.page_size,
        }
    )


def _audit_page(page: AdminAuditLogPage) -> ExpressJsonResponse:
    items: list[dict[str, object]] = []
    for item in page.items:
        serialized: dict[str, object] = {
            "id": item.id,
            "eventType": item.event_type,
            "outcome": item.outcome,
            "userId": item.user_id,
            "actorUserId": item.actor_user_id,
            "targetUserId": item.target_user_id,
            "reasonCode": item.reason_code,
            "createdAt": _iso(item.created_at),
        }
        if item.details_json is not None:
            serialized["detailsJson"] = dict(item.details_json)
        items.append(serialized)
    return ExpressJsonResponse(
        content={
            "items": items,
            "total": page.total,
            "page": page.page,
            "pageSize": page.page_size,
        }
    )


def build_admin_router(*, prefix: Literal["/admin", "/manage-api"] = "/admin") -> APIRouter:
    router = APIRouter(prefix=prefix)

    @router.get("/users")
    @router.head("/users")
    async def list_users(
        request: Request,
        _actor_id: AdminActor,
        services: InjectedPhase6Services,
        query: Annotated[UserListQuery, Query()],
    ) -> ExpressJsonResponse:
        _reject_repeated_query(request, ("page", "pageSize", "status", "email", "role"))
        try:
            input = AdminUserListInput(
                page=query.page,
                page_size=query.page_size,
                status=UserStatus(query.status) if query.status is not None else None,
                email=query.email,
                role=query.role,
            )
            return _user_page(await services.list_users(input))
        except DomainError as error:
            _raise_public(error)

    @router.get("/audit-logs")
    @router.head("/audit-logs")
    async def list_audit_logs(
        request: Request,
        _actor_id: AdminActor,
        services: InjectedPhase6Services,
        query: Annotated[AuditLogQuery, Query()],
    ) -> ExpressJsonResponse:
        _reject_repeated_query(
            request,
            (
                "page",
                "pageSize",
                "createdAtFrom",
                "createdAtTo",
                "eventType",
                "outcome",
                "userId",
                "actorUserId",
                "targetUserId",
                "reasonCode",
            ),
        )
        try:
            input = AuditLogListInput(
                page=query.page,
                page_size=query.page_size,
                created_at_from=_parse_date(query.created_at_from),
                created_at_to=_parse_date(query.created_at_to),
                event_type=query.event_type,
                outcome=query.outcome,
                user_id=query.user_id,
                actor_user_id=query.actor_user_id,
                target_user_id=query.target_user_id,
                reason_code=query.reason_code,
            )
            return _audit_page(await services.list_audit_logs(input))
        except DomainError as error:
            _raise_public(error)

    @router.patch("/users/{user_id}/status")
    async def set_user_status(
        user_id: str,
        request: Request,
        actor_id: AdminActor,
        services: InjectedPhase6Services,
        body: Annotated[StatusBody, Body()],
    ) -> ExpressJsonResponse:
        user_id = _admin_path_parameter(request, "id", user_id)
        try:
            assert_self_status_change_allowed(actor_id, user_id, body.status)
            result = await services.set_user_status(
                actor_user_id=actor_id,
                target_user_id=user_id,
                status=body.status,
                reason_code=body.reason_code,
                details={"route": "PATCH /admin/users/:id/status"},
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(
            content={
                "statusChanged": result.status_changed,
                "revokedRefreshTokenCount": result.revoked_refresh_token_count,
            }
        )

    @router.post("/users/{user_id}/roles")
    async def assign_role(
        user_id: str,
        request: Request,
        actor_id: AdminActor,
        services: InjectedPhase6Services,
        body: Annotated[RoleBody, Body()],
    ) -> ExpressJsonResponse:
        user_id = _admin_path_parameter(request, "id", user_id)
        try:
            result = await services.assign_role(
                actor_user_id=actor_id,
                target_user_id=user_id,
                service_key=body.service_key,
                name=body.name,
                reason_code=body.reason_code,
                details={"route": "POST /admin/users/:id/roles"},
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(
            content={"roleAssigned": result.role_assigned, "roleId": result.role_id}
        )

    @router.delete("/users/{user_id}/roles/{role_id}")
    async def remove_role(
        user_id: str,
        role_id: str,
        request: Request,
        actor_id: AdminActor,
        services: InjectedPhase6Services,
        body: Annotated[ReasonBody, Body()],
    ) -> ExpressJsonResponse:
        user_id = _admin_path_parameter(request, "id", user_id)
        role_id = _admin_path_parameter(request, "roleId", role_id)
        try:
            # Express accepts a non-empty whitespace path parameter, then the role lookup misses.
            if not role_id.strip():
                raise DomainError(404, "ROLE_NOT_FOUND", "Role not found")
            role = await services.find_role_by_id(role_id)
            if role is None:
                raise DomainError(404, "ROLE_NOT_FOUND", "Role not found")
            assert_self_admin_role_removal_allowed(actor_id, user_id, role)
            result = await services.remove_role(
                actor_user_id=actor_id,
                target_user_id=user_id,
                service_key=role.service_key,
                name=role.name,
                reason_code=body.reason_code,
                details={
                    "roleId": role_id,
                    "route": "DELETE /admin/users/:id/roles/:roleId",
                },
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(
            content={
                "roleRemoved": result.role_removed,
                "roleId": result.role_id,
                "revokedRefreshTokenCount": result.revoked_refresh_token_count,
            }
        )

    @router.post("/users/{user_id}/revoke-sessions")
    async def revoke_sessions(
        user_id: str,
        request: Request,
        actor_id: AdminActor,
        services: InjectedPhase6Services,
        body: Annotated[ReasonBody, Body()],
    ) -> ExpressJsonResponse:
        user_id = _admin_path_parameter(request, "id", user_id)
        try:
            assert_self_session_revoke_allowed(actor_id, user_id)
            result = await services.revoke_sessions(
                actor_user_id=actor_id,
                target_user_id=user_id,
                reason_code=body.reason_code,
                details={"route": "POST /admin/users/:id/revoke-sessions"},
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(content={"revokedCount": result.revoked_count})

    return router
