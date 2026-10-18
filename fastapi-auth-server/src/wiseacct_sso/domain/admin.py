"""Pure administrator contracts shared by the Phase 6 HTTP and persistence layers."""

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal

from wiseacct_sso.domain.users import DomainError, UserStatus

type AuditOutcome = Literal["request", "success", "failure"]
type AdminAuditEventType = Literal[
    "admin_user_status_changed",
    "admin_user_role_assigned",
    "admin_user_role_removed",
    "admin_user_sessions_revoked",
]
type AuditDetailValue = str | int | float | bool | None
type AuditDetails = Mapping[str, AuditDetailValue]

DEFAULT_PAGE: Final = 1
DEFAULT_PAGE_SIZE: Final = 25
MAX_PAGE_SIZE: Final = 100
DEFAULT_AUDIT_RETENTION_DAYS: Final = 180
MAX_AUDIT_DETAILS_JSON_UNITS: Final = 2048
REDACTED_AUDIT_VALUE: Final = "[REDACTED]"

_SENSITIVE_DETAIL_KEY = re.compile(r"(token|password|secret|code|email)", re.IGNORECASE)
_SENSITIVE_DETAIL_VALUE = re.compile(
    r"(token|password|secret|Bearer\s+|oauth-code|handoff-code)", re.IGNORECASE
)
_EMAIL_LIKE_DETAIL_VALUE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class AdminRoleProfile:
    id: str
    service_key: str
    name: str


@dataclass(frozen=True, slots=True)
class AdminUserProfile:
    id: str
    email: str | None
    name: str | None
    status: UserStatus
    created_at: datetime
    roles: tuple[AdminRoleProfile, ...]


@dataclass(frozen=True, slots=True)
class AdminUserListInput:
    page: int = DEFAULT_PAGE
    page_size: int = DEFAULT_PAGE_SIZE
    status: UserStatus | None = None
    email: str | None = None
    role: str | None = None

    def __post_init__(self) -> None:
        _assert_page(self.page, self.page_size)
        if self.email is not None and not self.email.strip():
            raise DomainError(400, "INVALID_REQUEST", "Invalid request")
        if self.role is not None:
            parse_role_filter(self.role)


@dataclass(frozen=True, slots=True)
class AdminUserPage:
    items: tuple[AdminUserProfile, ...]
    total: int
    page: int
    page_size: int


@dataclass(frozen=True, slots=True)
class AuditLogListInput:
    page: int = DEFAULT_PAGE
    page_size: int = DEFAULT_PAGE_SIZE
    created_at_from: datetime | None = None
    created_at_to: datetime | None = None
    event_type: str | None = None
    outcome: AuditOutcome | None = None
    user_id: str | None = None
    actor_user_id: str | None = None
    target_user_id: str | None = None
    reason_code: str | None = None

    def __post_init__(self) -> None:
        _assert_page(self.page, self.page_size)
        for value in (
            self.event_type,
            self.user_id,
            self.actor_user_id,
            self.target_user_id,
            self.reason_code,
        ):
            if value is not None and not value.strip():
                raise DomainError(400, "INVALID_REQUEST", "Invalid request")
        if self.outcome not in {None, "request", "success", "failure"}:
            raise DomainError(400, "INVALID_REQUEST", "Invalid request")


@dataclass(frozen=True, slots=True)
class StoredAuditLogRecord:
    id: str
    event_type: str
    outcome: str
    user_id: str | None
    actor_user_id: str | None
    target_user_id: str | None
    reason_code: str | None
    details_json: object
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AdminAuditLogListItem:
    id: str
    event_type: str
    outcome: str
    user_id: str | None
    actor_user_id: str | None
    target_user_id: str | None
    reason_code: str | None
    created_at: datetime
    details_json: AuditDetails | None = None


@dataclass(frozen=True, slots=True)
class AdminAuditLogPage:
    items: tuple[AdminAuditLogListItem, ...]
    total: int
    page: int
    page_size: int


@dataclass(frozen=True, slots=True)
class AdminAuditRecord:
    event_type: AdminAuditEventType
    actor_user_id: str | None
    target_user_id: str | None
    reason_code: str
    details_json: AuditDetails | None = None
    outcome: Literal["success"] = "success"


@dataclass(frozen=True, slots=True)
class AuditRetentionCleanupResult:
    cutoff: datetime
    deleted_count: int
    dry_run: bool
    retention_days: int


class AuditRetentionCleanupConfigurationError(ValueError):
    pass


def _assert_page(page: int, page_size: int) -> None:
    if not isinstance(page, int) or isinstance(page, bool) or page < 1:
        raise DomainError(400, "INVALID_REQUEST", "Invalid request")
    if (
        not isinstance(page_size, int)
        or isinstance(page_size, bool)
        or not 1 <= page_size <= MAX_PAGE_SIZE
    ):
        raise DomainError(400, "INVALID_REQUEST", "Invalid request")


def parse_user_status(value: str | UserStatus) -> UserStatus:
    try:
        return UserStatus(value)
    except ValueError as error:
        raise DomainError(400, "INVALID_USER_STATUS", "Unsupported user status") from error


def parse_role_filter(value: str) -> tuple[str | None, str]:
    """Return ``(service_key, role_name)`` using the Express one/two-part grammar."""

    parts = value.split(":")
    if len(parts) > 2 or not parts[0].strip():
        raise DomainError(400, "INVALID_REQUEST", "Invalid request")
    if len(parts) == 1:
        return None, parts[0]
    if not parts[1].strip():
        raise DomainError(400, "INVALID_REQUEST", "Invalid request")
    return parts[0], parts[1]


def assert_user_id(user_id: str) -> None:
    if not user_id.strip():
        raise DomainError(400, "INVALID_USER_ID", "User id is required")


def assert_role_input(service_key: str, name: str) -> None:
    if not service_key.strip() or not name.strip():
        raise DomainError(400, "INVALID_ROLE", "Role service key and name are required")


def assert_self_status_change_allowed(
    actor_user_id: str, target_user_id: str, status: str | UserStatus
) -> None:
    parsed = parse_user_status(status)
    if actor_user_id == target_user_id and parsed in {UserStatus.SUSPENDED, UserStatus.DELETED}:
        raise DomainError(403, "FORBIDDEN", "Admins cannot suspend or delete their own account")


def assert_self_admin_role_removal_allowed(
    actor_user_id: str, target_user_id: str, role: AdminRoleProfile
) -> None:
    if actor_user_id == target_user_id and role.service_key == "temis" and role.name == "admin":
        raise DomainError(403, "FORBIDDEN", "Admins cannot remove their own admin role")


def assert_self_session_revoke_allowed(actor_user_id: str, target_user_id: str) -> None:
    if actor_user_id == target_user_id:
        raise DomainError(403, "FORBIDDEN", "Admins cannot revoke their own sessions")


def should_revoke_for_status(status: str | UserStatus) -> bool:
    return parse_user_status(status) in {UserStatus.SUSPENDED, UserStatus.DELETED}


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def sanitize_audit_details(details: Mapping[str, object]) -> dict[str, AuditDetailValue]:
    sanitized: dict[str, AuditDetailValue] = {}
    for key, value in details.items():
        if _SENSITIVE_DETAIL_KEY.search(key):
            sanitized[key] = REDACTED_AUDIT_VALUE
        elif isinstance(value, str) and (
            _SENSITIVE_DETAIL_VALUE.search(value) or _EMAIL_LIKE_DETAIL_VALUE.search(value)
        ):
            sanitized[key] = REDACTED_AUDIT_VALUE
        elif isinstance(value, float) and not math.isfinite(value):
            sanitized[key] = None
        elif value is None or isinstance(value, (str, int, float, bool)):
            sanitized[key] = value
        else:
            sanitized[key] = REDACTED_AUDIT_VALUE
    encoded = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
    if _utf16_units(encoded) > MAX_AUDIT_DETAILS_JSON_UNITS:
        raise DomainError(400, "AUDIT_DETAILS_TOO_LARGE", "Audit details exceed allowed size")
    return sanitized


def sanitize_audit_details_for_read(details: object) -> dict[str, AuditDetailValue] | None:
    if not isinstance(details, Mapping):
        return None
    try:
        return sanitize_audit_details({str(key): value for key, value in details.items()})
    except DomainError:
        return {"truncated": True}


def audit_log_page(
    records: tuple[StoredAuditLogRecord, ...], *, total: int, input: AuditLogListInput
) -> AdminAuditLogPage:
    return AdminAuditLogPage(
        items=tuple(
            AdminAuditLogListItem(
                id=record.id,
                event_type=record.event_type,
                outcome=record.outcome,
                user_id=record.user_id,
                actor_user_id=record.actor_user_id,
                target_user_id=record.target_user_id,
                reason_code=record.reason_code,
                details_json=sanitize_audit_details_for_read(record.details_json),
                created_at=record.created_at,
            )
            for record in records
        ),
        total=total,
        page=input.page,
        page_size=input.page_size,
    )


def audit_retention_cutoff(
    *, now: datetime, retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS
) -> datetime:
    if (
        not isinstance(retention_days, int)
        or isinstance(retention_days, bool)
        or retention_days < 1
    ):
        raise AuditRetentionCleanupConfigurationError("retentionDays must be a positive integer")
    return now - timedelta(days=retention_days)
