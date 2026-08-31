"""User-domain records and active-user authorization rules."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class UserStatus(StrEnum):
    PENDING_EMAIL_VERIFICATION = "PENDING_EMAIL_VERIFICATION"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    DELETED = "DELETED"


@dataclass(frozen=True, slots=True)
class Role:
    service_key: str
    name: str


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: str
    email: str | None
    email_verified: bool
    name: str | None
    roles: tuple[Role, ...]


@dataclass(frozen=True, slots=True)
class CurrentUserWithStatus(CurrentUser):
    status: UserStatus


class DomainError(Exception):
    """HTTP-shaped domain failure whose transport mapping is owned by routes."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class CurrentUserStore(Protocol):
    async def get_current_user(self, user_id: str) -> CurrentUser | None: ...


class ActiveUserStore(Protocol):
    async def get_current_user_with_status(self, user_id: str) -> CurrentUserWithStatus | None: ...


async def get_current_user(store: CurrentUserStore, user_id: str) -> CurrentUser | None:
    return await store.get_current_user(user_id)


async def require_active_user_for_token_issue(
    store: ActiveUserStore,
    user_id: str,
) -> CurrentUserWithStatus:
    user = await store.get_current_user_with_status(user_id)
    if user is None or user.status is not UserStatus.ACTIVE:
        raise DomainError(401, "UNAUTHORIZED", "Authentication is required")
    return user
