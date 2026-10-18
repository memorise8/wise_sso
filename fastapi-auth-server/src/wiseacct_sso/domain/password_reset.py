"""Pure password-reset token, policy, and result contracts."""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal

from wiseacct_sso.domain.auth import PasswordPolicy, assert_password_policy, normalize_email
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import sha256_token

PASSWORD_RESET_TOKEN_BYTES: Final = 32
PASSWORD_RESET_TOKEN_TTL: Final = timedelta(hours=1)

TokenBytesFactory = Callable[[int], bytes]


class InvalidResetTokenError(DomainError):
    """The intentionally generic public failure for every invalid-token cause."""

    def __init__(self) -> None:
        super().__init__(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token")


@dataclass(frozen=True, slots=True)
class IssuedPasswordResetToken:
    value: str
    token_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PasswordResetAccepted:
    status: Literal["accepted"] = "accepted"


@dataclass(frozen=True, slots=True)
class PasswordResetConfirmed:
    user_id: str


def normalize_reset_email(email: str) -> str:
    return normalize_email(email)


def assert_reset_password_policy(
    email: str,
    password: str,
    policy: PasswordPolicy,
) -> None:
    assert_password_policy(normalize_email(email), password, policy)


def issue_password_reset_token(
    now: datetime,
    *,
    random_bytes: TokenBytesFactory = secrets.token_bytes,
) -> IssuedPasswordResetToken:
    raw = random_bytes(PASSWORD_RESET_TOKEN_BYTES)
    if len(raw) != PASSWORD_RESET_TOKEN_BYTES:
        raise ValueError("password-reset token source must return exactly 32 bytes")
    value = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return IssuedPasswordResetToken(
        value=value,
        token_hash=sha256_token(value),
        expires_at=now + PASSWORD_RESET_TOKEN_TTL,
    )


def confirm_password_reset(user_id: str | None) -> PasswordResetConfirmed:
    if user_id is None:
        raise InvalidResetTokenError
    return PasswordResetConfirmed(user_id=user_id)
