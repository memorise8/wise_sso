"""Pure email-verification token and result contracts."""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal

from wiseacct_sso.domain.auth import normalize_email
from wiseacct_sso.domain.oauth import ClientHandoff
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import sha256_token

EMAIL_VERIFICATION_TOKEN_BYTES: Final = 32
EMAIL_VERIFICATION_TOKEN_TTL: Final = timedelta(hours=24)

TokenBytesFactory = Callable[[int], bytes]


class InvalidVerificationTokenError(DomainError):
    """The intentionally generic public failure for every invalid-token cause."""

    def __init__(self) -> None:
        super().__init__(
            400,
            "INVALID_VERIFICATION_TOKEN",
            "Invalid or expired verification token",
        )


@dataclass(frozen=True, slots=True)
class IssuedVerificationToken:
    value: str
    token_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerificationTokenRecord:
    token_id: str
    user_id: str
    expires_at: datetime
    used_at: datetime | None
    handoff: ClientHandoff | None


@dataclass(frozen=True, slots=True)
class VerificationAccepted:
    status: Literal["accepted"] = "accepted"


@dataclass(frozen=True, slots=True)
class VerificationConfirmed:
    user_id: str
    handoff: ClientHandoff | None
    status: Literal["verified"] = "verified"


def normalize_verification_email(email: str) -> str:
    """Use the same trim/lowercase contract as registration and login."""

    return normalize_email(email)


def issue_verification_token(
    now: datetime,
    *,
    random_bytes: TokenBytesFactory = secrets.token_bytes,
) -> IssuedVerificationToken:
    raw = random_bytes(EMAIL_VERIFICATION_TOKEN_BYTES)
    if len(raw) != EMAIL_VERIFICATION_TOKEN_BYTES:
        raise ValueError("verification token source must return exactly 32 bytes")
    value = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return IssuedVerificationToken(
        value=value,
        token_hash=sha256_token(value),
        expires_at=now + EMAIL_VERIFICATION_TOKEN_TTL,
    )


def confirm_verification_record(
    record: VerificationTokenRecord | None,
    *,
    now: datetime,
    activated_user_id: str | None,
) -> VerificationConfirmed:
    if record is None or record.used_at is not None or record.expires_at <= now:
        raise InvalidVerificationTokenError
    if activated_user_id is None:
        raise InvalidVerificationTokenError
    return VerificationConfirmed(user_id=activated_user_id, handoff=record.handoff)
