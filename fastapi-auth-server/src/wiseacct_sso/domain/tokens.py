"""Domain values shared by token issuance, verification, and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

ACCESS_TOKEN_KID_VALIDATION_GAP: Final = (
    "Express accepts a signature-valid RS256 access token with a wrong kid; "  # noqa: S105
    "FastAPI preserves that wrong kid behavior until the post-parity hardening gate."
)


class TokenValidationError(ValueError):
    """A deliberately generic JWT validation failure safe for service translation."""

    def __init__(self) -> None:
        super().__init__("Invalid token")


@dataclass(frozen=True, slots=True)
class RoleClaim:
    service_key: str
    name: str


@dataclass(frozen=True, slots=True)
class AccessTokenIdentity:
    user_id: str
    email: str | None
    name: str | None
    email_verified: bool
    roles: tuple[RoleClaim, ...]


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    identity: AccessTokenIdentity
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RefreshTokenClaims:
    user_id: str
    token_id: str
    audience: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class IssuedRefreshToken:
    token: str
    token_id: str
    token_hash: str
    expires_at: datetime
