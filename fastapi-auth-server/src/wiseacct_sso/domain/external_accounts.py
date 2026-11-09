"""Time-limited external (guest) account rules.

Expiry is a whole-day term: an account created or extended for N days stays usable
until the end of that day in Korea (23:59:59.999 KST). Values are stored as naive
UTC to match the PostgreSQL TIMESTAMP(3) columns.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from wiseacct_sso.domain.users import DomainError

MAX_EXTERNAL_ACCOUNT_DAYS = 365
KST = timezone(timedelta(hours=9))
# Roles an external account may hold. agent-hub:user is deliberately absent: the hub
# treats that role as staff membership and grants guests access per project instead.
EXTERNAL_ALLOWED_ROLES = frozenset({("gitlab", "user")})


def assert_term_days(days: object) -> int:
    if type(days) is not int or not 1 <= days <= MAX_EXTERNAL_ACCOUNT_DAYS:
        raise DomainError(
            400,
            "INVALID_ACCOUNT_TERM",
            f"Account term must be 1 to {MAX_EXTERNAL_ACCOUNT_DAYS} days",
        )
    return days


def end_of_kst_day(now: datetime, days: int) -> datetime:
    """Return the naive-UTC end of the KST day that is `days` after `now`."""

    local = now.replace(tzinfo=UTC).astimezone(KST)
    last_day = (local + timedelta(days=days)).date()
    end = datetime(last_day.year, last_day.month, last_day.day, tzinfo=KST) + timedelta(
        days=1, milliseconds=-1
    )
    return end.astimezone(UTC).replace(tzinfo=None)


def initial_expiry(now: datetime, days: int) -> datetime:
    return end_of_kst_day(now, assert_term_days(days))


def extended_expiry(now: datetime, current: datetime | None, days: int) -> datetime:
    """Add `days` to the later of today and the current expiry, capped at 365 days ahead."""

    assert_term_days(days)
    base = now if current is None or current <= now else current
    expiry = end_of_kst_day(base, days)
    if expiry > end_of_kst_day(now, MAX_EXTERNAL_ACCOUNT_DAYS):
        raise DomainError(
            400,
            "INVALID_ACCOUNT_TERM",
            f"An external account cannot run more than {MAX_EXTERNAL_ACCOUNT_DAYS} days ahead",
        )
    return expiry


def is_expired(expires_at: datetime | None, now: datetime) -> bool:
    return expires_at is not None and expires_at <= now


def assert_external_roles(roles: list[dict[str, str]]) -> None:
    if any((role["serviceKey"], role["name"]) not in EXTERNAL_ALLOWED_ROLES for role in roles):
        raise DomainError(
            403,
            "EXTERNAL_ROLE_NOT_ALLOWED",
            "External accounts may only hold the gitlab:user role",
        )
