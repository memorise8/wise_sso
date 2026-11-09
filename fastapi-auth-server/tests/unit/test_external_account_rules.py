from datetime import datetime

import pytest

from wiseacct_sso.domain.external_accounts import (
    MAX_EXTERNAL_ACCOUNT_DAYS,
    assert_external_roles,
    end_of_kst_day,
    extended_expiry,
    initial_expiry,
    is_expired,
)
from wiseacct_sso.domain.users import DomainError

# 2026-11-04 09:00 KST, stored as naive UTC like TIMESTAMP(3).
NOW = datetime(2026, 11, 4, 0, 0)


def test_term_ends_at_the_end_of_the_kst_day() -> None:
    assert initial_expiry(NOW, 90) == datetime(2027, 2, 2, 14, 59, 59, 999000)
    assert initial_expiry(NOW, 1) == datetime(2026, 11, 5, 14, 59, 59, 999000)
    # 15:30 UTC is already the next day in Korea.
    assert end_of_kst_day(datetime(2026, 11, 4, 15, 30), 1) == datetime(
        2026, 11, 6, 14, 59, 59, 999000
    )


@pytest.mark.parametrize("days", [0, -1, MAX_EXTERNAL_ACCOUNT_DAYS + 1, True, 1.5, "90"])
def test_term_must_be_whole_days_within_a_year(days: object) -> None:
    with pytest.raises(DomainError) as caught:
        initial_expiry(NOW, days)  # type: ignore[arg-type]
    assert caught.value.code == "INVALID_ACCOUNT_TERM"


def test_extension_adds_to_the_remaining_term_and_restarts_after_expiry() -> None:
    current = initial_expiry(NOW, 30)
    assert extended_expiry(NOW, current, 30) == initial_expiry(NOW, 60)
    expired = datetime(2026, 11, 1)
    assert extended_expiry(NOW, expired, 30) == initial_expiry(NOW, 30)


def test_extension_cannot_reach_beyond_a_year_ahead() -> None:
    current = initial_expiry(NOW, 300)
    with pytest.raises(DomainError) as caught:
        extended_expiry(NOW, current, 100)
    assert caught.value.code == "INVALID_ACCOUNT_TERM"
    assert extended_expiry(NOW, current, 65) == initial_expiry(NOW, MAX_EXTERNAL_ACCOUNT_DAYS)


def test_expiry_is_inclusive_and_absent_for_permanent_accounts() -> None:
    expiry = initial_expiry(NOW, 1)
    assert not is_expired(None, NOW)
    assert not is_expired(expiry, expiry.replace(microsecond=998000))
    assert is_expired(expiry, expiry)


def test_external_roles_are_limited_to_gitlab_user() -> None:
    assert_external_roles([{"serviceKey": "gitlab", "name": "user"}])
    for role in (
        {"serviceKey": "agent-hub", "name": "user"},
        {"serviceKey": "sso", "name": "admin"},
    ):
        with pytest.raises(DomainError) as caught:
            assert_external_roles([role])
        assert caught.value.code == "EXTERNAL_ROLE_NOT_ALLOWED"
