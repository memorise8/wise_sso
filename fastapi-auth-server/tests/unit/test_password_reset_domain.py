import re
from datetime import datetime, timedelta

import pytest

from wiseacct_sso.domain.auth import PasswordPolicy
from wiseacct_sso.domain.password_reset import (
    PASSWORD_RESET_TOKEN_TTL,
    InvalidResetTokenError,
    assert_reset_password_policy,
    confirm_password_reset,
    issue_password_reset_token,
    normalize_reset_email,
)
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import sha256_token

NOW = datetime(2026, 8, 31, 12, 0, 0)


def test_reset_token_is_exact_raw_32_base64url_hash_and_one_hour_ttl() -> None:
    issued = issue_password_reset_token(NOW, random_bytes=lambda size: bytes(range(size)))

    assert len(issued.value) == 43
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", issued.value)
    assert issued.token_hash == sha256_token(issued.value)
    assert issued.expires_at == NOW + timedelta(hours=1)
    assert PASSWORD_RESET_TOKEN_TTL == timedelta(hours=1)


def test_reset_email_and_password_policy_reuse_phase4_contracts() -> None:
    policy = PasswordPolicy(min_length=8, allowed_email_domain="company.com")

    assert normalize_reset_email(" User@Company.COM ") == "user@company.com"
    assert_reset_password_policy(" User@Company.COM ", "😀😀😀😀", policy)

    with pytest.raises(DomainError) as weak:
        assert_reset_password_policy("user@company.com", "short", policy)
    assert weak.value.code == "WEAK_PASSWORD"

    with pytest.raises(DomainError) as domain:
        assert_reset_password_policy("user@example.com", "long-enough", policy)
    assert domain.value.code == "EMAIL_DOMAIN_NOT_ALLOWED"


def test_reset_hash_uses_node_string_semantics_for_lone_surrogate() -> None:
    # The injected bytes make the raw token deterministic; hashing itself is the shared helper.
    issued = issue_password_reset_token(NOW, random_bytes=lambda size: b"a" * size)
    assert issued.token_hash == sha256_token(issued.value)
    assert sha256_token("reset-\ud800") == sha256_token("reset-�")


def test_reset_confirmation_has_exact_result_or_generic_error() -> None:
    assert confirm_password_reset("user-1").user_id == "user-1"

    with pytest.raises(InvalidResetTokenError) as raised:
        confirm_password_reset(None)
    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        400,
        "INVALID_RESET_TOKEN",
        "Invalid or expired reset token",
    )
