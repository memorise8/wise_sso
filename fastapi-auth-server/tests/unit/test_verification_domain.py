import re
from datetime import datetime, timedelta

import pytest

from wiseacct_sso.domain.oauth import ClientHandoff
from wiseacct_sso.domain.verification import (
    EMAIL_VERIFICATION_TOKEN_TTL,
    InvalidVerificationTokenError,
    VerificationTokenRecord,
    confirm_verification_record,
    issue_verification_token,
    normalize_verification_email,
)
from wiseacct_sso.infrastructure.security import sha256_token

NOW = datetime(2026, 8, 31, 12, 0, 0)
CHALLENGE = "A" * 43


def handoff() -> ClientHandoff:
    return ClientHandoff(
        client_id="temis",
        audience="temis-api",
        redirect_uri="https://financenow.kr/auth/callback",
        state="caller-state",
        code_challenge=CHALLENGE,
    )


def test_verification_token_is_exact_raw_32_base64url_hash_and_24_hour_ttl() -> None:
    issued = issue_verification_token(NOW, random_bytes=lambda size: b"\xff" * size)

    assert len(issued.value) == 43
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", issued.value)
    assert issued.token_hash == sha256_token(issued.value)
    assert issued.expires_at == NOW + timedelta(hours=24)
    assert EMAIL_VERIFICATION_TOKEN_TTL == timedelta(hours=24)


def test_verification_token_rejects_broken_random_source() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        issue_verification_token(NOW, random_bytes=lambda _size: b"short")


def test_verification_email_normalization_reuses_auth_contract() -> None:
    assert normalize_verification_email("  User@Company.COM ") == "user@company.com"


@pytest.mark.parametrize("record", [None, "used", "expired"])
def test_all_invalid_verification_causes_have_one_public_error(record: str | None) -> None:
    value = None
    if record is not None:
        value = VerificationTokenRecord(
            token_id="token-1",
            user_id="user-1",
            expires_at=NOW if record == "expired" else NOW + timedelta(hours=1),
            used_at=NOW if record == "used" else None,
            handoff=None,
        )

    with pytest.raises(InvalidVerificationTokenError) as raised:
        confirm_verification_record(value, now=NOW, activated_user_id="user-1")

    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        400,
        "INVALID_VERIFICATION_TOKEN",
        "Invalid or expired verification token",
    )


def test_confirmation_preserves_handoff_and_exact_result_status() -> None:
    metadata = handoff()
    record = VerificationTokenRecord(
        token_id="token-1",
        user_id="pending-user",
        expires_at=NOW + timedelta(seconds=1),
        used_at=None,
        handoff=metadata,
    )

    confirmed = confirm_verification_record(record, now=NOW, activated_user_id="active-user")

    assert confirmed.status == "verified"
    assert confirmed.user_id == "active-user"
    assert confirmed.handoff == metadata


def test_activation_race_uses_same_generic_verification_error() -> None:
    record = VerificationTokenRecord(
        token_id="token-1",
        user_id="pending-user",
        expires_at=NOW + timedelta(seconds=1),
        used_at=None,
        handoff=None,
    )
    with pytest.raises(InvalidVerificationTokenError):
        confirm_verification_record(record, now=NOW, activated_user_id=None)
