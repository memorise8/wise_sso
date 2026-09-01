from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.tokens import (
    ACCESS_TOKEN_KID_VALIDATION_GAP,
    AccessTokenIdentity,
    RoleClaim,
    TokenValidationError,
)
from wiseacct_sso.infrastructure.security import JwtTokenCodec, sha256_token


def codec(synthetic_settings: Settings) -> JwtTokenCodec:
    return JwtTokenCodec.from_settings(synthetic_settings)


def identity() -> AccessTokenIdentity:
    return AccessTokenIdentity(
        user_id="auth-user-1",
        email="user@example.com",
        name="홍길동",
        email_verified=True,
        roles=(RoleClaim(service_key="temis", name="user"),),
    )


def test_access_token_has_exact_express_claim_and_header_contract(
    synthetic_settings: Settings,
) -> None:
    tokens = codec(synthetic_settings)
    token = tokens.issue_access_token(identity(), audience="temis")
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(
        token,
        jwt.PyJWK.from_dict(synthetic_settings.jwt_access_public_jwk.model_dump()).key,
        algorithms=["RS256"],
        issuer=synthetic_settings.jwt_issuer,
        audience="temis",
    )

    assert header == {
        "alg": "RS256",
        "kid": synthetic_settings.jwt_access_key_id,
        "typ": "JWT",
    }
    assert set(payload) == {
        "sub",
        "email",
        "name",
        "email_verified",
        "type",
        "roles",
        "iat",
        "exp",
        "iss",
        "aud",
    }
    assert payload == {
        "sub": "auth-user-1",
        "email": "user@example.com",
        "name": "홍길동",
        "email_verified": True,
        "type": "access",
        "roles": [{"serviceKey": "temis", "name": "user"}],
        "iat": payload["iat"],
        "exp": payload["iat"] + synthetic_settings.access_token_expires_in,
        "iss": synthetic_settings.jwt_issuer,
        "aud": "temis",
    }

    verified = tokens.verify_access_token(token, audience="temis")
    assert verified.identity == identity()
    assert verified.issued_at == datetime.fromtimestamp(payload["iat"], UTC)
    assert verified.expires_at == datetime.fromtimestamp(payload["exp"], UTC)


def test_access_token_supports_nullable_profile_claims(synthetic_settings: Settings) -> None:
    tokens = codec(synthetic_settings)
    anonymous_profile = AccessTokenIdentity(
        user_id="auth-user-2",
        email=None,
        name=None,
        email_verified=False,
        roles=(),
    )

    verified = tokens.verify_access_token(
        tokens.issue_access_token(anonymous_profile, audience="ledger-api"),
        audience="ledger-api",
    )

    assert verified.identity == anonymous_profile
    assert verified.audience == "ledger-api"


@pytest.mark.parametrize(
    ("algorithm", "claim_type", "issuer", "audience", "expires_at"),
    [
        ("HS256", "access", None, "temis", None),
        ("RS256", "refresh", None, "temis", None),
        ("RS256", "access", "https://wrong-issuer.example", "temis", None),
        ("RS256", "access", None, "wrong-audience", None),
        ("RS256", "access", None, "temis", 0),
    ],
)
def test_access_verification_rejects_invalid_tokens_generically(
    synthetic_settings: Settings,
    algorithm: str,
    claim_type: str,
    issuer: str | None,
    audience: str,
    expires_at: int | None,
) -> None:
    tokens = codec(synthetic_settings)
    now = datetime.now(UTC)
    payload = {
        "sub": "auth-user-1",
        "email": "user@example.com",
        "name": "Test User",
        "email_verified": True,
        "type": claim_type,
        "roles": [],
        "iat": int(now.timestamp()),
        "exp": (
            expires_at if expires_at is not None else int((now + timedelta(minutes=5)).timestamp())
        ),
        "iss": issuer or synthetic_settings.jwt_issuer,
        "aud": audience,
    }
    key = (
        "not-the-refresh-secret-but-long-enough"
        if algorithm == "HS256"
        else synthetic_settings.jwt_access_private_key
    )
    token = jwt.encode(payload, key, algorithm=algorithm)

    with pytest.raises(TokenValidationError, match=r"^Invalid token$") as error:
        tokens.verify_access_token(token, audience="temis")

    assert error.value.__cause__ is None


def test_wrong_access_kid_remains_an_explicit_express_parity_gap(
    synthetic_settings: Settings,
) -> None:
    tokens = codec(synthetic_settings)
    token = jwt.encode(
        {
            "sub": "auth-user-1",
            "email": None,
            "name": None,
            "email_verified": False,
            "type": "access",
            "roles": [],
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "iss": synthetic_settings.jwt_issuer,
            "aud": "temis",
        },
        synthetic_settings.jwt_access_private_key,
        algorithm="RS256",
        headers={"kid": "wrong-but-signature-valid"},
    )

    assert "wrong kid" in ACCESS_TOKEN_KID_VALIDATION_GAP.lower()
    assert tokens.verify_access_token(token, audience="temis").identity.user_id == "auth-user-1"


def test_refresh_token_has_exact_contract_random_id_and_hash(
    synthetic_settings: Settings,
) -> None:
    tokens = codec(synthetic_settings)
    issued = tokens.issue_refresh_token(user_id="auth-user-1", audience="ledger-api")
    header = jwt.get_unverified_header(issued.token)
    payload = jwt.decode(
        issued.token,
        synthetic_settings.jwt_refresh_secret,
        algorithms=["HS256"],
    )

    assert header == {"alg": "HS256", "typ": "JWT"}
    assert set(payload) == {"sub", "type", "tokenId", "audience", "iat", "exp"}
    assert payload == {
        "sub": "auth-user-1",
        "type": "refresh",
        "tokenId": issued.token_id,
        "audience": "ledger-api",
        "iat": payload["iat"],
        "exp": payload["iat"] + synthetic_settings.refresh_token_expires_in_days * 86_400,
    }
    assert len(issued.token_id) == 64
    assert all(character in "0123456789abcdef" for character in issued.token_id)
    assert issued.token_hash == sha256_token(issued.token)
    assert issued.expires_at == datetime.fromtimestamp(payload["exp"], UTC)

    verified = tokens.verify_refresh_token(issued.token)
    assert verified.user_id == "auth-user-1"
    assert verified.token_id == issued.token_id
    assert verified.audience == "ledger-api"

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        tokens.verify_refresh_token(issued.token, audience="temis")


@pytest.mark.parametrize(
    ("algorithm", "claim_type", "audience", "expires_at"),
    [
        ("HS384", "refresh", "temis", None),
        ("HS256", "access", "temis", None),
        ("HS256", "refresh", "wrong-audience", None),
        ("HS256", "refresh", "temis", 0),
    ],
)
def test_refresh_verification_rejects_invalid_tokens_generically(
    synthetic_settings: Settings,
    algorithm: str,
    claim_type: str,
    audience: str,
    expires_at: int | None,
) -> None:
    refresh_secret = (
        "synthetic-invalid-hs384-secret-that-is-at-least-forty-eight-bytes"
        if algorithm == "HS384"
        else synthetic_settings.jwt_refresh_secret
    )
    verification_settings = synthetic_settings.model_copy(
        update={"jwt_refresh_secret": refresh_secret}
    )
    tokens = codec(verification_settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "auth-user-1",
            "type": claim_type,
            "tokenId": "a" * 64,
            "audience": audience,
            "iat": int(now.timestamp()),
            "exp": (
                expires_at if expires_at is not None else int((now + timedelta(days=1)).timestamp())
            ),
        },
        refresh_secret,
        algorithm=algorithm,
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$") as error:
        tokens.verify_refresh_token(token, audience="temis")

    assert error.value.__cause__ is None


def test_refresh_verification_requires_a_64_hex_token_id(synthetic_settings: Settings) -> None:
    tokens = codec(synthetic_settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "auth-user-1",
            "type": "refresh",
            "tokenId": "not-a-valid-token-id",
            "audience": "temis",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=1)).timestamp()),
        },
        synthetic_settings.jwt_refresh_secret,
        algorithm="HS256",
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        tokens.verify_refresh_token(token, audience="temis")


def test_refresh_without_audience_uses_express_default_audience_parity(
    synthetic_settings: Settings,
) -> None:
    tokens = codec(synthetic_settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "auth-user-1",
            "type": "refresh",
            "tokenId": "a" * 64,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=1)).timestamp()),
        },
        synthetic_settings.jwt_refresh_secret,
        algorithm="HS256",
    )

    verified = tokens.verify_refresh_token(token)

    assert verified.audience == synthetic_settings.jwt_audience
    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        tokens.verify_refresh_token(token, audience="ledger-api")


@pytest.mark.parametrize("invalid_audience", ["", 123, None])
def test_refresh_rejects_invalid_explicit_audience_claim(
    synthetic_settings: Settings,
    invalid_audience: object,
) -> None:
    tokens = codec(synthetic_settings)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "auth-user-1",
            "type": "refresh",
            "tokenId": "a" * 64,
            "audience": invalid_audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=1)).timestamp()),
        },
        synthetic_settings.jwt_refresh_secret,
        algorithm="HS256",
    )

    with pytest.raises(TokenValidationError, match=r"^Invalid token$"):
        tokens.verify_refresh_token(token, audience=synthetic_settings.jwt_audience)


def test_sha256_token_matches_node_utf8_hex_contract() -> None:
    assert sha256_token("토큰.token") == (
        "78f0807ef13c93dd71cd76031f1d19fe82941a02c0ce36b1a54415dfacc534c6"
    )


@pytest.mark.parametrize("unpaired_surrogate", ["\ud800", "\udfff"])
def test_sha256_token_replaces_unpaired_surrogates_like_node(
    unpaired_surrogate: str,
) -> None:
    assert sha256_token(f"unknown-{unpaired_surrogate}-refresh") == sha256_token(
        "unknown-\ufffd-refresh"
    )


def test_sha256_token_preserves_valid_surrogate_pair_as_astral_character() -> None:
    assert sha256_token("jwt-\ud83d\ude00-value") == sha256_token(f"jwt-{chr(0x1F600)}-value")
