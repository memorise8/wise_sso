import pytest

from wiseacct_sso.domain.oauth import (
    MAX_CALLER_STATE_LENGTH,
    AuthHandoffMetadata,
    ClientHandoff,
    InvalidOAuthContract,
    InvalidProviderProfile,
    OAuthStateMetadata,
    normalize_provider_profile,
)

CHALLENGE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"


def test_oauth_state_serializes_exact_strict_camelcase_contract() -> None:
    metadata = OAuthStateMetadata(
        client_id="temis",
        redirect_uri="https://financenow.kr/auth/callback",
        caller_state="state",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
    )
    serialized = metadata.to_serialized("google")

    assert serialized == {
        "provider": "google",
        "clientId": "temis",
        "redirectUri": "https://financenow.kr/auth/callback",
        "callerState": "state",
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
    }
    assert OAuthStateMetadata.from_serialized(serialized) == ("google", metadata)


def test_oauth_state_allows_optional_handoff_pair_but_not_half_a_pair() -> None:
    metadata = OAuthStateMetadata(
        client_id="temis",
        redirect_uri="https://financenow.kr/auth/callback",
        caller_state=None,
        code_challenge=None,
        code_challenge_method=None,
    )
    assert metadata.to_serialized("naver")["codeChallenge"] is None

    with pytest.raises(InvalidOAuthContract):
        OAuthStateMetadata(
            client_id="temis",
            redirect_uri="https://financenow.kr/auth/callback",
            caller_state=None,
            code_challenge=CHALLENGE,
            code_challenge_method=None,
        )


@pytest.mark.parametrize("method", ["plain", "s256", "RS256"])
def test_pkce_is_s256_only(method: str) -> None:
    with pytest.raises(InvalidOAuthContract):
        OAuthStateMetadata(
            client_id="temis",
            redirect_uri="https://financenow.kr/auth/callback",
            caller_state=None,
            code_challenge=CHALLENGE,
            code_challenge_method=method,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("challenge", ["a" * 42, "a" * 129, "a" * 42 + "+"])
def test_pkce_challenge_uses_express_length_and_alphabet(challenge: str) -> None:
    with pytest.raises(InvalidOAuthContract):
        OAuthStateMetadata(
            client_id="temis",
            redirect_uri="https://financenow.kr/auth/callback",
            caller_state=None,
            code_challenge=challenge,
            code_challenge_method="S256",
        )


def test_caller_state_is_optional_nonempty_and_bounded_to_512() -> None:
    OAuthStateMetadata("temis", "https://example.com/callback", "s" * 512, None, None)
    OAuthStateMetadata("temis", "https://example.com/callback", "😀" * 256, None, None)

    for state in ("", "s" * (MAX_CALLER_STATE_LENGTH + 1), "😀" * 257):
        with pytest.raises(InvalidOAuthContract):
            OAuthStateMetadata("temis", "https://example.com/callback", state, None, None)


def test_state_parser_rejects_extra_missing_snake_case_and_unknown_provider() -> None:
    valid: dict[str, object] = {
        "provider": "kakao",
        "clientId": "temis",
        "redirectUri": "https://example.com/callback",
        "callerState": None,
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
    }
    for mutation in (
        {**valid, "extra": True},
        {key: value for key, value in valid.items() if key != "clientId"},
        {**valid, "client_id": valid["clientId"]},
        {**valid, "provider": "github"},
    ):
        with pytest.raises(InvalidOAuthContract):
            OAuthStateMetadata.from_serialized(mutation)


def test_client_handoff_has_exact_camelcase_serialization_and_requires_pkce() -> None:
    handoff = ClientHandoff(
        client_id="temis",
        audience="temis-api",
        redirect_uri="https://example.com/callback",
        state=None,
        code_challenge=CHALLENGE,
    )
    serialized = handoff.to_serialized()

    assert set(serialized) == {
        "clientId",
        "audience",
        "redirectUri",
        "state",
        "codeChallenge",
        "codeChallengeMethod",
    }
    assert ClientHandoff.from_serialized(serialized) == handoff


def test_stored_auth_handoff_has_exact_express_shape_and_optional_provider_omission() -> None:
    metadata = AuthHandoffMetadata(
        client_id="temis",
        audience="temis-api",
        redirect_uri="https://example.com/callback",
        user_id="user-1",
        provider="google",
        login_method="oauth",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
        state="caller-state",
        expires_at_epoch_ms=1_788_177_720_000,
    )
    serialized = metadata.to_serialized()

    assert serialized == {
        "clientId": "temis",
        "audience": "temis-api",
        "redirectUri": "https://example.com/callback",
        "userId": "user-1",
        "provider": "google",
        "loginMethod": "oauth",
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
        "state": "caller-state",
        "expiresAtEpochMs": 1_788_177_720_000,
    }
    assert AuthHandoffMetadata.from_serialized(serialized) == metadata

    password = AuthHandoffMetadata(
        client_id="temis",
        audience="temis-api",
        redirect_uri="https://example.com/callback",
        user_id="user-1",
        provider=None,
        login_method="password",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
        state=None,
        expires_at_epoch_ms=1,
    )
    assert "provider" not in password.to_serialized()


def test_stored_auth_handoff_parser_is_strict_and_rejects_boolean_expiry() -> None:
    valid: dict[str, object] = {
        "clientId": "temis",
        "audience": "temis-api",
        "redirectUri": "https://example.com/callback",
        "userId": "user-1",
        "loginMethod": "password",
        "codeChallenge": CHALLENGE,
        "codeChallengeMethod": "S256",
        "state": None,
        "expiresAtEpochMs": 1,
    }
    for mutation in ({**valid, "extra": 1}, {**valid, "expiresAtEpochMs": True}):
        with pytest.raises(InvalidOAuthContract):
            AuthHandoffMetadata.from_serialized(mutation)


def test_google_profile_normalization_preserves_verified_boolean() -> None:
    profile = normalize_provider_profile(
        "google",
        {
            "sub": "google-1",
            "email": "user@example.com",
            "email_verified": True,
            "name": "User",
            "picture": "https://example.com/picture.png",
        },
    )
    assert profile.provider_user_id == "google-1"
    assert profile.email_verified is True
    assert profile.profile_url == "https://example.com/picture.png"


def test_naver_profile_normalization_is_never_verified() -> None:
    profile = normalize_provider_profile(
        "naver",
        {"response": {"id": "naver-1", "email": "user@example.com"}},
    )
    assert profile.provider_user_id == "naver-1"
    assert profile.email_verified is False
    assert profile.name is None


@pytest.mark.parametrize(("provider_id", "expected"), [(123, "123"), ("123", "123")])
def test_kakao_profile_normalization_stringifies_number_id(
    provider_id: int | str, expected: str
) -> None:
    profile = normalize_provider_profile(
        "kakao",
        {
            "id": provider_id,
            "kakao_account": {
                "email": "user@example.com",
                "profile": {"nickname": "User", "profile_image_url": "https://example.com/p.png"},
            },
        },
    )
    assert profile.provider_user_id == expected
    assert profile.email_verified is False


@pytest.mark.parametrize(
    ("provider", "raw"),
    [
        ("google", {"sub": ""}),
        ("google", {"sub": "id", "email_verified": "true"}),
        ("naver", {"response": {"id": 1}}),
        ("kakao", {"id": True}),
    ],
)
def test_provider_profile_rejects_wrong_provider_specific_types(provider: str, raw: object) -> None:
    with pytest.raises(InvalidProviderProfile):
        normalize_provider_profile(provider, raw)  # type: ignore[arg-type]
