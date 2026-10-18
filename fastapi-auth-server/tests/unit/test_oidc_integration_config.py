import pytest
from pydantic import ValidationError

from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH


def oidc_policy(**overrides: object) -> dict[str, object]:
    return {
        "clientId": "cloudflare-access-dash",
        "redirectUris": ["https://team.cloudflareaccess.com/cdn-cgi/access/callback"],
        "clientSecretHash": DUMMY_PASSWORD_HASH,
        "requiredRoles": [{"serviceKey": "agent-hub", "name": "user"}],
        "groupsServiceKeys": ["agent-hub"],
        **overrides,
    }


def settings_with(settings: Settings, **updates: object) -> Settings:
    return Settings.model_validate(settings.model_dump() | updates)


def test_oidc_defaults_do_not_enable_routes(synthetic_settings: Settings) -> None:
    assert not synthetic_settings.oidc_enabled
    assert synthetic_settings.oidc_clients == ()
    assert synthetic_settings.oidc_public_origin is None


def test_explicit_oidc_settings_preserve_legacy_clients(synthetic_settings: Settings) -> None:
    settings = settings_with(
        synthetic_settings,
        oidc_enabled=True,
        oidc_clients=[oidc_policy()],
        oidc_public_origin="https://auth.example.test",
        oidc_google_redirect_uri="https://auth.example.test/oauth2/providers/google/callback",
        oauth_enabled_providers=("google",),
        google_client_id="synthetic-oidc-google",
        google_client_secret="synthetic-oidc-google-secret",
    )
    assert settings.auth_clients == synthetic_settings.auth_clients
    assert settings.google_redirect_uri == synthetic_settings.google_redirect_uri
    assert settings.oidc_clients[0].require_pkce


@pytest.mark.parametrize(
    "updates",
    [
        {"oidc_enabled": True},
        {"oidc_enabled": True, "oidc_public_origin": "https://auth.example.test"},
        {"oidc_clients": [oidc_policy(clientId="temis")]},
        {"oidc_clients": [oidc_policy(), oidc_policy()]},
        {"oidc_public_origin": "https://auth.example.test/"},
        {"oidc_public_origin": "https://auth.example.test?"},
        {"oidc_public_origin": "https://auth.example.test#"},
        {"oidc_public_origin": "https://user:pass@auth.example.test"},
        {"oidc_public_origin": "https://auth.example.test\n"},
        {"oidc_public_origin": "http://127.0.0.1:4001"},
        {"oidc_google_redirect_uri": "https://auth.example.test/auth/google/callback"},
        {
            "node_env": "development",
            "oidc_clients": [oidc_policy(redirectUris=["http://127.0.0.1/callback"])],
        },
    ],
)
def test_invalid_oidc_configuration_fails_closed(
    synthetic_settings: Settings, updates: dict[str, object]
) -> None:
    with pytest.raises(ValidationError):
        settings_with(synthetic_settings, **updates)


def test_oidc_rejects_legacy_audience_collision(synthetic_settings: Settings) -> None:
    with pytest.raises(ValidationError, match="audiences"):
        settings_with(
            synthetic_settings,
            jwt_audience="cloudflare-access-dash",
            oidc_clients=[oidc_policy()],
        )


def test_oidc_invalid_secret_is_not_echoed_in_settings_error(synthetic_settings: Settings) -> None:
    accidental_plaintext = "synthetic-plaintext-must-not-appear"
    with pytest.raises(ValidationError) as caught:
        settings_with(
            synthetic_settings,
            oidc_clients=[oidc_policy(clientSecretHash=accidental_plaintext)],
        )
    assert accidental_plaintext not in str(caught.value)
