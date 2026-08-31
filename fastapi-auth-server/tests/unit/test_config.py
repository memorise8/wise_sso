from pathlib import Path

import pytest
from pydantic import ValidationError

from wiseacct_sso.config import Settings

ROOT = Path(__file__).parents[2]


def example_settings() -> Settings:
    return Settings(_env_file=ROOT / ".env.example")  # type: ignore[call-arg]


def example_values() -> dict[str, object]:
    return example_settings().model_dump(by_alias=False)


def test_settings_parse_checkpoint_environment() -> None:
    settings = example_settings()

    assert settings.access_token_expires_in == 900
    assert settings.port == 4001
    assert settings.jwt_access_algorithm == "RS256"
    assert settings.auth_clients[0].client_id == "temis"
    assert settings.oauth_enabled_providers == ()
    assert settings.cors_allowed_origins == (
        "http://127.0.0.1:3001",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )


def test_settings_reject_mismatched_jwk_kid() -> None:
    values = example_values()
    values["jwt_access_key_id"] = "different-key"

    with pytest.raises(ValidationError, match="must match"):
        Settings.model_validate(values)


def test_settings_reject_invalid_cors_origin() -> None:
    values = example_values()
    values["cors_allowed_origins"] = ("https://example.invalid/path",)

    with pytest.raises(ValidationError, match="scheme, host"):
        Settings.model_validate(values)


def test_production_rejects_dev_mail_and_placeholder_secret() -> None:
    values = example_values()
    values.update(
        node_env="production",
        jwt_refresh_secret="replace-refresh-secret",
        mail_provider="dev",
    )

    with pytest.raises(ValidationError):
        Settings.model_validate(values)


def test_enabled_oauth_provider_requires_credentials() -> None:
    values = example_values()
    values["oauth_enabled_providers"] = ("google",)
    values["google_client_id"] = None
    values["google_client_secret"] = None

    with pytest.raises(ValidationError, match="GOOGLE_CLIENT_ID"):
        Settings.model_validate(values)


def test_settings_do_not_implicitly_read_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("JWT_REFRESH_SECRET=real-secret-must-not-load\n")

    with pytest.raises(ValidationError):
        Settings()  # type: ignore[call-arg]
