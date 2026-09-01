import base64
import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from wiseacct_sso.config import RelyingClientPolicy, Settings

ROOT = Path(__file__).parents[2]
NODE_EXECUTABLE = shutil.which("node")

REDIRECT_CANONICALIZATION_CASES = (
    ("HTTPS://EXAMPLE.COM:443", "https://example.com/"),
    ("http://EXAMPLE.COM:80/callback", "http://example.com/callback"),
    (
        "https://Example.COM:8443/a%2Fb?next=%2fkeep#Section",
        "https://example.com:8443/a%2Fb?next=%2fkeep#Section",
    ),
    ("https://example.com/a b", "https://example.com/a%20b"),
    ("https://b\u00fccher.example/callback", "https://xn--bcher-kva.example/callback"),
    ("https://example.com/a/../b", "https://example.com/b"),
    ("https://example.com/%2e%2e/callback", "https://example.com/callback"),
    ("https://example.com/a/./b", "https://example.com/a/b"),
    ("https://example.com/a/%2E/b", "https://example.com/a/b"),
    ("https://example.com/a/%2E./b", "https://example.com/b"),
    ("https://example.com/a/.%2e/b", "https://example.com/b"),
    ("https://example.com/a//b", "https://example.com/a//b"),
    ("https://example.com/a\\b", "https://example.com/a/b"),
    ("https:example.com/callback", "https://example.com/callback"),
    ("https:/example.com/callback", "https://example.com/callback"),
    ("https:\\example.com\\callback", "https://example.com/callback"),
    (
        "https://user:pa ss@EXAMPLE.com:443/a b?q=a b#f g",
        "https://user:pa%20ss@example.com/a%20b?q=a%20b#f%20g",
    ),
    (
        "HTTP://[2001:0DB8:0:0:0:0:0:1]:80/a",
        "http://[2001:db8::1]/a",
    ),
    (
        "https://b\u00fccher.example/\uacbd\ub85c?q=\ud55c\uae00#\uc870\uac01",
        "https://xn--bcher-kva.example/%EA%B2%BD%EB%A1%9C?q=%ED%95%9C%EA%B8%80#%EC%A1%B0%EA%B0%81",
    ),
    (
        "https://example.com/a\\b?x=one\\two#f\\g",
        "https://example.com/a/b?x=one\\two#f\\g",
    ),
    ("https://example.com/cb?", "https://example.com/cb?"),
    ("https://example.com/cb#", "https://example.com/cb#"),
    ("https://example.com/cb?#", "https://example.com/cb?#"),
    ("http://127.1/callback", "http://127.0.0.1/callback"),
    ("http://2130706433/callback", "http://127.0.0.1/callback"),
    ("http://0x7f000001/callback", "http://127.0.0.1/callback"),
    ("http://0177.0.0.1/callback", "http://127.0.0.1/callback"),
    ("https://fa\u00df.de/callback", "https://xn--fa-hia.de/callback"),
    (
        "https://example.com/a?q='[]|^`{}\\\"<>",
        "https://example.com/a?q=%27[]|^`{}\\%22%3C%3E",
    ),
    (
        "https://example.com/a#'[]|^`{}\\\"<>",
        "https://example.com/a#'[]|^%60{}\\%22%3C%3E",
    ),
    ("https://\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com/a", "https://example.com/a"),
    (
        "https://\u4f8b\u3048\u3002\u30c6\u30b9\u30c8/a",
        "https://xn--r8jz45g.xn--zckzah/a",
    ),
    (
        "https://u[name]:p=ass@example.com/a",
        "https://u%5Bname%5D:p%3Dass@example.com/a",
    ),
    ("https://%65xample.com/a", "https://example.com/a"),
    ("https://%E4%BE%8B%E3%81%88.com/a", "https://xn--r8jz45g.com/a"),
)


def relying_client(redirect_uri: str) -> RelyingClientPolicy:
    return RelyingClientPolicy.model_validate(
        {
            "clientId": "additional-client",
            "audience": "additional-client",
            "allowedRedirectUris": [redirect_uri],
            "allowedOrigins": ["https://example.com"],
            "defaultRole": {"serviceKey": "additional-client", "name": "pending"},
        }
    )


def example_settings() -> Settings:
    return Settings(_env_file=ROOT / ".env.example")  # type: ignore[call-arg]


def example_values() -> dict[str, object]:
    return example_settings().model_dump(by_alias=False)


def replace_signing_key(values: dict[str, object], key_id: str) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    values["jwt_access_private_key"] = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    values["jwt_access_public_jwk"] = {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        )
        .rstrip(b"=")
        .decode(),
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig",
        "kid": key_id,
    }
    values["jwt_access_key_id"] = key_id


def make_production_ready(values: dict[str, object]) -> None:
    values.update(
        node_env="production",
        jwt_refresh_secret="production-refresh-secret",
        mail_provider="smtp",
        smtp_host="smtp.example.com",
    )


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


@pytest.mark.parametrize(("raw", "expected"), REDIRECT_CANONICALIZATION_CASES)
def test_relying_client_canonicalizes_redirect_uri(raw: str, expected: str) -> None:
    assert relying_client(raw).allowed_redirect_uris == (expected,)


@pytest.mark.skipif(NODE_EXECUTABLE is None, reason="Node.js is not installed")
def test_redirect_uri_canonicalization_matches_node_url_oracle() -> None:
    raw_values = [raw for raw, _ in REDIRECT_CANONICALIZATION_CASES]
    assert NODE_EXECUTABLE is not None
    completed = subprocess.run(  # noqa: S603 - fixed local Node binary and static script
        [
            NODE_EXECUTABLE,
            "-e",
            "const xs=JSON.parse(process.argv[1]);"
            "process.stdout.write(JSON.stringify(xs.map(x => new URL(x).toString())));",
            json.dumps(raw_values),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    node_values = json.loads(completed.stdout)

    python_values = [relying_client(raw).allowed_redirect_uris[0] for raw in raw_values]
    assert python_values == node_values


def test_settings_reject_mismatched_jwk_kid() -> None:
    values = example_values()
    values["jwt_access_key_id"] = "different-key"

    with pytest.raises(ValidationError, match="must match"):
        Settings.model_validate(values)


def test_settings_reject_access_key_smaller_than_2048_bits() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # noqa: S505 - intentionally rejected fixture
    )
    public_numbers = private_key.public_key().public_numbers()
    values = example_values()
    values["jwt_access_private_key"] = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    values["jwt_access_public_jwk"] = {
        "kty": "RSA",
        "n": base64.urlsafe_b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")
        )
        .rstrip(b"=")
        .decode(),
        "e": "AQAB",
        "alg": "RS256",
        "use": "sig",
        "kid": values["jwt_access_key_id"],
    }

    with pytest.raises(ValidationError, match="at least 2048 bits"):
        Settings.model_validate(values)


def test_settings_reject_invalid_cors_origin() -> None:
    values = example_values()
    values["cors_allowed_origins"] = ("https://example.invalid/path",)

    with pytest.raises(ValidationError, match="scheme, host"):
        Settings.model_validate(values)


@pytest.mark.parametrize(
    "origin",
    ("http://127.1", "http://2130706433", "http://0x7f000001", "http://0177.0.0.1"),
)
def test_relying_client_rejects_noncanonical_numeric_ipv4_origin(origin: str) -> None:
    with pytest.raises(ValidationError, match="scheme, host"):
        RelyingClientPolicy.model_validate(
            {
                "clientId": "additional-client",
                "audience": "additional-client",
                "allowedRedirectUris": ["https://example.com/callback"],
                "allowedOrigins": [origin],
                "defaultRole": {"serviceKey": "additional-client", "name": "pending"},
            }
        )


@pytest.mark.parametrize(
    "redirect_uri",
    (
        "http://example.123/callback",
        "http://a.0x10/callback",
        "http://08/callback",
        "http://09/callback",
        "https://a\u200db.example/callback",
        "https://example%zz.com/callback",
        "https://exa mple.com/callback",
    ),
)
def test_relying_client_rejects_urls_rejected_by_node(redirect_uri: str) -> None:
    with pytest.raises(ValidationError, match="valid URLs"):
        relying_client(redirect_uri)


def test_production_detects_numeric_ipv4_redirect_as_localhost() -> None:
    values = example_values()
    numeric_client = relying_client("http://127.1/callback")
    values.update(
        node_env="production",
        jwt_refresh_secret="production-refresh-secret",
        mail_provider="smtp",
        smtp_host="smtp.example.com",
        auth_clients=(*values["auth_clients"], numeric_client),  # type: ignore[misc]
    )

    with pytest.raises(ValidationError, match="localhost clients are forbidden"):
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


def test_production_rejects_synthetic_access_key_fingerprint_with_different_key_id() -> None:
    values = example_values()
    make_production_ready(values)
    public_jwk = dict(cast(dict[str, object], values["jwt_access_public_jwk"]))
    public_jwk["kid"] = "production-key-1"
    values["jwt_access_public_jwk"] = public_jwk
    values["jwt_access_key_id"] = "production-key-1"

    with pytest.raises(ValidationError, match="synthetic JWT access signing credentials"):
        Settings.model_validate(values)


def test_production_rejects_synthetic_access_key_id_with_different_key() -> None:
    values = example_values()
    make_production_ready(values)
    replace_signing_key(values, "synthetic-fastapi-key-1")

    with pytest.raises(ValidationError, match="synthetic JWT access signing credentials"):
        Settings.model_validate(values)


def test_production_accepts_nonfixture_access_key_and_key_id() -> None:
    values = example_values()
    make_production_ready(values)
    replace_signing_key(values, "production-key-1")

    settings = Settings.model_validate(values)

    assert settings.node_env == "production"
    assert settings.jwt_access_key_id == "production-key-1"


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
