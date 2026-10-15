from __future__ import annotations

import base64

import pytest
from starlette.datastructures import Headers

from wiseacct_sso.api.oidc.parsing import (
    ParseError,
    extract_client_credentials,
    parse_urlencoded,
)


def test_urlencoded_parser_preserves_unicode_and_rejects_duplicates() -> None:
    assert parse_urlencoded(b"scope=openid+email&state=%ED%95%9C%EA%B8%80", max_bytes=1024) == {
        "scope": "openid email",
        "state": "한글",
    }

    with pytest.raises(ParseError):
        parse_urlencoded(b"state=one&state=two", max_bytes=1024)


@pytest.mark.parametrize(
    "value",
    [b"state=%", b"state=%0", b"state=%GG", b"state=%ff", b"state", b"=value"],
)
def test_urlencoded_parser_rejects_ambiguous_or_invalid_input(value: bytes) -> None:
    with pytest.raises(ParseError):
        parse_urlencoded(value, max_bytes=1024)


def test_basic_client_credentials_are_decoded_strictly() -> None:
    encoded = base64.b64encode(b"client-a:correct+horse%25battery").decode("ascii")

    credentials = extract_client_credentials(
        Headers({"authorization": f"Basic {encoded}"}),
        {"grant_type": "authorization_code"},
    )

    assert credentials.client_id == "client-a"
    assert credentials.client_secret == "correct horse%battery"
    assert credentials.method == "client_secret_basic"


def test_client_authentication_methods_cannot_be_mixed() -> None:
    encoded = base64.b64encode(b"client-a:secret").decode("ascii")

    with pytest.raises(ParseError):
        extract_client_credentials(
            Headers({"authorization": f"Basic {encoded}"}),
            {"client_id": "client-a", "client_secret": "secret"},
        )


def test_client_credentials_are_bounded_before_secret_verification() -> None:
    oversized_basic = base64.b64encode(f"client:{'s' * 4_000}".encode()).decode("ascii")

    with pytest.raises(ParseError):
        extract_client_credentials(Headers({"authorization": f"Basic {oversized_basic}"}), {})
    with pytest.raises(ParseError):
        extract_client_credentials(Headers(), {"client_id": "client", "client_secret": "s" * 1_025})


@pytest.mark.parametrize(
    "authorization",
    [
        "Bearer value",
        "Basic",
        "Basic !!!",
        "Basic Y2xpZW50",
        "Basic OmJhZA==",
        f"Basic {base64.b64encode(b'client:%GG').decode('ascii')}",
    ],
)
def test_malformed_basic_client_authentication_is_rejected(authorization: str) -> None:
    with pytest.raises(ParseError):
        extract_client_credentials(Headers({"authorization": authorization}), {})
