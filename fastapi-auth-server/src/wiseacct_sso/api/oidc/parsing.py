"""Strict, dependency-free parsing for the OIDC HTTP boundary."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import unquote_to_bytes

from starlette.datastructures import Headers

MAX_QUERY_BYTES = 8_192
MAX_FORM_BYTES = 8_192
MAX_FIELDS = 16
_BAD_PERCENT = re.compile(rb"%(?![0-9A-Fa-f]{2})")
_TOKEN = re.compile(r"^[\x21-\x7e]+$")


class ParseError(ValueError):
    """The request is malformed or uses an intentionally unsupported encoding."""


class ClientAuthenticationError(ParseError):
    """No single well-formed OAuth client authentication method was supplied."""


def parse_urlencoded(raw: bytes, *, max_bytes: int, max_fields: int = MAX_FIELDS) -> dict[str, str]:
    if len(raw) > max_bytes:
        raise ParseError("encoded input is too large")
    if not raw:
        return {}
    fields = raw.split(b"&")
    if len(fields) > max_fields:
        raise ParseError("too many fields")
    parsed: dict[str, str] = {}
    for field in fields:
        if not field or b"=" not in field:
            raise ParseError("invalid form encoding")
        raw_name, raw_value = field.split(b"=", 1)
        if not raw_name or _BAD_PERCENT.search(raw_name) or _BAD_PERCENT.search(raw_value):
            raise ParseError("invalid form encoding")
        try:
            name = unquote_to_bytes(raw_name.replace(b"+", b" ")).decode("utf-8", "strict")
            value = unquote_to_bytes(raw_value.replace(b"+", b" ")).decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise ParseError("invalid UTF-8") from error
        if name in parsed:
            raise ParseError("duplicate field")
        parsed[name] = value
    return parsed


@dataclass(frozen=True, slots=True)
class ClientCredentials:
    client_id: str
    client_secret: str
    method: str


def extract_client_credentials(headers: Headers, form: dict[str, str]) -> ClientCredentials:
    authorization_values = headers.getlist("authorization")
    body_client_id = form.get("client_id")
    body_secret = form.get("client_secret")
    if authorization_values:
        if len(authorization_values) != 1 or body_client_id is not None or body_secret is not None:
            raise ParseError("multiple client authentication methods")
        scheme, separator, encoded = authorization_values[0].partition(" ")
        if (
            not separator
            or scheme.lower() != "basic"
            or not encoded
            or len(encoded) > 4_096
            or any(character.isspace() for character in encoded)
        ):
            raise ClientAuthenticationError("invalid client authorization")
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8", "strict")
        except (binascii.Error, UnicodeDecodeError) as error:
            raise ClientAuthenticationError("invalid client authorization") from error
        encoded_client_id, colon, encoded_client_secret = decoded.partition(":")
        if not colon:
            raise ClientAuthenticationError("invalid client authorization")
        try:
            client_id = _decode_component(encoded_client_id)
            client_secret = _decode_component(encoded_client_secret)
        except ParseError as error:
            raise ClientAuthenticationError("invalid client authorization") from error
        if (
            not client_id
            or len(client_id) > 128
            or not client_secret
            or len(client_secret) > 1_024
            or not _TOKEN.fullmatch(client_id)
        ):
            raise ClientAuthenticationError("invalid client authorization")
        return ClientCredentials(client_id, client_secret, "client_secret_basic")
    if body_client_id is None or body_secret is None or not body_client_id or not body_secret:
        raise ClientAuthenticationError("missing client authentication")
    if (
        len(body_client_id) > 128
        or len(body_secret) > 1_024
        or not _TOKEN.fullmatch(body_client_id)
    ):
        raise ClientAuthenticationError("invalid client authentication")
    return ClientCredentials(body_client_id, body_secret, "client_secret_post")


def _decode_component(value: str) -> str:
    raw = value.encode("utf-8")
    if _BAD_PERCENT.search(raw):
        raise ParseError("invalid client authorization")
    try:
        return unquote_to_bytes(raw.replace(b"+", b" ")).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ParseError("invalid client authorization") from error
