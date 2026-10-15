"""Strict, independent configuration models for the optional OIDC provider."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Annotated, Self
from urllib.parse import parse_qsl, urlsplit

from argon2 import extract_parameters
from argon2.low_level import Type
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]

_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")
_SCOPE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_DEFAULT_SCOPES = ("openid", "email", "profile")
_SUPPORTED_SCOPES = frozenset(_DEFAULT_SCOPES)


class OidcRoleRequirement(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, populate_by_name=True
    )

    service_key: NonEmptyString = Field(alias="serviceKey", max_length=64)
    name: NonEmptyString = Field(max_length=64)

    @model_validator(mode="after")
    def reject_ambiguous_group_delimiter(self) -> Self:
        if ":" in self.service_key or ":" in self.name:
            raise ValueError("OIDC role identifiers must not contain ':'")
        return self


class OidcClientPolicy(BaseModel):
    """One confidential OIDC client; values are never URL-normalized."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, hide_input_in_errors=True, populate_by_name=True
    )

    client_id: NonEmptyString = Field(alias="clientId", max_length=128)
    redirect_uris: tuple[NonEmptyString, ...] = Field(
        alias="redirectUris", min_length=1, max_length=16
    )
    client_secret_hash: NonEmptyString = Field(alias="clientSecretHash", repr=False)
    required_roles: tuple[OidcRoleRequirement, ...] = Field(
        alias="requiredRoles", min_length=1, max_length=32
    )
    groups_service_keys: tuple[NonEmptyString, ...] = Field(
        alias="groupsServiceKeys", min_length=1, max_length=32
    )
    require_pkce: bool = Field(default=True, alias="requirePkce")
    allowed_scopes: tuple[NonEmptyString, ...] = Field(
        default=_DEFAULT_SCOPES, alias="allowedScopes", min_length=1, max_length=16
    )

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        if _CLIENT_ID.fullmatch(value) is None:
            raise ValueError("OIDC clientId contains unsupported characters")
        return value

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("OIDC redirectUris must be unique")
        for value in values:
            _validate_redirect_uri(value)
        return values

    @field_validator("client_secret_hash")
    @classmethod
    def validate_secret_hash(cls, value: str) -> str:
        try:
            parameters = extract_parameters(value)
        except Exception as error:
            raise ValueError("OIDC clientSecretHash must be an Argon2id PHC hash") from error
        if (
            parameters.type is not Type.ID
            or parameters.version != 19
            or not 8_192 <= parameters.memory_cost <= 65_536
            or not 1 <= parameters.time_cost <= 4
            or not 1 <= parameters.parallelism <= 4
            or parameters.hash_len < 32
            or parameters.salt_len < 16
        ):
            raise ValueError("OIDC clientSecretHash must be an Argon2id PHC hash")
        return value

    @field_validator("groups_service_keys")
    @classmethod
    def validate_group_service_keys(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("OIDC groupsServiceKeys must be unique")
        if any(":" in value or len(value) > 64 for value in values):
            raise ValueError("OIDC group service keys are invalid")
        return values

    @field_validator("allowed_scopes")
    @classmethod
    def validate_allowed_scopes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("OIDC allowedScopes must be unique")
        if "openid" not in values or any(value not in _SUPPORTED_SCOPES for value in values):
            raise ValueError("OIDC allowedScopes must include openid")
        if any(_SCOPE.fullmatch(value) is None for value in values):
            raise ValueError("OIDC allowedScopes contains an invalid scope")
        return values

    @model_validator(mode="after")
    def validate_role_projection(self) -> Self:
        projected = set(self.groups_service_keys)
        if any(role.service_key not in projected for role in self.required_roles):
            raise ValueError("requiredRoles service keys must be included in groupsServiceKeys")
        if len(set(self.required_roles)) != len(self.required_roles):
            raise ValueError("OIDC requiredRoles must be unique")
        return self

    def accepts_redirect_uri(self, value: str) -> bool:
        return value in self.redirect_uris


@dataclass(frozen=True, slots=True)
class OidcClientRegistry:
    clients: tuple[OidcClientPolicy, ...]

    def __post_init__(self) -> None:
        identifiers = [client.client_id for client in self.clients]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("OIDC clientId values must be unique")

    def get(self, client_id: str) -> OidcClientPolicy | None:
        return next((client for client in self.clients if client.client_id == client_id), None)

    def require(self, client_id: str) -> OidcClientPolicy:
        client = self.get(client_id)
        if client is None:
            raise ValueError("unknown OIDC client")
        return client


def _validate_redirect_uri(value: str) -> None:
    if (
        value != value.strip()
        or any(character.isspace() or ord(character) <= 0x20 for character in value)
        or "#" in value
        or "*" in value
        or "\\" in value
    ):
        raise ValueError("OIDC redirectUris must be exact absolute URLs without fragments")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("OIDC redirectUris must be valid absolute URLs") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or not parsed.hostname.isascii()
        or "%" in parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is None and ":" in parsed.netloc.rsplit("]", 1)[-1])
    ):
        raise ValueError("OIDC redirectUris must be valid absolute URLs")
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError("OIDC redirectUris must use HTTPS")
    if any(
        name in {"code", "state", "error", "error_description"}
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
    ):
        raise ValueError("OIDC redirectUris must not predefine authorization response parameters")


def parse_oidc_clients_json(
    raw: str | list[object] | tuple[object, ...], *, allow_loopback: bool = False
) -> OidcClientRegistry:
    """Parse one complete client registry without leaking secret-bearing input in errors."""

    try:
        decoded: object = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as error:
        raise ValueError("OIDC_CLIENTS_JSON must be valid JSON") from error
    if not isinstance(decoded, (list, tuple)):
        raise ValueError("OIDC_CLIENTS_JSON must be an array")
    try:
        clients = tuple(OidcClientPolicy.model_validate(item) for item in decoded)
        registry = OidcClientRegistry(clients)
    except (TypeError, ValueError) as error:
        raise ValueError("OIDC_CLIENTS_JSON contains an invalid client policy") from error
    if not allow_loopback and any(
        urlsplit(uri).scheme != "https" for client in clients for uri in client.redirect_uris
    ):
        raise ValueError("OIDC loopback redirectUris are allowed only in test mode")
    return registry
