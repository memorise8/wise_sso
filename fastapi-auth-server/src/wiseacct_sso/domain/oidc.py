"""Pure OIDC policy, scope, role projection, and PKCE rules."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Protocol

from wiseacct_sso.domain.users import Role

_PKCE_VALUE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_S256_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$")
MAX_GROUPS = 64
MAX_GROUP_VALUE_LENGTH = 129
MAX_GROUPS_PAYLOAD_LENGTH = 4096


class OidcRequiredRole(Protocol):
    @property
    def service_key(self) -> str: ...

    @property
    def name(self) -> str: ...


class OidcClientRolePolicy(Protocol):
    @property
    def required_roles(self) -> tuple[OidcRequiredRole, ...]: ...

    @property
    def groups_service_keys(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    user_id: str
    email: str
    name: str | None
    email_verified: bool
    roles: tuple[Role, ...]


def has_required_role(identity: OidcIdentity, client: OidcClientRolePolicy) -> bool:
    actual = {(role.service_key, role.name) for role in identity.roles}
    return any(
        (required.service_key, required.name) in actual for required in client.required_roles
    )


def project_groups(identity: OidcIdentity, client: OidcClientRolePolicy) -> tuple[str, ...]:
    allowed = set(client.groups_service_keys)
    projected: set[str] = set()
    for role in identity.roles:
        if role.service_key not in allowed:
            continue
        if ":" in role.service_key or ":" in role.name:
            raise ValueError("OIDC group role identifiers must not contain ':'")
        group = f"{role.service_key}:{role.name}"
        if len(group) > MAX_GROUP_VALUE_LENGTH:
            raise ValueError("OIDC group value exceeds the release limit")
        projected.add(group)
    groups = tuple(sorted(projected))
    encoded_size = len(json.dumps(groups, ensure_ascii=True, separators=(",", ":")).encode())
    if len(groups) > MAX_GROUPS or encoded_size > MAX_GROUPS_PAYLOAD_LENGTH:
        raise ValueError("OIDC groups claim exceeds the release limit")
    return groups


def parse_requested_scopes(raw_scope: str, allowed_scopes: tuple[str, ...]) -> tuple[str, ...]:
    if not raw_scope or len(raw_scope) > 1024:
        raise ValueError("invalid OIDC scope")
    scopes = tuple(dict.fromkeys(raw_scope.split()))
    if not scopes or "openid" not in scopes or any(scope not in allowed_scopes for scope in scopes):
        raise ValueError("invalid OIDC scope")
    return scopes


def validate_pkce_request(
    code_challenge: str | None,
    code_challenge_method: str | None,
    *,
    required: bool,
) -> None:
    if code_challenge is None:
        if required or code_challenge_method is not None:
            raise ValueError("PKCE S256 is required")
        return
    if code_challenge_method != "S256" or _S256_CHALLENGE.fullmatch(code_challenge) is None:
        raise ValueError("PKCE S256 is required")


def verify_pkce(code_verifier: str | None, stored_challenge: str | None) -> bool:
    if stored_challenge is None:
        return code_verifier is None
    if code_verifier is None or _PKCE_VALUE.fullmatch(code_verifier) is None:
        return False
    challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
    challenge_text = challenge.rstrip(b"=").decode("ascii")
    return hmac.compare_digest(challenge_text, stored_challenge)
