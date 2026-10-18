"""Pure OAuth, PKCE, state, handoff, and provider-profile contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, cast

type OAuthProvider = Literal["google", "naver", "kakao"]
type LoginMethod = Literal["oauth", "password"]
type PKCEMethod = Literal["S256"]

OAUTH_PROVIDERS: Final[tuple[OAuthProvider, ...]] = ("google", "naver", "kakao")
MAX_CALLER_STATE_LENGTH: Final = 512
PKCE_CHALLENGE_PATTERN: Final = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


class InvalidOAuthContract(ValueError):
    """Stored or incoming OAuth metadata does not match the strict contract."""


class InvalidProviderProfile(ValueError):
    """A provider response does not match its provider-specific profile shape."""


def _nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidOAuthContract(f"{field} must be a non-empty string")
    return value


def javascript_string_length(value: str) -> int:
    """Return JavaScript/Zod string length in UTF-16 code units."""

    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def _nullable_state(value: object, field: str = "callerState") -> str | None:
    if value is None:
        return None
    state = _nonempty(value, field)
    if javascript_string_length(state) > MAX_CALLER_STATE_LENGTH:
        raise InvalidOAuthContract(f"{field} must be at most 512 characters")
    return state


def _pkce_pair(challenge: object, method: object) -> tuple[str | None, PKCEMethod | None]:
    if challenge is None and method is None:
        return None, None
    if not isinstance(challenge, str) or not PKCE_CHALLENGE_PATTERN.fullmatch(challenge):
        raise InvalidOAuthContract("codeChallenge must match the PKCE contract")
    if method != "S256":
        raise InvalidOAuthContract("codeChallengeMethod must be S256")
    return challenge, "S256"


def _strict_keys(data: Mapping[str, object], expected: set[str]) -> None:
    if set(data) != expected:
        raise InvalidOAuthContract("metadata must use the exact camelCase contract")


@dataclass(frozen=True, slots=True)
class ClientHandoff:
    client_id: str
    audience: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    code_challenge_method: PKCEMethod = "S256"

    def __post_init__(self) -> None:
        _nonempty(self.client_id, "clientId")
        _nonempty(self.audience, "audience")
        _nonempty(self.redirect_uri, "redirectUri")
        _nullable_state(self.state, "state")
        _pkce_pair(self.code_challenge, self.code_challenge_method)

    def to_serialized(self) -> dict[str, object]:
        return {
            "clientId": self.client_id,
            "audience": self.audience,
            "redirectUri": self.redirect_uri,
            "state": self.state,
            "codeChallenge": self.code_challenge,
            "codeChallengeMethod": self.code_challenge_method,
        }

    @classmethod
    def from_serialized(cls, data: Mapping[str, object]) -> ClientHandoff:
        _strict_keys(
            data,
            {
                "clientId",
                "audience",
                "redirectUri",
                "state",
                "codeChallenge",
                "codeChallengeMethod",
            },
        )
        challenge, method = _pkce_pair(data["codeChallenge"], data["codeChallengeMethod"])
        if challenge is None or method is None:
            raise InvalidOAuthContract("client handoff requires PKCE")
        return cls(
            client_id=_nonempty(data["clientId"], "clientId"),
            audience=_nonempty(data["audience"], "audience"),
            redirect_uri=_nonempty(data["redirectUri"], "redirectUri"),
            state=_nullable_state(data["state"], "state"),
            code_challenge=challenge,
            code_challenge_method=method,
        )


@dataclass(frozen=True, slots=True)
class OAuthStateMetadata:
    client_id: str
    redirect_uri: str
    caller_state: str | None
    code_challenge: str | None
    code_challenge_method: PKCEMethod | None

    def __post_init__(self) -> None:
        _nonempty(self.client_id, "clientId")
        _nonempty(self.redirect_uri, "redirectUri")
        _nullable_state(self.caller_state)
        _pkce_pair(self.code_challenge, self.code_challenge_method)

    def to_serialized(self, provider: OAuthProvider) -> dict[str, object]:
        if provider not in OAUTH_PROVIDERS:
            raise InvalidOAuthContract("unsupported OAuth provider")
        return {
            "provider": provider,
            "clientId": self.client_id,
            "redirectUri": self.redirect_uri,
            "callerState": self.caller_state,
            "codeChallenge": self.code_challenge,
            "codeChallengeMethod": self.code_challenge_method,
        }

    @classmethod
    def from_serialized(
        cls, data: Mapping[str, object]
    ) -> tuple[OAuthProvider, OAuthStateMetadata]:
        _strict_keys(
            data,
            {
                "provider",
                "clientId",
                "redirectUri",
                "callerState",
                "codeChallenge",
                "codeChallengeMethod",
            },
        )
        provider_value = data["provider"]
        if provider_value not in OAUTH_PROVIDERS:
            raise InvalidOAuthContract("unsupported OAuth provider")
        challenge, method = _pkce_pair(data["codeChallenge"], data["codeChallengeMethod"])
        metadata = cls(
            client_id=_nonempty(data["clientId"], "clientId"),
            redirect_uri=_nonempty(data["redirectUri"], "redirectUri"),
            caller_state=_nullable_state(data["callerState"]),
            code_challenge=challenge,
            code_challenge_method=method,
        )
        return provider_value, metadata


@dataclass(frozen=True, slots=True)
class AuthHandoffMetadata:
    """Strict value stored behind a one-time client authorization code."""

    client_id: str
    audience: str
    redirect_uri: str
    user_id: str
    provider: OAuthProvider | None
    login_method: LoginMethod
    code_challenge: str
    code_challenge_method: PKCEMethod
    state: str | None
    expires_at_epoch_ms: int

    def __post_init__(self) -> None:
        _nonempty(self.client_id, "clientId")
        _nonempty(self.audience, "audience")
        _nonempty(self.redirect_uri, "redirectUri")
        _nonempty(self.user_id, "userId")
        if self.provider is not None and self.provider not in OAUTH_PROVIDERS:
            raise InvalidOAuthContract("unsupported OAuth provider")
        if self.login_method not in ("oauth", "password"):
            raise InvalidOAuthContract("unsupported login method")
        _pkce_pair(self.code_challenge, self.code_challenge_method)
        _nullable_state(self.state, "state")
        if isinstance(self.expires_at_epoch_ms, bool) or self.expires_at_epoch_ms <= 0:
            raise InvalidOAuthContract("expiresAtEpochMs must be a positive integer")

    def to_serialized(self) -> dict[str, object]:
        serialized: dict[str, object] = {
            "clientId": self.client_id,
            "audience": self.audience,
            "redirectUri": self.redirect_uri,
            "userId": self.user_id,
            "loginMethod": self.login_method,
            "codeChallenge": self.code_challenge,
            "codeChallengeMethod": self.code_challenge_method,
            "state": self.state,
            "expiresAtEpochMs": self.expires_at_epoch_ms,
        }
        if self.provider is not None:
            serialized["provider"] = self.provider
        return serialized

    @classmethod
    def from_serialized(cls, data: Mapping[str, object]) -> AuthHandoffMetadata:
        required = {
            "clientId",
            "audience",
            "redirectUri",
            "userId",
            "loginMethod",
            "codeChallenge",
            "codeChallengeMethod",
            "state",
            "expiresAtEpochMs",
        }
        if set(data) not in (required, required | {"provider"}):
            raise InvalidOAuthContract("metadata must use the exact camelCase contract")
        provider_value = data.get("provider")
        if provider_value is not None and provider_value not in OAUTH_PROVIDERS:
            raise InvalidOAuthContract("unsupported OAuth provider")
        login_method = data["loginMethod"]
        if login_method not in ("oauth", "password"):
            raise InvalidOAuthContract("unsupported login method")
        challenge, method = _pkce_pair(data["codeChallenge"], data["codeChallengeMethod"])
        if challenge is None or method is None:
            raise InvalidOAuthContract("auth handoff requires PKCE")
        expires = data["expiresAtEpochMs"]
        if isinstance(expires, bool) or not isinstance(expires, int):
            raise InvalidOAuthContract("expiresAtEpochMs must be a positive integer")
        return cls(
            client_id=_nonempty(data["clientId"], "clientId"),
            audience=_nonempty(data["audience"], "audience"),
            redirect_uri=_nonempty(data["redirectUri"], "redirectUri"),
            user_id=_nonempty(data["userId"], "userId"),
            provider=provider_value,
            login_method=login_method,
            code_challenge=challenge,
            code_challenge_method=method,
            state=_nullable_state(data["state"], "state"),
            expires_at_epoch_ms=expires,
        )


@dataclass(frozen=True, slots=True)
class OAuthProfile:
    provider: OAuthProvider
    provider_user_id: str
    email: str | None
    email_verified: bool
    name: str | None
    profile_url: str | None


def _optional_string(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidProviderProfile(f"{field} must be a string")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InvalidProviderProfile(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def normalize_provider_profile(provider: OAuthProvider, raw: object) -> OAuthProfile:
    user = _mapping(raw, "profile")
    if provider == "google":
        provider_id = user.get("sub")
        if not isinstance(provider_id, str) or not provider_id:
            raise InvalidProviderProfile("google sub must be a non-empty string")
        verified = user.get("email_verified", False)
        if not isinstance(verified, bool):
            raise InvalidProviderProfile("google email_verified must be boolean")
        return OAuthProfile(
            provider=provider,
            provider_user_id=provider_id,
            email=_optional_string(user.get("email"), "google email"),
            email_verified=verified is True,
            name=_optional_string(user.get("name"), "google name"),
            profile_url=_optional_string(user.get("picture"), "google picture"),
        )
    if provider == "naver":
        response = _mapping(user.get("response"), "naver response")
        provider_id = response.get("id")
        if not isinstance(provider_id, str) or not provider_id:
            raise InvalidProviderProfile("naver id must be a non-empty string")
        return OAuthProfile(
            provider=provider,
            provider_user_id=provider_id,
            email=_optional_string(response.get("email"), "naver email"),
            email_verified=False,
            name=_optional_string(response.get("name"), "naver name"),
            profile_url=_optional_string(response.get("profile_image"), "naver profile_image"),
        )
    if provider == "kakao":
        provider_id = user.get("id")
        if isinstance(provider_id, bool) or not isinstance(provider_id, str | int):
            raise InvalidProviderProfile("kakao id must be a string or number")
        account_value = user.get("kakao_account")
        account = {} if account_value is None else _mapping(account_value, "kakao account")
        profile_value = account.get("profile")
        profile = {} if profile_value is None else _mapping(profile_value, "kakao profile")
        return OAuthProfile(
            provider=provider,
            provider_user_id=str(provider_id),
            email=_optional_string(account.get("email"), "kakao email"),
            email_verified=False,
            name=_optional_string(profile.get("nickname"), "kakao nickname"),
            profile_url=_optional_string(
                profile.get("profile_image_url"), "kakao profile_image_url"
            ),
        )
    raise InvalidProviderProfile("unsupported OAuth provider")
