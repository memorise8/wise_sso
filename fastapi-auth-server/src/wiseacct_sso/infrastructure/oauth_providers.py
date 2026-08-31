"""HTTP boundary for the three OAuth providers used by the Express service."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from wiseacct_sso.config import Settings
from wiseacct_sso.domain.oauth import OAuthProfile, OAuthProvider
from wiseacct_sso.infrastructure.redis import node_utf8_bytes

PROVIDER_HTTP_TIMEOUT_SECONDS: Final = 10.0
FOLLOW_PROVIDER_REDIRECTS: Final = False

_EMAIL = re.compile(
    r"^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-.]*)[A-Z0-9_+\-]@"
    r"([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$",
    re.IGNORECASE | re.ASCII,
)


@dataclass(frozen=True, slots=True)
class OAuthProviderConfig:
    authorize_endpoint: str
    token_endpoint: str
    user_info_endpoint: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str


class OAuthProviderConfigurationError(Exception):
    """Internal configuration error for later application-layer mapping."""

    def __init__(
        self, code: Literal["OAUTH_PROVIDER_DISABLED", "OAUTH_PROVIDER_MISCONFIGURED"], message: str
    ) -> None:
        super().__init__(message)
        self.code = code


class OAuthProviderDisabledError(OAuthProviderConfigurationError):
    def __init__(self, provider: OAuthProvider) -> None:
        super().__init__("OAUTH_PROVIDER_DISABLED", f"OAuth provider is disabled: {provider}")
        self.provider = provider


class OAuthProviderMisconfiguredError(OAuthProviderConfigurationError):
    def __init__(self, setting_name: str) -> None:
        super().__init__("OAUTH_PROVIDER_MISCONFIGURED", f"{setting_name} is not configured")
        self.setting_name = setting_name


class OAuthProviderRequestError(Exception):
    """Base class for failures while calling an OAuth provider."""


class OAuthProviderInfrastructureError(OAuthProviderRequestError):
    """Transport, timeout, non-2xx, or malformed-JSON failure (maps to internal 500)."""


class OAuthProviderInvalidResponseError(OAuthProviderRequestError):
    """Valid JSON that violates the provider schema (maps to 400 INVALID_REQUEST)."""


class OAuthProviderCallbackError(Exception):
    """An explicit provider callback query error (maps to OAUTH_PROVIDER_ERROR)."""

    code: Final = "OAUTH_PROVIDER_ERROR"

    def __init__(self, provider_error: str, description: str | None = None) -> None:
        super().__init__("OAuth provider returned an error")
        self.provider_error = provider_error
        self.description = description


class _TokenResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    access_token: str = Field(min_length=1)


def _reject_explicit_nulls(value: object, optional_fields: frozenset[str]) -> object:
    if isinstance(value, Mapping) and any(
        value.get(field) is None for field in optional_fields if field in value
    ):
        raise ValueError("provider optional fields must be omitted rather than null")
    return value


class _GoogleUser(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    sub: str = Field(min_length=1)
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    picture: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        return _reject_explicit_nulls(
            value, frozenset({"email", "email_verified", "name", "picture"})
        )


class _NaverResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    id: str = Field(min_length=1)
    email: str | None = None
    name: str | None = None
    profile_image: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        return _reject_explicit_nulls(value, frozenset({"email", "name", "profile_image"}))


class _NaverUser(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    response: _NaverResponse


class _KakaoProfile(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    nickname: str | None = None
    profile_image_url: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        return _reject_explicit_nulls(value, frozenset({"nickname", "profile_image_url"}))


class _KakaoAccount(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    email: str | None = None
    profile: _KakaoProfile | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        return _reject_explicit_nulls(value, frozenset({"email", "profile"}))


class _KakaoUser(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    id: str | int | float
    kakao_account: _KakaoAccount | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, value: object) -> object:
        return _reject_explicit_nulls(value, frozenset({"kakao_account"}))


def _required(value: str | None, setting_name: str) -> str:
    if not value:
        raise OAuthProviderMisconfiguredError(setting_name)
    return value


def provider_config_for(settings: Settings, provider: OAuthProvider) -> OAuthProviderConfig:
    if provider not in settings.oauth_enabled_providers:
        raise OAuthProviderDisabledError(provider)
    if provider == "google":
        return OAuthProviderConfig(
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
            _required(settings.google_client_id, "GOOGLE_CLIENT_ID"),
            _required(settings.google_client_secret, "GOOGLE_CLIENT_SECRET"),
            settings.google_redirect_uri,
            "openid email profile",
        )
    if provider == "naver":
        return OAuthProviderConfig(
            "https://nid.naver.com/oauth2.0/authorize",
            "https://nid.naver.com/oauth2.0/token",
            "https://openapi.naver.com/v1/nid/me",
            _required(settings.naver_client_id, "NAVER_CLIENT_ID"),
            _required(settings.naver_client_secret, "NAVER_CLIENT_SECRET"),
            settings.naver_redirect_uri,
            "email profile",
        )
    return OAuthProviderConfig(
        "https://kauth.kakao.com/oauth/authorize",
        "https://kauth.kakao.com/oauth/token",
        "https://kapi.kakao.com/v2/user/me",
        _required(settings.kakao_client_id, "KAKAO_CLIENT_ID"),
        _required(settings.kakao_client_secret, "KAKAO_CLIENT_SECRET"),
        settings.kakao_redirect_uri,
        "profile_nickname profile_image account_email",
    )


def authorization_url(config: OAuthProviderConfig, state: str) -> str:
    return _url_search_params_set(
        config.authorize_endpoint,
        [
            ("response_type", "code"),
            ("client_id", config.client_id),
            ("redirect_uri", config.redirect_uri),
            ("scope", config.scope),
            ("state", state),
        ],
    )


def _url_search_params_set(url: str, values: list[tuple[str, str]]) -> str:
    """Apply WHATWG URLSearchParams.set ordering and form-encoding semantics."""

    parsed = urlsplit(url)
    had_empty_fragment = url.endswith("#")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in values:
        replaced = False
        updated: list[tuple[str, str]] = []
        for existing_name, existing_value in query:
            if existing_name != name:
                updated.append((existing_name, existing_value))
            elif not replaced:
                updated.append((name, value))
                replaced = True
        if not replaced:
            updated.append((name, value))
        query = updated
    result = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, _form_encode_query(query), parsed.fragment)
    )
    return f"{result}#" if had_empty_fragment else result


def _form_encode_query(query: list[tuple[str, str]]) -> str:
    def component(value: str) -> str:
        encoded = quote_plus(node_utf8_bytes(value), safe="*.-_")
        return encoded.replace("~", "%7E")

    return "&".join(f"{component(name)}={component(value)}" for name, value in query)


def _optional_email(value: str | None) -> str | None:
    if value is not None and _EMAIL.fullmatch(value) is None:
        raise ValueError("invalid provider email")
    return value


def _optional_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid provider profile URL")
    return value


def _javascript_string(value: str | int | float) -> str:
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def normalize_profile(provider: OAuthProvider, raw_user: object) -> OAuthProfile:
    try:
        if provider == "google":
            google_user = _GoogleUser.model_validate(raw_user)
            return OAuthProfile(
                provider,
                google_user.sub,
                _optional_email(google_user.email),
                google_user.email_verified is True,
                google_user.name,
                _optional_url(google_user.picture),
            )
        if provider == "naver":
            naver_user = _NaverUser.model_validate(raw_user).response
            return OAuthProfile(
                provider,
                naver_user.id,
                _optional_email(naver_user.email),
                False,
                naver_user.name,
                _optional_url(naver_user.profile_image),
            )
        kakao_user = _KakaoUser.model_validate(raw_user)
        account = kakao_user.kakao_account
        profile = account.profile if account else None
        return OAuthProfile(
            provider,
            _javascript_string(kakao_user.id),
            _optional_email(account.email if account else None),
            False,
            profile.nickname if profile else None,
            _optional_url(profile.profile_image_url if profile else None),
        )
    except (ValidationError, ValueError) as error:
        raise OAuthProviderInvalidResponseError("OAuth provider profile is invalid") from error


def _provider_json(response: httpx.Response) -> object:
    try:
        return response.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise OAuthProviderInfrastructureError("OAuth provider returned malformed JSON") from error


class OAuthProviderClient:
    """Calls provider endpoints without following redirects.

    Express ky may follow provider redirects. Phase 5 intentionally uses ``False`` to avoid
    forwarding authorization data to an unexpected origin; this is a documented parity gap.
    """

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=PROVIDER_HTTP_TIMEOUT_SECONDS,
            follow_redirects=FOLLOW_PROVIDER_REDIRECTS,
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def fetch_profile(
        self, provider: OAuthProvider, config: OAuthProviderConfig, code: str
    ) -> OAuthProfile:
        try:
            token_response = await self._client.post(
                config.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "redirect_uri": config.redirect_uri,
                    "code": code,
                },
                headers={"content-type": "application/x-www-form-urlencoded"},
                timeout=PROVIDER_HTTP_TIMEOUT_SECONDS,
                follow_redirects=FOLLOW_PROVIDER_REDIRECTS,
            )
            token_response.raise_for_status()
        except httpx.HTTPError as error:
            raise OAuthProviderInfrastructureError("OAuth token request failed") from error
        token_json = _provider_json(token_response)
        try:
            token = _TokenResponse.model_validate(token_json).access_token
        except ValidationError as error:
            raise OAuthProviderInvalidResponseError("OAuth token response is invalid") from error
        try:
            user_response = await self._client.get(
                config.user_info_endpoint,
                headers={"authorization": f"Bearer {token}"},
                timeout=PROVIDER_HTTP_TIMEOUT_SECONDS,
                follow_redirects=FOLLOW_PROVIDER_REDIRECTS,
            )
            user_response.raise_for_status()
        except httpx.HTTPError as error:
            raise OAuthProviderInfrastructureError("OAuth profile request failed") from error
        return normalize_profile(provider, _provider_json(user_response))
