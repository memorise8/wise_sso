"""Express-compatible Phase 4 direct password authentication routes."""

from __future__ import annotations

import re
from typing import Literal, Self
from urllib.parse import urlsplit

from fastapi import APIRouter, Body, Request, Response
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from wiseacct_sso.api.dependencies import (
    InjectedPhase4Services,
    InjectedPhase5Services,
    audit_context,
)
from wiseacct_sso.api.errors import ExpressJsonResponse, PublicHttpError
from wiseacct_sso.application.auth import (
    AuthHandoffExchangeInput,
    LoginInput,
    RegisterInput,
    TokenPair,
)
from wiseacct_sso.domain.oauth import ClientHandoff, javascript_string_length
from wiseacct_sso.domain.users import DomainError

_EMAIL = re.compile(
    r"^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-.]*)[A-Z0-9_+\-]@"
    r"([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$",
    re.IGNORECASE | re.ASCII,
)
_ABSOLUTE_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_HOST_REQUIRED_SCHEMES = frozenset({"ftp", "http", "https", "ws", "wss"})
_WHATWG_EDGE_WHITESPACE = "".join(chr(value) for value in range(0x21))


def _valid_url_hostname(hostname: str | None) -> bool:
    return (
        hostname is not None
        and bool(hostname)
        and not any(
            character.isspace() or ord(character) <= 0x20 or 0xD800 <= ord(character) <= 0xDFFF
            for character in hostname
        )
    )


def _contains_bounded_url_invalid_character(value: str) -> bool:
    return any(
        character.isspace() or ord(character) <= 0x20 or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


def _is_absolute_zod_url(value: str) -> bool:
    """Bounded WHATWG-URL equivalent for the public handoff validation surface."""

    normalized = value.strip(_WHATWG_EDGE_WHITESPACE)
    match = _ABSOLUTE_URL_SCHEME.match(normalized)
    if match is None:
        return False
    scheme = normalized[: match.end() - 1].lower()
    try:
        parsed = urlsplit(normalized)
        _ = parsed.port
    except ValueError:
        return False
    remainder = normalized[match.end() :]
    if scheme == "file":
        if not remainder.startswith("//") or remainder == "///":
            return not _contains_bounded_url_invalid_character(remainder)
        authority = remainder[2:].split("/", 1)[0]
        return not authority or _valid_url_hostname(authority)
    if scheme not in _HOST_REQUIRED_SCHEMES:
        if _contains_bounded_url_invalid_character(remainder):
            return False
        if not remainder.startswith("//") or remainder == "//":
            return True
        return _valid_url_hostname(parsed.hostname)
    if parsed.hostname is None:
        repaired_remainder = remainder.lstrip("/")
        if not repaired_remainder:
            return False
        try:
            repaired = urlsplit(f"{scheme}://{repaired_remainder}")
            _ = repaired.port
        except ValueError:
            return False
        hostname = repaired.hostname
    else:
        hostname = parsed.hostname
    return _valid_url_hostname(hostname)


class _Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    email: str
    password: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_email(self) -> Self:
        if _EMAIL.fullmatch(self.email) is None:
            raise ValueError("invalid email")
        return self


class RegisterBody(_Credentials):
    model_config = ConfigDict(extra="ignore")
    name: str | None = Field(default=None, min_length=1)


class LoginBody(_Credentials):
    model_config = ConfigDict(extra="forbid", validate_by_alias=True, validate_by_name=False)

    client_id: str | None = Field(default=None, min_length=1, alias="clientId")
    redirect_uri: str | None = Field(default=None, min_length=1, alias="redirectUri")
    state: str | None = Field(default=None, min_length=1)
    code_challenge: str | None = Field(
        default=None, min_length=43, max_length=128, alias="codeChallenge"
    )
    code_challenge_method: Literal["S256"] | None = Field(default=None, alias="codeChallengeMethod")

    @model_validator(mode="after")
    def validate_handoff(self) -> Self:
        values = (
            self.client_id,
            self.redirect_uri,
            self.state,
            self.code_challenge,
            self.code_challenge_method,
        )
        if any(value is not None for value in values):
            required = (
                self.client_id,
                self.redirect_uri,
                self.code_challenge,
                self.code_challenge_method,
            )
            if not all(value is not None for value in required):
                raise ValueError("incomplete SSO handoff")
        if (
            self.code_challenge is not None
            and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", self.code_challenge) is None
        ):
            raise ValueError("invalid PKCE challenge")
        if self.state is not None and javascript_string_length(self.state) > 512:
            raise ValueError("state exceeds 512 UTF-16 code units")
        if self.redirect_uri is not None and not _is_absolute_zod_url(self.redirect_uri):
            raise ValueError("invalid redirect URL")
        return self

    @property
    def is_handoff(self) -> bool:
        return self.client_id is not None


class RefreshBody(BaseModel):
    refresh_token: str = Field(min_length=1, alias="refreshToken")


class EmailBody(BaseModel):
    email: str

    @model_validator(mode="after")
    def validate_email(self) -> Self:
        if _EMAIL.fullmatch(self.email) is None:
            raise ValueError("invalid email")
        return self


class PasswordResetConfirmBody(BaseModel):
    token: str = Field(min_length=1)
    password: str = Field(min_length=1)


class EmailVerificationRequestBody(EmailBody):
    model_config = ConfigDict(extra="forbid", validate_by_alias=True, validate_by_name=False)

    client_id: str | None = Field(default=None, min_length=1, alias="clientId")
    redirect_uri: str | None = Field(default=None, min_length=1, alias="redirectUri")
    state: str | None = Field(default=None, min_length=1)
    code_challenge: str | None = Field(
        default=None, min_length=43, max_length=128, alias="codeChallenge"
    )
    code_challenge_method: Literal["S256"] | None = Field(default=None, alias="codeChallengeMethod")

    @model_validator(mode="after")
    def validate_handoff(self) -> Self:
        values = (
            self.client_id,
            self.redirect_uri,
            self.state,
            self.code_challenge,
            self.code_challenge_method,
        )
        if any(value is not None for value in values):
            required = (
                self.client_id,
                self.redirect_uri,
                self.code_challenge,
                self.code_challenge_method,
            )
            if not all(value is not None for value in required):
                raise ValueError("incomplete SSO handoff")
        if (
            self.code_challenge is not None
            and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", self.code_challenge) is None
        ):
            raise ValueError("invalid PKCE challenge")
        if self.state is not None and javascript_string_length(self.state) > 512:
            raise ValueError("state exceeds 512 UTF-16 code units")
        if self.redirect_uri is not None and not _is_absolute_zod_url(self.redirect_uri):
            raise ValueError("invalid redirect URL")
        return self

    @property
    def is_handoff(self) -> bool:
        return self.client_id is not None


class EmailVerificationConfirmBody(BaseModel):
    token: str = Field(min_length=1)


class AuthExchangeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1, alias="clientId")
    redirect_uri: str = Field(min_length=1, alias="redirectUri")
    code: str = Field(min_length=1)
    code_verifier: str = Field(min_length=1, alias="codeVerifier")

    @model_validator(mode="after")
    def validate_redirect_uri(self) -> Self:
        if not _is_absolute_zod_url(self.redirect_uri):
            raise ValueError("invalid redirect URL")
        return self


_AUTH_EXCHANGE_BODY = TypeAdapter(AuthExchangeBody)


def _raise_public(error: DomainError) -> None:
    raise PublicHttpError(error.status_code, error.code, error.message) from None


def _tokens(pair: TokenPair) -> ExpressJsonResponse:
    return ExpressJsonResponse(
        content={
            "accessToken": pair.access_token,
            "refreshToken": pair.refresh_token,
        }
    )


def _handoff(
    request: Request,
    *,
    client_id: str | None,
    redirect_uri: str | None,
    state: str | None,
    code_challenge: str | None,
    code_challenge_method: Literal["S256"] | None,
) -> ClientHandoff:
    if (
        client_id is None
        or redirect_uri is None
        or code_challenge is None
        or code_challenge_method is None
    ):
        raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request")
    client = next(
        (
            candidate
            for candidate in request.app.state.settings.auth_clients
            if candidate.client_id == client_id
        ),
        None,
    )
    if client is None or redirect_uri not in client.allowed_redirect_uris:
        raise PublicHttpError(400, "INVALID_CLIENT_REDIRECT_URI", "Invalid request")
    return ClientHandoff(
        client_id=client.client_id,
        audience=client.audience,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )


def build_auth_router() -> APIRouter:
    router = APIRouter(prefix="/auth")

    async def options() -> Response:
        return Response(
            content="POST",
            media_type="text/html",
            headers={
                "allow": "POST",
                "etag": 'W/"4-Yf+Bwwqjx254r+pisuO9HfpJ6FQ"',
            },
        )

    router.add_api_route("/register", options, methods=["OPTIONS"], include_in_schema=False)
    router.add_api_route("/login", options, methods=["OPTIONS"], include_in_schema=False)
    router.add_api_route("/refresh", options, methods=["OPTIONS"], include_in_schema=False)
    router.add_api_route("/logout", options, methods=["OPTIONS"], include_in_schema=False)
    router.add_api_route("/exchange", options, methods=["OPTIONS"], include_in_schema=False)
    router.add_api_route(
        "/password-reset/request", options, methods=["OPTIONS"], include_in_schema=False
    )
    router.add_api_route(
        "/password-reset/confirm", options, methods=["OPTIONS"], include_in_schema=False
    )
    router.add_api_route(
        "/email-verification/request", options, methods=["OPTIONS"], include_in_schema=False
    )
    router.add_api_route(
        "/email-verification/confirm", options, methods=["OPTIONS"], include_in_schema=False
    )

    @router.post("/register", status_code=202)
    async def register(
        body: RegisterBody,
        request: Request,
        services: InjectedPhase4Services,
    ) -> ExpressJsonResponse:
        try:
            await services.register(
                RegisterInput(email=body.email, password=body.password, name=body.name),
                audit_context(request),
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(status_code=202, content={"status": "accepted"})

    @router.post("/login")
    async def login(
        body: LoginBody,
        request: Request,
        services: InjectedPhase5Services,
    ) -> ExpressJsonResponse:
        if body.is_handoff and not hasattr(services, "exchange_auth_handoff"):
            raise PublicHttpError(
                503,
                "AUTH_HANDOFF_UNAVAILABLE",
                "Authentication handoff is not available",
            )
        handoff = None
        if body.is_handoff:
            handoff = _handoff(
                request,
                client_id=body.client_id,
                redirect_uri=body.redirect_uri,
                state=body.state,
                code_challenge=body.code_challenge,
                code_challenge_method=body.code_challenge_method,
            )
        try:
            if handoff is None:
                pair = await services.login(
                    LoginInput(email=body.email, password=body.password), audit_context(request)
                )
                return _tokens(pair)
            redirect_url = await services.login(
                LoginInput(email=body.email, password=body.password),
                audit_context(request),
                handoff,
            )
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(content={"redirectUrl": redirect_url})

    @router.post("/refresh")
    async def refresh(
        body: RefreshBody,
        request: Request,
        services: InjectedPhase4Services,
    ) -> ExpressJsonResponse:
        try:
            pair = await services.refresh(body.refresh_token, audit_context(request))
        except DomainError as error:
            _raise_public(error)
        return _tokens(pair)

    @router.post("/logout", status_code=204)
    async def logout(
        body: RefreshBody,
        request: Request,
        services: InjectedPhase4Services,
    ) -> Response:
        try:
            await services.logout(body.refresh_token, audit_context(request))
        except DomainError as error:
            _raise_public(error)
        return Response(status_code=204)

    @router.post("/password-reset/request", status_code=202)
    async def request_password_reset(
        body: EmailBody,
        request: Request,
        services: InjectedPhase5Services,
    ) -> ExpressJsonResponse:
        try:
            await services.request_password_reset(body.email, audit_context(request))
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(status_code=202, content={"status": "accepted"})

    @router.post("/password-reset/confirm", status_code=204)
    async def confirm_password_reset(
        body: PasswordResetConfirmBody,
        request: Request,
        services: InjectedPhase5Services,
    ) -> Response:
        try:
            await services.confirm_password_reset(body.token, body.password, audit_context(request))
        except DomainError as error:
            _raise_public(error)
        return Response(status_code=204)

    @router.post("/email-verification/request", status_code=202)
    async def request_email_verification(
        body: EmailVerificationRequestBody,
        request: Request,
        services: InjectedPhase5Services,
    ) -> ExpressJsonResponse:
        handoff = None
        if body.is_handoff:
            handoff = _handoff(
                request,
                client_id=body.client_id,
                redirect_uri=body.redirect_uri,
                state=body.state,
                code_challenge=body.code_challenge,
                code_challenge_method=body.code_challenge_method,
            )
        try:
            await services.request_email_verification(body.email, audit_context(request), handoff)
        except DomainError as error:
            _raise_public(error)
        return ExpressJsonResponse(status_code=202, content={"status": "accepted"})

    @router.post("/email-verification/confirm")
    async def confirm_email_verification(
        body: EmailVerificationConfirmBody,
        request: Request,
        services: InjectedPhase5Services,
    ) -> ExpressJsonResponse:
        try:
            result = await services.confirm_email_verification(body.token, audit_context(request))
        except DomainError as error:
            _raise_public(error)
        content: dict[str, str] = {"status": result.status}
        if result.redirect_url is not None:
            content["redirectUrl"] = result.redirect_url
        return ExpressJsonResponse(content=content)

    @router.post("/exchange")
    async def exchange_auth_handoff(
        request: Request,
        services: InjectedPhase5Services,
        raw_body: object | None = Body(default=None),
    ) -> ExpressJsonResponse:
        try:
            body = _AUTH_EXCHANGE_BODY.validate_python(raw_body)
        except ValidationError:
            try:
                await services.invalid_auth_handoff_exchange(audit_context(request))
            except DomainError as error:
                _raise_public(error)
            raise RuntimeError("Invalid handoff exchange handler returned unexpectedly") from None
        try:
            pair = await services.exchange_auth_handoff(
                AuthHandoffExchangeInput(
                    client_id=body.client_id,
                    redirect_uri=body.redirect_uri,
                    code=body.code,
                    code_verifier=body.code_verifier,
                ),
                audit_context(request),
            )
        except DomainError as error:
            _raise_public(error)
        return _tokens(pair)

    return router
