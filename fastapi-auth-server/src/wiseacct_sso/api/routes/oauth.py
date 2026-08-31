"""Express-compatible OAuth start and callback HTTP routes."""

from __future__ import annotations

import re
from typing import Literal, Self
from urllib.parse import quote

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, model_validator

from wiseacct_sso.api.dependencies import InjectedPhase5Services, audit_context
from wiseacct_sso.api.errors import PublicHttpError
from wiseacct_sso.api.routes.auth import _is_absolute_zod_url
from wiseacct_sso.application.auth import OAuthStartInput
from wiseacct_sso.domain.oauth import OAUTH_PROVIDERS, OAuthProvider, javascript_string_length
from wiseacct_sso.domain.users import DomainError


class OAuthStartQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(default="temis", min_length=1)
    redirect_uri: str | None = Field(default=None, min_length=1)
    state: str | None = Field(default=None, min_length=1)
    code_challenge: str = Field(min_length=43, max_length=128)
    code_challenge_method: Literal["S256"] = "S256"

    @model_validator(mode="after")
    def validate_query(self) -> Self:
        if re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", self.code_challenge) is None:
            raise ValueError("invalid PKCE challenge")
        if self.state is not None and javascript_string_length(self.state) > 512:
            raise ValueError("state exceeds 512 UTF-16 code units")
        if self.redirect_uri is not None and not _is_absolute_zod_url(self.redirect_uri):
            raise ValueError("invalid redirect URL")
        return self


_OAUTH_START_QUERY = TypeAdapter(OAuthStartQuery)


def _raise_public(error: DomainError) -> None:
    raise PublicHttpError(error.status_code, error.code, error.message) from None


def _start_query(request: Request) -> OAuthStartQuery:
    if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params):
        raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request")
    try:
        return _OAUTH_START_QUERY.validate_python(dict(request.query_params))
    except ValidationError:
        raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request") from None


def _redirect_media_type(accept: str | None) -> Literal["text", "html"] | None:
    accepted: list[tuple[str, str, float, int]] = []
    for index, item in enumerate(("*/*" if accept is None else accept).split(",")):
        parts = [part.strip() for part in item.split(";")]
        media = parts[0].lower()
        if "/" not in media:
            continue
        media_type, media_subtype = media.split("/", 1)
        quality = 1.0
        has_media_parameter = False
        for parameter in parts[1:]:
            name, separator, value = parameter.partition("=")
            if not separator:
                has_media_parameter = True
                continue
            if name.strip().lower() == "q":
                try:
                    quality = float(value.strip().strip('"'))
                except ValueError:
                    quality = 0.0
                break
            has_media_parameter = True
        if has_media_parameter:
            continue
        accepted.append((media_type, media_subtype, quality, index))

    priorities: list[tuple[float, int, int, int, Literal["text", "html"]]] = []
    provided: tuple[tuple[Literal["text", "html"], str], ...] = (
        ("text", "plain"),
        ("html", "html"),
    )
    for provided_index, (name, subtype) in enumerate(provided):
        best = (0.0, -1, -1)
        for media_type, media_subtype, quality, accept_index in accepted:
            if media_type not in {"*", "text"} or media_subtype not in {"*", subtype}:
                continue
            specificity = (4 if media_type == "text" else 0) | (
                2 if media_subtype == subtype else 0
            )
            if (specificity, quality, accept_index) > (best[1], best[0], best[2]):
                best = (quality, specificity, accept_index)
        if best[0] > 0:
            priorities.append((best[0], best[1], -best[2], -provided_index, name))
    if not priorities:
        return None
    return max(priorities)[4]


def _escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _express_redirect(request: Request, url: str) -> Response:
    location = quote(url, safe=":/%#?=@[]!$&'()*+,;")
    selected = _redirect_media_type(request.headers.get("accept"))
    if selected == "html":
        body = f"<p>Found. Redirecting to {_escape_html(location)}</p>".encode()
        media_type = "text/html"
    elif selected == "text":
        body = f"Found. Redirecting to {location}".encode()
        media_type = "text/plain"
    else:
        body = b""
        media_type = None
    response = Response(
        content=b"" if request.method == "HEAD" else body,
        status_code=302,
        headers={"location": location, "vary": "Accept"},
        media_type=media_type,
    )
    response.headers["content-length"] = str(len(body))
    return response


def build_oauth_router() -> APIRouter:
    router = APIRouter(prefix="/auth")

    async def options() -> Response:
        return Response(
            content="GET,HEAD",
            media_type="text/html",
            headers={
                "allow": "GET,HEAD",
                "etag": 'W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"',
            },
        )

    for provider in OAUTH_PROVIDERS:
        router.add_api_route(f"/{provider}", options, methods=["OPTIONS"], include_in_schema=False)
        router.add_api_route(
            f"/{provider}/callback", options, methods=["OPTIONS"], include_in_schema=False
        )

    def add_provider_routes(provider: OAuthProvider) -> None:
        async def start(
            request: Request,
            services: InjectedPhase5Services,
        ) -> Response:
            query = _start_query(request)
            try:
                authorization_url = await services.oauth_start(
                    provider,
                    OAuthStartInput(
                        client_id=query.client_id,
                        redirect_uri=query.redirect_uri,
                        caller_state=query.state,
                        code_challenge=query.code_challenge,
                        code_challenge_method=query.code_challenge_method,
                    ),
                )
            except DomainError as error:
                _raise_public(error)
            return _express_redirect(request, authorization_url)

        async def callback(
            request: Request,
            services: InjectedPhase5Services,
        ) -> Response:
            context = audit_context(request)
            provider_errors = request.query_params.getlist("error")
            if len(provider_errors) > 1 or (provider_errors and provider_errors[0]):
                try:
                    await services.oauth_provider_error(provider, context)
                except DomainError as error:
                    _raise_public(error)
                raise RuntimeError("OAuth provider error handler returned unexpectedly")

            code_values = request.query_params.getlist("code")
            state_values = request.query_params.getlist("state")
            if len(code_values) != 1 or not code_values[0]:
                raise PublicHttpError(400, "INVALID_REQUEST", "Invalid request")
            if len(state_values) != 1 or not state_values[0]:
                raise PublicHttpError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state")
            try:
                result = await services.oauth_callback(
                    provider, code_values[0], state_values[0], context
                )
            except DomainError as error:
                _raise_public(error)
            return _express_redirect(request, result.redirect_url)

        router.add_api_route(
            f"/{provider}",
            start,
            methods=["GET", "HEAD"],
            name=f"{provider}_oauth_start",
        )
        router.add_api_route(
            f"/{provider}/callback",
            callback,
            methods=["GET", "HEAD"],
            name=f"{provider}_oauth_callback",
        )

    for provider in OAUTH_PROVIDERS:
        add_provider_routes(provider)

    return router
