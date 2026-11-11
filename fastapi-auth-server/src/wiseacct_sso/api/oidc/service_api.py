"""Machine-to-machine endpoints for trusted services (client_credentials bearer tokens)."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from wiseacct_sso.api.errors import error_response
from wiseacct_sso.application.service_clients import ServiceAuthError, ServiceClientAuth
from wiseacct_sso.application.service_invitations import (
    ServiceInvitationRequest,
    ServiceInvitationResult,
    ServiceInvitationService,
)
from wiseacct_sso.domain.users import DomainError

EXTERNAL_INVITE_SCOPE = "external-invite"
MAX_BODY_BYTES = 8_192


class ExternalInvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    email: str = Field(max_length=320)
    days: int
    gitlab: bool
    return_to: str = Field(max_length=2048)
    invited_by: str = Field(max_length=200)
    note: str | None = Field(default=None, max_length=500)


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat(timespec="milliseconds") + "Z"


def _payload(result: ServiceInvitationResult) -> dict[str, str]:
    values = {
        "status": result.status,
        "invitation_id": result.invitation_id,
        "expires_at": _iso(result.expires_at),
        "account_type": result.account_type,
        "account_status": result.account_status,
    }
    return {key: value for key, value in values.items() if value is not None}


def _auth_error(error: ServiceAuthError) -> Response:
    messages = {
        "invalid_token": "A valid service access token is required",
        "insufficient_scope": "The token does not allow this operation",
        "RATE_LIMITED": "Too many requests",
    }
    response = error_response(error.status_code, error.code, messages.get(error.code, error.code))
    if error.status_code in {401, 403}:
        response.headers["www-authenticate"] = (
            f'Bearer error="{error.code}", scope="{EXTERNAL_INVITE_SCOPE}"'
        )
    return response


def register_service_routes(
    app: FastAPI, auth: ServiceClientAuth, invitations: ServiceInvitationService
) -> None:
    @app.post("/oauth2/service/external-invitations", include_in_schema=False)
    async def external_invitations(request: Request) -> Response:
        try:
            caller = await auth.authenticate(
                request.headers.get("authorization"), EXTERNAL_INVITE_SCOPE
            )
        except ServiceAuthError as error:
            return _auth_error(error)
        if request.scope.get("query_string") or not request.headers.get(
            "content-type", ""
        ).startswith("application/json"):
            return error_response(400, "INVALID_REQUEST", "Send a JSON body without a query")
        raw = await request.body()
        try:
            if len(raw) > MAX_BODY_BYTES:
                raise ValueError("body too large")
            body = ExternalInvitationBody.model_validate(json.loads(raw))
        except (ValueError, ValidationError):
            return error_response(400, "INVALID_REQUEST", "Invalid invitation request")
        try:
            result = await invitations.invite(
                caller.client_id,
                ServiceInvitationRequest(
                    email=body.email,
                    days=body.days,
                    gitlab=body.gitlab,
                    return_to=body.return_to,
                    invited_by=body.invited_by,
                    note=body.note,
                ),
            )
        except DomainError as error:
            code = (
                error.code
                if error.status_code != 400 or error.code == "INVALID_RETURN_TO"
                else "INVALID_REQUEST"
            )
            return error_response(error.status_code, code, error.message)
        return JSONResponse(_payload(result), headers={"cache-control": "no-store"})
