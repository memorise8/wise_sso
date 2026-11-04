"""Same-origin employee invitation administration and public password setup."""

import hmac
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from wiseacct_sso.api.routes.admin import AdminActor
from wiseacct_sso.application.invitations import EmployeeInvitationService
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcRoleRequirement

from .app import _form, _require_origin, _required_fields
from .parsing import ParseError

COOKIE = "__Host-wise_invitation_csrf"


class InvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Annotated[str, Field(min_length=3, max_length=320)]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    roles: Annotated[list[OidcRoleRequirement], Field(min_length=1, max_length=32)]


def register_invitation_routes(
    app: FastAPI,
    api: FastAPI,
    service: EmployeeInvitationService,
    origin: str,
    root: Path,
) -> None:
    @api.get("/invitations")
    async def list_invitations(actor: AdminActor) -> dict[str, object]:
        return {"items": await service.list_invitations(actor)}

    @api.post("/invitations", status_code=201)
    async def create(body: InvitationBody, actor: AdminActor) -> dict[str, str]:
        identifier = await service.create(
            actor, body.email, body.name, [r.model_dump(by_alias=True) for r in body.roles]
        )
        return {"id": identifier}

    @api.post("/invitations/{identifier}/resend", status_code=204)
    async def resend(identifier: str, actor: AdminActor) -> Response:
        await service.resend(actor, identifier)
        return Response(status_code=204)

    @api.post("/invitations/{identifier}/cancel", status_code=204)
    async def cancel(identifier: str, actor: AdminActor) -> Response:
        await service.cancel(actor, identifier)
        return Response(status_code=204)

    @app.get("/oauth2/invitations/accept", include_in_schema=False)
    async def form() -> Response:
        csrf = secrets.token_urlsafe(32)
        page = (root / "employee-invitation.html").read_text().replace("__INVITATION_CSRF__", csrf)
        response = HTMLResponse(page, headers={"cache-control": "no-store"})
        response.set_cookie(
            COOKIE, csrf, secure=True, httponly=True, samesite="lax", path="/", max_age=1800
        )
        return response

    @app.post("/oauth2/invitations/accept", include_in_schema=False)
    async def accept(request: Request) -> Response:
        try:
            _require_origin(request, origin)
            data = _required_fields(
                await _form(request, allowed=frozenset({"token", "password", "csrf_token"})),
                ("token", "password", "csrf_token"),
            )
            csrf = request.cookies.get(COOKIE, "")
            if (
                not csrf
                or not csrf.isascii()
                or not data["csrf_token"].isascii()
                or not hmac.compare_digest(csrf, data["csrf_token"])
            ):
                raise ParseError("Invalid CSRF")
            if len(data["password"]) > 1024:
                raise ParseError("Invalid password")
            await service.accept(data["token"], data["password"])
        except ParseError:
            return Response("Invalid request", status_code=400)
        except DomainError as error:
            return Response(error.code, status_code=error.status_code)
        response = Response(
            "Employee account activated. Return to your approved service to log in."
        )
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response
