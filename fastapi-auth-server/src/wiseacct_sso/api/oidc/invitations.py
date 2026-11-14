"""Same-origin employee/external invitation administration and public password setup."""

import hmac
import secrets
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from wiseacct_sso.api.errors import error_response
from wiseacct_sso.api.routes.admin import AdminActor
from wiseacct_sso.application.external_accounts import ExternalAccountService
from wiseacct_sso.application.invitations import EmployeeInvitationService, IssuedInvitation
from wiseacct_sso.application.service_invitations import allowed_return_to
from wiseacct_sso.domain.external_accounts import MAX_EXTERNAL_ACCOUNT_DAYS
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcRoleRequirement

from .app import _form, _require_origin, _required_fields
from .parsing import ParseError

COOKIE = "__Host-wise_invitation_csrf"


Delivery = Literal["mail", "link"]
TermDays = Annotated[int, Field(strict=True, ge=1, le=MAX_EXTERNAL_ACCOUNT_DAYS)]
Reason = Annotated[str, Field(min_length=1, max_length=128)]


class InvitationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Annotated[str, Field(min_length=3, max_length=320)]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    roles: Annotated[list[OidcRoleRequirement], Field(min_length=1, max_length=32)]
    delivery: Delivery = "mail"


class ResendBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    delivery: Delivery = "mail"


class ExternalAccountBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: Annotated[str, Field(min_length=3, max_length=320)]
    name: Annotated[str, Field(min_length=1, max_length=200)]
    days: TermDays
    roles: Annotated[list[OidcRoleRequirement], Field(max_length=32)] = []
    delivery: Delivery = "link"


class ExtendBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    days: TermDays
    reason: Reason


class BulkExtendBody(ExtendBody):
    user_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(min_length=1, max_length=100, alias="userIds"),
    ]


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Reason


class ExternalMemoBody(ReasonBody):
    company: Annotated[str, Field(max_length=200)]
    project: Annotated[str, Field(max_length=200)]


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat(timespec="milliseconds") + "Z"


def _issued(result: IssuedInvitation) -> dict[str, str | None]:
    return {
        "id": result.id,
        "invitationUrl": result.url,
        "accountExpiresAt": _iso(result.account_expires_at),
    }


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

    external = ExternalAccountService(database=service.database, admin=service.admin)

    @api.exception_handler(DomainError)
    async def domain_error(_request: Request, error: DomainError) -> Response:
        # Duplicate accounts, closed invitations and term/role rules are client errors.
        return error_response(error.status_code, error.code, error.message)

    @api.post("/invitations", status_code=201)
    async def create(body: InvitationBody, actor: AdminActor) -> dict[str, str | None]:
        return _issued(
            await service.create(
                actor,
                body.email,
                body.name,
                [r.model_dump(by_alias=True) for r in body.roles],
                delivery=body.delivery,
            )
        )

    @api.post("/invitations/{identifier}/resend")
    async def resend(
        identifier: str, actor: AdminActor, body: ResendBody | None = None
    ) -> dict[str, str | None]:
        delivery = body.delivery if body is not None else "mail"
        return _issued(await service.resend(actor, identifier, delivery))

    @api.get("/external-accounts")
    async def list_external(
        actor: AdminActor,
        page: Annotated[int, Query(ge=1, le=2_147_483_647)] = 1,
        expires_within: Annotated[int | None, Query(alias="expiresWithin")] = None,
    ) -> dict[str, object]:
        return await external.list_accounts(actor, page=page, expires_within=expires_within)

    @api.post("/external-accounts", status_code=201)
    async def create_external(
        body: ExternalAccountBody, actor: AdminActor
    ) -> dict[str, str | None]:
        return _issued(
            await service.create(
                actor,
                body.email,
                body.name,
                [r.model_dump(by_alias=True) for r in body.roles],
                kind="EXTERNAL",
                days=body.days,
                delivery=body.delivery,
            )
        )

    @api.post("/external-accounts/extend-bulk")
    async def extend_bulk(body: BulkExtendBody, actor: AdminActor) -> dict[str, object]:
        extended = await external.extend_many(actor, body.user_ids, body.days, body.reason)
        return {
            "items": [
                {"id": user_id, "accountExpiresAt": _iso(expiry)}
                for user_id, expiry in extended.items()
            ]
        }

    @api.patch("/external-accounts/{user_id}/memo", status_code=204)
    async def update_memo(user_id: str, body: ExternalMemoBody, actor: AdminActor) -> Response:
        await external.update_memo(
            actor, user_id, company=body.company, project=body.project, reason=body.reason
        )
        return Response(status_code=204)

    @api.post("/external-accounts/{user_id}/extend")
    async def extend(user_id: str, body: ExtendBody, actor: AdminActor) -> dict[str, str | None]:
        expiry = await external.extend(actor, user_id, body.days, body.reason)
        return {"accountExpiresAt": _iso(expiry)}

    @api.post("/external-accounts/{user_id}/suspend", status_code=204)
    async def suspend(user_id: str, body: ReasonBody, actor: AdminActor) -> Response:
        await external.set_suspended(actor, user_id, True, body.reason)
        return Response(status_code=204)

    @api.post("/external-accounts/{user_id}/reactivate", status_code=204)
    async def reactivate(user_id: str, body: ReasonBody, actor: AdminActor) -> Response:
        await external.set_suspended(actor, user_id, False, body.reason)
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
            return_to = await service.accept(data["token"], data["password"])
        except ParseError:
            return Response("Invalid request", status_code=400)
        except DomainError as error:
            return Response(error.code, status_code=error.status_code)
        response: Response
        if return_to is None or not allowed_return_to(return_to, service.return_to_prefixes):
            response = Response("Account activated. Return to your approved service to log in.")
        elif "application/json" in request.headers.get("accept", ""):
            # The accept page posts with fetch, which cannot follow a cross-site redirect.
            response = JSONResponse({"returnTo": return_to})
        else:
            response = RedirectResponse(return_to, status_code=303)
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="lax", path="/")
        return response
