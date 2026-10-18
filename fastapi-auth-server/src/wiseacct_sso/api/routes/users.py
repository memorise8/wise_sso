"""Authenticated current-user route."""

from fastapi import APIRouter, Header, Response

from wiseacct_sso.api.dependencies import InjectedPhase4Services
from wiseacct_sso.api.errors import ExpressJsonResponse, PublicHttpError
from wiseacct_sso.domain.users import CurrentUser, DomainError


def _bearer(authorization: str | None) -> str:
    parts = authorization.split(" ") if authorization is not None else []
    if len(parts) < 2 or parts[0] != "Bearer" or not parts[1]:
        raise PublicHttpError(401, "UNAUTHORIZED", "Bearer access token is required")
    return parts[1]


def build_users_router() -> APIRouter:
    router = APIRouter(prefix="/users")

    def user_response(user: CurrentUser) -> ExpressJsonResponse:
        return ExpressJsonResponse(
            content={
                "id": user.id,
                "email": user.email,
                "email_verified": user.email_verified,
                "name": user.name,
                "roles": [
                    {"serviceKey": role.service_key, "name": role.name} for role in user.roles
                ],
            }
        )

    async def resolve_current_user(
        services: InjectedPhase4Services, authorization: str | None
    ) -> CurrentUser:
        try:
            return await services.current_user(_bearer(authorization))
        except DomainError as error:
            raise PublicHttpError(error.status_code, error.code, error.message) from None

    @router.get("/me")
    async def me(
        services: InjectedPhase4Services,
        authorization: str | None = Header(default=None),
    ) -> ExpressJsonResponse:
        user = await resolve_current_user(services, authorization)
        return user_response(user)

    @router.head("/me")
    async def head_me(
        services: InjectedPhase4Services,
        authorization: str | None = Header(default=None),
    ) -> ExpressJsonResponse:
        user = await resolve_current_user(services, authorization)
        return user_response(user)

    @router.options("/me")
    async def options_me() -> Response:
        return Response(
            content="GET,HEAD",
            media_type="text/html",
            headers={
                "allow": "GET,HEAD",
                "etag": 'W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"',
            },
        )

    return router
