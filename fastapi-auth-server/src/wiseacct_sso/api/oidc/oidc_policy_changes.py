"""관리자 전용 서비스 접근 정책 요청·승인 API."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from fastapi import FastAPI, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy

Actor = Callable[[Request], Awaitable[str]]
Page = Annotated[int, Query(ge=1, le=2_147_483_647)]
PageSize = Annotated[int, Query(alias="pageSize", ge=1, le=100)]


class PolicyReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    reason_code: str = Field(alias="reasonCode", min_length=1, max_length=128)


class RequestPolicyBody(PolicyReasonBody):
    expected_version: int = Field(alias="expectedVersion", ge=1, strict=True)
    proposed: EditableOidcPolicy | None = None
    rollback_to_version: int | None = Field(
        default=None, alias="rollbackToVersion", ge=1, strict=True
    )

    @model_validator(mode="after")
    def validate_change(self) -> Self:
        if (self.proposed is None) == (self.rollback_to_version is None):
            raise ValueError("변경 정책 또는 되돌릴 버전 중 하나를 지정하세요.")
        return self


class DecidePolicyBody(PolicyReasonBody):
    decision: Literal["APPROVE", "REJECT"]


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _response(payload: dict[str, object], *, status: int = 200) -> JSONResponse:
    return JSONResponse(
        jsonable_encoder(payload, custom_encoder={datetime: _utc}),
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


def register_oidc_policy_routes(
    api: FastAPI,
    *,
    services: Phase6Services,
    actor: Actor,
    client_ids: tuple[str, ...],
) -> None:
    @api.get("/clients/{client_id}/policy", include_in_schema=False)
    async def current_policy(request: Request, client_id: str) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.oidc_policy_change_service(client_ids=client_ids).current(
            actor_id=actor_id, client_id=client_id
        )
        return _response(result)

    @api.get("/clients/{client_id}/policy-changes", include_in_schema=False)
    async def policy_history(
        request: Request,
        client_id: str,
        page: Page = 1,
        page_size: PageSize = 25,
        status: Literal["PENDING", "APPLIED", "REJECTED"] | None = None,
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.oidc_policy_change_service(client_ids=client_ids).history(
            actor_id=actor_id,
            client_id=client_id,
            page=page,
            page_size=page_size,
            status=status,
        )
        return _response(result)

    @api.post("/clients/{client_id}/policy-changes", include_in_schema=False)
    async def request_policy(
        request: Request, client_id: str, body: RequestPolicyBody
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.oidc_policy_change_service(client_ids=client_ids).request(
            actor_id=actor_id,
            client_id=client_id,
            expected_version=body.expected_version,
            proposed=body.proposed,
            rollback_to_version=body.rollback_to_version,
            reason=body.reason_code,
        )
        return _response(result, status=201)

    @api.get("/clients/{client_id}/policy-changes/{request_id}", include_in_schema=False)
    async def get_change(request: Request, client_id: str, request_id: str) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.oidc_policy_change_service(client_ids=client_ids).get(
            actor_id=actor_id, client_id=client_id, request_id=request_id
        )
        return _response(result)

    @api.post(
        "/clients/{client_id}/policy-changes/{request_id}/decision",
        include_in_schema=False,
    )
    async def decide_change(
        request: Request, client_id: str, request_id: str, body: DecidePolicyBody
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.oidc_policy_change_service(client_ids=client_ids).decide(
            actor_id=actor_id,
            client_id=client_id,
            request_id=request_id,
            decision=body.decision,
            reason=body.reason_code,
        )
        return _response(result)
