"""쿠키 기반 관리자 전용 권한 점검 API."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Self

from fastapi import FastAPI, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator

from wiseacct_sso.api.dependencies import Phase6Services
from wiseacct_sso.domain.access_reviews import ItemDecision, ReviewDecision

Actor = Callable[[Request], Awaitable[str]]
Page = Annotated[int, Query(ge=1, le=2_147_483_647)]
PageSize = Annotated[int, Query(alias="pageSize", ge=1, le=100)]


class ReviewReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason_code: str = Field(alias="reasonCode", min_length=1, max_length=128)


class StartReviewBody(ReviewReasonBody):
    title: str = Field(min_length=1, max_length=160)
    service_keys: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] | None = Field(
        default=None, alias="serviceKeys", min_length=1, max_length=100
    )


class DecideReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ReviewDecision
    reason_code: str | None = Field(default=None, alias="reasonCode", min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_revoke_reason(self) -> Self:
        if self.decision == "REVOKE" and not (self.reason_code or "").strip():
            raise ValueError("회수 사유를 입력하세요.")
        return self


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


def register_access_review_routes(api: FastAPI, *, services: Phase6Services, actor: Actor) -> None:
    @api.post("/access-reviews", include_in_schema=False)
    async def start_review(request: Request, body: StartReviewBody) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().start(
            actor_id=actor_id,
            title=body.title,
            reason=body.reason_code,
            service_keys=body.service_keys,
        )
        return _response(result, status=201)

    @api.get("/access-reviews", include_in_schema=False)
    async def list_reviews(
        request: Request, page: Page = 1, page_size: PageSize = 25
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().list(
            actor_id=actor_id, page=page, page_size=page_size
        )
        return _response(result)

    @api.get("/access-reviews/{review_id}", include_in_schema=False)
    async def get_review(request: Request, review_id: str) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().get(actor_id=actor_id, review_id=review_id)
        return _response(result)

    @api.get("/access-reviews/{review_id}/items", include_in_schema=False)
    async def list_items(
        request: Request,
        review_id: str,
        page: Page = 1,
        page_size: PageSize = 25,
        decision: ItemDecision | None = None,
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().items(
            actor_id=actor_id,
            review_id=review_id,
            page=page,
            page_size=page_size,
            decision=decision,
        )
        return _response(result)

    @api.post("/access-reviews/{review_id}/items/{item_id}/decision", include_in_schema=False)
    async def decide_item(
        request: Request, review_id: str, item_id: str, body: DecideReviewBody
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().decide(
            actor_id=actor_id,
            review_id=review_id,
            item_id=item_id,
            decision=body.decision,
            reason=body.reason_code,
        )
        return _response(result)

    @api.post("/access-reviews/{review_id}/complete", include_in_schema=False)
    async def complete_review(
        request: Request, review_id: str, body: ReviewReasonBody
    ) -> JSONResponse:
        actor_id = await actor(request)
        result = await services.access_review_service().complete(
            actor_id=actor_id, review_id=review_id, reason=body.reason_code
        )
        return _response(result)
