"""Injected Phase 4 HTTP service boundary."""

from __future__ import annotations

from typing import Annotated, Protocol, cast

from fastapi import Depends, Request

from wiseacct_sso.application.auth import (
    LoginInput,
    RegisterInput,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.domain.users import CurrentUser


class Phase4Services(Protocol):
    async def enforce_rate_limit(
        self,
        *,
        client_key: str,
        route: str,
        method: str,
        context: RequestAuditContext,
    ) -> int | None: ...

    async def register(self, input: RegisterInput, context: RequestAuditContext) -> None: ...

    async def login(self, input: LoginInput, context: RequestAuditContext) -> TokenPair: ...

    async def refresh(self, refresh_token: str, context: RequestAuditContext) -> TokenPair: ...

    async def logout(self, refresh_token: str, context: RequestAuditContext) -> None: ...

    async def current_user(self, access_token: str) -> CurrentUser: ...


def phase4_services(request: Request) -> Phase4Services:
    return cast(Phase4Services, request.app.state.phase4_services)


InjectedPhase4Services = Annotated[Phase4Services, Depends(phase4_services)]


def audit_context(request: Request) -> RequestAuditContext:
    forwarded = request.headers.get("x-forwarded-for")
    forwarded_address = forwarded.split(",", 1)[0].strip() if forwarded else None
    client_address = request.client.host if request.client is not None else None
    return RequestAuditContext(
        ip_address=forwarded_address or client_address,
        user_agent=request.headers.get("user-agent"),
    )
