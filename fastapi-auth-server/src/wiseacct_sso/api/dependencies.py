"""Injected Phase 4 HTTP service boundary."""

from __future__ import annotations

from typing import Annotated, Never, Protocol, cast, overload

from fastapi import Depends, Request

from wiseacct_sso.application.auth import (
    AuthHandoffExchangeInput,
    EmailVerificationResult,
    LoginInput,
    OAuthCallbackResult,
    OAuthStartInput,
    RegisterInput,
    RequestAuditContext,
    TokenPair,
)
from wiseacct_sso.domain.oauth import ClientHandoff, OAuthProvider
from wiseacct_sso.domain.password_reset import PasswordResetAccepted, PasswordResetConfirmed
from wiseacct_sso.domain.users import CurrentUser
from wiseacct_sso.domain.verification import VerificationAccepted


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


class Phase5Services(Protocol):
    """Complete Phase 5 HTTP boundary while Phase 4 injection remains compatible."""

    async def enforce_rate_limit(
        self,
        *,
        client_key: str,
        route: str,
        method: str,
        context: RequestAuditContext,
    ) -> int | None: ...

    async def register(self, input: RegisterInput, context: RequestAuditContext) -> None: ...

    @overload
    async def login(
        self, input: LoginInput, context: RequestAuditContext, handoff: None = None
    ) -> TokenPair: ...

    @overload
    async def login(
        self, input: LoginInput, context: RequestAuditContext, handoff: ClientHandoff
    ) -> str: ...

    async def refresh(self, refresh_token: str, context: RequestAuditContext) -> TokenPair: ...

    async def logout(self, refresh_token: str, context: RequestAuditContext) -> None: ...

    async def current_user(self, access_token: str) -> CurrentUser: ...

    async def request_email_verification(
        self,
        email: str,
        context: RequestAuditContext,
        handoff: ClientHandoff | None = None,
    ) -> VerificationAccepted: ...

    async def confirm_email_verification(
        self, token: str, context: RequestAuditContext
    ) -> EmailVerificationResult: ...

    async def request_password_reset(
        self, email: str, context: RequestAuditContext
    ) -> PasswordResetAccepted: ...

    async def confirm_password_reset(
        self, token: str, password: str, context: RequestAuditContext
    ) -> PasswordResetConfirmed: ...

    async def exchange_auth_handoff(
        self, input: AuthHandoffExchangeInput, context: RequestAuditContext
    ) -> TokenPair: ...

    async def invalid_auth_handoff_exchange(self, context: RequestAuditContext) -> Never: ...

    async def oauth_start(self, provider: OAuthProvider, input: OAuthStartInput) -> str: ...

    async def oauth_provider_error(
        self, provider: OAuthProvider, context: RequestAuditContext
    ) -> Never: ...

    async def oauth_callback(
        self,
        provider: OAuthProvider,
        code: str,
        state: str,
        context: RequestAuditContext,
    ) -> OAuthCallbackResult: ...


def phase5_services(request: Request) -> Phase5Services:
    return cast(Phase5Services, request.app.state.phase4_services)


InjectedPhase5Services = Annotated[Phase5Services, Depends(phase5_services)]


def audit_context(request: Request) -> RequestAuditContext:
    forwarded = request.headers.get("x-forwarded-for")
    forwarded_address = forwarded.split(",", 1)[0].strip() if forwarded else None
    client_address = request.client.host if request.client is not None else None
    return RequestAuditContext(
        ip_address=forwarded_address or client_address,
        user_agent=request.headers.get("user-agent"),
    )
