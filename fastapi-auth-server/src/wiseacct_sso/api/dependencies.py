"""Injected Phase 4 HTTP service boundary."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Never, Protocol, cast, overload

from fastapi import Depends, Request

from wiseacct_sso.application.admin import (
    AssignRoleResult,
    RemoveRoleResult,
    RevokeSessionsResult,
    SetUserStatusResult,
)
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
from wiseacct_sso.domain.admin import (
    AdminAuditLogPage,
    AdminRoleProfile,
    AdminUserListInput,
    AdminUserPage,
    AuditLogListInput,
)
from wiseacct_sso.domain.oauth import ClientHandoff, OAuthProvider
from wiseacct_sso.domain.password_reset import PasswordResetAccepted, PasswordResetConfirmed
from wiseacct_sso.domain.users import CurrentUser, UserStatus
from wiseacct_sso.domain.verification import VerificationAccepted

MAX_AUDIT_IP_ADDRESS_LENGTH = 255
MAX_AUDIT_USER_AGENT_LENGTH = 512


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


class Phase6Services(Protocol):
    """Administrator HTTP boundary backed by the Phase 6 application service."""

    async def authenticate_admin(self, access_token: str, *, route: str, method: str) -> str: ...

    async def list_users(self, input: AdminUserListInput) -> AdminUserPage: ...

    async def list_audit_logs(self, input: AuditLogListInput) -> AdminAuditLogPage: ...

    async def find_role_by_id(self, role_id: str) -> AdminRoleProfile | None: ...

    async def set_user_status(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        status: str | UserStatus,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> SetUserStatusResult: ...

    async def assign_role(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        service_key: str,
        name: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
    ) -> AssignRoleResult: ...

    async def remove_role(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        service_key: str,
        name: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> RemoveRoleResult: ...

    async def revoke_sessions(
        self,
        *,
        actor_user_id: str,
        target_user_id: str,
        reason_code: str,
        details: Mapping[str, object] | None = None,
        now: datetime | None = None,
    ) -> RevokeSessionsResult: ...


def phase6_services(request: Request) -> Phase6Services:
    return cast(Phase6Services, request.app.state.phase6_services)


InjectedPhase6Services = Annotated[Phase6Services, Depends(phase6_services)]


def _bounded_audit_value(value: str | None, *, limit: int, truncate: bool) -> str | None:
    if value is None or any(
        ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
    ):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] if truncate else None


def request_audit_context(
    *,
    forwarded_for: str | None,
    user_agent: str | None,
    client_address: str | None,
) -> RequestAuditContext:
    """Build bounded audit metadata without deciding which proxies are trustworthy.

    The first X-Forwarded-For hop matches the frozen application contract. Canonical
    trusted-proxy selection remains an external ingress/refreeze prerequisite; this
    helper must not expand trust or use forwarded data as a rate-limit identity.
    """

    forwarded_candidate = forwarded_for.split(",", 1)[0] if forwarded_for else None
    forwarded_address = _bounded_audit_value(
        forwarded_candidate,
        limit=MAX_AUDIT_IP_ADDRESS_LENGTH,
        truncate=False,
    )
    socket_address = _bounded_audit_value(
        client_address,
        limit=MAX_AUDIT_IP_ADDRESS_LENGTH,
        truncate=False,
    )
    return RequestAuditContext(
        ip_address=forwarded_address or socket_address,
        user_agent=_bounded_audit_value(
            user_agent,
            limit=MAX_AUDIT_USER_AGENT_LENGTH,
            truncate=True,
        ),
    )


def audit_context(request: Request) -> RequestAuditContext:
    return request_audit_context(
        forwarded_for=request.headers.get("x-forwarded-for"),
        user_agent=request.headers.get("user-agent"),
        client_address=request.client.host if request.client is not None else None,
    )
