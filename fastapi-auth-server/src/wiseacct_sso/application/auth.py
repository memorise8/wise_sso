"""Password, verification, handoff, and OAuth application orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, NoReturn, Protocol, overload
from urllib.parse import parse_qsl, quote_plus, urlsplit, urlunsplit
from uuid import uuid4

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.config import RelyingClientPolicy
from wiseacct_sso.domain.auth import (
    PENDING_PASSWORD_CREDENTIAL_TTL,
    PasswordAuthFailure,
    PasswordAuthReason,
    PasswordPolicy,
    assert_password_policy,
    normalize_email,
)
from wiseacct_sso.domain.oauth import (
    MAX_CALLER_STATE_LENGTH,
    PKCE_CHALLENGE_PATTERN,
    ClientHandoff,
    OAuthProfile,
    OAuthProvider,
    javascript_string_length,
)
from wiseacct_sso.domain.password_reset import (
    PasswordResetAccepted,
    PasswordResetConfirmed,
    assert_reset_password_policy,
    confirm_password_reset,
    issue_password_reset_token,
    normalize_reset_email,
)
from wiseacct_sso.domain.tokens import (
    AccessTokenIdentity,
    IssuedRefreshToken,
    RoleClaim,
    TokenValidationError,
)
from wiseacct_sso.domain.users import CurrentUser, DomainError, Role, UserStatus
from wiseacct_sso.domain.verification import (
    InvalidVerificationTokenError,
    VerificationAccepted,
    VerificationTokenRecord,
    confirm_verification_record,
    issue_verification_token,
    normalize_verification_email,
)
from wiseacct_sso.infrastructure.auth_state import (
    AuthHandoffConsumeInput,
    AuthHandoffCreateInput,
    AuthHandoffStore,
    OAuthStateMetadata,
    OAuthStateStore,
)
from wiseacct_sso.infrastructure.mail import MailService
from wiseacct_sso.infrastructure.oauth_providers import (
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderConfigurationError,
    OAuthProviderInfrastructureError,
    OAuthProviderInvalidResponseError,
    authorization_url,
)
from wiseacct_sso.infrastructure.redis import RedisStateStore, node_utf8_bytes, rate_limit_key
from wiseacct_sso.infrastructure.security import (
    DUMMY_PASSWORD_HASH,
    AsyncPasswordHasher,
    JwtTokenCodec,
    sha256_token,
)
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import UserStatus as PersistenceUserStatus
from wiseacct_sso.persistence.models import application_uuid, utc_now_ms
from wiseacct_sso.persistence.stores import (
    AuditEventInsert,
    AuditStore,
    CurrentUserRecord,
    DefaultRole,
    EmailVerificationStore,
    EmailVerificationTokenInsert,
    FailedLoginStore,
    LogoutStore,
    OAuthIdentityStore,
    OAuthProfileRecord,
    PasswordAuthStore,
    PasswordRegistration,
    PasswordResetStore,
    PasswordResetTokenInsert,
    PendingPasswordUpsert,
    RefreshReplacement,
    RefreshRotationConflict,
    RefreshRotationStore,
    RefreshTokenInsert,
    RefreshTokenRecord,
    TokenIssueStore,
    UserReadStore,
    VerificationHandoff,
)


@dataclass(frozen=True, slots=True)
class RequestAuditContext:
    ip_address: str | None
    user_agent: str | None


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str


@dataclass(frozen=True, slots=True)
class LoginInput:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class RegisterInput(LoginInput):
    name: str | None


@dataclass(frozen=True, slots=True)
class OAuthStartInput:
    client_id: str = "temis"
    redirect_uri: str | None = None
    caller_state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None


@dataclass(frozen=True, slots=True)
class AuthHandoffExchangeInput:
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str


@dataclass(frozen=True, slots=True)
class OAuthCallbackResult:
    redirect_url: str


@dataclass(frozen=True, slots=True)
class EmailVerificationResult:
    user_id: str
    redirect_url: str | None
    status: Literal["verified"] = "verified"


class ProviderConfigResolver(Protocol):
    def __call__(self, provider: OAuthProvider) -> OAuthProviderConfig: ...


DatabaseProvider = Callable[[], Database]
RedisProvider = Callable[[], RedisStateStore]


def _domain_status(status: PersistenceUserStatus) -> UserStatus:
    return UserStatus(status.value)


def _current_user(record: CurrentUserRecord) -> CurrentUser:
    return CurrentUser(
        id=record.id,
        email=record.email,
        email_verified=record.email_verified,
        name=record.name,
        roles=tuple(Role(service_key=role.service_key, name=role.name) for role in record.roles),
    )


def _identity(record: CurrentUserRecord) -> AccessTokenIdentity:
    return AccessTokenIdentity(
        user_id=record.id,
        email=record.email,
        name=record.name,
        email_verified=record.email_verified,
        roles=tuple(
            RoleClaim(service_key=role.service_key, name=role.name) for role in record.roles
        ),
    )


class Phase5AuthService:
    """Concrete runtime service; retryable callbacks contain database effects only."""

    def __init__(
        self,
        *,
        database: DatabaseProvider,
        redis: RedisProvider,
        passwords: AsyncPasswordHasher,
        tokens: JwtTokenCodec,
        password_policy: PasswordPolicy,
        default_audience: str,
        rate_limit_window_seconds: int,
        rate_limit_max_requests: int,
        mail: MailService | None = None,
        verification_url_base: str = "",
        password_reset_url_base: str = "",
        auth_clients: tuple[RelyingClientPolicy, ...] = (),
        provider_config: ProviderConfigResolver | None = None,
        oauth_client: OAuthProviderClient | None = None,
    ) -> None:
        self._database = database
        self._redis = redis
        self._passwords = passwords
        self._tokens = tokens
        self._password_policy = password_policy
        self._default_audience = default_audience
        self._rate_limit_window_seconds = rate_limit_window_seconds
        self._rate_limit_max_requests = rate_limit_max_requests
        self._mail = mail
        self._verification_url_base = verification_url_base
        self._password_reset_url_base = password_reset_url_base
        self._auth_clients = {client.client_id: client for client in auth_clients}
        self._provider_config = provider_config
        self._oauth_client = oauth_client
        self._users = UserReadStore()
        self._password_store = PasswordAuthStore()
        self._failed_logins = FailedLoginStore()
        self._token_issue = TokenIssueStore()
        self._rotation = RefreshRotationStore()
        self._logout = LogoutStore()
        self._audit = AuditStore()
        self._verification = EmailVerificationStore()
        self._password_reset = PasswordResetStore()
        self._oauth_identities = OAuthIdentityStore()

    def bind_oauth_client(self, client: OAuthProviderClient) -> None:
        """Attach one lifespan-owned provider client without silently leaking another."""

        if self._oauth_client is not None and self._oauth_client is not client:
            raise RuntimeError("OAuth provider client is already bound")
        self._oauth_client = client

    def unbind_oauth_client(self, client: OAuthProviderClient | None = None) -> None:
        """Detach only the expected client, so stale shutdown cannot detach a replacement."""

        if client is None or self._oauth_client is client:
            self._oauth_client = None

    async def enforce_rate_limit(
        self,
        *,
        client_key: str,
        route: str,
        method: str,
        context: RequestAuditContext,
    ) -> int | None:
        count = await self._redis().increment_with_ttl(
            rate_limit_key(client_key, route), self._rate_limit_window_seconds
        )
        if count <= self._rate_limit_max_requests:
            return None
        await self._write_audit(
            event_type="rate_limit_exceeded",
            outcome="failure",
            user_id=None,
            context=context,
            reason_code="RATE_LIMITED",
            details_json={
                "route": route,
                "method": method,
                "maxRequests": self._rate_limit_max_requests,
                "windowSeconds": self._rate_limit_window_seconds,
                "retryAfterSeconds": self._rate_limit_window_seconds,
            },
        )
        return self._rate_limit_window_seconds

    async def register(self, input: RegisterInput, context: RequestAuditContext) -> None:
        email = normalize_email(input.email)
        assert_password_policy(email, input.password, self._password_policy)
        password_hash = await self._passwords.hash_password(input.password)
        now = utc_now_ms()

        async def mutate(connection: AsyncConnection) -> tuple[str, str | None]:
            existing = await self._users.find_by_email(connection, email=email)
            if existing is not None:
                credential = await self._password_store.find_credential_by_email(
                    connection, email=email
                )
                if credential is None and existing.email_verified:
                    await self._password_store.upsert_pending_password(
                        connection,
                        pending=PendingPasswordUpsert(
                            id=application_uuid(),
                            user_id=existing.id,
                            email=email,
                            password_hash=password_hash,
                            expires_at=now + PENDING_PASSWORD_CREDENTIAL_TTL,
                            created_at=now,
                            updated_at=now,
                        ),
                    )
                return existing.id, None if credential is None else credential.user_id
            user_id = application_uuid()
            await self._password_store.create_user_with_password(
                connection,
                registration=PasswordRegistration(
                    user_id=user_id,
                    credential_id=application_uuid(),
                    email=email,
                    name=input.name,
                    password_hash=password_hash,
                    status=PersistenceUserStatus.PENDING_EMAIL_VERIFICATION,
                    created_at=now,
                    updated_at=now,
                ),
            )
            return user_id, user_id

        _registered_user_id, audit_user_id = await self._database().transaction(
            database_only_transaction(mutate)
        )
        await self._write_audit(
            event_type="register_request",
            outcome="request",
            user_id=audit_user_id,
            context=context,
        )

    @overload
    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: None = None,
    ) -> TokenPair: ...

    @overload
    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: ClientHandoff,
    ) -> str: ...

    async def login(
        self,
        input: LoginInput,
        context: RequestAuditContext,
        handoff: ClientHandoff | None = None,
    ) -> TokenPair | str:
        validated_client = None if handoff is None else self._client_for_handoff(handoff)
        email = normalize_email(input.email)
        async with self._database().connection() as connection:
            credential = await self._password_store.find_credential_by_email(
                connection, email=email
            )
        password_hash = credential.password_hash if credential is not None else DUMMY_PASSWORD_HASH
        verified = await self._passwords.verify_password(password_hash, input.password)
        now = utc_now_ms()
        locked = (
            credential is not None
            and credential.locked_until is not None
            and credential.locked_until > now
        )

        if (
            credential is not None
            and _domain_status(credential.user_status) is UserStatus.PENDING_EMAIL_VERIFICATION
            and verified
            and not locked
        ):
            failure = PasswordAuthFailure(
                user_id=credential.user_id, reason_code="EMAIL_VERIFICATION_REQUIRED"
            )
            await self._audit_login_failure(failure, context)
            raise failure

        can_login = (
            credential is not None
            and _domain_status(credential.user_status) is UserStatus.ACTIVE
            and not locked
            and verified
        )
        if not can_login:
            if (
                credential is not None
                and _domain_status(credential.user_status) is UserStatus.ACTIVE
                and not locked
            ):

                async def mark_failure(connection: AsyncConnection) -> None:
                    await self._failed_logins.record_failure(
                        connection,
                        user_id=credential.user_id,
                        locked_until=now + timedelta(minutes=15),
                        updated_at=now,
                    )

                await self._database().transaction(database_only_transaction(mark_failure))
            reason: PasswordAuthReason = (
                "ACCOUNT_LOCKED"
                if locked
                else "INVALID_CREDENTIALS"
                if credential is not None
                and _domain_status(credential.user_status) is UserStatus.ACTIVE
                else "USER_INACTIVE"
            )
            failure = PasswordAuthFailure(
                user_id=None if credential is None else credential.user_id,
                reason_code=reason,
            )
            await self._audit_login_failure(failure, context)
            raise failure

        if credential is None:
            raise RuntimeError("successful authentication lost its credential")

        async def mark_success(connection: AsyncConnection) -> CurrentUserRecord | None:
            await self._password_store.mark_login_success(
                connection, user_id=credential.user_id, updated_at=now
            )
            return await self._users.find_current(connection, user_id=credential.user_id)

        user = await self._database().transaction(database_only_transaction(mark_success))
        if user is None:
            raise DomainError(401, "INVALID_CREDENTIALS", "Invalid email or password")
        await self._write_audit(
            event_type="login_success",
            outcome="success",
            user_id=user.id,
            context=context,
        )
        if handoff is not None:
            if validated_client is None:
                raise AssertionError("validated handoff client was unexpectedly absent")
            code = await self._handoffs().create(
                AuthHandoffCreateInput(
                    client_id=validated_client.client_id,
                    audience=validated_client.audience,
                    redirect_uri=handoff.redirect_uri,
                    user_id=user.id,
                    login_method="password",
                    code_challenge=handoff.code_challenge,
                    code_challenge_method="S256",
                    state=handoff.state,
                )
            )
            return _redirect_with_code(handoff.redirect_uri, code, handoff.state)
        return await self._issue_pair(user.id, self._default_audience)

    async def request_email_verification(
        self,
        email: str,
        context: RequestAuditContext,
        handoff: ClientHandoff | None = None,
    ) -> VerificationAccepted:
        normalized = normalize_verification_email(email)
        validated_handoff = None
        if handoff is not None:
            client = self._client_for_handoff(handoff)
            validated_handoff = VerificationHandoff(
                client_id=client.client_id,
                audience=client.audience,
                redirect_uri=handoff.redirect_uri,
                state=handoff.state,
                code_challenge=handoff.code_challenge,
            )
        now = utc_now_ms()
        async with self._database().connection() as connection:
            user = await self._verification.find_eligible_user(
                connection, email=normalized, now=now
            )
        audit_user_id = None if user is None else user.id
        if (
            user is not None
            and user.email
            and (
                user.status is PersistenceUserStatus.PENDING_EMAIL_VERIFICATION
                or user.has_pending_password_credential
            )
        ):
            issued = issue_verification_token(now)

            async def create(connection: AsyncConnection) -> None:
                await self._verification.create_token(
                    connection,
                    token=EmailVerificationTokenInsert(
                        id=application_uuid(),
                        user_id=user.id,
                        token_hash=issued.token_hash,
                        expires_at=issued.expires_at,
                        created_at=now,
                        handoff=validated_handoff,
                    ),
                )

            await self._database().transaction(database_only_transaction(create))
            await self._mailer().send_email_verification(
                to=user.email,
                verification_url=_url_with_token(self._verification_url_base, issued.value),
            )
        await self._write_audit(
            event_type="email_verification_request",
            outcome="request",
            user_id=audit_user_id,
            context=context,
        )
        return VerificationAccepted()

    async def confirm_email_verification(
        self, token: str, context: RequestAuditContext
    ) -> EmailVerificationResult:
        now = utc_now_ms()
        try:

            async def confirm(
                connection: AsyncConnection,
            ) -> tuple[VerificationTokenRecord, str | None]:
                record = await self._verification.find_token(
                    connection, token_hash=sha256_token(token)
                )
                domain_record = None
                if record is not None:
                    handoff = None
                    if record.handoff is not None:
                        handoff = ClientHandoff(
                            client_id=record.handoff.client_id,
                            audience=record.handoff.audience,
                            redirect_uri=record.handoff.redirect_uri,
                            state=record.handoff.state,
                            code_challenge=record.handoff.code_challenge,
                            code_challenge_method="S256",
                        )
                    domain_record = VerificationTokenRecord(
                        token_id=record.id,
                        user_id=record.user_id,
                        expires_at=record.expires_at,
                        used_at=record.used_at,
                        handoff=handoff,
                    )
                if (
                    domain_record is None
                    or domain_record.used_at is not None
                    or domain_record.expires_at <= now
                ):
                    raise InvalidVerificationTokenError
                activated = await self._verification.confirm(
                    connection,
                    token_id=domain_record.token_id,
                    user_id=domain_record.user_id,
                    used_at=now,
                )
                return domain_record, activated

            domain_record, activated = await self._database().transaction(
                database_only_transaction(confirm)
            )
            result = confirm_verification_record(
                domain_record, now=now, activated_user_id=activated
            )
        except Exception:
            await self._write_audit(
                event_type="email_verification_confirm",
                outcome="failure",
                user_id=None,
                context=context,
                reason_code="INVALID_VERIFICATION_TOKEN",
            )
            raise
        await self._write_audit(
            event_type="email_verification_confirm",
            outcome="success",
            user_id=result.user_id,
            context=context,
        )
        if result.handoff is None:
            return EmailVerificationResult(user_id=result.user_id, redirect_url=None)
        try:
            redirect_url = await self._create_persisted_password_handoff(
                result.user_id, result.handoff
            )
        except Exception:
            await self._write_audit(
                event_type="email_verification_confirm",
                outcome="failure",
                user_id=result.user_id,
                context=context,
                reason_code="AUTH_HANDOFF_CREATE_FAILED",
            )
            raise
        return EmailVerificationResult(user_id=result.user_id, redirect_url=redirect_url)

    async def request_password_reset(
        self, email: str, context: RequestAuditContext
    ) -> PasswordResetAccepted:
        normalized = normalize_reset_email(email)
        async with self._database().connection() as connection:
            user = await self._password_reset.find_active_user(connection, email=normalized)
        if user is not None:
            now = utc_now_ms()
            issued = issue_password_reset_token(now)

            async def create(connection: AsyncConnection) -> None:
                await self._password_reset.create_token(
                    connection,
                    token=PasswordResetTokenInsert(
                        id=application_uuid(),
                        user_id=user.id,
                        token_hash=issued.token_hash,
                        expires_at=issued.expires_at,
                        created_at=now,
                    ),
                )

            await self._database().transaction(database_only_transaction(create))
            await self._mailer().send_password_reset(
                to=user.email,
                reset_url=_url_with_token(self._password_reset_url_base, issued.value),
            )
        async with self._database().connection() as connection:
            audit_credential = await self._password_store.find_credential_by_email(
                connection, email=normalized
            )
        await self._write_audit(
            event_type="password_reset_request",
            outcome="request",
            user_id=None if audit_credential is None else audit_credential.user_id,
            context=context,
        )
        return PasswordResetAccepted()

    async def confirm_password_reset(
        self, token: str, password: str, context: RequestAuditContext
    ) -> PasswordResetConfirmed:
        try:
            reset_policy = PasswordPolicy(
                min_length=self._password_policy.min_length,
                allowed_email_domain=None,
            )
            assert_reset_password_policy("", password, reset_policy)
            password_hash = await self._passwords.hash_password(password)
            now = utc_now_ms()

            async def reset(connection: AsyncConnection) -> str | None:
                return await self._password_reset.confirm(
                    connection,
                    token_hash=sha256_token(token),
                    password_hash=password_hash,
                    now=now,
                )

            user_id = await self._database().transaction(database_only_transaction(reset))
            result = confirm_password_reset(user_id)
        except Exception:
            await self._write_audit(
                event_type="password_reset_confirm",
                outcome="failure",
                user_id=None,
                context=context,
                reason_code="INVALID_RESET_TOKEN",
            )
            raise
        await self._write_audit(
            event_type="password_reset_confirm",
            outcome="success",
            user_id=result.user_id,
            context=context,
        )
        return result

    async def exchange_auth_handoff(
        self, input: AuthHandoffExchangeInput, context: RequestAuditContext
    ) -> TokenPair:
        handoff = await self._handoffs().consume(
            AuthHandoffConsumeInput(
                client_id=input.client_id,
                redirect_uri=input.redirect_uri,
                code=input.code,
                code_verifier=input.code_verifier,
            )
        )
        details: dict[str, object] = {
            "route": "/auth/exchange",
            "clientId": input.client_id,
        }
        if handoff is None:
            await self._write_audit(
                event_type="auth_handoff_exchange_failure",
                outcome="failure",
                user_id=None,
                context=context,
                reason_code="INVALID_AUTH_HANDOFF_CODE",
                details_json=details,
            )
            raise DomainError(400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code")
        try:
            pair = await self._issue_pair(handoff.user_id, handoff.audience)
            await self._write_audit(
                event_type="auth_handoff_exchange_success",
                outcome="success",
                user_id=handoff.user_id,
                context=context,
                provider=handoff.provider,
                details_json={"route": "/auth/exchange", "clientId": handoff.client_id},
            )
            return pair
        except Exception as error:
            await self._write_audit(
                event_type="auth_handoff_exchange_failure",
                outcome="failure",
                user_id=handoff.user_id,
                context=context,
                provider=handoff.provider,
                reason_code=(
                    error.code if isinstance(error, DomainError) else "AUTH_HANDOFF_EXCHANGE_FAILED"
                ),
                details_json={"route": "/auth/exchange", "clientId": handoff.client_id},
            )
            raise

    async def invalid_auth_handoff_exchange(self, context: RequestAuditContext) -> NoReturn:
        """Audit a malformed exchange body before returning the generic code error."""

        await self._write_audit(
            event_type="auth_handoff_exchange_failure",
            outcome="failure",
            user_id=None,
            context=context,
            reason_code="INVALID_AUTH_HANDOFF_CODE",
            details_json={"route": "/auth/exchange"},
        )
        raise DomainError(400, "INVALID_AUTH_HANDOFF_CODE", "Invalid authorization code")

    async def oauth_start(self, provider: OAuthProvider, input: OAuthStartInput) -> str:
        config = self._resolve_provider_config(provider)
        client = self._auth_clients.get(input.client_id)
        if client is None:
            raise DomainError(400, "INVALID_OAUTH_CLIENT", "Invalid OAuth client")
        redirect_uri = input.redirect_uri or client.allowed_redirect_uris[0]
        if redirect_uri not in client.allowed_redirect_uris:
            raise DomainError(400, "INVALID_REDIRECT_URI", "Invalid redirect URI")
        invalid_state = input.caller_state is not None and (
            not input.caller_state
            or javascript_string_length(input.caller_state) > MAX_CALLER_STATE_LENGTH
        )
        invalid_pkce = (
            input.code_challenge is None
            or PKCE_CHALLENGE_PATTERN.fullmatch(input.code_challenge) is None
            or input.code_challenge_method not in (None, "S256")
        )
        if invalid_state or invalid_pkce:
            raise DomainError(400, "INVALID_OAUTH_REQUEST", "Invalid OAuth request")
        metadata = OAuthStateMetadata(
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            caller_state=input.caller_state,
            code_challenge=input.code_challenge,
            code_challenge_method="S256",
        )
        state = await self._oauth_states().create(provider, metadata)
        return authorization_url(config, state)

    async def oauth_callback(
        self,
        provider: OAuthProvider,
        code: str,
        state: str,
        context: RequestAuditContext,
    ) -> OAuthCallbackResult:
        if not code:
            raise DomainError(400, "MISSING_AUTHORIZATION_CODE", "Authorization code is required")
        config = self._resolve_provider_config(provider)
        oauth_client = self._oauth_client
        if oauth_client is None:
            raise DomainError(
                503,
                "OAUTH_PROVIDER_UNAVAILABLE",
                "OAuth provider is unavailable",
            )
        metadata = await self._oauth_states().consume(provider, state)
        if (
            metadata is None
            or metadata.code_challenge is None
            or metadata.code_challenge_method != "S256"
        ):
            raise DomainError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state")
        client = self._auth_clients.get(metadata.client_id)
        if client is None:
            raise DomainError(400, "INVALID_OAUTH_STATE", "Invalid OAuth state")
        try:
            profile = await oauth_client.fetch_profile(provider, config, code)
        except OAuthProviderInvalidResponseError:
            raise DomainError(400, "INVALID_REQUEST", "Invalid request") from None
        except OAuthProviderInfrastructureError:
            raise DomainError(500, "INTERNAL_SERVER_ERROR", "Internal server error") from None
        now = utc_now_ms()

        async def resolve(connection: AsyncConnection) -> str:
            existing = await self._oauth_identities.find_by_provider_id(
                connection,
                provider=profile.provider,
                provider_user_id=profile.provider_user_id,
            )
            user = existing
            if user is None:
                user = await self._oauth_identities.resolve_or_create(
                    connection,
                    profile=_oauth_profile_record(profile),
                    default_role=DefaultRole(
                        service_key=client.default_role.service_key,
                        name=client.default_role.name,
                    ),
                    now=now,
                )
            if user.status is not PersistenceUserStatus.ACTIVE:
                raise DomainError(401, "UNAUTHORIZED", "Authentication is required")
            return user.id

        try:
            user_id = await self._database().transaction(database_only_transaction(resolve))
        except IntegrityError as error:
            if _sqlstate(error) != "23505":
                raise
            async with self._database().connection() as connection:
                canonical = await self._oauth_identities.find_by_provider_id(
                    connection,
                    provider=profile.provider,
                    provider_user_id=profile.provider_user_id,
                )
            if canonical is None or canonical.status is not PersistenceUserStatus.ACTIVE:
                raise DomainError(
                    400,
                    "OAUTH_PROVIDER_ERROR",
                    "OAuth provider returned an error",
                ) from None
            user_id = canonical.id
        await self._write_audit(
            event_type="login_success",
            outcome="success",
            user_id=user_id,
            context=context,
            provider=provider,
        )
        handoff_code = await self._handoffs().create(
            AuthHandoffCreateInput(
                client_id=client.client_id,
                audience=client.audience,
                redirect_uri=metadata.redirect_uri,
                user_id=user_id,
                provider=provider,
                login_method="oauth",
                code_challenge=metadata.code_challenge,
                code_challenge_method="S256",
                state=metadata.caller_state,
            )
        )
        return OAuthCallbackResult(
            _redirect_with_code(metadata.redirect_uri, handoff_code, metadata.caller_state)
        )

    async def oauth_provider_error(
        self, provider: OAuthProvider, context: RequestAuditContext
    ) -> NoReturn:
        """Record the provider-declared callback error before returning its generic 400."""

        await self._write_audit(
            event_type="login_failure",
            outcome="failure",
            user_id=None,
            context=context,
            reason_code="OAUTH_PROVIDER_ERROR",
            provider=provider,
        )
        raise DomainError(400, "OAUTH_PROVIDER_ERROR", "OAuth provider returned an error")

    async def refresh(self, refresh_token: str, context: RequestAuditContext) -> TokenPair:
        try:
            claims = self._tokens.verify_refresh_token(refresh_token)
            old_hash = sha256_token(refresh_token)
            now = utc_now_ms()

            async def rotate(
                connection: AsyncConnection,
            ) -> tuple[CurrentUserRecord, IssuedRefreshToken, str]:
                issued_refresh: IssuedRefreshToken | None = None

                def replacement_factory(record: RefreshTokenRecord) -> RefreshReplacement:
                    nonlocal issued_refresh
                    issued_refresh = self._tokens.issue_refresh_token(
                        user_id=record.user_id, audience=record.audience
                    )
                    return RefreshReplacement(
                        id=application_uuid(),
                        token_hash=issued_refresh.token_hash,
                        expires_at=issued_refresh.expires_at.replace(tzinfo=None),
                        created_at=now,
                    )

                rotated = await self._rotation.rotate(
                    connection,
                    old_token_hash=old_hash,
                    expected_audience=claims.audience,
                    now=now,
                    replacement_factory=replacement_factory,
                )
                if rotated is None:
                    raise RefreshRotationConflict("refresh token was not rotatable")
                user = await self._users.find_current_active(connection, user_id=rotated.user_id)
                if user is None:
                    raise RefreshRotationConflict("refresh user was not active")
                if issued_refresh is None:
                    raise RuntimeError("refresh rotation did not produce exactly one replacement")
                access_token = self._tokens.issue_access_token(
                    _identity(user), audience=claims.audience
                )
                return user, issued_refresh, access_token

            user, issued_refresh, access_token = await self._database().transaction(
                database_only_transaction(rotate)
            )
            await self._write_audit(
                event_type="refresh",
                outcome="success",
                user_id=user.id,
                context=context,
            )
            return TokenPair(
                access_token=access_token,
                refresh_token=issued_refresh.token,
            )
        except TokenValidationError:
            await self._audit_refresh_failure(context)
            raise DomainError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token") from None
        except RefreshRotationConflict:
            await self._audit_refresh_failure(context)
            raise DomainError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token") from None
        except Exception:
            await self._audit_refresh_failure(context)
            raise

    async def logout(self, refresh_token: str, context: RequestAuditContext) -> None:
        now = utc_now_ms()
        async with self._database().connection() as connection:
            autocommit = await connection.execution_options(isolation_level="AUTOCOMMIT")
            user_id = await self._logout.revoke(
                autocommit, token_hash=sha256_token(refresh_token), revoked_at=now
            )
        await self._write_audit(
            event_type="logout",
            outcome="success",
            user_id=user_id,
            context=context,
        )

    async def current_user(self, access_token: str) -> CurrentUser:
        try:
            claims = self._tokens.verify_access_token(access_token)
        except TokenValidationError:
            raise DomainError(401, "INVALID_TOKEN", "Invalid token") from None
        async with self._database().connection() as connection:
            user = await self._users.find_current_active(
                connection, user_id=claims.identity.user_id
            )
        if user is None:
            raise DomainError(401, "UNAUTHORIZED", "Authentication is required")
        return _current_user(user)

    async def _issue_pair(self, user_id: str, audience: str) -> TokenPair:
        issued = self._tokens.issue_refresh_token(user_id=user_id, audience=audience)
        created_at = utc_now_ms()

        async def persist(connection: AsyncConnection) -> TokenPair | None:
            user = await self._token_issue.issue_for_active_user(
                connection,
                user_id=user_id,
                refresh=RefreshTokenInsert(
                    id=application_uuid(),
                    token_hash=issued.token_hash,
                    audience=audience,
                    expires_at=issued.expires_at.replace(tzinfo=None),
                    created_at=created_at,
                ),
            )
            if user is None:
                return None
            return TokenPair(
                access_token=self._tokens.issue_access_token(_identity(user), audience=audience),
                refresh_token=issued.token,
            )

        pair = await self._database().transaction(database_only_transaction(persist))
        if pair is None:
            raise DomainError(401, "UNAUTHORIZED", "Authentication is required")
        return pair

    def _client_for_handoff(self, handoff: ClientHandoff) -> RelyingClientPolicy:
        client = self._auth_clients.get(handoff.client_id)
        if (
            client is None
            or handoff.redirect_uri not in client.allowed_redirect_uris
            or handoff.audience != client.audience
        ):
            raise DomainError(400, "INVALID_CLIENT_REDIRECT_URI", "Invalid request")
        return client

    async def _create_persisted_password_handoff(self, user_id: str, handoff: ClientHandoff) -> str:
        code = await self._handoffs().create(
            AuthHandoffCreateInput(
                client_id=handoff.client_id,
                audience=handoff.audience,
                redirect_uri=handoff.redirect_uri,
                user_id=user_id,
                login_method="password",
                code_challenge=handoff.code_challenge,
                code_challenge_method="S256",
                state=handoff.state,
            )
        )
        return _redirect_with_code(handoff.redirect_uri, code, handoff.state)

    def _mailer(self) -> MailService:
        if self._mail is None:
            raise RuntimeError("mail service is not configured")
        return self._mail

    def _oauth_states(self) -> OAuthStateStore:
        return OAuthStateStore(self._redis())

    def _handoffs(self) -> AuthHandoffStore:
        return AuthHandoffStore(self._redis())

    def _resolve_provider_config(self, provider: OAuthProvider) -> OAuthProviderConfig:
        if self._provider_config is None:
            raise RuntimeError("OAuth provider configuration is not configured")
        try:
            return self._provider_config(provider)
        except OAuthProviderConfigurationError as error:
            status = 404 if error.code == "OAUTH_PROVIDER_DISABLED" else 500
            message = (
                "OAuth provider is disabled" if status == 404 else "OAuth provider is misconfigured"
            )
            raise DomainError(status, error.code, message) from None

    async def _audit_login_failure(
        self, failure: PasswordAuthFailure, context: RequestAuditContext
    ) -> None:
        await self._write_audit(
            event_type="lockout" if failure.reason_code == "ACCOUNT_LOCKED" else "login_failure",
            outcome="failure",
            user_id=failure.user_id,
            context=context,
            reason_code=failure.reason_code,
        )

    async def _audit_refresh_failure(self, context: RequestAuditContext) -> None:
        await self._write_audit(
            event_type="refresh",
            outcome="failure",
            user_id=None,
            context=context,
            reason_code="REFRESH_FAILED",
        )

    async def _write_audit(
        self,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None,
        context: RequestAuditContext,
        reason_code: str | None = None,
        details_json: dict[str, object] | None = None,
        provider: str | None = None,
    ) -> None:
        event = AuditEventInsert(
            id=str(uuid4()),
            event_type=event_type,
            outcome=outcome,
            created_at=utc_now_ms(),
            user_id=user_id,
            ip_address=context.ip_address,
            user_agent=context.user_agent,
            reason_code=reason_code,
            details_json=details_json,
            provider=provider,
        )

        async def create(connection: AsyncConnection) -> None:
            await self._audit.create(connection, event=event)

        await self._database().transaction(database_only_transaction(create))


def _url_with_token(base_url: str, token: str) -> str:
    if not base_url:
        raise RuntimeError("mail URL base is not configured")
    return _url_with_query(base_url, token=token)


def _redirect_with_code(redirect_uri: str, code: str, state: str | None) -> str:
    values = {"code": code}
    if state:
        values["state"] = state
    return _url_with_query(redirect_uri, **values)


def _url_with_query(url: str, **values: str) -> str:
    parsed = urlsplit(url)
    had_empty_fragment = url.endswith("#")
    query = parse_qsl(parsed.query, keep_blank_values=True)
    for name, value in values.items():
        replaced = False
        updated: list[tuple[str, str]] = []
        for existing_name, existing_value in query:
            if existing_name != name:
                updated.append((existing_name, existing_value))
            elif not replaced:
                updated.append((name, value))
                replaced = True
        if not replaced:
            updated.append((name, value))
        query = updated
    result = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, _form_encode_query(query), parsed.fragment)
    )
    return f"{result}#" if had_empty_fragment else result


def _form_encode_query(query: list[tuple[str, str]]) -> str:
    def component(value: str) -> str:
        encoded = quote_plus(node_utf8_bytes(value), safe="*.-_")
        return encoded.replace("~", "%7E")

    return "&".join(f"{component(name)}={component(value)}" for name, value in query)


def _oauth_profile_record(profile: OAuthProfile) -> OAuthProfileRecord:
    return OAuthProfileRecord(
        provider=profile.provider,
        provider_user_id=profile.provider_user_id,
        email=profile.email,
        email_verified=profile.email_verified,
        name=profile.name,
        profile_url=profile.profile_url,
    )


def _sqlstate(error: IntegrityError) -> str | None:
    value = getattr(error.orig, "sqlstate", None)
    return value if isinstance(value, str) else None


# Phase 4 imports remain valid while the runtime migrates to the expanded service.
Phase4AuthService = Phase5AuthService
