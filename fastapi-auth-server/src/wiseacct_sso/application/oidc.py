"""Application orchestration for the opt-in OIDC provider."""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Literal, NoReturn, Protocol
from urllib.parse import urlencode
from uuid import uuid4

import structlog
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.auth import PasswordAuthFailure, PasswordAuthReason, normalize_email
from wiseacct_sso.domain.oauth import OAuthProvider
from wiseacct_sso.domain.oidc import (
    OidcIdentity,
    has_required_role,
    parse_requested_scopes,
    project_groups,
    validate_pkce_request,
    verify_pkce,
)
from wiseacct_sso.domain.users import Role
from wiseacct_sso.infrastructure.oauth_providers import (
    OAuthProviderClient,
    OAuthProviderConfig,
    OAuthProviderConfigurationError,
    OAuthProviderInfrastructureError,
    OAuthProviderInvalidResponseError,
    authorization_url,
)
from wiseacct_sso.infrastructure.oidc_state import (
    OidcAuthorizationCodeCreateInput,
    OidcAuthorizationCodeStore,
    OidcAuthorizationTransaction,
    OidcAuthorizationTransactionCreateInput,
    OidcAuthorizationTransactionStore,
    OidcProviderStateCreateInput,
    OidcProviderStateStore,
)
from wiseacct_sso.infrastructure.oidc_tokens import (
    OidcAccessTokenCreateInput,
    OidcAccessTokenStore,
    OidcIdTokenIdentity,
    OidcIdTokenSigner,
)
from wiseacct_sso.infrastructure.redis import RedisStateStore
from wiseacct_sso.infrastructure.security import (
    DUMMY_PASSWORD_HASH,
    AsyncPasswordHasher,
    sha256_token,
)
from wiseacct_sso.infrastructure.sso_sessions import (
    SSO_SESSION_TTL_SECONDS,
    SsoSession,
    SsoSessionStore,
)
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence.database import Database, database_only_transaction
from wiseacct_sso.persistence.models import UserStatus as PersistenceUserStatus
from wiseacct_sso.persistence.models import utc_now_ms
from wiseacct_sso.persistence.oidc import OidcIdentityStore, OidcUserRecord
from wiseacct_sso.persistence.stores import (
    AuditEventInsert,
    AuditStore,
    FailedLoginStore,
    PasswordAuthStore,
    PasswordCredentialRecord,
)

DatabaseProvider = Callable[[], Database]
RedisProvider = Callable[[], RedisStateStore]
ProviderConfigResolver = Callable[[OAuthProvider], OAuthProviderConfig]
OAuthClientProvider = Callable[[], OAuthProviderClient]
ClockMs = Callable[[], int]


class CleanupLogger(Protocol):
    def warning(self, event: str, **metadata: object) -> object: ...


@dataclass(frozen=True, slots=True)
class OidcRequestContext:
    ip_address: str | None
    user_agent: str | None
    session_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    client_id: str
    redirect_uri: str
    response_type: str
    scopes: tuple[str, ...]
    state: str | None
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: str | None
    prompt: str | None = None
    max_age: int | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationStart:
    transaction_id: str
    csrf_token: str
    browser_binding: str
    clear_session: bool = False


@dataclass(frozen=True, slots=True)
class AuthorizationResult:
    redirect_url: str
    session_token: str | None = field(default=None, repr=False)
    session_max_age: int = 0


@dataclass(frozen=True, slots=True)
class TokenExchangeInput:
    client_id: str
    client_secret: str
    grant_type: str
    code: str
    redirect_uri: str
    code_verifier: str | None


@dataclass(frozen=True, slots=True)
class TokenResponse:
    access_token: str
    expires_in: int
    id_token: str
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105 - OAuth token type, not a secret


@dataclass(frozen=True, slots=True)
class UserInfo:
    sub: str
    email: str
    email_verified: Literal[True]
    name: str | None
    groups: tuple[str, ...]


ADMIN_AUTH_MAX_AGE_SECONDS = 15 * 60
ADMIN_BROWSER_CLIENT = "wise-sso-admin"


@dataclass(frozen=True, slots=True)
class AdminBrowserIdentity:
    user_id: str
    email: str
    csrf_token: str = field(repr=False)
    auth_time: int


class OidcServiceError(Exception):
    """Protocol-safe error consumed by the isolated OIDC HTTP boundary."""

    def __init__(
        self,
        error: str,
        description: str,
        *,
        status_code: int = 400,
        redirect_uri: str | None = None,
        state: str | None = None,
        www_authenticate: bool = False,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code
        self.redirect_uri = redirect_uri
        self.state = state
        self.www_authenticate = www_authenticate


class OidcService:
    """OIDC provider service with no legacy token or account-creation side effects."""

    def __init__(
        self,
        *,
        database: DatabaseProvider,
        passwords: AsyncPasswordHasher,
        clients: OidcClientRegistry,
        transactions: OidcAuthorizationTransactionStore,
        provider_states: OidcProviderStateStore,
        codes: OidcAuthorizationCodeStore,
        access_tokens: OidcAccessTokenStore,
        id_tokens: OidcIdTokenSigner,
        sessions: SsoSessionStore | None = None,
        provider_config: ProviderConfigResolver | None = None,
        oauth_client: OAuthClientProvider | None = None,
        redis: RedisProvider | None = None,
        client_rate_limit_window_seconds: int = 60,
        client_rate_limit_max_requests: int = 20,
        access_token_ttl_seconds: int = 300,
        clock_ms: ClockMs | None = None,
        logger: CleanupLogger | None = None,
    ) -> None:
        if client_rate_limit_window_seconds <= 0 or client_rate_limit_max_requests <= 0:
            raise ValueError("OIDC client rate-limit settings must be positive")
        if access_token_ttl_seconds <= 0:
            raise ValueError("OIDC access-token expiry must be positive")
        self._sessions = sessions
        self._database = database
        self._passwords = passwords
        self._clients = clients
        self._transactions = transactions
        self._provider_states = provider_states
        self._codes = codes
        self._access_tokens = access_tokens
        self._id_tokens = id_tokens
        self._provider_config = provider_config
        self._oauth_client = oauth_client
        self._redis = redis
        self._client_rate_limit_window_seconds = client_rate_limit_window_seconds
        self._client_rate_limit_max_requests = client_rate_limit_max_requests
        self._access_token_ttl_seconds = access_token_ttl_seconds
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self._logger = logger or structlog.get_logger()
        self._password_store = PasswordAuthStore()
        self._failed_logins = FailedLoginStore()
        self._identities = OidcIdentityStore()
        self._audit = AuditStore()

    async def begin_authorization(
        self, request: AuthorizationRequest, context: OidcRequestContext
    ) -> AuthorizationStart | AuthorizationResult:
        client = self._client(request.client_id)
        redirect_uri = self._validated_redirect(client, request.redirect_uri)
        if request.response_type != "code":
            self._raise_authorization_error(
                "unsupported_response_type",
                "Only the authorization code flow is supported",
                redirect_uri,
                request.state,
            )
        if request.prompt not in (None, "none", "login", "consent", "select_account"):
            self._raise_authorization_error(
                "invalid_request", "Unsupported prompt", redirect_uri, request.state
            )
        if request.max_age is not None and (
            type(request.max_age) is not int or not 0 <= request.max_age <= 2_147_483_647
        ):
            self._raise_authorization_error(
                "invalid_request", "Invalid max_age", redirect_uri, request.state
            )
        try:
            scopes = parse_requested_scopes(" ".join(request.scopes), client.allowed_scopes)
            validate_pkce_request(
                request.code_challenge,
                request.code_challenge_method,
                required=client.require_pkce,
            )
        except ValueError as error:
            code = "invalid_scope" if "scope" in str(error).lower() else "invalid_request"
            self._raise_authorization_error(code, str(error), redirect_uri, request.state)

        clear_session = False
        session = (
            await self._sessions.get(context.session_token) if self._sessions is not None else None
        )
        if context.session_token and session is None:
            clear_session = True
        can_reuse = (
            session is not None
            and request.prompt in (None, "none")
            and request.max_age != 0
            and (
                request.max_age is None
                or self._clock_ms() // 1000 - session.auth_time <= request.max_age
            )
        )
        if can_reuse and session is not None:
            # Reuse authentication only: the target client's DB authorization is checked afresh.
            transaction = OidcAuthorizationTransaction(
                client_id=client.client_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                state=request.state,
                nonce=request.nonce,
                code_challenge=request.code_challenge,
                code_challenge_method="S256" if request.code_challenge is not None else None,
                browser_binding_hash="",
                csrf_hash="",
                expires_at_epoch_ms=self._clock_ms() + 60_000,
            )
            try:
                return await self._complete_authorization(
                    session.user_id,
                    transaction,
                    context,
                    login_method="sso",
                    existing_session=session,
                )
            except OidcServiceError as error:
                if error.error != "login_required":
                    self._raise_authorization_error(
                        error.error, error.description, redirect_uri, request.state
                    )
                if self._sessions is not None:
                    await self._sessions.revoke(context.session_token)
                clear_session = True
        if request.prompt == "none":
            self._raise_authorization_error(
                "login_required", "Interactive login is required", redirect_uri, request.state
            )

        csrf_token = secrets.token_urlsafe(32)
        browser_binding = secrets.token_urlsafe(32)
        record = OidcAuthorizationTransactionCreateInput(
            client_id=client.client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=request.state,
            nonce=request.nonce,
            code_challenge=request.code_challenge,
            code_challenge_method="S256" if request.code_challenge is not None else None,
            browser_binding=browser_binding,
            csrf_token=csrf_token,
        )
        transaction_id = await self._transactions.create(record)
        return AuthorizationStart(transaction_id, csrf_token, browser_binding, clear_session)

    async def password_login(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        csrf_token: str,
        email: str,
        password: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult:
        transaction = await self._bound_transaction(transaction_id, browser_binding)
        if not transaction.csrf_matches(csrf_token):
            raise OidcServiceError("invalid_request", "Invalid login transaction")

        credential = await self._authenticate_password(
            email, password, context, transaction.client_id
        )

        consumed = await self._transactions.consume(transaction_id, browser_binding=browser_binding)
        if consumed is None or consumed != transaction:
            raise OidcServiceError("invalid_request", "Invalid login transaction")
        return await self._complete_authorization(
            credential.user_id,
            consumed,
            context,
            login_method="password",
            reset_password_login=True,
            verified_password_hash=credential.password_hash,
        )

    async def _authenticate_password(
        self, email: str, password: str, context: OidcRequestContext, client_id: str
    ) -> PasswordCredentialRecord:
        normalized_email = normalize_email(email)
        async with self._database().connection() as connection:
            credential = await self._password_store.find_credential_by_email(
                connection, email=normalized_email
            )
        password_hash = credential.password_hash if credential is not None else DUMMY_PASSWORD_HASH
        verified = await self._passwords.verify_password(password_hash, password)
        now = utc_now_ms()
        locked = (
            credential is not None
            and credential.locked_until is not None
            and credential.locked_until > now
        )
        can_login = (
            credential is not None
            and credential.user_status is PersistenceUserStatus.ACTIVE
            and not locked
            and verified
        )
        if not can_login:
            if (
                credential is not None
                and credential.user_status is PersistenceUserStatus.ACTIVE
                and not locked
            ):

                async def record_failure(connection: AsyncConnection) -> None:
                    await self._failed_logins.record_failure(
                        connection,
                        user_id=credential.user_id,
                        locked_until=now + timedelta(minutes=15),
                        updated_at=now,
                    )

                await self._database().transaction(database_only_transaction(record_failure))
            reason: PasswordAuthReason = (
                "ACCOUNT_LOCKED"
                if locked
                else "EMAIL_VERIFICATION_REQUIRED"
                if credential is not None
                and credential.user_status is PersistenceUserStatus.PENDING_EMAIL_VERIFICATION
                and verified
                else "INVALID_CREDENTIALS"
                if credential is not None and credential.user_status is PersistenceUserStatus.ACTIVE
                else "USER_INACTIVE"
            )
            failure = PasswordAuthFailure(
                user_id=None if credential is None else credential.user_id,
                reason_code=reason,
            )
            await self._write_failure_audit(
                event_type="oidc_authorize",
                user_id=failure.user_id,
                client_id=client_id,
                reason_code=reason,
                context=context,
            )
            raise failure
        if credential is None:
            raise RuntimeError("successful OIDC authentication lost its credential")
        return credential

    async def admin_login_start(self, redirect_uri: str) -> AuthorizationStart:
        csrf, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        transaction = await self._transactions.create(
            OidcAuthorizationTransactionCreateInput(
                client_id=ADMIN_BROWSER_CLIENT,
                redirect_uri=redirect_uri,
                scopes=("openid",),
                state=None,
                nonce=None,
                code_challenge=None,
                code_challenge_method=None,
                browser_binding=binding,
                csrf_token=csrf,
                admin_browser=True,
            )
        )
        return AuthorizationStart(transaction, csrf, binding)

    @staticmethod
    def _admin_eligible(user: OidcUserRecord | None) -> bool:
        return (
            user is not None
            and user.status is PersistenceUserStatus.ACTIVE
            and bool(user.email)
            and user.email_verified
            and user.user_type == "EMPLOYEE"
            and any(role.service_key == "sso" and role.name == "admin" for role in user.roles)
        )

    async def admin_browser_identity(self, context: OidcRequestContext) -> AdminBrowserIdentity:
        session = (
            await self._sessions.get(context.session_token) if self._sessions is not None else None
        )
        if (
            session is None
            or self._clock_ms() // 1000 - session.auth_time >= ADMIN_AUTH_MAX_AGE_SECONDS
        ):
            raise OidcServiceError(
                "login_required", "Administrator reauthentication is required", status_code=401
            )
        async with self._database().engine.begin() as connection:
            user = await self._identities.lock_user(connection, user_id=session.user_id)
            if (
                user is None
                or user.status is not PersistenceUserStatus.ACTIVE
                or user.session_version != session.version
            ):
                raise OidcServiceError(
                    "login_required", "Administrator session is no longer valid", status_code=401
                )
            if not self._admin_eligible(user):
                await self._create_audit(
                    connection,
                    event_type="admin_authorization_failure",
                    outcome="failure",
                    user_id=session.user_id,
                    client_id=ADMIN_BROWSER_CLIENT,
                    reason_code="FORBIDDEN",
                    context=context,
                )
            else:
                return AdminBrowserIdentity(
                    user.id, user.email or "", session.csrf, session.auth_time
                )
        raise OidcServiceError(
            "access_denied", "Active employee SSO admin role is required", status_code=403
        )

    async def admin_password_login(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        csrf_token: str,
        email: str,
        password: str,
        redirect_uri: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult:
        transaction = await self._bound_transaction(
            transaction_id, browser_binding, admin_browser=True
        )
        if (
            transaction.client_id != ADMIN_BROWSER_CLIENT
            or transaction.redirect_uri != redirect_uri
            or not transaction.csrf_matches(csrf_token)
        ):
            raise OidcServiceError("invalid_request", "Invalid admin login transaction")
        await self._enforce_client_rate_limit(ADMIN_BROWSER_CLIENT)
        credential = await self._authenticate_password(
            email, password, context, ADMIN_BROWSER_CLIENT
        )
        consumed = await self._transactions.consume(transaction_id, browser_binding=browser_binding)
        if consumed is None or consumed != transaction:
            raise OidcServiceError("invalid_request", "Invalid admin login transaction")
        prepared: str | None = None
        denied = False
        try:
            async with self._database().engine.begin() as connection:
                user = await self._identities.lock_user(connection, user_id=credential.user_id)
                current = await self._password_store.find_credential_by_email(
                    connection, email=credential.email
                )
                if (
                    current is None
                    or current.user_id != credential.user_id
                    or not hmac.compare_digest(current.password_hash, credential.password_hash)
                ):
                    raise OidcServiceError(
                        "login_required", "Credentials changed; authenticate again"
                    )
                if not self._admin_eligible(user):
                    denied = True
                    await self._create_audit(
                        connection,
                        event_type="admin_authorization_failure",
                        outcome="failure",
                        user_id=credential.user_id,
                        client_id=ADMIN_BROWSER_CLIENT,
                        reason_code="FORBIDDEN",
                        context=context,
                    )
                else:
                    if self._sessions is None or user is None:
                        raise OidcServiceError(
                            "temporarily_unavailable",
                            "Session store is unavailable",
                            status_code=503,
                        )
                    await self._password_store.mark_login_success(
                        connection, user_id=user.id, updated_at=utc_now_ms()
                    )
                    prepared = await self._sessions.create(
                        user.id, user.session_version, self._clock_ms() // 1000
                    )
                    await self._create_audit(
                        connection,
                        event_type="admin_browser_login",
                        outcome="success",
                        user_id=user.id,
                        client_id=ADMIN_BROWSER_CLIENT,
                        reason_code=None,
                        context=context,
                    )
                    await self._sessions.revoke(context.session_token)
        except Exception:
            if prepared is not None and self._sessions is not None:
                try:
                    await self._sessions.revoke(prepared)
                except Exception as error:
                    self._report_cleanup_failure("revoke_admin_login_session", error)
            raise
        if denied or prepared is None:
            raise OidcServiceError(
                "access_denied", "Active employee SSO admin role is required", status_code=403
            )
        return AuthorizationResult(
            redirect_uri, session_token=prepared, session_max_age=SSO_SESSION_TTL_SECONDS
        )

    async def provider_start(
        self,
        *,
        transaction_id: str,
        browser_binding: str,
        provider: OAuthProvider,
    ) -> str:
        await self._bound_transaction(transaction_id, browser_binding)
        config = self._resolve_provider_config(provider)
        provider_state = await self._provider_states.create(
            OidcProviderStateCreateInput(
                provider=provider,
                transaction_id=transaction_id,
                browser_binding=browser_binding,
            )
        )
        return authorization_url(config, provider_state)

    async def provider_callback(
        self,
        *,
        provider: OAuthProvider,
        code: str,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> AuthorizationResult:
        provider_state = await self._provider_states.consume_for_provider(
            state, provider, browser_binding
        )
        if provider_state is None:
            raise OidcServiceError("invalid_request", "Invalid provider state")
        transaction = await self._bound_transaction(provider_state.transaction_id, browser_binding)
        if not code:
            raise OidcServiceError("invalid_request", "Authorization code is required")
        if self._oauth_client is None:
            raise OidcServiceError(
                "temporarily_unavailable", "OAuth provider is unavailable", status_code=503
            )
        try:
            profile = await self._oauth_client().fetch_profile(
                provider, self._resolve_provider_config(provider), code
            )
        except OAuthProviderInvalidResponseError:
            raise OidcServiceError("access_denied", "Provider profile is invalid") from None
        except OAuthProviderInfrastructureError:
            raise OidcServiceError(
                "temporarily_unavailable", "OAuth provider is unavailable", status_code=503
            ) from None

        consumed = await self._transactions.consume(
            provider_state.transaction_id, browser_binding=browser_binding
        )
        if consumed is None or consumed != transaction:
            raise OidcServiceError("invalid_request", "Invalid login transaction")
        async with self._database().connection() as connection:
            user_id = await self._identities.find_existing_social_user_id(
                connection,
                provider=profile.provider,
                provider_user_id=profile.provider_user_id,
            )
        if user_id is None:
            await self._write_failure_audit(
                event_type="oidc_authorize",
                user_id=None,
                client_id=consumed.client_id,
                reason_code="OIDC_IDENTITY_NOT_LINKED",
                context=context,
                provider=provider,
            )
            raise OidcServiceError("access_denied", "Account is not eligible", status_code=403)
        return await self._complete_authorization(
            user_id,
            consumed,
            context,
            login_method="oauth",
            provider=provider,
        )

    async def provider_error(
        self,
        *,
        provider: OAuthProvider,
        state: str,
        browser_binding: str,
        context: OidcRequestContext,
    ) -> NoReturn:
        provider_state = await self._provider_states.consume_for_provider(
            state, provider, browser_binding
        )
        if provider_state is None:
            raise OidcServiceError("invalid_request", "Invalid provider state")
        transaction = await self._transactions.consume(
            provider_state.transaction_id, browser_binding=browser_binding
        )
        if transaction is None:
            raise OidcServiceError("invalid_request", "Invalid login transaction")
        await self._write_failure_audit(
            event_type="oidc_authorize",
            user_id=None,
            client_id=transaction.client_id,
            reason_code="OIDC_PROVIDER_DENIED",
            context=context,
            provider=provider,
        )
        raise OidcServiceError("access_denied", "Provider authorization was denied")

    async def exchange_code(
        self, input: TokenExchangeInput, context: OidcRequestContext
    ) -> TokenResponse:
        if input.grant_type != "authorization_code":
            raise OidcServiceError("unsupported_grant_type", "Unsupported grant type")
        await self._enforce_client_rate_limit(input.client_id)
        client = self._clients.get(input.client_id)
        expected_hash = DUMMY_PASSWORD_HASH if client is None else client.client_secret_hash
        authenticated = await self._passwords.verify_password(expected_hash, input.client_secret)
        if client is None or not authenticated:
            raise OidcServiceError(
                "invalid_client",
                "Client authentication failed",
                status_code=401,
                www_authenticate=True,
            )

        stored = await self._codes.consume_for_client(input.code, client.client_id)
        if stored is None:
            raise OidcServiceError("invalid_grant", "Invalid authorization code")
        if stored.redirect_uri != input.redirect_uri:
            await self._audit_token_failure(stored.user_id, client.client_id, context)
            raise OidcServiceError("invalid_grant", "Invalid authorization code")
        if stored.code_challenge is not None:
            if input.code_verifier is None or not verify_pkce(
                input.code_verifier, stored.code_challenge
            ):
                await self._audit_token_failure(stored.user_id, client.client_id, context)
                raise OidcServiceError("invalid_grant", "Invalid authorization code")
        elif client.require_pkce:
            await self._audit_token_failure(stored.user_id, client.client_id, context)
            raise OidcServiceError("invalid_grant", "Invalid authorization code")
        elif not verify_pkce(input.code_verifier, None):
            await self._audit_token_failure(stored.user_id, client.client_id, context)
            raise OidcServiceError("invalid_grant", "Invalid authorization code")

        prepared_access_token: str | None = None
        denial: str | None = None
        response: TokenResponse | None = None
        try:
            async with self._database().engine.begin() as connection:
                user = await self._identities.lock_user(connection, user_id=stored.user_id)
                identity, denial = self._eligible_identity(user, client)
                if (
                    user is not None
                    and stored.session_version is not None
                    and user.session_version != stored.session_version
                ):
                    identity, denial = None, "OIDC_SESSION_REVOKED"
                if identity is None:
                    await self._create_audit(
                        connection,
                        event_type="oidc_token",
                        outcome="failure",
                        user_id=stored.user_id,
                        client_id=client.client_id,
                        reason_code=denial,
                        context=context,
                    )
                else:
                    prepared_access_token = await self._access_tokens.create(
                        OidcAccessTokenCreateInput(
                            client_id=client.client_id,
                            user_id=identity.user_id,
                            scopes=stored.scopes,
                            session_version=user.session_version if user is not None else None,
                        )
                    )
                    groups = project_groups(identity, client)
                    id_token = self._id_tokens.issue(
                        OidcIdTokenIdentity(
                            user_id=identity.user_id,
                            email=identity.email,
                            email_verified=identity.email_verified,
                            name=identity.name,
                            groups=groups,
                        ),
                        client_id=client.client_id,
                        nonce=stored.nonce,
                        **({"auth_time": stored.auth_time} if stored.auth_time is not None else {}),
                    )
                    await self._create_audit(
                        connection,
                        event_type="oidc_token",
                        outcome="success",
                        user_id=identity.user_id,
                        client_id=client.client_id,
                        reason_code=None,
                        context=context,
                    )
                    response = TokenResponse(
                        access_token=prepared_access_token,
                        expires_in=self._access_token_ttl_seconds,
                        id_token=id_token,
                    )
        except Exception:
            if prepared_access_token is not None:
                await self._best_effort_revoke_access(prepared_access_token)
            raise
        if response is None:
            raise OidcServiceError("invalid_grant", "Invalid authorization code")
        return response

    async def userinfo(self, access_token: str) -> UserInfo:
        stored = await self._access_tokens.get(access_token)
        if stored is None:
            raise OidcServiceError(
                "invalid_token", "Invalid access token", status_code=401, www_authenticate=True
            )
        client = self._clients.get(stored.client_id)
        if client is None:
            await self._best_effort_revoke_access(access_token)
            raise OidcServiceError(
                "invalid_token", "Invalid access token", status_code=401, www_authenticate=True
            )
        async with self._database().engine.begin() as connection:
            user = await self._identities.lock_user(connection, user_id=stored.user_id)
            identity, _ = self._eligible_identity(user, client)
            if (
                user is not None
                and stored.session_version is not None
                and user.session_version != stored.session_version
            ):
                identity = None
            if identity is None:
                await self._best_effort_revoke_access(access_token)
                raise OidcServiceError(
                    "invalid_token",
                    "Invalid access token",
                    status_code=401,
                    www_authenticate=True,
                )
            return UserInfo(
                sub=identity.user_id,
                email=identity.email,
                email_verified=True,
                name=identity.name,
                groups=project_groups(identity, client),
            )

    async def _complete_authorization(
        self,
        user_id: str,
        transaction: OidcAuthorizationTransaction,
        context: OidcRequestContext,
        *,
        login_method: str,
        reset_password_login: bool = False,
        provider: str | None = None,
        existing_session: SsoSession | None = None,
        verified_password_hash: str | None = None,
    ) -> AuthorizationResult:
        client = self._client(transaction.client_id)
        prepared_code: str | None = None
        prepared_session: str | None = None
        auth_time = (
            existing_session.auth_time if existing_session is not None else self._clock_ms() // 1000
        )
        denial: str | None = None
        try:
            async with self._database().engine.begin() as connection:
                user = await self._identities.lock_user(connection, user_id=user_id)
                if existing_session is not None and (
                    user is None
                    or user.status is not PersistenceUserStatus.ACTIVE
                    or user.session_version != existing_session.version
                ):
                    raise OidcServiceError("login_required", "Interactive login is required")
                if (
                    verified_password_hash is not None
                    and user is not None
                    and user.email is not None
                ):
                    current = await self._password_store.find_credential_by_email(
                        connection, email=user.email
                    )
                    if (
                        current is None
                        or current.user_id != user.id
                        or not hmac.compare_digest(current.password_hash, verified_password_hash)
                    ):
                        raise OidcServiceError(
                            "login_required", "Credentials changed; authenticate again"
                        )
                identity, denial = self._eligible_identity(user, client)
                if identity is None:
                    await self._create_audit(
                        connection,
                        event_type="oidc_authorize",
                        outcome="failure",
                        user_id=user_id,
                        client_id=client.client_id,
                        reason_code=denial,
                        context=context,
                        provider=provider,
                    )
                else:
                    if reset_password_login:
                        await self._password_store.mark_login_success(
                            connection, user_id=user_id, updated_at=utc_now_ms()
                        )
                    prepared_code = await self._codes.create(
                        OidcAuthorizationCodeCreateInput(
                            client_id=client.client_id,
                            redirect_uri=transaction.redirect_uri,
                            user_id=user_id,
                            scopes=transaction.scopes,
                            nonce=transaction.nonce,
                            code_challenge=transaction.code_challenge,
                            code_challenge_method=transaction.code_challenge_method,
                            auth_time=auth_time,
                            session_version=user.session_version if user is not None else None,
                        )
                    )
                    if self._sessions is not None and existing_session is None:
                        if user is None:
                            raise RuntimeError("Missing authenticated user")
                        prepared_session = await self._sessions.create(
                            user.id, user.session_version, auth_time
                        )
                    await self._create_audit(
                        connection,
                        event_type="oidc_authorize",
                        outcome="success",
                        user_id=user_id,
                        client_id=client.client_id,
                        reason_code=None,
                        context=context,
                        provider=provider,
                        details={"loginMethod": login_method},
                    )
                    if prepared_session is not None and self._sessions is not None:
                        await self._sessions.revoke(context.session_token)
        except Exception:
            if prepared_code is not None:
                await self._best_effort_consume_code(prepared_code, client.client_id)
            if prepared_session is not None and self._sessions is not None:
                try:
                    await self._sessions.revoke(prepared_session)
                except Exception as error:
                    self._report_cleanup_failure("revoke_sso_session", error)
            raise
        if prepared_code is None:
            raise OidcServiceError("access_denied", "Account is not eligible", status_code=403)
        return AuthorizationResult(
            _url_with_query(
                transaction.redirect_uri,
                code=prepared_code,
                **({"state": transaction.state} if transaction.state is not None else {}),
            ),
            session_token=prepared_session,
            session_max_age=SSO_SESSION_TTL_SECONDS if prepared_session is not None else 0,
        )

    async def session_logout_token(self, token: str | None) -> str | None:
        session = await self._sessions.get(token) if self._sessions is not None else None
        if session is None:
            return None
        async with self._database().engine.begin() as connection:
            user = await self._identities.lock_user(connection, user_id=session.user_id)
            if (
                user is None
                or user.status is not PersistenceUserStatus.ACTIVE
                or user.session_version != session.version
            ):
                if self._sessions is not None:
                    await self._sessions.revoke(token)
                return None
        return session.csrf

    async def end_session(
        self, token: str | None, csrf_token: str, context: OidcRequestContext
    ) -> None:
        session = await self._sessions.get(token) if self._sessions is not None else None
        if session is None or not hmac.compare_digest(session.csrf, csrf_token):
            raise OidcServiceError("invalid_request", "Invalid logout request")
        if self._sessions is None:
            raise OidcServiceError("invalid_request", "No central session")
        await self._sessions.revoke(token)
        async with self._database().engine.begin() as connection:
            await self._create_audit(
                connection,
                event_type="oidc_session_logout",
                outcome="success",
                user_id=session.user_id,
                client_id="sso",
                reason_code=None,
                context=context,
            )

    async def _bound_transaction(
        self, transaction_id: str, browser_binding: str, *, admin_browser: bool = False
    ) -> OidcAuthorizationTransaction:
        transaction = await self._transactions.get(transaction_id, browser_binding=browser_binding)
        if transaction is None or transaction.admin_browser != admin_browser:
            raise OidcServiceError("invalid_request", "Invalid login transaction")
        if transaction.expires_at_epoch_ms <= self._clock_ms():
            await self._transactions.discard(transaction_id)
            raise OidcServiceError("invalid_request", "Invalid login transaction")
        return transaction

    def _eligible_identity(
        self, user: OidcUserRecord | None, client: OidcClientPolicy
    ) -> tuple[OidcIdentity | None, str | None]:
        if user is None or user.status is not PersistenceUserStatus.ACTIVE:
            return None, "OIDC_USER_INACTIVE"
        if not user.email or not user.email_verified:
            return None, "OIDC_EMAIL_UNVERIFIED"
        if (user.user_type or "UNCLASSIFIED") not in client.allowed_user_types:
            return None, "OIDC_USER_TYPE_DENIED"
        identity = OidcIdentity(
            user_id=user.id,
            email=user.email,
            email_verified=True,
            name=user.name,
            roles=tuple(Role(role.service_key, role.name) for role in user.roles),
        )
        if not has_required_role(identity, client):
            return None, "OIDC_REQUIRED_ROLE_MISSING"
        try:
            project_groups(identity, client)
        except ValueError:
            return None, "OIDC_GROUPS_INVALID"
        return identity, None

    def _client(self, client_id: str) -> OidcClientPolicy:
        client = self._clients.get(client_id)
        if client is None:
            raise OidcServiceError("invalid_request", "Unknown client")
        return client

    @staticmethod
    def _validated_redirect(client: OidcClientPolicy, redirect_uri: str) -> str:
        if redirect_uri not in client.redirect_uris:
            raise OidcServiceError("invalid_request", "Invalid redirect URI")
        return redirect_uri

    @staticmethod
    def _raise_authorization_error(
        error: str, description: str, redirect_uri: str, state: str | None
    ) -> NoReturn:
        raise OidcServiceError(error, description, redirect_uri=redirect_uri, state=state)

    def _resolve_provider_config(self, provider: OAuthProvider) -> OAuthProviderConfig:
        if self._provider_config is None:
            raise OidcServiceError(
                "temporarily_unavailable", "OAuth provider is unavailable", status_code=503
            )
        try:
            return self._provider_config(provider)
        except OAuthProviderConfigurationError:
            raise OidcServiceError(
                "temporarily_unavailable", "OAuth provider is unavailable", status_code=503
            ) from None

    async def _audit_token_failure(
        self, user_id: str, client_id: str, context: OidcRequestContext
    ) -> None:
        await self._write_failure_audit(
            event_type="oidc_token",
            user_id=user_id,
            client_id=client_id,
            reason_code="OIDC_INVALID_GRANT",
            context=context,
        )

    async def _enforce_client_rate_limit(self, client_id: str) -> None:
        if self._redis is None:
            return
        key = f"wiseacct:oidc:rate-limit:client:{sha256_token(client_id)}"
        count = await self._redis().increment_with_ttl(key, self._client_rate_limit_window_seconds)
        if count > self._client_rate_limit_max_requests:
            raise OidcServiceError(
                "temporarily_unavailable",
                "Too many token requests",
                status_code=429,
            )

    async def _write_failure_audit(
        self,
        *,
        event_type: str,
        user_id: str | None,
        client_id: str,
        reason_code: str,
        context: OidcRequestContext,
        provider: str | None = None,
    ) -> None:
        async def write(connection: AsyncConnection) -> None:
            await self._create_audit(
                connection,
                event_type=event_type,
                outcome="failure",
                user_id=user_id,
                client_id=client_id,
                reason_code=reason_code,
                context=context,
                provider=provider,
            )

        await self._database().transaction(database_only_transaction(write))

    async def _create_audit(
        self,
        connection: AsyncConnection,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None,
        client_id: str,
        reason_code: str | None,
        context: OidcRequestContext,
        provider: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        safe_details: dict[str, object] = {"clientId": client_id}
        if details:
            safe_details.update(details)
        await self._audit.create(
            connection,
            event=AuditEventInsert(
                id=str(uuid4()),
                event_type=event_type,
                outcome=outcome,
                created_at=utc_now_ms(),
                user_id=user_id,
                provider=provider,
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                reason_code=reason_code,
                details_json=safe_details,
            ),
        )

    async def _best_effort_consume_code(self, code: str, client_id: str) -> None:
        del client_id
        try:
            await self._codes.discard(code)
        except Exception as error:
            self._report_cleanup_failure("discard_authorization_code", error)

    async def _best_effort_revoke_access(self, token: str) -> None:
        try:
            await self._access_tokens.revoke(token)
        except Exception as error:
            self._report_cleanup_failure("revoke_access_token", error)

    def _report_cleanup_failure(self, operation: str, error: Exception) -> None:
        try:
            self._logger.warning(
                "oidc_cleanup_failure",
                operation=operation,
                error_type=type(error).__name__[:64],
            )
        except Exception:
            return


def _url_with_query(url: str, **values: str) -> str:
    base, fragment_marker, fragment = url.partition("#")
    separator = "?" if "?" not in base else "" if base.endswith(("?", "&")) else "&"
    rendered = f"{base}{separator}{urlencode(values)}"
    return rendered if not fragment_marker else f"{rendered}#{fragment}"
