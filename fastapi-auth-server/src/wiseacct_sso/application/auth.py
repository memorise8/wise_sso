"""Phase 4 password-auth application service with explicit transaction ownership."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.domain.auth import (
    PENDING_PASSWORD_CREDENTIAL_TTL,
    PasswordAuthFailure,
    PasswordAuthReason,
    PasswordPolicy,
    assert_password_policy,
    normalize_email,
)
from wiseacct_sso.domain.tokens import (
    AccessTokenIdentity,
    IssuedRefreshToken,
    RoleClaim,
    TokenValidationError,
)
from wiseacct_sso.domain.users import CurrentUser, DomainError, Role, UserStatus
from wiseacct_sso.infrastructure.redis import RedisStateStore, rate_limit_key
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
    FailedLoginStore,
    LogoutStore,
    PasswordAuthStore,
    PasswordRegistration,
    PendingPasswordUpsert,
    RefreshReplacement,
    RefreshRotationConflict,
    RefreshRotationStore,
    RefreshTokenInsert,
    RefreshTokenRecord,
    TokenIssueStore,
    UserReadStore,
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


class Phase4AuthService:
    """Concrete runtime service; all retryable callbacks contain database effects only."""

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
    ) -> None:
        self._database = database
        self._redis = redis
        self._passwords = passwords
        self._tokens = tokens
        self._password_policy = password_policy
        self._default_audience = default_audience
        self._rate_limit_window_seconds = rate_limit_window_seconds
        self._rate_limit_max_requests = rate_limit_max_requests
        self._users = UserReadStore()
        self._password_store = PasswordAuthStore()
        self._failed_logins = FailedLoginStore()
        self._token_issue = TokenIssueStore()
        self._rotation = RefreshRotationStore()
        self._logout = LogoutStore()
        self._audit = AuditStore()

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

    async def login(self, input: LoginInput, context: RequestAuditContext) -> TokenPair:
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
        return await self._issue_pair(user.id, self._default_audience)

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
        )

        async def create(connection: AsyncConnection) -> None:
            await self._audit.create(connection, event=event)

        await self._database().transaction(database_only_transaction(create))
