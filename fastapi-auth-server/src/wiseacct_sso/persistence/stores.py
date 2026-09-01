"""Concurrency-sensitive SQL primitives shared with the Express implementation."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast

from sqlalchemy import delete, exists, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.sql.elements import ColumnElement

from wiseacct_sso.domain.admin import (
    AdminAuditLogPage,
    AdminAuditRecord,
    AdminRoleProfile,
    AdminUserListInput,
    AdminUserPage,
    AdminUserProfile,
    AuditLogListInput,
    AuditRetentionCleanupResult,
    StoredAuditLogRecord,
    audit_log_page,
    audit_retention_cutoff,
    parse_role_filter,
)
from wiseacct_sso.domain.users import UserStatus as DomainUserStatus
from wiseacct_sso.persistence.models import (
    AuditLog,
    EmailVerificationToken,
    PasswordCredential,
    PasswordResetToken,
    PendingPasswordCredential,
    RefreshToken,
    Role,
    SocialAccount,
    SubjectReservation,
    User,
    UserRole,
    UserStatus,
    application_uuid,
)


def _require_one(rowcount: int, operation: str) -> None:
    if rowcount != 1:
        raise RuntimeError(f"{operation} count was not one")


@dataclass(frozen=True, slots=True)
class RoleAssignment:
    service_key: str
    name: str


@dataclass(frozen=True, slots=True)
class CurrentUserRecord:
    id: str
    email: str | None
    email_verified: bool
    name: str | None
    status: UserStatus
    roles: tuple[RoleAssignment, ...]


@dataclass(frozen=True, slots=True)
class PasswordCredentialRecord:
    user_id: str
    email: str
    password_hash: str
    failed_login_count: int
    locked_until: datetime | None
    user_status: UserStatus


@dataclass(frozen=True, slots=True)
class PasswordRegistration:
    user_id: str
    credential_id: str
    email: str
    name: str | None
    password_hash: str
    status: UserStatus
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PendingPasswordUpsert:
    id: str
    user_id: str
    email: str
    password_hash: str
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


class _UserRow(Protocol):
    id: object
    email: str | None
    emailVerified: object
    name: str | None
    status: str | UserStatus


class UserReadStore:
    async def find_by_email(
        self, connection: AsyncConnection, *, email: str
    ) -> CurrentUserRecord | None:
        user = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.emailVerified,
                    User.c.name,
                    User.c.status,
                )
                .where(User.c.email == email)
                .limit(1)
            )
        ).one_or_none()
        if user is None:
            return None
        return await self._with_roles(connection, user)

    async def find_current_active(
        self, connection: AsyncConnection, *, user_id: str
    ) -> CurrentUserRecord | None:
        user = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.emailVerified,
                    User.c.name,
                    User.c.status,
                )
                .where(User.c.id == user_id, User.c.status == UserStatus.ACTIVE)
                .limit(1)
            )
        ).one_or_none()
        if user is None:
            return None
        return await self._with_roles(connection, user)

    async def find_current(
        self, connection: AsyncConnection, *, user_id: str
    ) -> CurrentUserRecord | None:
        """Read current claims without authorizing status, matching password login ordering."""

        user = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.emailVerified,
                    User.c.name,
                    User.c.status,
                )
                .where(User.c.id == user_id)
                .limit(1)
            )
        ).one_or_none()
        if user is None:
            return None
        return await self._with_roles(connection, user)

    async def _with_roles(self, connection: AsyncConnection, user: object) -> CurrentUserRecord:
        typed_user = cast(_UserRow, user)
        user_id = str(typed_user.id)
        role_rows = (
            await connection.execute(
                select(Role.c.serviceKey, Role.c.name)
                .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
                .where(UserRole.c.userId == user_id)
            )
        ).all()
        return CurrentUserRecord(
            id=user_id,
            email=typed_user.email,
            email_verified=bool(typed_user.emailVerified),
            name=typed_user.name,
            status=UserStatus(typed_user.status),
            roles=tuple(
                RoleAssignment(service_key=str(row.serviceKey), name=str(row.name))
                for row in role_rows
            ),
        )


class PasswordAuthStore:
    """Password-auth persistence primitives; callers own the transaction boundary."""

    async def find_credential_by_email(
        self, connection: AsyncConnection, *, email: str
    ) -> PasswordCredentialRecord | None:
        row = (
            await connection.execute(
                select(
                    PasswordCredential.c.userId,
                    PasswordCredential.c.email,
                    PasswordCredential.c.passwordHash,
                    PasswordCredential.c.failedLoginCount,
                    PasswordCredential.c.lockedUntil,
                    User.c.status.label("userStatus"),
                )
                .select_from(
                    PasswordCredential.join(User, PasswordCredential.c.userId == User.c.id)
                )
                .where(PasswordCredential.c.email == email)
                .limit(1)
            )
        ).one_or_none()
        if row is None:
            return None
        return PasswordCredentialRecord(
            user_id=str(row.userId),
            email=str(row.email),
            password_hash=str(row.passwordHash),
            failed_login_count=int(row.failedLoginCount),
            locked_until=row.lockedUntil,
            user_status=UserStatus(row.userStatus),
        )

    async def create_user_with_password(
        self, connection: AsyncConnection, *, registration: PasswordRegistration
    ) -> None:
        created_user = await connection.execute(
            insert(User).values(
                id=registration.user_id,
                email=registration.email,
                name=registration.name,
                status=registration.status,
                createdAt=registration.created_at,
                updatedAt=registration.updated_at,
                emailVerified=False,
            )
        )
        _require_one(created_user.rowcount, "user registration insert")
        created_credential = await connection.execute(
            insert(PasswordCredential).values(
                id=registration.credential_id,
                userId=registration.user_id,
                email=registration.email.lower(),
                passwordHash=registration.password_hash,
                createdAt=registration.created_at,
                updatedAt=registration.updated_at,
            )
        )
        _require_one(created_credential.rowcount, "password credential insert")

    async def upsert_pending_password(
        self, connection: AsyncConnection, *, pending: PendingPasswordUpsert
    ) -> None:
        statement = postgresql_insert(PendingPasswordCredential).values(
            id=pending.id,
            userId=pending.user_id,
            email=pending.email.lower(),
            passwordHash=pending.password_hash,
            expiresAt=pending.expires_at,
            createdAt=pending.created_at,
            updatedAt=pending.updated_at,
        )
        result = await connection.execute(
            statement.on_conflict_do_update(
                index_elements=[PendingPasswordCredential.c.userId],
                set_={
                    "email": statement.excluded.email,
                    "passwordHash": statement.excluded.passwordHash,
                    "expiresAt": statement.excluded.expiresAt,
                    "updatedAt": statement.excluded.updatedAt,
                },
            )
        )
        _require_one(result.rowcount, "pending password credential upsert")

    async def mark_login_success(
        self, connection: AsyncConnection, *, user_id: str, updated_at: datetime
    ) -> None:
        result = await connection.execute(
            update(PasswordCredential)
            .where(PasswordCredential.c.userId == user_id)
            .values(failedLoginCount=0, lockedUntil=None, updatedAt=updated_at)
        )
        _require_one(result.rowcount, "password login-success reset")


@dataclass(frozen=True, slots=True)
class FailedLoginResult:
    found: bool
    failed_login_count: int | None
    locked_until: datetime | None


class FailedLoginStore:
    """Mirror Prisma's atomic increment then conditional threshold update."""

    async def record_failure(
        self,
        connection: AsyncConnection,
        *,
        user_id: str,
        locked_until: datetime,
        updated_at: datetime,
        threshold: int = 5,
    ) -> FailedLoginResult:
        if threshold < 1:
            raise ValueError("threshold must be positive")
        incremented = await connection.execute(
            update(PasswordCredential)
            .where(PasswordCredential.c.userId == user_id)
            .values(
                failedLoginCount=PasswordCredential.c.failedLoginCount + 1,
                updatedAt=updated_at,
            )
            .returning(PasswordCredential.c.failedLoginCount)
        )
        if incremented.rowcount == 0:
            return FailedLoginResult(False, None, None)
        if incremented.rowcount != 1:
            raise RuntimeError("password credential increment count was not one")
        incremented_row = incremented.one_or_none()
        if incremented_row is None:
            raise RuntimeError("password credential increment did not return its count")

        locked = await connection.execute(
            update(PasswordCredential)
            .where(
                PasswordCredential.c.userId == user_id,
                PasswordCredential.c.failedLoginCount >= threshold,
            )
            .values(lockedUntil=locked_until, updatedAt=updated_at)
            .returning(PasswordCredential.c.lockedUntil)
        )
        if locked.rowcount not in {0, 1}:
            raise RuntimeError("password credential lock update count exceeded one")
        locked_row = locked.one_or_none()
        if locked.rowcount == 1 and locked_row is None:
            raise RuntimeError("password credential lock update did not return its timestamp")
        return FailedLoginResult(
            True,
            int(incremented_row.failedLoginCount),
            None if locked_row is None else locked_row.lockedUntil,
        )


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    user_id: str
    audience: str


@dataclass(frozen=True, slots=True)
class RefreshReplacement:
    id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime


RefreshReplacementFactory = Callable[[RefreshTokenRecord], RefreshReplacement]


@dataclass(frozen=True, slots=True)
class RefreshTokenInsert:
    id: str
    token_hash: str
    audience: str
    expires_at: datetime
    created_at: datetime


class TokenIssueStore:
    """Lock an active user, read its claims, then persist its refresh token."""

    async def issue_for_active_user(
        self,
        connection: AsyncConnection,
        *,
        user_id: str,
        refresh: RefreshTokenInsert,
    ) -> CurrentUserRecord | None:
        locked = (
            await connection.execute(
                select(User.c.id)
                .where(User.c.id == user_id, User.c.status == UserStatus.ACTIVE)
                .with_for_update()
            )
        ).one_or_none()
        if locked is None:
            return None

        user = await UserReadStore().find_current_active(connection, user_id=user_id)
        if user is None:
            return None
        created = await connection.execute(
            insert(RefreshToken).values(
                id=refresh.id,
                tokenHash=refresh.token_hash,
                userId=user_id,
                audience=refresh.audience,
                expiresAt=refresh.expires_at,
                createdAt=refresh.created_at,
            )
        )
        _require_one(created.rowcount, "refresh token insert")
        return user


class RefreshRotationConflict(RuntimeError):
    """Signal a lost conditional revoke so the enclosing transaction rolls back."""


class RefreshRotationStore:
    """Perform the Express-compatible read→user lock→conditional revoke→insert order."""

    async def rotate(
        self,
        connection: AsyncConnection,
        *,
        old_token_hash: str,
        expected_audience: str,
        now: datetime,
        replacement: RefreshReplacement | None = None,
        replacement_factory: RefreshReplacementFactory | None = None,
    ) -> RefreshTokenRecord | None:
        if (replacement is None) == (replacement_factory is None):
            raise ValueError("exactly one refresh replacement source is required")
        stored = (
            await connection.execute(
                select(RefreshToken.c.userId, RefreshToken.c.audience)
                .where(RefreshToken.c.tokenHash == old_token_hash)
                .limit(1)
            )
        ).one_or_none()
        if stored is None or stored.audience != expected_audience:
            return None

        token_record = RefreshTokenRecord(user_id=str(stored.userId), audience=str(stored.audience))

        locked_user = (
            await connection.execute(
                select(User.c.id)
                .where(User.c.id == stored.userId, User.c.status == UserStatus.ACTIVE)
                .with_for_update()
            )
        ).one_or_none()
        if locked_user is None:
            return None

        revoked = await connection.execute(
            update(RefreshToken)
            .where(
                RefreshToken.c.tokenHash == old_token_hash,
                RefreshToken.c.revokedAt.is_(None),
                RefreshToken.c.expiresAt > now,
            )
            .values(revokedAt=now)
        )
        if revoked.rowcount != 1:
            raise RefreshRotationConflict("refresh token conditional revoke count was not one")

        selected_replacement = (
            replacement_factory(token_record) if replacement_factory is not None else replacement
        )
        if selected_replacement is None:
            raise RuntimeError("refresh replacement source returned no replacement")
        inserted = await connection.execute(
            insert(RefreshToken).values(
                id=selected_replacement.id,
                tokenHash=selected_replacement.token_hash,
                userId=stored.userId,
                audience=stored.audience,
                expiresAt=selected_replacement.expires_at,
                createdAt=selected_replacement.created_at,
            )
        )
        _require_one(inserted.rowcount, "refresh rotation insert")
        return token_record


class LogoutStore:
    """Mirror Express logout's deliberately non-transactional find-then-update."""

    async def revoke(
        self, connection: AsyncConnection, *, token_hash: str, revoked_at: datetime
    ) -> str | None:
        stored = (
            await connection.execute(
                select(RefreshToken.c.userId)
                .where(
                    RefreshToken.c.tokenHash == token_hash,
                    RefreshToken.c.revokedAt.is_(None),
                )
                .limit(1)
            )
        ).one_or_none()
        await connection.execute(
            update(RefreshToken)
            .where(
                RefreshToken.c.tokenHash == token_hash,
                RefreshToken.c.revokedAt.is_(None),
            )
            .values(revokedAt=revoked_at)
        )
        return None if stored is None else str(stored.userId)


@dataclass(frozen=True, slots=True)
class VerificationEligibleUser:
    id: str
    email: str | None
    status: UserStatus
    has_pending_password_credential: bool


@dataclass(frozen=True, slots=True)
class VerificationHandoff:
    client_id: str
    audience: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    code_challenge_method: str = "S256"


@dataclass(frozen=True, slots=True)
class EmailVerificationTokenInsert:
    id: str
    user_id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime
    handoff: VerificationHandoff | None = None


@dataclass(frozen=True, slots=True)
class EmailVerificationTokenRecord:
    id: str
    user_id: str
    expires_at: datetime
    used_at: datetime | None
    handoff: VerificationHandoff | None


@dataclass(frozen=True, slots=True)
class DefaultRole:
    service_key: str = "temis"
    name: str = "user"


DEFAULT_ROLE = DefaultRole()


async def _seed_temis_and_assign_default_role(
    connection: AsyncConnection,
    *,
    user_id: str,
    default_role: DefaultRole,
) -> None:
    """Mirror the four Prisma role upserts, then its skip-duplicates assignment."""

    for service_key, name in (
        ("temis", "pending"),
        ("temis", "user"),
        ("temis", "admin"),
        (default_role.service_key, default_role.name),
    ):
        await connection.execute(
            postgresql_insert(Role)
            .values(id=application_uuid(), serviceKey=service_key, name=name)
            .on_conflict_do_nothing(index_elements=[Role.c.serviceKey, Role.c.name])
        )

    assigned_role = (
        await connection.execute(
            select(Role.c.id)
            .where(
                Role.c.serviceKey == default_role.service_key,
                Role.c.name == default_role.name,
            )
            .limit(1)
        )
    ).one_or_none()
    if assigned_role is None:
        raise RuntimeError("default role upsert did not resolve a role")
    await connection.execute(
        postgresql_insert(UserRole)
        .values(id=application_uuid(), userId=user_id, roleId=assigned_role.id)
        .on_conflict_do_nothing(index_elements=[UserRole.c.userId, UserRole.c.roleId])
    )


class EmailVerificationStore:
    """Email verification primitives in the exact Express statement order."""

    async def find_eligible_user(
        self, connection: AsyncConnection, *, email: str, now: datetime
    ) -> VerificationEligibleUser | None:
        row = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.status,
                    PendingPasswordCredential.c.expiresAt.label("pendingExpiresAt"),
                )
                .select_from(
                    User.outerjoin(
                        PendingPasswordCredential,
                        PendingPasswordCredential.c.userId == User.c.id,
                    )
                )
                .where(User.c.email == email)
                .limit(1)
            )
        ).one_or_none()
        if row is None:
            return None
        return VerificationEligibleUser(
            id=str(row.id),
            email=row.email,
            status=UserStatus(row.status),
            has_pending_password_credential=(
                row.pendingExpiresAt is not None and row.pendingExpiresAt > now
            ),
        )

    async def create_token(
        self, connection: AsyncConnection, *, token: EmailVerificationTokenInsert
    ) -> None:
        handoff = token.handoff
        result = await connection.execute(
            insert(EmailVerificationToken).values(
                id=token.id,
                userId=token.user_id,
                tokenHash=token.token_hash,
                expiresAt=token.expires_at,
                createdAt=token.created_at,
                handoffClientId=None if handoff is None else handoff.client_id,
                handoffAudience=None if handoff is None else handoff.audience,
                handoffRedirectUri=None if handoff is None else handoff.redirect_uri,
                handoffState=None if handoff is None else handoff.state,
                handoffCodeChallenge=None if handoff is None else handoff.code_challenge,
                handoffCodeChallengeMethod=(
                    None if handoff is None else handoff.code_challenge_method
                ),
            )
        )
        _require_one(result.rowcount, "email verification token insert")

    async def find_token(
        self, connection: AsyncConnection, *, token_hash: str
    ) -> EmailVerificationTokenRecord | None:
        row = (
            await connection.execute(
                select(
                    EmailVerificationToken.c.id,
                    EmailVerificationToken.c.userId,
                    EmailVerificationToken.c.expiresAt,
                    EmailVerificationToken.c.usedAt,
                    EmailVerificationToken.c.handoffClientId,
                    EmailVerificationToken.c.handoffAudience,
                    EmailVerificationToken.c.handoffRedirectUri,
                    EmailVerificationToken.c.handoffState,
                    EmailVerificationToken.c.handoffCodeChallenge,
                    EmailVerificationToken.c.handoffCodeChallengeMethod,
                )
                .where(EmailVerificationToken.c.tokenHash == token_hash)
                .limit(1)
            )
        ).one_or_none()
        if row is None:
            return None
        handoff = None
        if (
            row.handoffClientId
            and row.handoffAudience
            and row.handoffRedirectUri
            and row.handoffCodeChallenge
            and row.handoffCodeChallengeMethod == "S256"
        ):
            handoff = VerificationHandoff(
                client_id=str(row.handoffClientId),
                audience=str(row.handoffAudience),
                redirect_uri=str(row.handoffRedirectUri),
                state=row.handoffState,
                code_challenge=str(row.handoffCodeChallenge),
            )
        return EmailVerificationTokenRecord(
            id=str(row.id),
            user_id=str(row.userId),
            expires_at=row.expiresAt,
            used_at=row.usedAt,
            handoff=handoff,
        )

    async def confirm(
        self,
        connection: AsyncConnection,
        *,
        token_id: str,
        user_id: str,
        used_at: datetime,
        default_role: DefaultRole = DEFAULT_ROLE,
    ) -> str | None:
        user = (
            await connection.execute(
                select(User.c.id, User.c.email, User.c.status).where(User.c.id == user_id).limit(1)
            )
        ).one_or_none()
        pending = (
            await connection.execute(
                select(PendingPasswordCredential).where(
                    PendingPasswordCredential.c.userId == user_id
                )
            )
        ).one_or_none()
        can_activate = (
            user is not None and UserStatus(user.status) is UserStatus.PENDING_EMAIL_VERIFICATION
        )
        can_attach = pending is not None and pending.expiresAt > used_at
        if not can_activate and not can_attach:
            return None

        consumed = await connection.execute(
            update(EmailVerificationToken)
            .where(
                EmailVerificationToken.c.id == token_id,
                EmailVerificationToken.c.userId == user_id,
                EmailVerificationToken.c.usedAt.is_(None),
                EmailVerificationToken.c.expiresAt > used_at,
            )
            .values(usedAt=used_at)
        )
        if consumed.rowcount != 1:
            return None

        if can_activate:
            if user is None:
                raise AssertionError("activation eligibility unexpectedly lost its user")
            reservation = None
            if user.email:
                reservation_email = str(user.email).lower()
                reservation = (
                    await connection.execute(
                        select(SubjectReservation.c.subjectId)
                        .where(SubjectReservation.c.email == reservation_email)
                        .limit(1)
                    )
                ).one_or_none()
            reserved_id = None if reservation is None else str(reservation.subjectId)
            if reserved_id and reserved_id != user_id:
                existing_subject = (
                    await connection.execute(
                        select(User.c.id).where(User.c.id == reserved_id).limit(1)
                    )
                ).one_or_none()
                if existing_subject is not None:
                    return None
            activated_id = reserved_id or user_id
            activated = await connection.execute(
                update(User)
                .where(User.c.id == user_id, User.c.status == UserStatus.PENDING_EMAIL_VERIFICATION)
                .values(
                    **({"id": activated_id} if reserved_id else {}),
                    status=UserStatus.ACTIVE,
                    emailVerified=True,
                    updatedAt=used_at,
                )
            )
            if activated.rowcount != 1:
                return None
            await _seed_temis_and_assign_default_role(
                connection, user_id=activated_id, default_role=default_role
            )
            return activated_id

        if pending is None:
            return None
        created = await connection.execute(
            insert(PasswordCredential).values(
                id=application_uuid(),
                userId=pending.userId,
                email=pending.email,
                passwordHash=pending.passwordHash,
                createdAt=used_at,
                updatedAt=used_at,
                passwordUpdatedAt=used_at,
            )
        )
        _require_one(created.rowcount, "pending password credential attach")
        removed = await connection.execute(
            delete(PendingPasswordCredential).where(PendingPasswordCredential.c.userId == user_id)
        )
        _require_one(removed.rowcount, "pending password credential delete")
        return user_id


@dataclass(frozen=True, slots=True)
class PasswordResetUser:
    id: str
    email: str


@dataclass(frozen=True, slots=True)
class PasswordResetTokenInsert:
    id: str
    user_id: str
    token_hash: str
    expires_at: datetime
    created_at: datetime


class PasswordResetStore:
    async def find_active_user(
        self, connection: AsyncConnection, *, email: str
    ) -> PasswordResetUser | None:
        row = (
            await connection.execute(
                select(PasswordCredential.c.userId, PasswordCredential.c.email)
                .select_from(
                    PasswordCredential.join(User, PasswordCredential.c.userId == User.c.id)
                )
                .where(PasswordCredential.c.email == email, User.c.status == UserStatus.ACTIVE)
                .limit(1)
            )
        ).one_or_none()
        return None if row is None else PasswordResetUser(id=str(row.userId), email=str(row.email))

    async def create_token(
        self, connection: AsyncConnection, *, token: PasswordResetTokenInsert
    ) -> None:
        result = await connection.execute(
            insert(PasswordResetToken).values(
                id=token.id,
                userId=token.user_id,
                tokenHash=token.token_hash,
                expiresAt=token.expires_at,
                createdAt=token.created_at,
            )
        )
        _require_one(result.rowcount, "password reset token insert")

    async def confirm(
        self,
        connection: AsyncConnection,
        *,
        token_hash: str,
        password_hash: str,
        now: datetime,
    ) -> str | None:
        token = (
            await connection.execute(
                select(PasswordResetToken.c.id, PasswordResetToken.c.userId)
                .where(
                    PasswordResetToken.c.tokenHash == token_hash,
                    PasswordResetToken.c.usedAt.is_(None),
                    PasswordResetToken.c.expiresAt > now,
                )
                .limit(1)
            )
        ).one_or_none()
        if token is None:
            return None
        consumed = await connection.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.c.id == token.id,
                PasswordResetToken.c.usedAt.is_(None),
                PasswordResetToken.c.expiresAt > now,
            )
            .values(usedAt=now)
        )
        if consumed.rowcount != 1:
            return None
        locked = (
            await connection.execute(
                select(User.c.id).where(User.c.id == token.userId).with_for_update()
            )
        ).one_or_none()
        if locked is None:
            return None
        updated = await connection.execute(
            update(PasswordCredential)
            .where(PasswordCredential.c.userId == token.userId)
            .values(
                passwordHash=password_hash,
                failedLoginCount=0,
                lockedUntil=None,
                passwordUpdatedAt=now,
                updatedAt=now,
            )
        )
        _require_one(updated.rowcount, "password reset credential update")
        await connection.execute(
            update(RefreshToken)
            .where(RefreshToken.c.userId == token.userId, RefreshToken.c.revokedAt.is_(None))
            .values(revokedAt=now)
        )
        return str(token.userId)


@dataclass(frozen=True, slots=True)
class OAuthProfileRecord:
    provider: str
    provider_user_id: str
    email: str | None
    email_verified: bool
    name: str | None
    profile_url: str | None


@dataclass(frozen=True, slots=True)
class OAuthUserRecord:
    id: str
    email: str | None
    email_verified: bool
    name: str | None
    profile_url: str | None
    status: UserStatus


class OAuthIdentityStore:
    async def find_by_provider_id(
        self,
        connection: AsyncConnection,
        *,
        provider: str,
        provider_user_id: str,
    ) -> OAuthUserRecord | None:
        row = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.emailVerified,
                    User.c.name,
                    User.c.profileUrl,
                    User.c.status,
                )
                .select_from(SocialAccount.join(User, SocialAccount.c.userId == User.c.id))
                .where(
                    SocialAccount.c.provider == provider,
                    SocialAccount.c.providerUserId == provider_user_id,
                )
                .limit(1)
            )
        ).one_or_none()
        return None if row is None else self._record(row)

    async def resolve_or_create(
        self,
        connection: AsyncConnection,
        *,
        profile: OAuthProfileRecord,
        default_role: DefaultRole,
        now: datetime,
    ) -> OAuthUserRecord:
        normalized_email = profile.email.strip().lower() if profile.email is not None else None
        if normalized_email and profile.email_verified:
            existing = (
                await connection.execute(
                    select(User).where(User.c.email == normalized_email).limit(1)
                )
            ).one_or_none()
            if existing is not None:
                if (
                    UserStatus(existing.status) is UserStatus.PENDING_EMAIL_VERIFICATION
                    and not existing.emailVerified
                ):
                    removed = await connection.execute(delete(User).where(User.c.id == existing.id))
                    _require_one(removed.rowcount, "pending OAuth identity replacement delete")
                elif UserStatus(existing.status) is UserStatus.ACTIVE and existing.emailVerified:
                    linked = await connection.execute(
                        insert(SocialAccount).values(
                            id=application_uuid(),
                            provider=profile.provider,
                            providerUserId=profile.provider_user_id,
                            providerEmail=normalized_email,
                            userId=existing.id,
                            createdAt=now,
                        )
                    )
                    _require_one(linked.rowcount, "OAuth identity attach")
                    return self._record(existing)

        user_email = normalized_email
        if user_email:
            email_owner = (
                await connection.execute(
                    select(User.c.id).where(User.c.email == user_email).limit(1)
                )
            ).one_or_none()
            if email_owner is not None:
                user_email = None
        reserved = None
        if user_email:
            reserved = (
                await connection.execute(
                    select(SubjectReservation.c.subjectId)
                    .where(SubjectReservation.c.email == user_email)
                    .limit(1)
                )
            ).one_or_none()
        user_id = str(reserved.subjectId) if reserved is not None else application_uuid()
        created = await connection.execute(
            insert(User)
            .values(
                id=user_id,
                email=user_email,
                emailVerified=profile.email_verified,
                name=profile.name,
                profileUrl=profile.profile_url,
                status=UserStatus.ACTIVE,
                createdAt=now,
                updatedAt=now,
            )
            .returning(
                User.c.id,
                User.c.email,
                User.c.emailVerified,
                User.c.name,
                User.c.profileUrl,
                User.c.status,
            )
        )
        created_user = created.one_or_none()
        if created_user is None:
            raise RuntimeError("OAuth user insert did not return a user")
        social = await connection.execute(
            insert(SocialAccount).values(
                id=application_uuid(),
                provider=profile.provider,
                providerUserId=profile.provider_user_id,
                providerEmail=profile.email,
                userId=user_id,
                createdAt=now,
            )
        )
        _require_one(social.rowcount, "OAuth social account insert")
        await _seed_temis_and_assign_default_role(
            connection, user_id=user_id, default_role=default_role
        )
        return self._record(created_user)

    @staticmethod
    def _record(row: object) -> OAuthUserRecord:
        typed = cast(_OAuthUserRow, row)
        return OAuthUserRecord(
            id=str(typed.id),
            email=typed.email,
            email_verified=bool(typed.emailVerified),
            name=typed.name,
            profile_url=typed.profileUrl,
            status=UserStatus(typed.status),
        )


class _OAuthUserRow(Protocol):
    id: object
    email: str | None
    emailVerified: object
    name: str | None
    profileUrl: str | None
    status: str | UserStatus


@dataclass(frozen=True, slots=True)
class AuditEventInsert:
    id: str
    event_type: str
    outcome: str
    created_at: datetime
    user_id: str | None = None
    actor_user_id: str | None = None
    target_user_id: str | None = None
    provider: str | None = None
    service_key: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    reason_code: str | None = None
    details_json: Mapping[str, object] | None = None


class AuditStore:
    async def create(self, connection: AsyncConnection, *, event: AuditEventInsert) -> None:
        result = await connection.execute(
            insert(AuditLog).values(
                id=event.id,
                eventType=event.event_type,
                outcome=event.outcome,
                createdAt=event.created_at,
                userId=event.user_id,
                actorUserId=event.actor_user_id,
                targetUserId=event.target_user_id,
                provider=event.provider,
                serviceKey=event.service_key,
                ipAddress=event.ip_address,
                userAgent=event.user_agent,
                reasonCode=event.reason_code,
                detailsJson=None if event.details_json is None else dict(event.details_json),
            )
        )
        _require_one(result.rowcount, "audit event insert")

    async def find_user_id_by_email(self, connection: AsyncConnection, *, email: str) -> str | None:
        row = (
            await connection.execute(
                select(User.c.id).where(User.c.email == email.strip().lower()).limit(1)
            )
        ).one_or_none()
        return None if row is None else str(row.id)

    async def find_user_id_by_password_email(
        self, connection: AsyncConnection, *, email: str
    ) -> str | None:
        row = (
            await connection.execute(
                select(PasswordCredential.c.userId)
                .where(PasswordCredential.c.email == email.strip().lower())
                .limit(1)
            )
        ).one_or_none()
        return None if row is None else str(row.userId)


class _AdminUserRow(Protocol):
    id: object
    email: str | None
    name: str | None
    status: str | UserStatus
    createdAt: datetime


class AdminDirectoryStore:
    """Connection-scoped administrator directory reads matching Prisma selection rules."""

    async def list_users(
        self, connection: AsyncConnection, *, input: AdminUserListInput
    ) -> AdminUserPage:
        conditions: list[ColumnElement[bool]] = []
        if input.status is not None:
            conditions.append(User.c.status == input.status)
        if input.email is not None:
            conditions.append(User.c.email.ilike(f"%{input.email.strip()}%"))
        if input.role is not None:
            service_key, role_name = parse_role_filter(input.role)
            role_conditions = [
                UserRole.c.userId == User.c.id,
                UserRole.c.roleId == Role.c.id,
                Role.c.name == role_name,
            ]
            if service_key is not None:
                role_conditions.append(Role.c.serviceKey == service_key)
            conditions.append(
                exists(select(1).select_from(UserRole.join(Role)).where(*role_conditions))
            )

        page_rows = (
            await connection.execute(
                select(User.c.id, User.c.email, User.c.name, User.c.status, User.c.createdAt)
                .where(*conditions)
                .order_by(User.c.createdAt.desc())
                .offset((input.page - 1) * input.page_size)
                .limit(input.page_size)
            )
        ).all()
        total = int(
            (
                await connection.execute(select(func.count()).select_from(User).where(*conditions))
            ).scalar_one()
        )

        user_ids = [str(row.id) for row in page_rows]
        roles_by_user: dict[str, list[AdminRoleProfile]] = {user_id: [] for user_id in user_ids}
        if user_ids:
            role_rows = (
                await connection.execute(
                    select(
                        UserRole.c.userId,
                        Role.c.id,
                        Role.c.serviceKey,
                        Role.c.name,
                    )
                    .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
                    .where(UserRole.c.userId.in_(user_ids))
                )
            ).all()
            for role_row in role_rows:
                roles_by_user[str(role_row.userId)].append(
                    AdminRoleProfile(
                        id=str(role_row.id),
                        service_key=str(role_row.serviceKey),
                        name=str(role_row.name),
                    )
                )

        return AdminUserPage(
            items=tuple(
                self._profile(row, roles=tuple(roles_by_user[str(row.id)])) for row in page_rows
            ),
            total=total,
            page=input.page,
            page_size=input.page_size,
        )

    async def find_role_by_id(
        self, connection: AsyncConnection, *, role_id: str
    ) -> AdminRoleProfile | None:
        row = (
            await connection.execute(
                select(Role.c.id, Role.c.serviceKey, Role.c.name)
                .where(Role.c.id == role_id)
                .limit(1)
            )
        ).one_or_none()
        return (
            None
            if row is None
            else AdminRoleProfile(
                id=str(row.id), service_key=str(row.serviceKey), name=str(row.name)
            )
        )

    async def is_active_temis_admin(self, connection: AsyncConnection, *, user_id: str) -> bool:
        row = (
            await connection.execute(
                select(User.c.id)
                .select_from(
                    User.join(UserRole, UserRole.c.userId == User.c.id).join(
                        Role, Role.c.id == UserRole.c.roleId
                    )
                )
                .where(
                    User.c.id == user_id,
                    User.c.status == UserStatus.ACTIVE,
                    Role.c.serviceKey == "temis",
                    Role.c.name == "admin",
                )
                .limit(1)
            )
        ).one_or_none()
        return row is not None

    @staticmethod
    def _profile(row: object, *, roles: tuple[AdminRoleProfile, ...]) -> AdminUserProfile:
        typed = cast(_AdminUserRow, row)
        return AdminUserProfile(
            id=str(typed.id),
            email=typed.email,
            name=typed.name,
            status=DomainUserStatus(typed.status),
            created_at=typed.createdAt,
            roles=roles,
        )


class AdminMutationStore:
    """Atomic admin mutation primitives; the application owns the transaction boundary."""

    async def update_user_status(
        self,
        connection: AsyncConnection,
        *,
        user_id: str,
        status: DomainUserStatus,
        updated_at: datetime,
    ) -> bool:
        result = await connection.execute(
            update(User).where(User.c.id == user_id).values(status=status, updatedAt=updated_at)
        )
        if result.rowcount not in {0, 1}:
            raise RuntimeError("admin user status update count exceeded one")
        return result.rowcount == 1

    async def lock_user_for_refresh_token_revocation(
        self, connection: AsyncConnection, *, user_id: str
    ) -> bool:
        row = (
            await connection.execute(
                select(User.c.id).where(User.c.id == user_id).with_for_update()
            )
        ).one_or_none()
        return row is not None

    async def revoke_all_refresh_tokens_for_user(
        self, connection: AsyncConnection, *, user_id: str, revoked_at: datetime
    ) -> int:
        if not await self.lock_user_for_refresh_token_revocation(connection, user_id=user_id):
            return 0
        result = await connection.execute(
            update(RefreshToken)
            .where(RefreshToken.c.userId == user_id, RefreshToken.c.revokedAt.is_(None))
            .values(revokedAt=revoked_at)
        )
        return int(result.rowcount)

    async def upsert_role(
        self, connection: AsyncConnection, *, service_key: str, name: str
    ) -> AdminRoleProfile:
        statement = postgresql_insert(Role).values(
            id=application_uuid(), serviceKey=service_key, name=name
        )
        row = (
            await connection.execute(
                statement.on_conflict_do_update(
                    index_elements=[Role.c.serviceKey, Role.c.name],
                    set_={"serviceKey": statement.excluded.serviceKey},
                ).returning(Role.c.id, Role.c.serviceKey, Role.c.name)
            )
        ).one_or_none()
        if row is None:
            raise RuntimeError("admin role upsert did not return a role")
        return AdminRoleProfile(id=str(row.id), service_key=str(row.serviceKey), name=str(row.name))

    async def find_role(
        self, connection: AsyncConnection, *, service_key: str, name: str
    ) -> AdminRoleProfile | None:
        row = (
            await connection.execute(
                select(Role.c.id, Role.c.serviceKey, Role.c.name)
                .where(Role.c.serviceKey == service_key, Role.c.name == name)
                .limit(1)
            )
        ).one_or_none()
        return (
            None
            if row is None
            else AdminRoleProfile(
                id=str(row.id), service_key=str(row.serviceKey), name=str(row.name)
            )
        )

    async def assign_role_to_user(
        self, connection: AsyncConnection, *, user_id: str, role_id: str
    ) -> bool:
        result = await connection.execute(
            postgresql_insert(UserRole)
            .values(id=application_uuid(), userId=user_id, roleId=role_id)
            .on_conflict_do_nothing(index_elements=[UserRole.c.userId, UserRole.c.roleId])
        )
        if result.rowcount not in {0, 1}:
            raise RuntimeError("admin user role insert count exceeded one")
        return result.rowcount == 1

    async def remove_role_from_user(
        self, connection: AsyncConnection, *, user_id: str, role_id: str
    ) -> bool:
        result = await connection.execute(
            delete(UserRole).where(UserRole.c.userId == user_id, UserRole.c.roleId == role_id)
        )
        return result.rowcount > 0

    async def create_admin_audit_log(
        self, connection: AsyncConnection, *, event: AdminAuditRecord, created_at: datetime
    ) -> None:
        result = await connection.execute(
            insert(AuditLog).values(
                id=application_uuid(),
                eventType=event.event_type,
                outcome=event.outcome,
                userId=event.target_user_id,
                actorUserId=event.actor_user_id,
                targetUserId=event.target_user_id,
                reasonCode=event.reason_code,
                detailsJson=(None if event.details_json is None else dict(event.details_json)),
                createdAt=created_at,
            )
        )
        _require_one(result.rowcount, "admin audit event insert")


class AdminAuditQueryStore:
    async def query(
        self, connection: AsyncConnection, *, input: AuditLogListInput
    ) -> AdminAuditLogPage:
        conditions: list[ColumnElement[bool]] = []
        if input.created_at_from is not None:
            conditions.append(AuditLog.c.createdAt >= _postgres_naive_utc(input.created_at_from))
        if input.created_at_to is not None:
            conditions.append(AuditLog.c.createdAt <= _postgres_naive_utc(input.created_at_to))
        for column, value in (
            (AuditLog.c.eventType, input.event_type),
            (AuditLog.c.outcome, input.outcome),
            (AuditLog.c.userId, input.user_id),
            (AuditLog.c.actorUserId, input.actor_user_id),
            (AuditLog.c.targetUserId, input.target_user_id),
            (AuditLog.c.reasonCode, input.reason_code),
        ):
            if value is not None:
                conditions.append(column == value)

        rows = (
            await connection.execute(
                select(
                    AuditLog.c.id,
                    AuditLog.c.eventType,
                    AuditLog.c.outcome,
                    AuditLog.c.userId,
                    AuditLog.c.actorUserId,
                    AuditLog.c.targetUserId,
                    AuditLog.c.reasonCode,
                    AuditLog.c.detailsJson,
                    AuditLog.c.createdAt,
                )
                .where(*conditions)
                .order_by(AuditLog.c.createdAt.desc())
                .offset((input.page - 1) * input.page_size)
                .limit(input.page_size)
            )
        ).all()
        total = int(
            (
                await connection.execute(
                    select(func.count()).select_from(AuditLog).where(*conditions)
                )
            ).scalar_one()
        )
        records = tuple(
            StoredAuditLogRecord(
                id=str(row.id),
                event_type=str(row.eventType),
                outcome=str(row.outcome),
                user_id=None if row.userId is None else str(row.userId),
                actor_user_id=(None if row.actorUserId is None else str(row.actorUserId)),
                target_user_id=(None if row.targetUserId is None else str(row.targetUserId)),
                reason_code=None if row.reasonCode is None else str(row.reasonCode),
                details_json=row.detailsJson,
                created_at=row.createdAt,
            )
            for row in rows
        )
        return audit_log_page(records, total=total, input=input)


def _postgres_naive_utc(value: datetime) -> datetime:
    """Bind instants safely to Prisma's PostgreSQL TIMESTAMP(3) columns."""

    if value.tzinfo is None or value.utcoffset() is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


class AuditRetentionStore:
    async def count_older_than(self, connection: AsyncConnection, *, cutoff: datetime) -> int:
        return int(
            (
                await connection.execute(
                    select(func.count()).select_from(AuditLog).where(AuditLog.c.createdAt < cutoff)
                )
            ).scalar_one()
        )

    async def delete_older_than(self, connection: AsyncConnection, *, cutoff: datetime) -> int:
        result = await connection.execute(delete(AuditLog).where(AuditLog.c.createdAt < cutoff))
        return int(result.rowcount)

    async def cleanup(
        self,
        connection: AsyncConnection,
        *,
        now: datetime,
        retention_days: int = 180,
        execute: bool = False,
    ) -> AuditRetentionCleanupResult:
        cutoff = audit_retention_cutoff(now=now, retention_days=retention_days)
        deleted_count = (
            await self.delete_older_than(connection, cutoff=cutoff)
            if execute
            else await self.count_older_than(connection, cutoff=cutoff)
        )
        return AuditRetentionCleanupResult(
            cutoff=cutoff,
            deleted_count=deleted_count,
            dry_run=not execute,
            retention_days=retention_days,
        )
