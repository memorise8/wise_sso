"""Database primitives for the isolated OIDC provider flow."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.persistence.models import Role, SocialAccount, User, UserRole, UserStatus
from wiseacct_sso.persistence.stores import RoleAssignment


@dataclass(frozen=True, slots=True)
class OidcUserRecord:
    id: str
    email: str | None
    email_verified: bool
    name: str | None
    status: UserStatus
    roles: tuple[RoleAssignment, ...]
    user_type: str | None = None
    session_version: int = 0
    account_expires_at: datetime | None = None


class _OidcUserRow(Protocol):
    id: object
    email: str | None
    emailVerified: object
    name: str | None
    status: str | UserStatus
    ssoSessionVersion: int
    userType: str | None
    accountExpiresAt: datetime | None


_ADMIN_ACCESS_USERS = text("""
SELECT u.id, u.email, u.name, u."userType", u."accountExpiresAt",
       COALESCE((
           SELECT jsonb_agg(jsonb_build_object(
               'id', r.id, 'serviceKey', r."serviceKey", 'name', r.name
           ) ORDER BY r."serviceKey", r.name, r.id)
           FROM "UserRole" ur
           JOIN "Role" r ON r.id = ur."roleId"
           WHERE ur."userId" = u.id
       ), '[]'::jsonb) AS roles
FROM "User" u
WHERE u.status = 'ACTIVE' AND u."emailVerified" AND u.email <> ''
ORDER BY u.id
""")


async def iter_admin_access_users(
    connection: AsyncConnection,
) -> AsyncIterator[tuple[OidcUserRecord, list[dict[str, str]]]]:
    async with connection.stream(_ADMIN_ACCESS_USERS) as result:
        async for row in result:
            roles = cast(list[dict[str, str]], row.roles)
            yield (
                OidcUserRecord(
                    id=row.id,
                    email=row.email,
                    email_verified=True,
                    name=row.name,
                    status=UserStatus.ACTIVE,
                    roles=tuple(
                        RoleAssignment(service_key=role["serviceKey"], name=role["name"])
                        for role in roles
                    ),
                    user_type=row.userType,
                    account_expires_at=row.accountExpiresAt,
                ),
                roles,
            )


class OidcIdentityStore:
    """Read OIDC identities without creating or linking accounts."""

    async def lock_user(
        self, connection: AsyncConnection, *, user_id: str
    ) -> OidcUserRecord | None:
        """Lock the user row before the final role check and success audit.

        Admin status changes lock this row directly. Role removal deletes the
        assignment first and then locks this row while revoking sessions. A plain
        MVCC role read after this lock therefore gives a linearizable decision
        without taking UserRole locks in the inverse order.
        """

        user = (
            await connection.execute(
                select(
                    User.c.id,
                    User.c.email,
                    User.c.emailVerified,
                    User.c.name,
                    User.c.status,
                    User.c.userType,
                    User.c.ssoSessionVersion,
                    User.c.accountExpiresAt,
                )
                .where(User.c.id == user_id)
                .with_for_update()
            )
        ).one_or_none()
        if user is None:
            return None
        return await self._with_roles(connection, user)

    async def find_existing_social_user_id(
        self,
        connection: AsyncConnection,
        *,
        provider: str,
        provider_user_id: str,
    ) -> str | None:
        """Resolve only an already-linked identity; OIDC never signs up or links."""

        row = (
            await connection.execute(
                select(SocialAccount.c.userId)
                .where(
                    SocialAccount.c.provider == provider,
                    SocialAccount.c.providerUserId == provider_user_id,
                )
                .limit(1)
            )
        ).one_or_none()
        return None if row is None else str(row.userId)

    async def _with_roles(self, connection: AsyncConnection, user: object) -> OidcUserRecord:
        typed = cast(_OidcUserRow, user)
        user_id = str(typed.id)
        rows = (
            await connection.execute(
                select(Role.c.serviceKey, Role.c.name)
                .select_from(UserRole.join(Role, UserRole.c.roleId == Role.c.id))
                .where(UserRole.c.userId == user_id)
            )
        ).all()
        return OidcUserRecord(
            id=user_id,
            email=typed.email,
            email_verified=bool(typed.emailVerified),
            name=typed.name,
            status=UserStatus(typed.status),
            user_type=typed.userType,
            session_version=typed.ssoSessionVersion,
            account_expires_at=typed.accountExpiresAt,
            roles=tuple(
                RoleAssignment(service_key=str(row.serviceKey), name=str(row.name)) for row in rows
            ),
        )
