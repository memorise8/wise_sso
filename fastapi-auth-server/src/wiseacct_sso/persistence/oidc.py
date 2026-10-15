"""Database primitives for the isolated OIDC provider flow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from sqlalchemy import select
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


class _OidcUserRow(Protocol):
    id: object
    email: str | None
    emailVerified: object
    name: str | None
    status: str | UserStatus


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
            roles=tuple(
                RoleAssignment(service_key=str(row.serviceKey), name=str(row.name)) for row in rows
            ),
        )
