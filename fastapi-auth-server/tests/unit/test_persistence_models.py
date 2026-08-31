from datetime import UTC
from typing import cast
from uuid import UUID

from sqlalchemy import DefaultClause, Enum
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP

from wiseacct_sso.persistence.catalog import CatalogEntry, diff_catalog, metadata_catalog
from wiseacct_sso.persistence.models import (
    AuditLog,
    RefreshToken,
    User,
    UserStatus,
    application_uuid,
    metadata,
    utc_now_ms,
)

EXPECTED_TABLES = {
    "AuditLog",
    "EmailVerificationToken",
    "PasswordCredential",
    "PasswordResetToken",
    "PendingPasswordCredential",
    "RefreshToken",
    "Role",
    "SocialAccount",
    "SubjectReservation",
    "User",
    "UserRole",
}
EXPECTED_COLUMNS = {
    "User": (
        "id",
        "email",
        "name",
        "profileUrl",
        "status",
        "createdAt",
        "updatedAt",
        "emailVerified",
    ),
    "PasswordCredential": (
        "id",
        "userId",
        "email",
        "passwordHash",
        "failedLoginCount",
        "lockedUntil",
        "passwordUpdatedAt",
        "createdAt",
        "updatedAt",
    ),
    "PendingPasswordCredential": (
        "id",
        "userId",
        "email",
        "passwordHash",
        "expiresAt",
        "createdAt",
        "updatedAt",
    ),
    "SubjectReservation": ("id", "email", "subjectId", "reason", "createdAt", "updatedAt"),
    "SocialAccount": ("id", "provider", "providerUserId", "providerEmail", "userId", "createdAt"),
    "RefreshToken": (
        "id",
        "tokenHash",
        "userId",
        "expiresAt",
        "revokedAt",
        "createdAt",
        "audience",
    ),
    "EmailVerificationToken": (
        "id",
        "tokenHash",
        "userId",
        "expiresAt",
        "usedAt",
        "createdAt",
        "handoffClientId",
        "handoffAudience",
        "handoffRedirectUri",
        "handoffState",
        "handoffCodeChallenge",
        "handoffCodeChallengeMethod",
    ),
    "PasswordResetToken": ("id", "tokenHash", "userId", "expiresAt", "usedAt", "createdAt"),
    "AuditLog": (
        "id",
        "userId",
        "eventType",
        "outcome",
        "provider",
        "serviceKey",
        "ipAddress",
        "userAgent",
        "reasonCode",
        "createdAt",
        "actorUserId",
        "targetUserId",
        "detailsJson",
    ),
    "Role": ("id", "serviceKey", "name"),
    "UserRole": ("id", "userId", "roleId"),
}


def test_metadata_has_exact_prisma_owned_table_set() -> None:
    assert set(metadata.tables) == EXPECTED_TABLES
    assert all(table.schema is None for table in metadata.tables.values())
    assert {
        name: tuple(column.name for column in table.columns)
        for name, table in metadata.tables.items()
    } == EXPECTED_COLUMNS


def test_postgresql_specific_types_and_defaults_are_explicit() -> None:
    status = User.c.status.type
    assert isinstance(status, Enum)
    assert status.name == "UserStatus"
    assert status.enums == [member.name for member in UserStatus]
    status_default = cast(DefaultClause, User.c.status.server_default)
    email_verified_default = cast(DefaultClause, User.c.emailVerified.server_default)
    audience_default = cast(DefaultClause, RefreshToken.c.audience.server_default)
    assert str(status_default.arg) == "'ACTIVE'"
    assert str(email_verified_default.arg) == "false"
    assert str(audience_default.arg) == "'temis'"
    assert isinstance(AuditLog.c.detailsJson.type, JSONB)

    for table in metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, TIMESTAMP):
                assert column.type.precision == 3
                assert column.type.timezone is False


def test_exact_named_constraints_indexes_and_cascades() -> None:
    catalog = metadata_catalog(metadata)
    names = {(entry.category, entry.name) for entry in catalog}
    assert ("primary_key", "User_pkey") in names
    assert ("index", "User_email_key") in names
    assert ("index", "SocialAccount_provider_providerUserId_key") in names
    assert ("index", "AuditLog_createdAt_idx") in names
    assert ("foreign_key", "PasswordCredential_userId_fkey") in names
    assert ("foreign_key", "AuditLog_targetUserId_fkey") in names
    assert ("enum", "UserStatus") in names

    audit_target = next(entry for entry in catalog if entry.name == "AuditLog_targetUserId_fkey")
    assert "ondelete=SET NULL;onupdate=CASCADE" in audit_target.definition
    user_role = next(entry for entry in catalog if entry.name == "UserRole_roleId_fkey")
    assert "ondelete=CASCADE;onupdate=CASCADE" in user_role.definition


def test_application_values_are_uuid_and_utc_naive_milliseconds() -> None:
    value = application_uuid()
    assert str(UUID(value)) == value

    now = utc_now_ms()
    assert now.tzinfo is None
    assert now.microsecond % 1_000 == 0
    offset = now.replace(tzinfo=UTC).utcoffset()
    assert offset is not None and offset.total_seconds() == 0


def test_catalog_diff_is_order_and_whitespace_insensitive_but_semantic() -> None:
    expected = [CatalogEntry("column", "User.id", "type=TEXT; nullable=false;default='temis'")]
    actual = [
        CatalogEntry("column", "User.id", " type=TEXT;   nullable=false;default='temis'::text ")
    ]
    assert diff_catalog(expected, actual).matches

    mismatch = diff_catalog(expected, [CatalogEntry("column", "User.id", "type=UUID")])
    assert mismatch.missing == tuple(expected)
    assert mismatch.unexpected == (CatalogEntry("column", "User.id", "type=UUID"),)


def test_updated_at_has_no_server_default_or_automatic_ddl_behavior() -> None:
    for table_name in (
        "User",
        "PasswordCredential",
        "PendingPasswordCredential",
        "SubjectReservation",
    ):
        updated_at = metadata.tables[table_name].c.updatedAt
        assert updated_at.server_default is None
        assert updated_at.onupdate is None
