from datetime import datetime

import pytest

from wiseacct_sso.domain.admin import (
    AdminRoleProfile,
    AdminUserListInput,
    AuditLogListInput,
    AuditRetentionCleanupConfigurationError,
    StoredAuditLogRecord,
    assert_self_admin_role_removal_allowed,
    assert_self_session_revoke_allowed,
    assert_self_status_change_allowed,
    audit_log_page,
    audit_retention_cutoff,
    parse_role_filter,
    sanitize_audit_details,
    sanitize_audit_details_for_read,
)
from wiseacct_sso.domain.users import DomainError, UserStatus

NOW = datetime(2026, 8, 31, 12, 0, 0)


def test_role_filter_matches_express_one_or_two_part_grammar() -> None:
    assert parse_role_filter("admin") == (None, "admin")
    assert parse_role_filter("temis:admin") == ("temis", "admin")
    for malformed in ("", " ", ":admin", "temis:", "temis:admin:extra"):
        with pytest.raises(DomainError) as caught:
            parse_role_filter(malformed)
        assert (caught.value.status_code, caught.value.code) == (400, "INVALID_REQUEST")

    for malformed_page in (0, 1.5, True):
        with pytest.raises(DomainError):
            AdminUserListInput(page=malformed_page)  # type: ignore[arg-type]


def test_self_protection_guards_match_admin_routes() -> None:
    with pytest.raises(DomainError, match="cannot suspend or delete"):
        assert_self_status_change_allowed("admin-1", "admin-1", UserStatus.SUSPENDED)
    assert_self_status_change_allowed("admin-1", "admin-1", UserStatus.ACTIVE)

    with pytest.raises(DomainError, match="cannot remove their own admin role"):
        assert_self_admin_role_removal_allowed(
            "admin-1", "admin-1", AdminRoleProfile("role-1", "temis", "admin")
        )
    assert_self_admin_role_removal_allowed(
        "admin-1", "admin-1", AdminRoleProfile("role-2", "temis", "user")
    )

    with pytest.raises(DomainError, match="cannot revoke their own sessions"):
        assert_self_session_revoke_allowed("admin-1", "admin-1")


def test_audit_details_are_redacted_bounded_and_read_safe() -> None:
    assert sanitize_audit_details(
        {
            "route": "/admin/users/:id/status",
            "refreshToken": "raw-refresh-token",
            "note": "reviewed person@example.test",
            "nested": {"safe": "not exposed"},
        }
    ) == {
        "route": "/admin/users/:id/status",
        "refreshToken": "[REDACTED]",
        "note": "[REDACTED]",
        "nested": "[REDACTED]",
    }

    with pytest.raises(DomainError) as caught:
        sanitize_audit_details({"note": "x" * 3000})
    assert caught.value.code == "AUDIT_DETAILS_TOO_LARGE"
    assert sanitize_audit_details_for_read({"note": "x" * 3000}) == {"truncated": True}
    assert sanitize_audit_details_for_read(["not", "an", "object"]) is None


def test_audit_page_redacts_persisted_details() -> None:
    input = AuditLogListInput(page=2, page_size=5)
    result = audit_log_page(
        (
            StoredAuditLogRecord(
                id="audit-1",
                event_type="admin_user_status_changed",
                outcome="success",
                user_id="target-1",
                actor_user_id="admin-1",
                target_user_id="target-1",
                reason_code="ADMIN_SUSPEND",
                details_json={"email": "person@example.test", "route": "/admin/users"},
                created_at=NOW,
            ),
        ),
        total=7,
        input=input,
    )
    assert result.page == 2 and result.page_size == 5 and result.total == 7
    assert result.items[0].details_json == {
        "email": "[REDACTED]",
        "route": "/admin/users",
    }


def test_retention_cutoff_is_strictly_configured_in_whole_positive_days() -> None:
    assert audit_retention_cutoff(now=NOW, retention_days=180) == datetime(2026, 3, 4, 12, 0, 0)
    for invalid in (0, -1, True):
        with pytest.raises(AuditRetentionCleanupConfigurationError):
            audit_retention_cutoff(now=NOW, retention_days=invalid)
