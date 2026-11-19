"""감사 로그 이메일 전달과 기존 민감 정보 제거를 검증합니다."""

from datetime import UTC, datetime

from wiseacct_sso.api.routes.admin import _audit_page
from wiseacct_sso.domain.admin import (
    AuditLogListInput,
    StoredAuditLogRecord,
    audit_log_page,
)


def test_audit_emails_reach_response_without_exposing_sensitive_details() -> None:
    record = StoredAuditLogRecord(
        id="audit-email-check",
        event_type="admin_oidc_policy_approved",
        outcome="success",
        user_id="user-id",
        actor_user_id="actor-id",
        target_user_id="target-id",
        reason_code="검토 완료",
        details_json={"password": "must-not-appear"},
        created_at=datetime(2026, 11, 18, tzinfo=UTC),
        user_email="user@example.invalid",
        actor_user_email="admin@example.invalid",
        target_user_email="target@example.invalid",
    )
    page = audit_log_page((record,), total=1, input=AuditLogListInput(page=1, page_size=20))
    item = page.items[0]
    assert item.user_email == "user@example.invalid"
    assert item.actor_user_email == "admin@example.invalid"
    assert item.target_user_email == "target@example.invalid"
    body = bytes(_audit_page(page).body).decode("utf-8")
    assert '"actorUserEmail":"admin@example.invalid"' in body
    assert '"targetUserEmail":"target@example.invalid"' in body
    assert "must-not-appear" not in body


def test_audit_record_without_email_remains_readable() -> None:
    record = StoredAuditLogRecord(
        id="audit-without-user",
        event_type="login_failure",
        outcome="failure",
        user_id=None,
        actor_user_id=None,
        target_user_id=None,
        reason_code=None,
        details_json=None,
        created_at=datetime(2026, 11, 18, tzinfo=UTC),
    )
    page = audit_log_page((record,), total=1, input=AuditLogListInput(page=1, page_size=20))
    assert page.items[0].actor_user_email is None
    assert page.total == 1
    assert _audit_page(page).status_code == 200
