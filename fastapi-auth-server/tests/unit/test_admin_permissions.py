"""viewer 조회 범위와 변경 요청 차단을 검증합니다."""

import pytest

from wiseacct_sso.domain.admin_permissions import viewer_read_allowed


@pytest.mark.parametrize(
    "path",
    [
        "/summary",
        "/users",
        "/users/test-user",
        "/users/test-user/sessions",
        "/clients",
        "/clients/gitlab-temis/members",
        "/roles",
        "/service-access",
        "/audit-logs",
    ],
)
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_viewer_can_read_approved_resources(method: str, path: str) -> None:
    assert viewer_read_allowed(method=method, path=path)


@pytest.mark.parametrize(
    "path",
    [
        "/users",
        "/users/test-user/status",
        "/users/test-user/type",
        "/users/type",
        "/users/test-user/roles",
        "/users/test-user/roles/test-role",
        "/users/test-user/revoke-sessions",
        "/users/test-user/unlock",
        "/audit-logs/export",
        "/external-accounts/test-user/extend",
        "/invitations",
    ],
)
@pytest.mark.parametrize("method", ["POST", "PATCH", "DELETE", "PUT"])
def test_viewer_cannot_mutate_resources(method: str, path: str) -> None:
    assert not viewer_read_allowed(method=method, path=path)


@pytest.mark.parametrize(
    "path",
    [
        "/operations",
        "/security/failure-ip",
        "/security/failure-account",
        "/security/locked",
        "/security/inactive",
        "/external-accounts",
        "/invitations",
        "/audit-logs/export",
        "/clients/test-client/secrets",
        "/users/test-user/unknown",
        "/unknown",
        "/summary/",
        "//summary",
    ],
)
def test_viewer_cannot_read_unapproved_resources(path: str) -> None:
    assert not viewer_read_allowed(method="GET", path=path)
