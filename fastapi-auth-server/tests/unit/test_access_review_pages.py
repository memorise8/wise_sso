"""점검 메뉴의 관리자 전용 표시를 검증합니다."""

import pytest
from test_sso_sessions import admin_login, admin_rig, viewer_rig


@pytest.mark.parametrize("viewer", [False, True])
def test_access_review_navigation_is_admin_only(viewer: bool) -> None:
    rig = viewer_rig() if viewer else admin_rig()
    assert admin_login(rig).status_code == 303
    response = rig.client.get("/oauth2/admin/dashboard")
    assert response.status_code == 200
    assert ('data-nav="reviews"' in response.text) is (not viewer)
    assert "/assets/admin-access-reviews.js?v=20261117-f6-review-ux" in response.text
    assert response.headers["cache-control"] == "no-store"
