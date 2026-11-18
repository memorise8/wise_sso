"""점검 API의 인증·권한·CSRF와 UTC 응답을 검증합니다."""

from datetime import datetime
from typing import cast
from unittest.mock import Mock

import pytest
from test_sso_sessions import ORIGIN, admin_csrf, admin_login, admin_rig, viewer_rig

from wiseacct_sso.application.access_reviews import AccessReviewService

CASES = [
    ("GET", "", None),
    ("POST", "", {"title": "권한 점검", "reasonCode": "정기 확인", "serviceKeys": ["sso"]}),
    ("GET", "/review-id", None),
    ("GET", "/review-id/items", None),
    ("POST", "/review-id/items/item-id/decision", {"decision": "KEEP", "reasonCode": "계속 사용"}),
    ("POST", "/review-id/complete", {"reasonCode": "확인 완료"}),
]


@pytest.mark.parametrize("method,path,body", CASES)
def test_review_api_denies_anonymous_and_viewer(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    rig = viewer_rig()
    factory = Mock()
    monkeypatch.setattr(rig.portal, "access_review_service", factory, raising=False)
    url = "/oauth2/admin/api/access-reviews" + path

    assert rig.client.request(method, url, json=body).status_code == 401
    assert admin_login(rig).status_code == 303
    csrf = admin_csrf(rig)
    response = rig.client.request(
        method,
        url,
        json=body,
        headers={"origin": ORIGIN, "x-admin-csrf": csrf},
    )
    assert response.status_code == 403
    factory.assert_not_called()


def test_review_start_requires_csrf_and_serializes_utc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = admin_rig()
    calls: list[dict[str, object]] = []

    class ReviewStub:
        async def start(self, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"id": "review-id", "startedAt": datetime(2026, 11, 17, 0, 0, 0)}

    stub = ReviewStub()
    factory = Mock(return_value=cast(AccessReviewService, stub))
    monkeypatch.setattr(rig.portal, "access_review_service", factory, raising=False)
    assert admin_login(rig).status_code == 303
    csrf = admin_csrf(rig)
    url = "/oauth2/admin/api/access-reviews"
    body = {"title": "권한 점검", "reasonCode": "정기 확인", "serviceKeys": ["sso"]}

    assert rig.client.post(url, json=body, headers={"origin": ORIGIN}).status_code == 403
    assert (
        rig.client.post(
            url,
            json=body,
            headers={"origin": "https://other.example.test", "x-admin-csrf": csrf},
        ).status_code
        == 403
    )
    factory.assert_not_called()

    response = rig.client.post(url, json=body, headers={"origin": ORIGIN, "x-admin-csrf": csrf})
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["startedAt"] == "2026-11-17T00:00:00+00:00"
    assert calls == [
        {
            "actor_id": rig.identities.user.id,
            "title": "권한 점검",
            "reason": "정기 확인",
            "service_keys": ("sso",),
        }
    ]


def test_keep_can_omit_reason_but_revoke_requires_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = admin_rig()
    calls: list[dict[str, object]] = []

    class ReviewStub:
        async def decide(self, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"decision": "KEEP"}

    monkeypatch.setattr(
        rig.portal,
        "access_review_service",
        lambda: cast(AccessReviewService, ReviewStub()),
        raising=False,
    )
    assert admin_login(rig).status_code == 303
    headers = {"origin": ORIGIN, "x-admin-csrf": admin_csrf(rig)}
    url = "/oauth2/admin/api/access-reviews/review-id/items/item-id/decision"

    assert rig.client.post(url, json={"decision": "REVOKE"}, headers=headers).status_code == 400
    assert calls == []

    response = rig.client.post(url, json={"decision": "KEEP"}, headers=headers)
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0]["reason"] is None
