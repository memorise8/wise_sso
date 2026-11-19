"""정책 API의 세션·viewer·CSRF·입력 검사를 검증합니다."""

from datetime import datetime
from typing import cast
from unittest.mock import Mock

import pytest
from test_sso_sessions import ORIGIN, admin_csrf, admin_login, admin_rig, viewer_rig

from wiseacct_sso.application.oidc_policy_changes import OidcPolicyChangeService

CASES = [
    ("GET", "/policy", None),
    ("GET", "/policy-changes", None),
    ("GET", "/policy-changes/request-id", None),
    (
        "POST",
        "/policy-changes",
        {
            "expectedVersion": 2,
            "rollbackToVersion": 1,
            "reasonCode": "복원 요청",
        },
    ),
    (
        "POST",
        "/policy-changes/request-id/decision",
        {
            "decision": "APPROVE",
            "reasonCode": "검토 완료",
        },
    ),
]


@pytest.mark.parametrize("method,path,body", CASES)
def test_policy_api_denies_anonymous_and_viewer(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    rig = viewer_rig()
    factory = Mock()
    monkeypatch.setattr(rig.portal, "oidc_policy_change_service", factory, raising=False)
    url = "/oauth2/admin/api/clients/gitlab" + path
    assert rig.client.request(method, url, json=body).status_code == 401
    assert admin_login(rig).status_code == 303
    response = rig.client.request(
        method,
        url,
        json=body,
        headers={"origin": ORIGIN, "x-admin-csrf": admin_csrf(rig)},
    )
    assert response.status_code == 403
    factory.assert_not_called()


@pytest.mark.parametrize("method,path,body", CASES)
def test_admin_policy_routes_delegate_and_return_utc(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
    body: dict[str, object] | None,
) -> None:
    rig = admin_rig()
    calls: list[dict[str, object]] = []

    class Stub:
        async def result(self, **kwargs: object) -> dict[str, object]:
            calls.append(kwargs)
            return {"checkedAt": datetime(2026, 11, 17, 0, 0)}

        current = result
        history = result
        get = result
        request = result
        decide = result

    factory = Mock(return_value=cast(OidcPolicyChangeService, Stub()))
    monkeypatch.setattr(rig.portal, "oidc_policy_change_service", factory, raising=False)
    assert admin_login(rig).status_code == 303
    response = rig.client.request(
        method,
        "/oauth2/admin/api/clients/gitlab" + path,
        json=body,
        headers={"origin": ORIGIN, "x-admin-csrf": admin_csrf(rig)},
    )
    assert response.status_code == (201 if method == "POST" and path == "/policy-changes" else 200)
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["checkedAt"] == "2026-11-17T00:00:00+00:00"
    assert len(calls) == 1
    assert calls[0]["actor_id"] == rig.identities.user.id
    assert calls[0]["client_id"] == "gitlab"


@pytest.mark.parametrize(
    "path,body",
    [
        (
            "/policy-changes",
            {
                "expectedVersion": 2,
                "rollbackToVersion": 1,
                "reasonCode": "복원 요청",
            },
        ),
        (
            "/policy-changes/request-id/decision",
            {
                "decision": "APPROVE",
                "reasonCode": "검토 완료",
            },
        ),
    ],
)
def test_policy_mutations_require_origin_and_csrf(
    monkeypatch: pytest.MonkeyPatch, path: str, body: dict[str, object]
) -> None:
    rig = admin_rig()
    factory = Mock()
    monkeypatch.setattr(rig.portal, "oidc_policy_change_service", factory, raising=False)
    assert admin_login(rig).status_code == 303
    csrf = admin_csrf(rig)
    url = "/oauth2/admin/api/clients/gitlab" + path
    for headers in (
        {"origin": ORIGIN},
        {"origin": "https://other.example.invalid", "x-admin-csrf": csrf},
    ):
        assert rig.client.post(url, json=body, headers=headers).status_code == 403
    factory.assert_not_called()


@pytest.mark.parametrize(
    "body",
    [
        {"expectedVersion": True, "rollbackToVersion": 1, "reasonCode": "검사"},
        {"expectedVersion": 2, "reasonCode": "검사"},
        {
            "expectedVersion": 2,
            "rollbackToVersion": 1,
            "reasonCode": "검사",
            "clientSecretHash": "허용하지 않는 필드",
        },
    ],
)
def test_invalid_policy_request_is_rejected_before_service(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    rig = admin_rig()
    factory = Mock()
    monkeypatch.setattr(rig.portal, "oidc_policy_change_service", factory, raising=False)
    assert admin_login(rig).status_code == 303
    response = rig.client.post(
        "/oauth2/admin/api/clients/gitlab/policy-changes",
        json=body,
        headers={"origin": ORIGIN, "x-admin-csrf": admin_csrf(rig)},
    )
    assert response.status_code == 400
    factory.assert_not_called()
