from __future__ import annotations

import pytest
from test_sso_sessions import ORIGIN, admin_csrf, admin_login, admin_rig

from wiseacct_sso.domain.admin import AuditLogListInput


def test_audit_export_requires_admin_csrf_and_preserves_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rig = admin_rig()
    calls: list[tuple[str, AuditLogListInput, str]] = []

    async def export(*, actor_user_id: str, input: AuditLogListInput, reason_code: str) -> bytes:
        calls.append((actor_user_id, input, reason_code))
        return b"event,outcome\\r\\nlogin_success,success\\r\\n"

    monkeypatch.setattr(rig.portal, "export_audit_csv", export, raising=False)
    url = "/oauth2/admin/api/audit-logs/export"
    body = {"reasonCode": "F7 검증"}
    params = {
        "eventType": "login_success",
        "outcome": "success",
        "actorUserId": "actor-1",
        "targetUserId": "target-1",
    }

    assert rig.client.post(url, json=body).status_code == 401
    assert admin_login(rig).status_code == 303
    assert rig.client.post(url, json=body, headers={"origin": ORIGIN}).status_code == 403

    csrf = admin_csrf(rig)
    headers = {"origin": ORIGIN, "x-admin-csrf": csrf}
    assert (
        rig.client.post(
            url, json=body, headers={**headers, "origin": "https://other.example.test"}
        ).status_code
        == 403
    )
    assert rig.client.post(url, json={"reasonCode": " "}, headers=headers).status_code == 400
    assert not calls

    response = rig.client.post(url, params=params, json=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == 'attachment; filename="audit-logs.csv"'
    assert response.content == b"event,outcome\\r\\nlogin_success,success\\r\\n"
    assert calls == [
        (
            rig.identities.user.id,
            AuditLogListInput(
                event_type="login_success",
                outcome="success",
                actor_user_id="actor-1",
                target_user_id="target-1",
            ),
            "F7 검증",
        )
    ]
