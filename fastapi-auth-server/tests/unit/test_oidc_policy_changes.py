"""편집 필드 제한·연결 설정 보존·승인 규칙을 검증합니다."""

import pytest
from pydantic import ValidationError

from wiseacct_sso.domain.oidc_policy_changes import (
    EditableOidcPolicy,
    assert_other_approver,
    assert_policy_version,
    policy_reason,
)
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH
from wiseacct_sso.oidc_config import OidcClientPolicy


def client_policy() -> OidcClientPolicy:
    return OidcClientPolicy.model_validate(
        {
            "clientId": "gitlab-test",
            "redirectUris": ["https://gitlab.example.invalid/auth/callback"],
            "clientSecretHash": DUMMY_PASSWORD_HASH,
            "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
            "groupsServiceKeys": ["gitlab"],
            "allowedUserTypes": ["EMPLOYEE", "EXTERNAL"],
            "allowWithoutRequiredRole": False,
            "ssoAutoLogin": True,
        }
    )


def test_editable_policy_contains_only_five_public_fields() -> None:
    policy = EditableOidcPolicy.from_client(client_policy())
    assert set(policy.public_payload()) == {
        "allowedUserTypes",
        "requiredRoles",
        "allowWithoutRequiredRole",
        "groupsServiceKeys",
        "ssoAutoLogin",
    }
    assert DUMMY_PASSWORD_HASH not in str(policy.public_payload())


@pytest.mark.parametrize(
    "key,value",
    [
        ("clientId", "other-client"),
        ("clientSecretHash", "synthetic-secret"),
        ("redirectUris", ["https://other.example.invalid/"]),
        ("requirePkce", False),
        ("allowedScopes", ["openid"]),
        ("signingKey", "synthetic-key"),
    ],
)
def test_policy_rejects_non_editable_fields(key: str, value: object) -> None:
    payload = EditableOidcPolicy.from_client(client_policy()).public_payload()
    payload[key] = value
    with pytest.raises(ValidationError):
        EditableOidcPolicy.model_validate(payload)


def test_policy_change_preserves_connection_settings() -> None:
    original = client_policy()
    payload = EditableOidcPolicy.from_client(original).public_payload()
    payload["ssoAutoLogin"] = False
    payload["allowedUserTypes"] = ["EMPLOYEE"]
    updated = EditableOidcPolicy.model_validate(payload).apply_to_client(original)

    assert updated.sso_auto_login is False
    assert updated.allowed_user_types == ("EMPLOYEE",)
    assert updated.client_id == original.client_id
    assert updated.redirect_uris == original.redirect_uris
    assert updated.client_secret_hash == original.client_secret_hash
    assert updated.require_pkce == original.require_pkce
    assert updated.allowed_scopes == original.allowed_scopes


def test_user_type_all_uses_none_and_round_trips() -> None:
    payload = EditableOidcPolicy.from_client(client_policy()).public_payload()
    payload["allowedUserTypes"] = None
    updated = EditableOidcPolicy.model_validate(payload).apply_to_client(client_policy())
    assert updated.allowed_user_types is None


@pytest.mark.parametrize("key", ["allowWithoutRequiredRole", "ssoAutoLogin"])
@pytest.mark.parametrize("value", ["true", 1, None])
def test_policy_requires_actual_booleans(key: str, value: object) -> None:
    payload = EditableOidcPolicy.from_client(client_policy()).public_payload()
    payload[key] = value
    with pytest.raises(ValidationError):
        EditableOidcPolicy.model_validate(payload)


def test_role_projection_must_include_required_service() -> None:
    payload = EditableOidcPolicy.from_client(client_policy()).public_payload()
    payload["groupsServiceKeys"] = ["other-service"]
    with pytest.raises(ValidationError):
        EditableOidcPolicy.model_validate(payload)


def test_policy_fingerprint_ignores_user_type_order() -> None:
    policy = EditableOidcPolicy.from_client(client_policy())
    payload = policy.public_payload()
    payload["allowedUserTypes"] = ["EXTERNAL", "EMPLOYEE"]
    assert EditableOidcPolicy.model_validate(payload).fingerprint() == policy.fingerprint()


def test_requester_cannot_approve_own_request() -> None:
    with pytest.raises(DomainError) as caught:
        assert_other_approver(requester_id="admin-a", approver_id="admin-a")
    assert caught.value.status_code == 403
    assert_other_approver(requester_id="admin-a", approver_id="admin-b")


def test_policy_requires_current_base_version() -> None:
    assert_policy_version(expected=2, current=2)
    with pytest.raises(DomainError) as caught:
        assert_policy_version(expected=1, current=2)
    assert caught.value.status_code == 409


@pytest.mark.parametrize("value", ["", " ", "a" * 129])
def test_policy_change_requires_bounded_reason(value: str) -> None:
    with pytest.raises(DomainError):
        policy_reason(value)
