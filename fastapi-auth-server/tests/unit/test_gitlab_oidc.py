from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from wiseacct_sso.domain.oidc import OidcIdentity, has_required_role, project_groups
from wiseacct_sso.domain.users import Role
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH
from wiseacct_sso.oidc_config import parse_oidc_clients_json

GITLAB_CLIENT_EXAMPLE = Path(__file__).parents[2] / "examples" / "gitlab" / "oidc-client.json"


def _client(
    client_id: str,
    redirect_uri: str,
    service_key: str,
) -> dict[str, object]:
    return {
        "clientId": client_id,
        "redirectUris": [redirect_uri],
        "clientSecretHash": DUMMY_PASSWORD_HASH,
        "requiredRoles": [{"serviceKey": service_key, "name": "user"}],
        "groupsServiceKeys": [service_key],
        "requirePkce": True,
        "allowedScopes": ["openid", "email", "profile"],
    }


def _gitlab_example() -> dict[str, object]:
    raw = cast(dict[str, object], json.loads(GITLAB_CLIENT_EXAMPLE.read_text()))
    assert raw["clientSecretHash"] == "REPLACE_WITH_ARGON2ID_HASH_OF_GITLAB_CLIENT_SECRET"
    return raw | {"clientSecretHash": DUMMY_PASSWORD_HASH}


def test_gitlab_client_is_distinct_from_cloudflare_policy() -> None:
    registry = parse_oidc_clients_json(
        json.dumps(
            [
                _client(
                    "cloudflare-access-dash",
                    "https://team.cloudflareaccess.com/cdn-cgi/access/callback",
                    "agent-hub",
                ),
                _gitlab_example(),
            ]
        )
    )
    cloudflare = registry.require("cloudflare-access-dash")
    gitlab = registry.require("gitlab-temis")
    agent_hub_user = OidcIdentity(
        user_id="user-1",
        email="user@example.test",
        name="Wise User",
        email_verified=True,
        roles=(Role(service_key="agent-hub", name="user"),),
    )
    gitlab_user = OidcIdentity(
        user_id="user-2",
        email="employee@example.test",
        name="Wise Employee",
        email_verified=True,
        roles=(Role(service_key="gitlab", name="user"),),
    )

    assert has_required_role(agent_hub_user, cloudflare)
    assert not has_required_role(agent_hub_user, gitlab)
    assert has_required_role(gitlab_user, gitlab)
    assert not has_required_role(gitlab_user, cloudflare)
    assert project_groups(gitlab_user, gitlab) == ("gitlab:user",)
    assert gitlab.required_roles[0].service_key == "gitlab"
    assert all(role.service_key != "agent-hub" for role in gitlab.required_roles)


def test_gitlab_callback_is_exact_and_pkce_is_required() -> None:
    gitlab = parse_oidc_clients_json(json.dumps([_gitlab_example()])).require("gitlab-temis")

    assert gitlab.require_pkce
    assert gitlab.allowed_scopes == ("openid", "profile", "email")
    assert gitlab.accepts_redirect_uri("https://gitlab.temis.me/users/auth/openid_connect/callback")
    assert not gitlab.accepts_redirect_uri(
        "https://gitlab.temis.me/users/auth/openid_connect/callback/"
    )
    assert not gitlab.accepts_redirect_uri(
        "http://gitlab.temis.me/users/auth/openid_connect/callback"
    )
