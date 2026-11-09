import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from wiseacct_sso.api.routes.system import build_system_router
from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH
from wiseacct_sso.oidc_config import OidcClientPolicy
from wiseacct_sso.ops.check_prod_env import validate_policy

ROOT = Path(__file__).parents[2]


def test_production_policy_examples_enforce_internal_and_customer_boundaries(
    synthetic_settings: Settings,
) -> None:
    examples = json.loads(
        (ROOT / "ops/deployment/oidc-clients.production.example.json").read_text()
    )
    for item in examples:
        item["clientSecretHash"] = DUMMY_PASSWORD_HASH
    clients = tuple(OidcClientPolicy.model_validate(x) for x in examples)
    settings = synthetic_settings.model_copy(
        update={"node_env": "production", "oidc_enabled": True, "oidc_clients": clients}
    )
    validate_policy(settings)
    changed = clients[0].model_copy(update={"allowed_user_types": ("CUSTOMER", "EMPLOYEE")})
    with pytest.raises(ValueError):
        validate_policy(settings.model_copy(update={"oidc_clients": (changed, *clients[1:])}))
    with pytest.raises(ValueError):
        validate_policy(settings.model_copy(update={"oidc_clients": clients[1:]}))


@pytest.mark.parametrize("enabled", [False, True])
def test_legacy_social_buttons_are_rendered_only_for_configured_providers(
    synthetic_settings: Settings, enabled: bool
) -> None:
    settings = synthetic_settings.model_copy(
        update={
            "oauth_enabled_providers": ("naver", "kakao") if enabled else (),
            "naver_client_id": "id",
            "naver_client_secret": "secret",
            "kakao_client_id": "id",
            "kakao_client_secret": "secret",
        }
    )
    app = FastAPI()
    app.include_router(
        build_system_router(
            settings=settings,
            readiness_check=lambda: True,
            static_root=ROOT / "src/wiseacct_sso/static",
            on_readiness_error=lambda _: None,
        )
    )
    with TestClient(app) as client:
        for path in ("/login", "/signup"):
            response = client.get(path)
            assert ('href="/auth/naver"' in response.text) is enabled
            assert ('href="/auth/kakao"' in response.text) is enabled
            assert response.headers["cache-control"] == "no-store"


def test_migration_is_additive_and_uses_system_actor() -> None:
    sql = (
        ROOT.parent
        / "auth-server/prisma/migrations/20261102000000_user_types_and_sso_admin/migration.sql"
    ).read_text()
    assert 'DELETE FROM "UserRole"' not in sql
    assert "'success',NULL,id" in sql
    assert "'success',NULL,\"userId\"" in sql
