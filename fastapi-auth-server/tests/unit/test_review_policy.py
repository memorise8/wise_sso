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


def test_direct_portal_visits_go_to_the_service_instead(synthetic_settings: Settings) -> None:
    # Opened without handoff params the legacy portal signed people into TEMIS from
    # the SSO domain, so direct visits are sent to the service's own login.
    settings = synthetic_settings.model_copy(
        update={"portal_entry_url": "https://service.example.test/login"}
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
    handoff = "client_id=temis&redirect_uri=x&code_challenge=c&code_challenge_method=S256"
    with TestClient(app, follow_redirects=False) as client:
        for path in ("/", "/login", "/signup"):
            response = client.get(path)
            assert response.status_code == 303, path
            assert response.headers["location"] == "https://service.example.test/login"
            assert response.headers["cache-control"] == "no-store"
            assert client.get(f"{path}?{handoff}").status_code == 200, path
        # Mail links and the callback still open the page directly.
        for path in ("/verify-email", "/password-reset", "/auth/callback"):
            assert client.get(path).status_code == 200, path


@pytest.mark.parametrize(
    "value", ["http://service.example.test/login", "https://user@service.example.test/", "/login"]
)
def test_portal_entry_url_must_be_https(synthetic_settings: Settings, value: str) -> None:
    with pytest.raises(ValueError, match="PORTAL_ENTRY_URL"):
        Settings.model_validate(
            {**synthetic_settings.model_dump(by_alias=True), "PORTAL_ENTRY_URL": value}
        )
