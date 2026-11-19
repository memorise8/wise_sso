"""승인된 정책을 매번 조회하고 연결 설정을 보존하는지 검증합니다."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from argon2 import PasswordHasher
from sqlalchemy.ext.asyncio import AsyncConnection

from wiseacct_sso.application.oidc import OidcService
from wiseacct_sso.application.oidc_policy_resolver import OidcPolicyResolver
from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence import oidc_policy_changes as store
from wiseacct_sso.persistence.database import Database


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def client() -> OidcClientPolicy:
    return OidcClientPolicy.model_validate(
        {
            "clientId": "gitlab",
            "redirectUris": ["https://gitlab.example.invalid/users/auth/openid_connect/callback"],
            "clientSecretHash": PasswordHasher().hash("synthetic-policy-test-only"),
            "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
            "groupsServiceKeys": ["gitlab"],
            "allowedUserTypes": ["EMPLOYEE"],
            "allowWithoutRequiredRole": False,
            "ssoAutoLogin": False,
            "requirePkce": True,
            "allowedScopes": ["openid", "email", "profile"],
        }
    )


@pytest.fixture
def rig(monkeypatch: pytest.MonkeyPatch, client: OidcClientPolicy) -> SimpleNamespace:
    connection = MagicMock(spec=AsyncConnection)

    @asynccontextmanager
    async def connect() -> AsyncIterator[AsyncConnection]:
        yield connection

    database = cast(Database, SimpleNamespace(connection=connect))
    resolver = OidcPolicyResolver(database=lambda: database)
    policy = EditableOidcPolicy.from_client(client)
    payload = policy.public_payload()
    payload["allowedUserTypes"] = ["CUSTOMER"]
    payload["allowWithoutRequiredRole"] = True
    payload["ssoAutoLogin"] = True
    updated = EditableOidcPolicy.model_validate(payload)
    read = AsyncMock(
        return_value={
            "clientId": client.client_id,
            "version": 2,
            "policy": updated.public_payload(),
        }
    )
    monkeypatch.setattr(store, "read_current", read)

    service = object.__new__(OidcService)
    service._clients = OidcClientRegistry((client,))
    service._policy_resolver = resolver
    return SimpleNamespace(
        resolver=resolver,
        service=service,
        read=read,
        connection=connection,
        updated=updated,
        original=policy,
    )


@pytest.mark.anyio
async def test_db_policy_preserves_connection_settings(
    rig: SimpleNamespace, client: OidcClientPolicy
) -> None:
    result = await rig.resolver.resolve(client)
    assert result.allowed_user_types == ("CUSTOMER",)
    assert result.allow_without_required_role is True
    assert result.sso_auto_login is True
    assert result.client_id == client.client_id
    assert result.client_secret_hash == client.client_secret_hash
    assert result.redirect_uris == client.redirect_uris
    assert result.require_pkce == client.require_pkce
    assert result.allowed_scopes == client.allowed_scopes
    rig.read.assert_awaited_once_with(rig.connection, client_id=client.client_id)


@pytest.mark.anyio
async def test_service_reads_new_policy_without_restart(
    rig: SimpleNamespace,
) -> None:
    first = await rig.service._client("gitlab")
    assert first.sso_auto_login is True
    rig.read.return_value = {"version": 3, "policy": rig.original.public_payload()}
    second = await rig.service._client("gitlab")
    assert second.sso_auto_login is False
    assert rig.read.await_count == 2


@pytest.mark.anyio
async def test_service_list_uses_same_db_policy(rig: SimpleNamespace) -> None:
    clients = await rig.service._resolved_clients()
    assert len(clients) == 1
    assert clients[0].allowed_user_types == ("CUSTOMER",)
    assert clients[0].sso_auto_login is True


@pytest.mark.anyio
async def test_unknown_client_does_not_read_db(rig: SimpleNamespace) -> None:
    assert await rig.service._resolved_client_or_none("unknown") is None
    rig.read.assert_not_awaited()


@pytest.mark.anyio
async def test_missing_db_policy_does_not_fall_back(rig: SimpleNamespace) -> None:
    rig.read.side_effect = DomainError(
        503, "POLICY_NOT_INITIALIZED", "서비스 정책이 초기화되지 않았습니다."
    )
    with pytest.raises(DomainError):
        await rig.service._client("gitlab")


@pytest.mark.anyio
async def test_db_failure_does_not_fall_back(rig: SimpleNamespace) -> None:
    rig.read.side_effect = RuntimeError("검사용 DB 연결 실패")
    with pytest.raises(RuntimeError, match="검사용 DB 연결 실패"):
        await rig.service._client("gitlab")


@pytest.mark.anyio
async def test_invalid_db_policy_is_rejected(rig: SimpleNamespace) -> None:
    rig.read.return_value = {
        "version": 2,
        "policy": {
            **rig.updated.public_payload(),
            "clientSecretHash": "정책에 저장하면 안 되는 값",
        },
    }
    with pytest.raises(DomainError):
        await rig.service._client("gitlab")
