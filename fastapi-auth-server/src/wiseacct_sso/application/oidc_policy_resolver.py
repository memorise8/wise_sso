"""환경변수의 연결 설정에 승인된 DB 접근 정책만 결합합니다."""

from __future__ import annotations

from collections.abc import Callable

from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy
from wiseacct_sso.persistence import oidc_policy_changes as store
from wiseacct_sso.persistence.database import Database


class OidcPolicyResolver:
    def __init__(self, *, database: Callable[[], Database]) -> None:
        self._database = database

    async def resolve(self, client: OidcClientPolicy) -> OidcClientPolicy:
        async with self._database().connection() as connection:
            row = await store.read_current(connection, client_id=client.client_id)
        policy = store.decode_policy(row["policy"])
        resolved = policy.apply_to_client(client)
        if resolved.client_id != client.client_id:
            raise DomainError(503, "POLICY_DATA_INVALID", "서비스 정책을 확인할 수 없습니다.")
        return resolved
