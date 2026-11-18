"""기존 환경변수 접근 정책을 DB에 최초 등록하는 수동 명령."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from typing import Any, cast

from sqlalchemy.ext.asyncio import create_async_engine

from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcClientRegistry
from wiseacct_sso.persistence.database import Database


async def run(*, actor_id: str, reason: str) -> dict[str, object]:
    try:
        raw = json.loads(os.environ["OIDC_CLIENTS_JSON"])
        if not isinstance(raw, list) or not raw:
            raise ValueError("서비스 목록 형식 오류")
        clients = tuple(OidcClientPolicy.model_validate(item) for item in raw)
        registry = OidcClientRegistry(clients)
        url = os.environ["DATABASE_URL"]
    except Exception:
        raise RuntimeError("환경변수의 서비스 설정 또는 DB 접속 설정을 확인하세요.") from None
    if url.startswith("postgres://"):
        url = "postgresql+asyncpg://" + url[len("postgres://") :]
    elif url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]
    if not url.startswith("postgresql+asyncpg://"):
        raise RuntimeError("지원하지 않는 DB 접속 형식입니다.")

    engine = create_async_engine(url)
    try:
        database = Database(engine=engine)
        # 이 명령은 토큰 인증을 사용하지 않고 트랜잭션 안에서 DB 역할을 검사합니다.
        admin = Phase6AdminService(database=lambda: database, tokens=cast(Any, None))
        service = admin.oidc_policy_change_service(
            client_ids=tuple(client.client_id for client in registry.clients)
        )
        return await service.initialize(actor_id=actor_id, clients=registry.clients, reason=reason)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="기존 정책은 유지하고 미등록 서비스의 접근 정책만 DB에 등록합니다."
    )
    parser.add_argument("--actor-id", required=True, help="실행을 책임지는 관리자 사용자 ID")
    parser.add_argument("--reason", required=True, help="감사 기록에 남길 등록 사유")
    args = parser.parse_args()
    try:
        result = asyncio.run(run(actor_id=args.actor_id, reason=args.reason))
    except DomainError as error:
        raise SystemExit(f"초기 등록 실패: {error.code}") from None
    except Exception:
        raise SystemExit(
            "초기 등록 실패: 설정·마이그레이션·DB 상태를 확인하세요. 비밀값은 출력하지 않습니다."
        ) from None
    print(
        f"초기 등록 완료: 신규 {result['initializedCount']}개, "
        f"기존 정책 유지 {result['retainedCount']}개"
    )


if __name__ == "__main__":
    main()
