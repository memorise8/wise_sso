"""기존 로컬 PostgreSQL의 독립 스키마에서 권한 점검을 검증합니다."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "fastapi-auth-server/src/wiseacct_sso"
MODULES = [
    ('wiseacct_sso.domain.admin', 'domain/admin.py'),
    ('wiseacct_sso.domain.access_reviews', 'domain/access_reviews.py'),
    ('wiseacct_sso.domain.oidc_policy_changes', 'domain/oidc_policy_changes.py'),
    ('wiseacct_sso.persistence.models', 'persistence/models.py'),
    ('wiseacct_sso.persistence.access_reviews', 'persistence/access_reviews.py'),
    ('wiseacct_sso.persistence.oidc_policy_changes', 'persistence/oidc_policy_changes.py'),
    ('wiseacct_sso.application.access_reviews', 'application/access_reviews.py'),
    ('wiseacct_sso.application.oidc_policy_changes', 'application/oidc_policy_changes.py'),
    ('wiseacct_sso.application.oidc_policy_resolver', 'application/oidc_policy_resolver.py'),
    ('wiseacct_sso.application.admin', 'application/admin.py'),
]
packet = {
    "modules": [
        (name, (ROOT / PREFIX / relative).read_text())
        for name, relative in MODULES
    ],
    "migrations": [
        (path.parent.name, path.read_text())
        for path in sorted(
            (ROOT / "auth-server/prisma/migrations").glob("*/migration.sql")
        )
    ],
}

PROGRAM = r'''
import asyncio
import importlib
import os
import re
import sys
import types
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import create_async_engine

for name, source in PACKET["modules"]:
    parent_name, _, short_name = name.rpartition(".")
    parent = importlib.import_module(parent_name)
    module = types.ModuleType(name)
    module.__package__ = parent_name
    sys.modules[name] = module
    setattr(parent, short_name, module)
    exec(compile(source, name, "exec"), module.__dict__)

from wiseacct_sso.application.access_reviews import AccessReviewService
from wiseacct_sso.application.admin import Phase6AdminService
from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.persistence.database import Database
from wiseacct_sso.persistence.models import (
    AccessReviewItem, AuditLog, RefreshToken,
    Role, User, UserRole, UserStatus, application_uuid, utc_now_ms,
)



async def check_policy_schema_constraints(engine):
    from sqlalchemy.exc import IntegrityError
    from wiseacct_sso.persistence.models import (
        OidcAccessPolicy, OidcPolicyChange, OidcPolicyDecision,
    )

    async def reject(connection, statement, expected_state):
        try:
            async with connection.begin_nested():
                await connection.execute(statement)
        except IntegrityError as error:
            actual = getattr(error.orig, "sqlstate", None)
            assert actual == expected_state, (actual, expected_state)
        else:
            raise AssertionError("잘못된 정책 데이터가 DB에서 허용됐습니다.")

    payload = {
        "allowedUserTypes": ["EMPLOYEE"],
        "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
        "allowWithoutRequiredRole": False,
        "groupsServiceKeys": ["gitlab"],
        "ssoAutoLogin": False,
    }
    now = utc_now_ms()
    async with engine.begin() as connection:
        await connection.execute(insert(OidcAccessPolicy).values(
            clientId="policy-schema-check",
            version=1, policy=payload, updatedAt=now,
        ))
        await connection.execute(insert(OidcPolicyChange).values(
            id="policy-request",
            clientId="policy-schema-check",
            baseVersion=1,
            beforePolicy=payload,
            proposedPolicy=payload,
            requestedById="policy-requester",
            reasonCode="정책 DB 제약 검사",
        ))
        decision = {
            "id": "policy-decision",
            "requestId": "policy-request",
            "requestedById": "policy-requester",
            "decidedById": "policy-approver",
            "decision": "APPROVE",
            "reasonCode": "정책 검토 완료",
        }

        await reject(
            connection,
            insert(OidcPolicyDecision).values(
                **{**decision, "decidedById": "policy-requester"}
            ),
            "23514",
        )
        await reject(
            connection,
            insert(OidcPolicyDecision).values(
                **{**decision, "requestedById": "forged-requester"}
            ),
            "23503",
        )
        await connection.execute(insert(OidcPolicyDecision).values(**decision))
        await reject(
            connection,
            insert(OidcPolicyDecision).values(
                **{**decision, "id": "duplicate-policy-decision"}
            ),
            "23505",
        )

        from sqlalchemy import update

        await reject(
            connection,
            update(OidcAccessPolicy).where(
                OidcAccessPolicy.c.clientId == "policy-schema-check"
            ).values(policy={**payload, "clientSecretHash": "synthetic-only"}),
            "23514",
        )
        await reject(
            connection,
            update(OidcPolicyChange).where(
                OidcPolicyChange.c.id == "policy-request"
            ).values(status="APPLIED", appliedVersion=None, resolvedAt=now),
            "23514",
        )
        await connection.execute(
            update(OidcPolicyChange).where(
                OidcPolicyChange.c.id == "policy-request"
            ).values(status="APPLIED", appliedVersion=2, resolvedAt=now)
        )

    print("통과: 정책 DB의 자기 승인·요청자 위조·중복 승인 차단")
    print("통과: 비밀 필드 저장 차단·승인 적용 버전 필수 제약")



async def check_policy_store(engine):
    from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy
    from wiseacct_sso.persistence import oidc_policy_changes as policies

    original = EditableOidcPolicy.model_validate({
        "allowedUserTypes": ["EMPLOYEE"],
        "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
        "allowWithoutRequiredRole": False,
        "groupsServiceKeys": ["gitlab"],
        "ssoAutoLogin": False,
    })
    changed_payload = original.public_payload()
    changed_payload["ssoAutoLogin"] = True
    changed = EditableOidcPolicy.model_validate(changed_payload)
    now = utc_now_ms()

    async with engine.begin() as connection:
        assert await policies.register_policy(
            connection, client_id="policy-store-check", policy=original, now=now
        )
        assert not await policies.register_policy(
            connection, client_id="policy-store-check", policy=changed, now=now
        )
        current = await policies.read_current(
            connection, client_id="policy-store-check", lock=True
        )
        assert current["version"] == 1
        assert policies.decode_policy(current["policy"]).sso_auto_login is False

        await policies.insert_change(
            connection,
            policies.NewPolicyChange(
                id="policy-store-request",
                client_id="policy-store-check",
                base_version=1, before=original, proposed=changed,
                requester_id="store-requester",
                requester_email="requester@example.invalid",
                reason="정책 저장 계층 검사", now=now,
            ),
        )
        request = await policies.read_change(
            connection, client_id="policy-store-check",
            request_id="policy-store-request", lock=True,
        )
        assert request["status"] == "PENDING"

        await policies.insert_decision(
            connection, request_id="policy-store-request",
            requester_id="store-requester",
            decider_id="store-approver",
            decider_email="approver@example.invalid",
            decision="APPROVE", reason="정책 검토 완료", now=now,
        )
        version = await policies.apply_policy(
            connection, client_id="policy-store-check",
            expected_version=1, policy=changed,
            actor_id="store-approver",
            actor_email="approver@example.invalid", now=now,
        )
        assert version == 2
        await policies.finish_change(
            connection, client_id="policy-store-check",
            request_id="policy-store-request", status="APPLIED",
            applied_version=version, now=now,
        )

        previous = await policies.read_version(
            connection, client_id="policy-store-check", version=1
        )
        current = await policies.read_version(
            connection, client_id="policy-store-check", version=2
        )
        assert previous.fingerprint() == original.fingerprint()
        assert current.fingerprint() == changed.fingerprint()

        await expect_error(policies.apply_policy(
            connection, client_id="policy-store-check",
            expected_version=1, policy=original,
            actor_id="store-approver", actor_email=None, now=now,
        ), 409)
        await expect_error(policies.finish_change(
            connection, client_id="policy-store-check",
            request_id="policy-store-request", status="REJECTED", now=now,
        ), 409)

        page = await policies.list_changes(
            connection, client_id="policy-store-check", page=1, page_size=25,
        )
        assert len(page["items"]) == 1
        assert page["items"][0]["status"] == "APPLIED"
        decision = await policies.read_decision(
            connection, request_id="policy-store-request"
        )
        assert decision["decidedByEmail"] == "approver@example.invalid"

    print("통과: 정책 초기 등록 재실행 시 기존 정책 보존")
    print("통과: 정책 버전 이력·이전 버전 조회·중복 처리 및 버전 충돌 차단")



async def check_policy_service(engine):
    import asyncio
    from unittest.mock import patch

    from sqlalchemy import delete, select
    from wiseacct_sso.application.oidc_policy_changes import OidcPolicyChangeService
    from wiseacct_sso.domain.oidc_policy_changes import EditableOidcPolicy
    from wiseacct_sso.persistence import oidc_policy_changes as policies
    from wiseacct_sso.persistence.models import (
        AuditLog, OidcPolicyChange, OidcPolicyDecision, Role, UserRole,
        application_uuid,
    )

    database = Database(engine=engine)
    admin = Phase6AdminService(database=lambda: database, tokens=object())
    client = "policy-service-check"
    service = OidcPolicyChangeService(admin=admin, client_ids=(client,))
    actors = ("f1-requester", "f1-approver", "f1-viewer")
    original = EditableOidcPolicy.model_validate({
        "allowedUserTypes": ["EMPLOYEE"],
        "requiredRoles": [{"serviceKey": "gitlab", "name": "user"}],
        "allowWithoutRequiredRole": False,
        "groupsServiceKeys": ["gitlab"],
        "ssoAutoLogin": False,
    })
    payload = original.public_payload()
    payload["ssoAutoLogin"] = True
    changed = EditableOidcPolicy.model_validate(payload)
    now = utc_now_ms()

    async with engine.begin() as connection:
        for actor in actors:
            await connection.execute(insert(User).values(
                id=actor, email=f"{actor}@example.invalid",
                name=actor, emailVerified=True,
                status=UserStatus.ACTIVE, userType="EMPLOYEE",
                createdAt=now, updatedAt=now,
            ))
        for actor, name in (
            ("f1-requester", "admin"),
            ("f1-approver", "admin"),
            ("f1-viewer", "viewer"),
        ):
            role_id = (
                await connection.execute(select(Role.c.id).where(
                    Role.c.serviceKey == "sso", Role.c.name == name
                ))
            ).scalar_one()
            await connection.execute(insert(UserRole).values(
                id=application_uuid(), userId=actor, roleId=role_id,
            ))

    from argon2 import PasswordHasher
    from wiseacct_sso.application.oidc_policy_resolver import OidcPolicyResolver
    from wiseacct_sso.oidc_config import OidcClientPolicy

    configured = OidcClientPolicy.model_validate({
        **original.public_payload(),
        "clientId": client,
        "redirectUris": ["https://policy.example.invalid/callback"],
        "clientSecretHash": PasswordHasher().hash("synthetic-policy-check-only"),
    })
    first_init = await service.initialize(
        actor_id="f1-requester", clients=(configured,), reason="초기 등록 검사"
    )
    second_init = await service.initialize(
        actor_id="f1-requester",
        clients=(changed.apply_to_client(configured),),
        reason="초기 등록 재실행 검사",
    )
    assert first_init == {"initializedCount": 1, "retainedCount": 0}
    assert second_init == {"initializedCount": 0, "retainedCount": 1}
    resolver = OidcPolicyResolver(database=lambda: database)
    assert (await resolver.resolve(configured)).sso_auto_login is False
    print("통과: 관리자 초기 등록 재실행 시 환경변수로 기존 DB 정책을 덮어쓰지 않음")

    async def request(policy, version, rollback=None):
        return await service.request(
            actor_id="f1-requester", client_id=client,
            expected_version=version, proposed=policy,
            rollback_to_version=rollback, reason="정책 변경 검사",
        )

    async def decide(request_id, actor="f1-approver", decision="APPROVE"):
        return await service.decide(
            actor_id=actor, client_id=client, request_id=request_id,
            decision=decision, reason="정책 검토 검사",
        )

    async def snapshot(request_id):
        async with engine.connect() as connection:
            current = await policies.read_current(connection, client_id=client)
            change = await policies.read_change(
                connection, client_id=client, request_id=request_id
            )
            decision = await policies.read_decision(
                connection, request_id=request_id
            )
            audits = (
                await connection.execute(select(AuditLog.c.id).where(
                    AuditLog.c.detailsJson["requestId"].astext == request_id
                ))
            ).scalars().all()
            return current, change, decision, tuple(sorted(audits))

    try:
        await expect_error(service.request(
            actor_id="f1-viewer", client_id=client,
            expected_version=1, proposed=changed, reason="권한 검사",
        ), 403)
        first = await request(changed, 1)
        first_id = first["id"]
        await expect_error(decide(first_id, actor="f1-requester"), 403)
        await expect_error(decide(first_id, actor="f1-viewer"), 403)

        async with engine.begin() as connection:
            requester_grant = dict((
                await connection.execute(select(UserRole).join(
                    Role, Role.c.id == UserRole.c.roleId
                ).where(
                    UserRole.c.userId == "f1-requester",
                    Role.c.serviceKey == "sso",
                    Role.c.name == "admin",
                ))
            ).mappings().one())
            await connection.execute(delete(UserRole).where(
                UserRole.c.id == requester_grant["id"]
            ))
        await expect_error(decide(first_id), 403)
        async with engine.begin() as connection:
            await connection.execute(insert(UserRole).values(**requester_grant))
        print("통과: viewer 요청·결정 차단과 자기 승인·요청자 권한 상실 차단")

        async def concurrent_decision():
            try:
                await decide(first_id)
                return 200
            except DomainError as error:
                return error.status_code

        results = await asyncio.gather(
            concurrent_decision(), concurrent_decision()
        )
        assert sorted(results) == [200, 409], results
        current, first, decision, audits = await snapshot(first_id)
        assert current["version"] == 2
        assert policies.decode_policy(current["policy"]) == changed
        effective = await resolver.resolve(configured)
        assert effective.sso_auto_login is True
        assert effective.client_secret_hash == configured.client_secret_hash
        assert effective.redirect_uris == configured.redirect_uris
        assert first["status"] == "APPLIED"
        assert first["appliedVersion"] == 2
        assert decision["decidedByEmail"] == "f1-approver@example.invalid"
        assert len(audits) == 2
        print("통과: 동시 승인은 한 번만 반영·정책 버전 및 승인자 이메일")

        rollback = await request(None, 2, rollback=1)
        rollback_id = rollback["id"]
        current, pending, _, _ = await snapshot(rollback_id)
        assert current["version"] == 2
        assert pending["status"] == "PENDING"
        assert pending["rollbackToVersion"] == 1
        await decide(rollback_id)
        current, _, _, _ = await snapshot(rollback_id)
        assert current["version"] == 3
        assert policies.decode_policy(current["policy"]) == original
        assert (await resolver.resolve(configured)).sso_auto_login is False
        print("통과: 승인·복원 직후 DB 정책 재조회·비밀값과 리다이렉트 설정 보존")
        print("통과: 되돌리기도 새 요청과 다른 관리자 승인 후 새 버전으로 적용")

        stale = await request(changed, 3)
        rejected = await request(changed, 3)
        await decide(rejected["id"], decision="REJECT")
        current, rejected_row, rejected_decision, _ = await snapshot(rejected["id"])
        assert current["version"] == 3
        assert rejected_row["status"] == "REJECTED"
        assert rejected_decision["decision"] == "REJECT"

        failure_request = await request(changed, 3)
        failure_id = failure_request["id"]
        before = await snapshot(failure_id)

        async def fail_audit(*args, **kwargs):
            raise RuntimeError("정책 감사 저장 실패 검사")

        with patch.object(
            type(admin._mutations), "create_admin_audit_log", new=fail_audit
        ):
            try:
                await decide(failure_id)
            except RuntimeError as error:
                assert str(error) == "정책 감사 저장 실패 검사"
            else:
                raise AssertionError("감사 저장 실패가 전파되지 않았습니다.")
        after = await snapshot(failure_id)
        assert before == after
        print("통과: 감사 실패 시 정책·버전·결정·요청 상태·감사 기록 전체 롤백")

        await decide(failure_id)
        await expect_error(decide(stale["id"]), 409)
        current, stale_row, stale_decision, _ = await snapshot(stale["id"])
        assert current["version"] == 4
        assert stale_row["status"] == "PENDING"
        assert stale_decision is None

        async with engine.connect() as connection:
            decision_count = len((
                await connection.execute(select(OidcPolicyDecision.c.id).join(
                    OidcPolicyChange,
                    OidcPolicyChange.c.id == OidcPolicyDecision.c.requestId,
                ).where(OidcPolicyChange.c.clientId == client))
            ).scalars().all())
            assert decision_count == 4
        print("통과: 거절은 정책 미변경·다른 승인 후 오래된 요청 승인 차단")
    finally:
        # 이후 F6 검사에서 관리자 수와 역할 목록에 영향을 주지 않습니다.
        async with engine.begin() as connection:
            await connection.execute(delete(UserRole).where(
                UserRole.c.userId.in_(actors)
            ))


async def expect_error(awaitable, status):
    try:
        await awaitable
    except DomainError as error:
        assert error.status_code == status, (error.code, error.status_code)
    else:
        raise AssertionError(f"예상한 {status} 오류가 발생하지 않았습니다.")


async def main():
    url = os.environ["DATABASE_URL"]
    parsed = urlsplit(url)
    if (
        parsed.hostname != "postgres"
        or parsed.path != "/fastapi_sso_dev"
        or os.environ.get("NODE_ENV") != "development"
        or os.environ.get("JWT_ISSUER") != "https://localhost:4444"
    ):
        raise SystemExit("중단: 지정한 로컬 개발 환경이 아닙니다.")

    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

    for index, (name, sql) in enumerate(PACKET["migrations"]):
        if name == "20260708000000_init":
            public_schema_statement = 'CREATE SCHEMA IF NOT EXISTS "public";'
            if sql.count(public_schema_statement) != 1:
                raise RuntimeError("초기 스키마 선언이 예상과 다릅니다.")
            sql = sql.replace(public_schema_statement, "", 1)
            PACKET["migrations"][index] = (name, sql)
        if re.search(
            r'\bpublic\s*\.|"public"\s*\.|\bsearch_path\b|'
            r'\b(?:CREATE|ALTER|DROP)\s+(?:DATABASE|SCHEMA|ROLE|EXTENSION)\b',
            sql, re.IGNORECASE,
        ):
            raise RuntimeError(f"격리 검토가 필요한 마이그레이션입니다: {name}")

    schema = "f6_review_check_" + uuid4().hex
    lifecycle = create_async_engine(url)
    engine = None
    created = False
    try:
        async with lifecycle.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            created = True

        engine = create_async_engine(
            url,
            isolation_level="READ COMMITTED",
            connect_args={"server_settings": {"search_path": schema}},
        )

        async with engine.connect() as connection:
            actual_schema = (
                await connection.execute(text("SELECT current_schema()"))
            ).scalar_one()
            if actual_schema != schema:
                raise RuntimeError("검증용 스키마 격리가 적용되지 않았습니다.")

        # 마이그레이션마다 커밋하여 PostgreSQL ENUM 변경 경계도 유지합니다.
        for name, sql in PACKET["migrations"]:
            async with engine.begin() as connection:
                raw = await connection.get_raw_connection()
                await raw.driver_connection.execute(sql)

        await check_policy_schema_constraints(engine)
        await check_policy_store(engine)
        await check_policy_service(engine)
        database = Database(engine=engine)
        admin = Phase6AdminService(database=lambda: database, tokens=object())
        reviews = AccessReviewService(admin=admin)
        now = utc_now_ms()
        assignments = {}

        async with engine.begin() as connection:
            for user_id in ("f6-admin-a", "f6-admin-b", "f6-target"):
                await connection.execute(insert(User).values(
                    id=user_id, email=f"{user_id}@f6.invalid",
                    name=user_id, emailVerified=True,
                    status=UserStatus.ACTIVE, userType="EMPLOYEE",
                    createdAt=now, updatedAt=now,
                ))

            grants = [
                ("f6-admin-a", "sso", "admin"),
                ("f6-admin-b", "sso", "admin"),
                ("f6-target", "sso", "viewer"),
                ("f6-target", "gitlab", "user"),
                ("f6-target", "f6-test", "user"),
            ]
            for user_id, service_key, role_name in grants:
                await connection.execute(
                    pg_insert(Role).values(
                        id=application_uuid(), serviceKey=service_key, name=role_name
                    ).on_conflict_do_nothing(
                        index_elements=[Role.c.serviceKey, Role.c.name]
                    )
                )
                role_id = (
                    await connection.execute(
                        select(Role.c.id).where(
                            Role.c.serviceKey == service_key, Role.c.name == role_name
                        )
                    )
                ).scalar_one()
                assignment = application_uuid()
                assignments[(user_id, service_key, role_name)] = assignment
                await connection.execute(insert(UserRole).values(
                    id=assignment, userId=user_id, roleId=role_id
                ))

            await connection.execute(insert(RefreshToken).values(
                id=application_uuid(), tokenHash="synthetic-f6-refresh",
                userId="f6-target", audience="gitlab",
                expiresAt=now + timedelta(days=1), createdAt=now,
            ))

        review = await reviews.start(
            actor_id="f6-admin-a", title="합성 데이터 권한 점검", reason="개발 검증"
        )
        review_id = review["id"]
        assert review["total"] == 5
        page = await reviews.items(actor_id="f6-admin-a", review_id=review_id)
        expected_order = sorted(
            page["items"],
            key=lambda row: (
                row["userEmail"] is None,
                (row["userEmail"] or "").lower(),
                row["userId"], row["serviceKey"], row["roleName"], row["id"],
            ),
        )
        assert [row["id"] for row in page["items"]] == [
            row["id"] for row in expected_order
        ]
        paged_ids = []
        for page_number in (1, 2, 3):
            part = await reviews.items(
                actor_id="f6-admin-a", review_id=review_id,
                page=page_number, page_size=2,
            )
            paged_ids.extend(row["id"] for row in part["items"])
        assert paged_ids == [row["id"] for row in expected_order]
        assert review["startedByEmail"] == "f6-admin-a@f6.invalid"
        print("통과: 사용자 우선 정렬·페이지 간 순서 유지·시작자 이메일")
        items = {row["userRoleId"]: row for row in page["items"]}
        assert any(row["roleName"] == "admin" for row in items.values())
        assert any(row["roleName"] == "viewer" for row in items.values())
        print("통과: 서비스 역할·중앙 admin·viewer 스냅샷 생성")

        await expect_error(reviews.complete(
            actor_id="f6-admin-a", review_id=review_id, reason="미결정 검사"
        ), 409)

        own = items[assignments[("f6-admin-a", "sso", "admin")]]
        await expect_error(reviews.decide(
            actor_id="f6-admin-a", review_id=review_id,
            item_id=own["id"], decision="REVOKE", reason="본인 보호 검사",
        ), 403)
        print("통과: 미결정 회차 완료 금지·본인 admin 회수 금지")

        target = items[assignments[("f6-target", "gitlab", "user")]]
        results = await asyncio.gather(
            *[
                reviews.decide(
                    actor_id="f6-admin-a", review_id=review_id,
                    item_id=target["id"], decision="REVOKE", reason="동시 결정 검사",
                )
                for _ in range(2)
            ],
            return_exceptions=True,
        )
        assert sum(isinstance(result, dict) for result in results) == 1
        errors = [result for result in results if isinstance(result, DomainError)]
        assert len(errors) == 1 and errors[0].status_code == 409

        async with engine.connect() as connection:
            assert (
                await connection.execute(select(User.c.ssoSessionVersion).where(
                    User.c.id == "f6-target"
                ))
            ).scalar_one() == 1
            assert (
                await connection.execute(select(RefreshToken.c.revokedAt).where(
                    RefreshToken.c.userId == "f6-target"
                ))
            ).scalar_one() is not None
        print("통과: 동시 결정은 한 번만 반영·역할 및 세션 회수")

        rollback_item = items[assignments[("f6-target", "f6-test", "user")]]
        async with engine.connect() as connection:
            audit_before = (
                await connection.execute(select(func.count()).select_from(AuditLog))
            ).scalar_one()

        original_audit = reviews._audit
        async def fail_audit(*args, **kwargs):
            raise RuntimeError("합성 감사 저장 실패")
        reviews._audit = fail_audit
        try:
            try:
                await reviews.decide(
                    actor_id="f6-admin-a", review_id=review_id,
                    item_id=rollback_item["id"], decision="REVOKE",
                    reason="전체 롤백 검사",
                )
            except RuntimeError as error:
                assert str(error) == "합성 감사 저장 실패"
            else:
                raise AssertionError("감사 저장 실패가 전파되지 않았습니다.")
        finally:
            reviews._audit = original_audit

        async with engine.connect() as connection:
            assert (
                await connection.execute(select(UserRole.c.id).where(
                    UserRole.c.id == rollback_item["userRoleId"]
                ))
            ).scalar_one() == rollback_item["userRoleId"]
            assert (
                await connection.execute(select(AccessReviewItem.c.decision).where(
                    AccessReviewItem.c.id == rollback_item["id"]
                ))
            ).scalar_one() == "PENDING"
            assert (
                await connection.execute(select(User.c.ssoSessionVersion).where(
                    User.c.id == "f6-target"
                ))
            ).scalar_one() == 1
            assert (
                await connection.execute(select(func.count()).select_from(AuditLog))
            ).scalar_one() == audit_before
        print("통과: 감사 저장 실패 시 역할·세션·결정·감사 기록 전체 롤백")

        stale = items[assignments[("f6-target", "sso", "viewer")]]
        fresh_id = application_uuid()
        async with engine.begin() as connection:
            await connection.execute(delete(UserRole).where(
                UserRole.c.id == stale["userRoleId"]
            ))
            await connection.execute(insert(UserRole).values(
                id=fresh_id, userId=stale["userId"], roleId=stale["roleId"]
            ))
        result = await reviews.decide(
            actor_id="f6-admin-a", review_id=review_id,
            item_id=stale["id"], decision="REVOKE", reason="재부여 보호 검사",
        )
        assert result["decision"] == "ALREADY_REMOVED"
        async with engine.connect() as connection:
            assert (
                await connection.execute(select(UserRole.c.id).where(
                    UserRole.c.id == fresh_id
                ))
            ).scalar_one() == fresh_id
        print("통과: 제거 후 재부여한 새 역할 할당 보호")

        page = await reviews.items(actor_id="f6-admin-a", review_id=review_id)
        for item in page["items"]:
            if item["decision"] == "PENDING":
                await reviews.decide(
                    actor_id="f6-admin-a", review_id=review_id,
                    item_id=item["id"], decision="KEEP", reason=None,
                )
        completed = await reviews.complete(
            actor_id="f6-admin-a", review_id=review_id, reason="검증 완료"
        )
        assert completed["status"] == "COMPLETED"
        assert completed["counts"]["PENDING"] == 0
        assert completed["completedByEmail"] == "f6-admin-a@f6.invalid"
        async with engine.connect() as connection:
            kept = (
                await connection.execute(
                    select(func.count()).select_from(AccessReviewItem).where(
                        AccessReviewItem.c.reviewId == review_id,
                        AccessReviewItem.c.decision == "KEEP",
                        AccessReviewItem.c.reasonCode == "권한 유지(변경 없음)",
                    )
                )
            ).scalar_one()
            assert kept > 0
        decided = await reviews.items(
            actor_id="f6-admin-a", review_id=review_id
        )
        assert all(
            row["decidedByEmail"] == "f6-admin-a@f6.invalid"
            for row in decided["items"]
        )
        print("통과: 유지 기본 사유·결정자 및 완료자 이메일")
        await expect_error(reviews.complete(
            actor_id="f6-admin-a", review_id=review_id, reason="중복 완료"
        ), 409)

        async with engine.begin() as connection:
            await connection.execute(delete(User).where(User.c.id == "f6-target"))
        page = await reviews.items(actor_id="f6-admin-a", review_id=review_id)
        preserved = [row for row in page["items"] if row["userId"] == "f6-target"]
        assert len(preserved) == 3
        assert all(row["userEmail"] == "f6-target@f6.invalid" for row in preserved)
        print("통과: 회차 완료·중복 완료 차단·원본 사용자 삭제 후 기록 보존")

        second = await reviews.start(
            actor_id="f6-admin-a", title="중앙 관리자 동시 회수",
            service_keys=("sso",), reason="마지막 관리자 보호 검사",
        )
        page = await reviews.items(
            actor_id="f6-admin-a", review_id=second["id"]
        )
        admins = {
            row["userId"]: row for row in page["items"]
            if row["roleName"] == "admin"
        }
        results = await asyncio.gather(
            reviews.decide(
                actor_id="f6-admin-a", review_id=second["id"],
                item_id=admins["f6-admin-b"]["id"], decision="REVOKE",
                reason="동시 관리자 회수 검사",
            ),
            reviews.decide(
                actor_id="f6-admin-b", review_id=second["id"],
                item_id=admins["f6-admin-a"]["id"], decision="REVOKE",
                reason="동시 관리자 회수 검사",
            ),
            return_exceptions=True,
        )
        assert sum(isinstance(result, dict) for result in results) == 1
        errors = [result for result in results if isinstance(result, DomainError)]
        assert len(errors) == 1 and errors[0].status_code == 403
        async with engine.connect() as connection:
            remaining = (
                await connection.execute(
                    select(func.count())
                    .select_from(UserRole.join(Role))
                    .where(Role.c.serviceKey == "sso", Role.c.name == "admin")
                )
            ).scalar_one()
            assert remaining == 1
        print("통과: 관리자 상호 동시 회수에서도 마지막 admin 유지")
    finally:
        if engine is not None:
            await engine.dispose()
        try:
            if created:
                async with lifecycle.begin() as connection:
                    await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
                print("검증 전용 스키마 삭제 완료")
        finally:
            await lifecycle.dispose()

asyncio.run(main())
'''

compile(PROGRAM, "<권한 점검 DB 검사>", "exec")
subprocess.run(
    [
        "docker", "exec", "-i",
        "wiseacct-sso-wiseacct-oauth-app-1", "python", "-"
    ],
    input="PACKET = " + repr(packet) + "\n" + PROGRAM,
    text=True,
    check=True,
)
