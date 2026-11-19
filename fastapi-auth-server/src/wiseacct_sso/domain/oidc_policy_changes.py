"""대시보드에서 변경할 수 있는 OIDC 접근 정책만 정의합니다."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wiseacct_sso.domain.users import DomainError
from wiseacct_sso.oidc_config import OidcClientPolicy, OidcRoleRequirement

type PolicyUserType = Literal["EMPLOYEE", "CUSTOMER", "EXTERNAL", "UNCLASSIFIED"]
GroupKey = Annotated[str, Field(min_length=1, max_length=64)]


class EditableOidcPolicy(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
    )

    allowed_user_types: tuple[PolicyUserType, ...] | None = Field(
        alias="allowedUserTypes", min_length=1, max_length=4
    )
    required_roles: tuple[OidcRoleRequirement, ...] = Field(
        alias="requiredRoles", min_length=1, max_length=32
    )
    allow_without_required_role: bool = Field(alias="allowWithoutRequiredRole", strict=True)
    groups_service_keys: tuple[GroupKey, ...] = Field(
        alias="groupsServiceKeys", min_length=1, max_length=32
    )
    sso_auto_login: bool = Field(alias="ssoAutoLogin", strict=True)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        groups = self.groups_service_keys
        if len(set(groups)) != len(groups):
            raise ValueError("그룹 서비스 키는 중복될 수 없습니다.")
        if any(key != key.strip() or ":" in key for key in groups):
            raise ValueError("그룹 서비스 키 형식이 올바르지 않습니다.")
        if len(set(self.required_roles)) != len(self.required_roles):
            raise ValueError("필요 역할은 중복될 수 없습니다.")
        if any(
            not role.service_key.strip()
            or not role.name.strip()
            or role.service_key != role.service_key.strip()
            or role.name != role.name.strip()
            for role in self.required_roles
        ):
            raise ValueError("필요 역할 형식이 올바르지 않습니다.")
        if any(role.service_key not in groups for role in self.required_roles):
            raise ValueError("필요 역할의 서비스 키가 그룹 목록에 포함돼야 합니다.")
        if self.allowed_user_types is not None and len(set(self.allowed_user_types)) != len(
            self.allowed_user_types
        ):
            raise ValueError("허용 사용자 유형은 중복될 수 없습니다.")
        return self

    @classmethod
    def from_client(cls, client: OidcClientPolicy) -> Self:
        return cls(
            allowedUserTypes=client.allowed_user_types,
            requiredRoles=client.required_roles,
            allowWithoutRequiredRole=client.allow_without_required_role,
            groupsServiceKeys=client.groups_service_keys,
            ssoAutoLogin=client.sso_auto_login,
        )

    def public_payload(self) -> dict[str, object]:
        """변경 요청·이력·응답에는 이 반환값만 사용합니다."""
        return cast(dict[str, object], self.model_dump(mode="json", by_alias=True))

    def apply_to_client(self, client: OidcClientPolicy) -> OidcClientPolicy:
        """연결 설정은 보존하고 접근 정책만 결합한 뒤 전체를 다시 검증합니다."""
        combined = client.model_dump(by_alias=True)
        combined.update(self.public_payload())
        return OidcClientPolicy.model_validate(combined)

    def fingerprint(self) -> str:
        """목록의 순서만 바뀐 요청은 같은 정책으로 판정합니다."""
        canonical = self.public_payload()
        canonical["allowedUserTypes"] = (
            sorted(self.allowed_user_types) if self.allowed_user_types is not None else None
        )
        canonical["requiredRoles"] = [
            {"serviceKey": role.service_key, "name": role.name}
            for role in sorted(self.required_roles, key=lambda role: (role.service_key, role.name))
        ]
        canonical["groupsServiceKeys"] = sorted(self.groups_service_keys)
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def policy_reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 128:
        raise DomainError(400, "INVALID_REQUEST", "사유는 1~128자로 입력하세요.")
    return value


def assert_other_approver(*, requester_id: str, approver_id: str) -> None:
    if requester_id == approver_id:
        raise DomainError(
            403,
            "POLICY_SELF_APPROVAL_FORBIDDEN",
            "본인의 정책 변경 요청은 승인할 수 없습니다.",
        )


def assert_policy_version(*, expected: int, current: int) -> None:
    if isinstance(expected, bool) or isinstance(current, bool) or expected < 1 or current < 1:
        raise DomainError(400, "INVALID_REQUEST", "정책 버전이 올바르지 않습니다.")
    if expected != current:
        raise DomainError(
            409,
            "POLICY_VERSION_CONFLICT",
            "요청 이후 정책이 변경됐습니다. 최신 정책으로 다시 요청하세요.",
        )
