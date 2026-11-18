"""권한 점검 입력과 상태 전이 규칙."""

from typing import Literal

from wiseacct_sso.domain.users import DomainError

type ReviewDecision = Literal["KEEP", "REVOKE"]
type ItemDecision = Literal["PENDING", "KEEP", "REVOKE", "ALREADY_REMOVED"]


def review_reason(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 128:
        raise DomainError(400, "INVALID_REQUEST", "사유는 1~128자로 입력하세요.")
    return value


def review_title(value: str) -> str:
    value = value.strip()
    if not 1 <= len(value) <= 160:
        raise DomainError(400, "INVALID_REQUEST", "점검 이름은 1~160자로 입력하세요.")
    return value


def review_page(page: int, page_size: int) -> None:
    if (
        isinstance(page, bool)
        or isinstance(page_size, bool)
        or not 1 <= page <= 2_147_483_647
        or not 1 <= page_size <= 100
    ):
        raise DomainError(400, "INVALID_REQUEST", "잘못된 페이지 요청입니다.")


def require_open_review(status: str) -> None:
    if status != "OPEN":
        raise DomainError(409, "ACCESS_REVIEW_CLOSED", "이미 완료된 점검입니다.")


def require_pending_item(decision: str) -> None:
    if decision != "PENDING":
        raise DomainError(409, "ACCESS_REVIEW_ITEM_DECIDED", "이미 결정된 항목입니다.")
