"""권한 점검 입력과 완료 상태 보호 규칙을 검증합니다."""

import pytest

from wiseacct_sso.domain.access_reviews import (
    require_open_review,
    require_pending_item,
    review_page,
    review_reason,
    review_title,
)
from wiseacct_sso.domain.users import DomainError


@pytest.mark.parametrize("value", ["", " ", "a" * 129])
def test_review_requires_bounded_reason(value: str) -> None:
    with pytest.raises(DomainError) as caught:
        review_reason(value)
    assert caught.value.status_code == 400


def test_review_normalizes_reason_and_title() -> None:
    assert review_reason("  정기 점검  ") == "정기 점검"
    assert review_title("  서비스 권한 점검  ") == "서비스 권한 점검"


@pytest.mark.parametrize("value", ["", " ", "a" * 161])
def test_review_requires_bounded_title(value: str) -> None:
    with pytest.raises(DomainError):
        review_title(value)


@pytest.mark.parametrize(
    "page,page_size",
    [(0, 25), (-1, 25), (1, 0), (1, 101), (True, 25), (1, True)],
)
def test_review_rejects_invalid_page(page: int, page_size: int) -> None:
    with pytest.raises(DomainError):
        review_page(page, page_size)


def test_review_accepts_maximum_page_size() -> None:
    review_page(1, 100)


@pytest.mark.parametrize("decision", ["KEEP", "REVOKE", "ALREADY_REMOVED"])
def test_final_decision_cannot_be_overwritten(decision: str) -> None:
    with pytest.raises(DomainError) as caught:
        require_pending_item(decision)
    assert caught.value.status_code == 409


def test_completed_review_cannot_be_changed() -> None:
    with pytest.raises(DomainError) as caught:
        require_open_review("COMPLETED")
    assert caught.value.status_code == 409


def test_open_review_and_pending_item_can_proceed() -> None:
    require_open_review("OPEN")
    require_pending_item("PENDING")
