import pytest

from wiseacct_sso.domain.users import (
    CurrentUser,
    CurrentUserWithStatus,
    DomainError,
    Role,
    UserStatus,
    get_current_user,
    require_active_user_for_token_issue,
)


class FakeUserStore:
    def __init__(self, user: CurrentUserWithStatus | None) -> None:
        self.user = user
        self.lookups: list[str] = []

    async def get_current_user(self, user_id: str) -> CurrentUser | None:
        self.lookups.append(user_id)
        return self.user

    async def get_current_user_with_status(self, user_id: str) -> CurrentUserWithStatus | None:
        self.lookups.append(user_id)
        return self.user


def current_user(status: UserStatus = UserStatus.ACTIVE) -> CurrentUserWithStatus:
    return CurrentUserWithStatus(
        id="user-1",
        email="user@example.com",
        email_verified=True,
        name="Example User",
        roles=(Role(service_key="temis", name="user"),),
        status=status,
    )


@pytest.mark.anyio
async def test_get_current_user_returns_store_response_unchanged() -> None:
    expected = current_user()
    store = FakeUserStore(expected)

    assert await get_current_user(store, "user-1") is expected
    assert store.lookups == ["user-1"]


@pytest.mark.anyio
async def test_require_active_user_returns_active_user() -> None:
    expected = current_user()
    store = FakeUserStore(expected)

    assert await require_active_user_for_token_issue(store, "user-1") is expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stored",
    [
        None,
        current_user(UserStatus.PENDING_EMAIL_VERIFICATION),
        current_user(UserStatus.SUSPENDED),
        current_user(UserStatus.DELETED),
    ],
)
async def test_require_active_user_has_exact_unauthorized_error(
    stored: CurrentUserWithStatus | None,
) -> None:
    store = FakeUserStore(stored)

    with pytest.raises(DomainError) as raised:
        await require_active_user_for_token_issue(store, "user-1")

    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        401,
        "UNAUTHORIZED",
        "Authentication is required",
    )
