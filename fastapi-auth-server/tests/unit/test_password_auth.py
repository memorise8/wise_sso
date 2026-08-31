from datetime import datetime, timedelta

import pytest

from wiseacct_sso.domain.auth import (
    DEFAULT_PASSWORD_POLICY,
    PasswordAuthFailure,
    PasswordCredentialRecord,
    PasswordPolicy,
    RegisterPasswordInput,
    assert_password_policy,
    login_with_password,
    normalize_email,
    register_with_password,
)
from wiseacct_sso.domain.users import CurrentUser, DomainError, UserStatus
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH

NOW = datetime(2026, 8, 31, 12, 0, 0)


class FakePasswordHasher:
    def __init__(self) -> None:
        self.hash_calls: list[str] = []
        self.verify_calls: list[tuple[str, str]] = []

    async def hash_password(self, password: str) -> str:
        self.hash_calls.append(password)
        return f"hash:{password}"

    async def verify_password(self, password_hash: str, password: str) -> bool:
        self.verify_calls.append((password_hash, password))
        return password_hash == f"hash:{password}"


class FakePasswordAuthStore:
    def __init__(self) -> None:
        self.users: dict[str, CurrentUser] = {}
        self.credentials: dict[str, PasswordCredentialRecord] = {}
        self.created_users: list[tuple[str, str | None, str, UserStatus]] = []
        self.pending_credentials: list[tuple[str, str, str, datetime]] = []
        self.successes: list[str] = []
        self.failures: list[str] = []

    async def find_user_by_email(self, email: str) -> CurrentUser | None:
        return self.users.get(email)

    async def create_user_with_password(
        self,
        *,
        email: str,
        name: str | None,
        password_hash: str,
        status: UserStatus,
    ) -> CurrentUser:
        self.created_users.append((email, name, password_hash, status))
        user = CurrentUser(
            id="user-created",
            email=email,
            email_verified=False,
            name=name,
            roles=(),
        )
        self.users[email] = user
        return user

    async def create_pending_password_credential(
        self,
        *,
        user_id: str,
        email: str,
        password_hash: str,
        expires_at: datetime,
    ) -> None:
        self.pending_credentials.append((user_id, email, password_hash, expires_at))

    async def find_credential_by_email(self, email: str) -> PasswordCredentialRecord | None:
        return self.credentials.get(email)

    async def mark_login_success(self, user_id: str) -> None:
        self.successes.append(user_id)

    async def mark_login_failure(self, user_id: str) -> None:
        self.failures.append(user_id)

    async def get_current_user(self, user_id: str) -> CurrentUser | None:
        return next((user for user in self.users.values() if user.id == user_id), None)


def user(*, email: str = "user@company.com", verified: bool = True) -> CurrentUser:
    return CurrentUser(
        id="user-1",
        email=email,
        email_verified=verified,
        name="Company User",
        roles=(),
    )


def credential(
    *,
    status: UserStatus = UserStatus.ACTIVE,
    locked_until: datetime | None = None,
) -> PasswordCredentialRecord:
    return PasswordCredentialRecord(
        user_id="user-1",
        email="user@company.com",
        password_hash="hash:correct-password-123",
        failed_login_count=0,
        locked_until=locked_until,
        user_status=status,
    )


def test_normalize_email_matches_express_trim_and_lowercase() -> None:
    assert normalize_email("  User@Company.COM  ") == "user@company.com"


def test_password_policy_counts_astral_emoji_as_two_utf16_code_units() -> None:
    assert_password_policy("user@example.com", "😀😀😀😀", DEFAULT_PASSWORD_POLICY)


def test_password_policy_rejects_seven_utf16_code_units() -> None:
    with pytest.raises(DomainError) as raised:
        assert_password_policy("user@example.com", "😀😀😀a", DEFAULT_PASSWORD_POLICY)

    assert (raised.value.code, raised.value.message) == (
        "WEAK_PASSWORD",
        "Password must be at least 8 characters",
    )


def test_password_policy_ascii_length_is_unchanged() -> None:
    assert_password_policy("user@example.com", "abcd1234", DEFAULT_PASSWORD_POLICY)

    with pytest.raises(DomainError):
        assert_password_policy("user@example.com", "abcd123", DEFAULT_PASSWORD_POLICY)


@pytest.mark.parametrize(
    ("password", "utf16_units"),
    [
        ("😀", 2),
        ("\ud800", 1),
        ("\udc00", 1),
        ("😀\ud800\udc00", 4),
    ],
)
def test_password_policy_counts_paired_and_lone_surrogates_as_js_utf16_units(
    password: str,
    utf16_units: int,
) -> None:
    assert_password_policy(
        "user@example.com",
        password,
        PasswordPolicy(min_length=utf16_units, allowed_email_domain=None),
    )

    with pytest.raises(DomainError):
        assert_password_policy(
            "user@example.com",
            password,
            PasswordPolicy(min_length=utf16_units + 1, allowed_email_domain=None),
        )


@pytest.mark.anyio
async def test_register_creates_pending_user_with_normalized_email() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()

    result = await register_with_password(
        store,
        passwords,
        RegisterPasswordInput(
            email=" User@Company.COM ",
            password="correct-password-123",
            name="Company User",
        ),
        clock=lambda: NOW,
    )

    assert result.user.email == "user@company.com"
    assert passwords.hash_calls == ["correct-password-123"]
    assert store.created_users == [
        (
            "user@company.com",
            "Company User",
            "hash:correct-password-123",
            UserStatus.PENDING_EMAIL_VERIFICATION,
        )
    ]


@pytest.mark.anyio
async def test_register_existing_user_returns_it_without_duplicate() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    existing = user(verified=False)
    store.users["user@company.com"] = existing
    store.credentials["user@company.com"] = credential(status=UserStatus.PENDING_EMAIL_VERIFICATION)

    result = await register_with_password(
        store,
        passwords,
        RegisterPasswordInput("USER@company.com", "another-password-123", "Ignored"),
        clock=lambda: NOW,
    )

    assert result.user is existing
    assert store.created_users == []
    assert store.pending_credentials == []


@pytest.mark.anyio
async def test_register_verified_oauth_user_creates_pending_password_link() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    existing = user(verified=True)
    store.users["user@company.com"] = existing

    result = await register_with_password(
        store,
        passwords,
        RegisterPasswordInput("USER@company.com", "correct-password-123", "Ignored"),
        clock=lambda: NOW,
    )

    assert result.user is existing
    assert store.pending_credentials == [
        (
            "user-1",
            "user@company.com",
            "hash:correct-password-123",
            NOW + timedelta(hours=24),
        )
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("policy", "email", "password", "status", "code", "message"),
    [
        (
            DEFAULT_PASSWORD_POLICY,
            "user@example.com",
            "short",
            400,
            "WEAK_PASSWORD",
            "Password must be at least 8 characters",
        ),
        (
            PasswordPolicy(min_length=8, allowed_email_domain="company.com"),
            "user@example.com",
            "password",
            403,
            "EMAIL_DOMAIN_NOT_ALLOWED",
            "Email domain is not allowed",
        ),
    ],
)
async def test_register_rejects_password_policy_before_hashing(
    policy: PasswordPolicy,
    email: str,
    password: str,
    status: int,
    code: str,
    message: str,
) -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()

    with pytest.raises(DomainError) as raised:
        await register_with_password(
            store,
            passwords,
            RegisterPasswordInput(email, password, None),
            policy=policy,
            clock=lambda: NOW,
        )

    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        status,
        code,
        message,
    )
    assert passwords.hash_calls == []


@pytest.mark.anyio
async def test_unknown_login_verifies_dummy_hash_and_does_not_touch_store_counters() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()

    with pytest.raises(PasswordAuthFailure) as raised:
        await login_with_password(
            store,
            passwords,
            email=" unknown@company.com ",
            password="wrong",
            clock=lambda: NOW,
        )

    assert passwords.verify_calls == [(DUMMY_PASSWORD_HASH, "wrong")]
    assert raised.value.public_code == "INVALID_CREDENTIALS"
    assert raised.value.reason_code == "USER_INACTIVE"
    assert raised.value.user_id is None
    assert store.failures == []
    assert store.successes == []


@pytest.mark.anyio
async def test_active_wrong_password_records_failure_only() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    store.credentials["user@company.com"] = credential()

    with pytest.raises(PasswordAuthFailure) as raised:
        await login_with_password(
            store,
            passwords,
            email="user@company.com",
            password="wrong",
            clock=lambda: NOW,
        )

    assert raised.value.reason_code == "INVALID_CREDENTIALS"
    assert store.failures == ["user-1"]
    assert store.successes == []


@pytest.mark.anyio
async def test_pending_verified_password_has_exact_verification_required_error() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    store.credentials["user@company.com"] = credential(status=UserStatus.PENDING_EMAIL_VERIFICATION)

    with pytest.raises(PasswordAuthFailure) as raised:
        await login_with_password(
            store,
            passwords,
            email="user@company.com",
            password="correct-password-123",
            clock=lambda: NOW,
        )

    error = raised.value
    assert (error.status_code, error.public_code, error.message) == (
        403,
        "EMAIL_VERIFICATION_REQUIRED",
        "Email verification is required before login",
    )
    assert (error.user_id, error.reason_code) == ("user-1", "EMAIL_VERIFICATION_REQUIRED")
    assert store.failures == []


@pytest.mark.anyio
@pytest.mark.parametrize("status", [UserStatus.SUSPENDED, UserStatus.DELETED])
async def test_inactive_login_is_generic_and_does_not_record_failure(status: UserStatus) -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    store.credentials["user@company.com"] = credential(status=status)

    with pytest.raises(PasswordAuthFailure) as raised:
        await login_with_password(
            store,
            passwords,
            email="user@company.com",
            password="correct-password-123",
            clock=lambda: NOW,
        )

    assert raised.value.reason_code == "USER_INACTIVE"
    assert raised.value.public_code == "INVALID_CREDENTIALS"
    assert store.failures == []


@pytest.mark.anyio
async def test_future_lock_is_generic_and_skips_failure_counter() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    store.credentials["user@company.com"] = credential(locked_until=NOW + timedelta(seconds=1))

    with pytest.raises(PasswordAuthFailure) as raised:
        await login_with_password(
            store,
            passwords,
            email="user@company.com",
            password="correct-password-123",
            clock=lambda: NOW,
        )

    assert raised.value.reason_code == "ACCOUNT_LOCKED"
    assert store.failures == []
    assert store.successes == []


@pytest.mark.anyio
async def test_lock_boundary_is_unlocked_and_success_returns_current_user() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    current = user()
    store.users[current.email or ""] = current
    store.credentials["user@company.com"] = credential(locked_until=NOW)

    result = await login_with_password(
        store,
        passwords,
        email="user@company.com",
        password="correct-password-123",
        clock=lambda: NOW,
    )

    assert result.user is current
    assert store.successes == ["user-1"]
    assert store.failures == []


@pytest.mark.anyio
async def test_missing_current_user_after_success_uses_exact_generic_error() -> None:
    store = FakePasswordAuthStore()
    passwords = FakePasswordHasher()
    store.credentials["user@company.com"] = credential()

    with pytest.raises(DomainError) as raised:
        await login_with_password(
            store,
            passwords,
            email="user@company.com",
            password="correct-password-123",
            clock=lambda: NOW,
        )

    assert (raised.value.status_code, raised.value.code, raised.value.message) == (
        401,
        "INVALID_CREDENTIALS",
        "Invalid email or password",
    )
    assert store.successes == ["user-1"]
