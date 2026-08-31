"""Pure password registration and login orchestration."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal, Protocol

from wiseacct_sso.domain.users import CurrentUser, DomainError, UserStatus
from wiseacct_sso.infrastructure.security import DUMMY_PASSWORD_HASH

DEFAULT_PASSWORD_MIN_LENGTH: Final = 8
PENDING_PASSWORD_CREDENTIAL_TTL: Final = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    min_length: int
    allowed_email_domain: str | None

    def __post_init__(self) -> None:
        if self.min_length < 1:
            raise ValueError("min_length must be positive")


DEFAULT_PASSWORD_POLICY: Final = PasswordPolicy(
    min_length=DEFAULT_PASSWORD_MIN_LENGTH,
    allowed_email_domain=None,
)


@dataclass(frozen=True, slots=True)
class RegisterPasswordInput:
    email: str
    password: str
    name: str | None


@dataclass(frozen=True, slots=True)
class PasswordCredentialRecord:
    user_id: str
    email: str
    password_hash: str
    failed_login_count: int
    locked_until: datetime | None
    user_status: UserStatus


@dataclass(frozen=True, slots=True)
class PasswordAuthResult:
    user: CurrentUser


PasswordAuthReason = Literal[
    "ACCOUNT_LOCKED",
    "EMAIL_VERIFICATION_REQUIRED",
    "INVALID_CREDENTIALS",
    "USER_INACTIVE",
]


class PasswordAuthFailure(DomainError):
    """Publicly generic login failure carrying private audit context."""

    def __init__(self, *, user_id: str | None, reason_code: PasswordAuthReason) -> None:
        verification_required = reason_code == "EMAIL_VERIFICATION_REQUIRED"
        super().__init__(
            403 if verification_required else 401,
            "EMAIL_VERIFICATION_REQUIRED" if verification_required else "INVALID_CREDENTIALS",
            (
                "Email verification is required before login"
                if verification_required
                else "Invalid email or password"
            ),
        )
        self.user_id = user_id
        self.reason_code = reason_code

    @property
    def public_code(self) -> str:
        return self.code


class PasswordHasher(Protocol):
    async def hash_password(self, password: str) -> str: ...

    async def verify_password(self, password_hash: str, password: str) -> bool: ...


class PasswordAuthStore(Protocol):
    async def find_user_by_email(self, email: str) -> CurrentUser | None: ...

    async def create_user_with_password(
        self,
        *,
        email: str,
        name: str | None,
        password_hash: str,
        status: UserStatus,
    ) -> CurrentUser: ...

    async def create_pending_password_credential(
        self,
        *,
        user_id: str,
        email: str,
        password_hash: str,
        expires_at: datetime,
    ) -> None: ...

    async def find_credential_by_email(self, email: str) -> PasswordCredentialRecord | None: ...

    async def mark_login_success(self, user_id: str) -> None: ...

    async def mark_login_failure(self, user_id: str) -> None: ...

    async def get_current_user(self, user_id: str) -> CurrentUser | None: ...


Clock = Callable[[], datetime]


def normalize_email(email: str) -> str:
    return email.strip().lower()


def assert_password_policy(email: str, password: str, policy: PasswordPolicy) -> None:
    password_utf16_code_units = len(password.encode("utf-16-le", errors="surrogatepass")) // 2
    if password_utf16_code_units < policy.min_length:
        raise DomainError(
            400,
            "WEAK_PASSWORD",
            f"Password must be at least {policy.min_length} characters",
        )
    if policy.allowed_email_domain and not email.endswith(f"@{policy.allowed_email_domain}"):
        raise DomainError(403, "EMAIL_DOMAIN_NOT_ALLOWED", "Email domain is not allowed")


async def register_with_password(
    store: PasswordAuthStore,
    passwords: PasswordHasher,
    input: RegisterPasswordInput,
    *,
    policy: PasswordPolicy = DEFAULT_PASSWORD_POLICY,
    clock: Clock,
) -> PasswordAuthResult:
    email = normalize_email(input.email)
    assert_password_policy(email, input.password, policy)
    password_hash = await passwords.hash_password(input.password)

    existing_user = await store.find_user_by_email(email)
    if existing_user is not None:
        existing_credential = await store.find_credential_by_email(email)
        if existing_credential is None and existing_user.email_verified:
            await store.create_pending_password_credential(
                user_id=existing_user.id,
                email=email,
                password_hash=password_hash,
                expires_at=clock() + PENDING_PASSWORD_CREDENTIAL_TTL,
            )
        return PasswordAuthResult(user=existing_user)

    user = await store.create_user_with_password(
        email=email,
        name=input.name,
        password_hash=password_hash,
        status=UserStatus.PENDING_EMAIL_VERIFICATION,
    )
    return PasswordAuthResult(user=user)


async def login_with_password(
    store: PasswordAuthStore,
    passwords: PasswordHasher,
    *,
    email: str,
    password: str,
    clock: Clock,
) -> PasswordAuthResult:
    normalized_email = normalize_email(email)
    credential = await store.find_credential_by_email(normalized_email)
    password_hash = credential.password_hash if credential is not None else DUMMY_PASSWORD_HASH
    verified = await passwords.verify_password(password_hash, password)
    locked = (
        credential is not None
        and credential.locked_until is not None
        and credential.locked_until > clock()
    )

    if (
        credential is not None
        and credential.user_status is UserStatus.PENDING_EMAIL_VERIFICATION
        and verified
        and not locked
    ):
        raise PasswordAuthFailure(
            user_id=credential.user_id,
            reason_code="EMAIL_VERIFICATION_REQUIRED",
        )

    can_login = (
        credential is not None
        and credential.user_status is UserStatus.ACTIVE
        and not locked
        and verified
    )
    if not can_login:
        if credential is not None and credential.user_status is UserStatus.ACTIVE and not locked:
            await store.mark_login_failure(credential.user_id)
        reason_code: PasswordAuthReason
        if locked:
            reason_code = "ACCOUNT_LOCKED"
        elif credential is not None and credential.user_status is UserStatus.ACTIVE:
            reason_code = "INVALID_CREDENTIALS"
        else:
            reason_code = "USER_INACTIVE"
        raise PasswordAuthFailure(
            user_id=credential.user_id if credential is not None else None,
            reason_code=reason_code,
        )

    if credential is None:
        raise RuntimeError("successful authentication did not retain its credential")

    await store.mark_login_success(credential.user_id)
    user = await store.get_current_user(credential.user_id)
    if user is None:
        raise DomainError(401, "INVALID_CREDENTIALS", "Invalid email or password")
    return PasswordAuthResult(user=user)
