"""Password hashing primitives compatible with the Express Argon2id policy."""

from __future__ import annotations

from typing import Final, Protocol

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

ARGON2_MEMORY_COST_KIB: Final = 19_456
ARGON2_TIME_COST: Final = 2
ARGON2_PARALLELISM: Final = 1
ARGON2_HASH_LENGTH: Final = 32
ARGON2_SALT_LENGTH: Final = 16
DEFAULT_PASSWORD_HASH_THREADS: Final = 4

# Existing Express dummy credential. Keeping it fixed prevents user-enumeration shortcuts.
DUMMY_PASSWORD_HASH: Final = (
    "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$"  # noqa: S105
    "U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM"
)


class _SyncPasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, hash: str, password: str) -> bool: ...


def build_password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        salt_len=ARGON2_SALT_LENGTH,
        type=Type.ID,
    )


class AsyncPasswordHasher:
    """Run memory-hard password work outside the event loop with bounded concurrency."""

    def __init__(
        self,
        *,
        max_threads: int = DEFAULT_PASSWORD_HASH_THREADS,
        hasher: _SyncPasswordHasher | None = None,
    ) -> None:
        if max_threads <= 0:
            raise ValueError("max_threads must be positive")
        self._hasher = hasher or build_password_hasher()
        self._limiter = anyio.CapacityLimiter(max_threads)

    async def hash_password(self, password: str) -> str:
        if not password:
            raise ValueError("password must not be empty")
        return await anyio.to_thread.run_sync(
            self._hasher.hash,
            password,
            limiter=self._limiter,
        )

    async def verify_password(self, password_hash: str, password: str) -> bool:
        if not password_hash:
            return False

        def verify() -> bool:
            try:
                return self._hasher.verify(password_hash, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False

        return await anyio.to_thread.run_sync(verify, limiter=self._limiter)
