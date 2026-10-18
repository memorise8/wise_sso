import threading
import time

import anyio
import pytest
from argon2 import extract_parameters

from wiseacct_sso.infrastructure.security import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LENGTH,
    ARGON2_TIME_COST,
    DUMMY_PASSWORD_HASH,
    AsyncPasswordHasher,
)

EXPRESS_GENERATED_PASSWORD_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$ABEiM0RVZneImaq7zN3u/w$"
    "zeuaFYFAbBFiUM3IwmEtHtc4d61aWWRsUGaZIOShyuI"
)


@pytest.mark.anyio
async def test_verifies_existing_express_argon2id_hash() -> None:
    passwords = AsyncPasswordHasher()

    assert (
        await passwords.verify_password(EXPRESS_GENERATED_PASSWORD_HASH, "express-fixture-password")
        is True
    )
    assert await passwords.verify_password(EXPRESS_GENERATED_PASSWORD_HASH, "wrong") is False
    assert await passwords.verify_password(DUMMY_PASSWORD_HASH, "wrong") is False


@pytest.mark.anyio
async def test_new_hash_uses_approved_argon2id_parameters() -> None:
    passwords = AsyncPasswordHasher()
    encoded = await passwords.hash_password("correct-password-123")
    parameters = extract_parameters(encoded)

    assert encoded.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert await passwords.verify_password(encoded, "correct-password-123") is True
    assert await passwords.verify_password(encoded, "wrong-password") is False
    assert parameters.memory_cost == ARGON2_MEMORY_COST_KIB
    assert parameters.time_cost == ARGON2_TIME_COST
    assert parameters.parallelism == ARGON2_PARALLELISM
    assert parameters.hash_len == ARGON2_HASH_LENGTH
    assert parameters.salt_len == ARGON2_SALT_LENGTH


@pytest.mark.anyio
async def test_malformed_hash_is_a_generic_verification_failure() -> None:
    passwords = AsyncPasswordHasher()

    assert await passwords.verify_password("not-an-argon2-hash", "password") is False
    assert await passwords.verify_password("", "password") is False


@pytest.mark.anyio
@pytest.mark.parametrize("unpaired_surrogate", ["\ud800", "\udfff"])
async def test_unpaired_utf16_surrogate_matches_node_replacement_character(
    unpaired_surrogate: str,
) -> None:
    passwords = AsyncPasswordHasher()

    encoded = await passwords.hash_password(f"before-{unpaired_surrogate}-after")

    assert await passwords.verify_password(encoded, "before-\ufffd-after") is True
    assert await passwords.verify_password(encoded, f"before-{unpaired_surrogate}-after") is True


@pytest.mark.anyio
async def test_valid_surrogate_pair_and_python_astral_character_interoperate() -> None:
    passwords = AsyncPasswordHasher()
    surrogate_pair = "before-\ud83d\ude00-after"
    python_astral = f"before-{chr(0x1F600)}-after"

    encoded_from_pair = await passwords.hash_password(surrogate_pair)
    encoded_from_astral = await passwords.hash_password(python_astral)

    assert await passwords.verify_password(encoded_from_pair, python_astral) is True
    assert await passwords.verify_password(encoded_from_astral, surrogate_pair) is True


class _ConcurrencyProbeHasher:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()

    def hash(self, password: str) -> str:
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.04)
        with self.lock:
            self.active -= 1
        return password

    def verify(self, hash: str, password: str) -> bool:
        return hash == password


@pytest.mark.anyio
async def test_password_work_is_bounded_off_the_event_loop() -> None:
    probe = _ConcurrencyProbeHasher()
    passwords = AsyncPasswordHasher(max_threads=2, hasher=probe)

    async with anyio.create_task_group() as tasks:
        for number in range(6):
            tasks.start_soon(passwords.hash_password, f"password-{number}")

    assert probe.peak == 2
