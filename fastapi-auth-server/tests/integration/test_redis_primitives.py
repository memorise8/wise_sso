import os
from collections.abc import AsyncIterator, Awaitable, Callable
from subprocess import CompletedProcess
from typing import cast
from uuid import uuid4

import anyio
import pytest
from redis.asyncio import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry

from wiseacct_sso.infrastructure.redis import RedisOptions, RedisStateStore, RedisUnavailableError

TEST_REDIS_URL = "redis://127.0.0.1:6380/15"
TEST_KEY_PREFIX = b"wiseacct:test:fastapi:redis-primitives:"
TEST_REDIS_CONTAINER = "wiseacct-sso-fastapi-dev-redis"
TEST_COMPOSE_PROJECT = "wiseacct-sso-fastapi-dev"
TEST_COMPOSE_SERVICE = "redis-fastapi-dev"
DOCKER = "/usr/bin/docker"


@pytest.fixture
async def real_redis() -> AsyncIterator[Redis]:
    if os.getenv("WISEACCT_FASTAPI_TEST_REDIS_URL") != TEST_REDIS_URL:
        pytest.skip(f"requires explicit isolated {TEST_REDIS_URL} opt-in")
    client = Redis.from_url(
        TEST_REDIS_URL,
        protocol=2,
        decode_responses=False,
        socket_connect_timeout=1,
        socket_timeout=1,
        max_connections=5,
        retry=Retry(NoBackoff(), 0),
        retry_on_timeout=False,
    )
    await cast(Awaitable[bool], client.ping())
    try:
        yield client
    finally:
        await client.aclose()


@pytest.fixture
async def store(real_redis: Redis) -> AsyncIterator[RedisStateStore]:
    del real_redis
    state = RedisStateStore.from_options(RedisOptions(TEST_REDIS_URL, max_connections=20))
    await state.start()
    try:
        yield state
    finally:
        await state.close()


@pytest.fixture
async def redis_key(real_redis: Redis) -> AsyncIterator[Callable[[str], bytes]]:
    keys: list[bytes] = []

    def create(label: str) -> bytes:
        key = TEST_KEY_PREFIX + label.encode() + b":" + uuid4().hex.encode()
        keys.append(key)
        return key

    try:
        yield create
    finally:
        if keys:
            await real_redis.delete(*keys)


async def _docker(*arguments: str, check: bool = True) -> CompletedProcess[bytes]:
    return await anyio.run_process(
        [DOCKER, *arguments],
        check=check,
    )


async def _assert_exact_candidate_container() -> None:
    if os.getenv("WISEACCT_FASTAPI_TEST_REDIS_CONTAINER") != TEST_REDIS_CONTAINER:
        pytest.skip(
            f"requires explicit WISEACCT_FASTAPI_TEST_REDIS_CONTAINER={TEST_REDIS_CONTAINER} opt-in"
        )
    inspected = await _docker(
        "inspect",
        "--format",
        '{{.Name}}|{{index .Config.Labels "com.docker.compose.project"}}|'
        '{{index .Config.Labels "com.docker.compose.service"}}',
        TEST_REDIS_CONTAINER,
    )
    assert inspected.stdout.decode().strip() == (
        f"/{TEST_REDIS_CONTAINER}|{TEST_COMPOSE_PROJECT}|{TEST_COMPOSE_SERVICE}"
    )


async def _wait_for_exact_candidate() -> None:
    for _ in range(50):
        result = await _docker(
            "exec",
            TEST_REDIS_CONTAINER,
            "redis-cli",
            "ping",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == b"PONG":
            return
        await anyio.sleep(0.1)
    pytest.fail(f"exact candidate Redis {TEST_REDIS_CONTAINER} did not become ready")


async def _restart_exact_candidate() -> None:
    result = await _docker("start", TEST_REDIS_CONTAINER, check=False)
    if result.returncode != 0:
        pytest.fail(f"failed to restart exact candidate Redis {TEST_REDIS_CONTAINER}")
    await _wait_for_exact_candidate()


@pytest.mark.anyio
async def test_nx_ex_and_one_time_consume_under_concurrency(
    store: RedisStateStore,
    real_redis: Redis,
    redis_key: Callable[[str], bytes],
) -> None:
    key = redis_key("consume")
    assert await store.set_if_absent(key, b"payload", 20) is True
    assert await store.set_if_absent(key, b"replacement", 20) is False
    assert 0 < await real_redis.ttl(key) <= 20

    results: list[bytes | None] = []

    async def consume_once() -> None:
        results.append(await store.consume(key))

    async with anyio.create_task_group() as tasks:
        for _ in range(25):
            tasks.start_soon(consume_once)

    assert results.count(b"payload") == 1
    assert results.count(None) == 24


@pytest.mark.anyio
async def test_raw_cas_does_not_normalize_serialization(
    store: RedisStateStore,
    real_redis: Redis,
    redis_key: Callable[[str], bytes],
) -> None:
    key = redis_key("cas")
    original = b'{ "clientId": "one", "state": null }'
    normalized = b'{"clientId":"one","state":null}'
    await real_redis.set(key, original, ex=20)

    assert await store.consume_if_exact(key, normalized) is None
    assert await store.get_raw(key) == original
    assert await store.consume_if_exact(key, original) == original
    assert await store.get_raw(key) is None


@pytest.mark.anyio
async def test_atomic_increment_exact_count_ttl_recovery_and_nonextension(
    store: RedisStateStore,
    real_redis: Redis,
    redis_key: Callable[[str], bytes],
) -> None:
    key = redis_key("rate")
    counts: list[int] = []

    async def increment() -> None:
        counts.append(await store.increment_with_ttl(key, 20))

    async with anyio.create_task_group() as tasks:
        for _ in range(50):
            tasks.start_soon(increment)

    assert sorted(counts) == list(range(1, 51))
    first_ttl = await real_redis.pttl(key)
    await anyio.sleep(0.05)
    assert await store.increment_with_ttl(key, 20) == 51
    assert await real_redis.pttl(key) <= first_ttl

    legacy_key = redis_key("legacy")
    await real_redis.set(legacy_key, b"7")
    assert await real_redis.ttl(legacy_key) == -1
    assert await store.increment_with_ttl(legacy_key, 20) == 8
    assert 0 < await real_redis.ttl(legacy_key) <= 20


@pytest.mark.anyio
async def test_outage_fails_closed_without_buffered_replay() -> None:
    unavailable = RedisStateStore.from_options(
        RedisOptions(
            "redis://127.0.0.1:6399/15",
            socket_connect_timeout_seconds=0.05,
            socket_timeout_seconds=0.05,
            max_connections=1,
        )
    )

    with pytest.raises(RedisUnavailableError):
        await unavailable.start()
    with pytest.raises(RedisUnavailableError):
        await unavailable.increment_with_ttl(TEST_KEY_PREFIX + b"unavailable", 20)


@pytest.mark.anyio
async def test_candidate_disconnect_does_not_replay_failed_mutation_after_restart(
    real_redis: Redis,
    redis_key: Callable[[str], bytes],
) -> None:
    await _assert_exact_candidate_container()
    key = redis_key("disconnect-no-replay")
    state = RedisStateStore.from_options(
        RedisOptions(
            TEST_REDIS_URL,
            socket_connect_timeout_seconds=0.2,
            socket_timeout_seconds=0.2,
            max_connections=1,
        )
    )
    await state.start()

    try:
        try:
            await _docker("stop", "--timeout", "5", TEST_REDIS_CONTAINER)
            with pytest.raises(RedisUnavailableError):
                await state.increment_with_ttl(key, 20)
            assert state.is_ready is False
        finally:
            await _restart_exact_candidate()

        # The failed command must not be queued or silently replayed on reconnect.
        await real_redis.connection_pool.disconnect()
        assert await real_redis.get(key) is None
        await state.start()
        assert await state.increment_with_ttl(key, 20) == 1
        assert await real_redis.get(key) == b"1"
    finally:
        await state.close()
