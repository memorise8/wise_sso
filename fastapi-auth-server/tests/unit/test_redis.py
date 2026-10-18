import logging
from unittest.mock import AsyncMock

import pytest

from wiseacct_sso.infrastructure.redis import (
    AUTH_HANDOFF_TTL_SECONDS,
    OAUTH_STATE_TTL_SECONDS,
    RedisOptions,
    RedisStateStore,
    RedisUnavailableError,
    auth_handoff_key,
    oauth_state_key,
    rate_limit_key,
    sha256_hex,
)


@pytest.fixture
def client() -> AsyncMock:
    mock = AsyncMock()
    mock.ping.return_value = True
    mock.set.return_value = True
    mock.get.return_value = b"raw"
    mock.eval.return_value = b"raw"
    return mock


@pytest.mark.anyio
async def test_start_pings_and_set_uses_atomic_nx_ex(client: AsyncMock) -> None:
    store = RedisStateStore(client)
    await store.start()

    assert await store.set_if_absent(b"key", b"value", 60) is True
    client.set.assert_awaited_once_with(b"key", b"value", nx=True, ex=60)


@pytest.mark.anyio
async def test_mutation_before_start_fails_closed_without_issuing_command(
    client: AsyncMock,
) -> None:
    store = RedisStateStore(client)

    with pytest.raises(RedisUnavailableError, match="Redis is unavailable"):
        await store.set_if_absent(b"key", b"value", 60)

    client.set.assert_not_awaited()


@pytest.mark.anyio
async def test_command_failure_marks_store_unready_and_logs_only_sanitized_type(
    client: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    client.get.side_effect = ConnectionError("redis://user:secret@host key=private")
    store = RedisStateStore(client)
    await store.start()

    with caplog.at_level(logging.WARNING):
        with pytest.raises(RedisUnavailableError) as failure:
            await store.get_raw(b"key")

    assert failure.value.operation == "get_raw"
    assert store.is_ready is False
    assert caplog.messages == [
        "redis_dependency_failure stage=command:get_raw exception_type=ConnectionError"
    ]
    assert "secret" not in caplog.text
    assert "private" not in caplog.text


@pytest.mark.anyio
async def test_start_and_owned_cleanup_failures_have_bounded_diagnostics(
    client: AsyncMock, caplog: pytest.LogCaptureFixture
) -> None:
    client.ping.side_effect = TimeoutError("redis://secret")
    client.aclose.side_effect = OSError("private-value")
    store = RedisStateStore(client, owns_client=True)

    with caplog.at_level(logging.WARNING):
        with pytest.raises(RedisUnavailableError) as failure:
            await store.start()

    assert failure.value.operation == "start"
    assert caplog.messages == [
        "redis_dependency_failure stage=owned_client_cleanup exception_type=OSError",
        "redis_dependency_failure stage=start exception_type=TimeoutError",
    ]
    assert "secret" not in caplog.text
    assert "private-value" not in caplog.text


@pytest.mark.anyio
async def test_raw_consume_and_compare_consume_preserve_exact_bytes(client: AsyncMock) -> None:
    store = RedisStateStore(client)
    await store.start()
    expected = b'{ "order": [2, 1] }'

    assert await store.consume(b"one") == b"raw"
    assert await store.consume_if_exact(b"two", expected) == b"raw"
    assert client.eval.await_args_list[1].args[-1] is expected


@pytest.mark.anyio
async def test_increment_requires_positive_integer_response(client: AsyncMock) -> None:
    client.eval.return_value = 8
    store = RedisStateStore(client)
    await store.start()

    assert await store.increment_with_ttl(b"rate", 10) == 8
    assert client.eval.await_args.args[-1] == 10

    client.eval.return_value = b"8"
    with pytest.raises(RedisUnavailableError):
        await store.increment_with_ttl(b"rate", 10)


def test_exact_key_and_hash_helpers_match_express_contract() -> None:
    assert OAUTH_STATE_TTL_SECONDS == 600
    assert AUTH_HANDOFF_TTL_SECONDS == 120
    assert oauth_state_key("opaque") == b"wiseacct:oauth-state:opaque"
    assert auth_handoff_key("code") == (
        b"wiseacct:auth-handoff:5694d08a2e53ffcae0c3103e5ad6f6076abd960eb1f8a56577040bc1028f702b"
    )
    assert rate_limit_key("127.0.0.1", "/auth/login") == (
        b"wiseacct:rate-limit:127.0.0.1:/auth/login"
    )
    assert sha256_hex(b"code") == sha256_hex("code")


def test_redis_options_reject_unbounded_values() -> None:
    with pytest.raises(ValueError):
        RedisOptions("redis://127.0.0.1:6380/15", socket_timeout_seconds=0)
    with pytest.raises(ValueError):
        RedisOptions("redis://127.0.0.1:6380/15", pool_wait_timeout_seconds=0)
    with pytest.raises(ValueError):
        RedisOptions("redis://127.0.0.1:6380/15", max_connections=0)
