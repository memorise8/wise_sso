"""Fail-closed Redis primitives compatible with the Express SSO runtime."""

from __future__ import annotations

import logging
from collections.abc import Awaitable
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, cast

from redis.asyncio import BlockingConnectionPool, Redis
from redis.backoff import NoBackoff
from redis.retry import Retry

OAUTH_STATE_KEY_PREFIX: Final = b"wiseacct:oauth-state:"
AUTH_HANDOFF_KEY_PREFIX: Final = b"wiseacct:auth-handoff:"
RATE_LIMIT_KEY_PREFIX: Final = b"wiseacct:rate-limit:"
OAUTH_STATE_TTL_SECONDS: Final = 10 * 60
AUTH_HANDOFF_TTL_SECONDS: Final = 2 * 60

_LOGGER: Final = logging.getLogger(__name__)

_CONSUME_SCRIPT: Final = """
local value = redis.call('GET', KEYS[1])
if value then redis.call('DEL', KEYS[1]) end
return value
""".strip()

_CONSUME_IF_EXACT_SCRIPT: Final = """
local value = redis.call('GET', KEYS[1])
if not value then return nil end
if value == ARGV[1] then redis.call('DEL', KEYS[1]); return value end
return nil
""".strip()

_INCREMENT_WITH_TTL_SCRIPT: Final = """
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
""".strip()


def _exception_type(error: BaseException) -> str:
    name = type(error).__name__[:64]
    safe = name and all(
        character.isascii() and (character.isalnum() or character == "_") for character in name
    )
    return name if safe else "Error"


def _diagnose(stage: str, error: BaseException) -> None:
    """Log only bounded classifier fields; never include Redis data or connection details."""

    _LOGGER.warning(
        "redis_dependency_failure stage=%s exception_type=%s",
        stage,
        _exception_type(error),
    )


def _failure(operation: str, stage: str, error: BaseException) -> RedisUnavailableError:
    _diagnose(stage, error)
    return RedisUnavailableError(operation, error)


class RedisUnavailableError(RuntimeError):
    """Redis state could not be read or mutated, so the request must fail closed."""

    def __init__(self, operation: str, cause: BaseException | None = None) -> None:
        super().__init__("Redis is unavailable for authentication state storage")
        self.operation = operation
        self.__cause__ = cause


@dataclass(frozen=True, slots=True)
class RedisOptions:
    """Finite connection limits; authentication mutations are never retried."""

    url: str
    socket_connect_timeout_seconds: float = 1.0
    socket_timeout_seconds: float = 1.0
    pool_wait_timeout_seconds: float = 1.0
    max_connections: int = 20

    def __post_init__(self) -> None:
        if (
            self.socket_connect_timeout_seconds <= 0
            or self.socket_timeout_seconds <= 0
            or self.pool_wait_timeout_seconds <= 0
        ):
            raise ValueError("Redis timeouts must be positive")
        if self.max_connections <= 0:
            raise ValueError("Redis max_connections must be positive")


def sha256_hex(value: str | bytes) -> str:
    raw = node_utf8_bytes(value) if isinstance(value, str) else value
    return sha256(raw).hexdigest()


def node_utf8_bytes(value: str) -> bytes:
    """Encode a JavaScript string as Node does before hashing or Redis transport."""

    normalized: list[str] = []
    index = 0
    while index < len(value):
        code_point = ord(value[index])
        if 0xD800 <= code_point <= 0xDBFF:
            if index + 1 < len(value):
                low_surrogate = ord(value[index + 1])
                if 0xDC00 <= low_surrogate <= 0xDFFF:
                    normalized.append(
                        chr(0x10000 + ((code_point - 0xD800) << 10) + low_surrogate - 0xDC00)
                    )
                    index += 2
                    continue
            normalized.append("\ufffd")
        elif 0xDC00 <= code_point <= 0xDFFF:
            normalized.append("\ufffd")
        else:
            normalized.append(value[index])
        index += 1
    return "".join(normalized).encode("utf-8")


def oauth_state_key(state: str) -> bytes:
    return OAUTH_STATE_KEY_PREFIX + node_utf8_bytes(state)


def auth_handoff_key(code: str) -> bytes:
    return AUTH_HANDOFF_KEY_PREFIX + sha256_hex(code).encode("ascii")


def rate_limit_key(client_key: str, route: str) -> bytes:
    return RATE_LIMIT_KEY_PREFIX + f"{client_key}:{route}".encode()


class RedisStateStore:
    """Small raw-bytes Redis boundary for one-time state and rate limits."""

    def __init__(self, client: Redis, *, owns_client: bool = False) -> None:
        self._client = client
        self._owns_client = owns_client
        self._ready = False

    @classmethod
    def from_options(cls, options: RedisOptions) -> RedisStateStore:
        pool = BlockingConnectionPool.from_url(
            options.url,
            protocol=2,
            decode_responses=False,
            socket_connect_timeout=options.socket_connect_timeout_seconds,
            socket_timeout=options.socket_timeout_seconds,
            timeout=options.pool_wait_timeout_seconds,
            max_connections=options.max_connections,
            retry=Retry(NoBackoff(), 0),
            retry_on_timeout=False,
        )
        client = Redis(connection_pool=pool)
        return cls(client, owns_client=True)

    @property
    def is_ready(self) -> bool:
        return self._ready

    async def start(self) -> None:
        try:
            response = await cast(Awaitable[bool], self._client.ping())
            if response is not True:
                raise TypeError("Redis PING returned an invalid response")
        except Exception as error:
            self._ready = False
            await self._close_owned_client_safely()
            raise _failure("start", "start", error) from error
        self._ready = True

    async def ping(self) -> None:
        """Probe the existing client without reading or mutating authentication state."""

        try:
            response = await cast(Awaitable[bool], self._client.ping())
            if response is not True:
                raise TypeError("Redis PING returned an invalid response")
        except Exception as error:
            self._ready = False
            raise _failure("ping", "command:ping", error) from error
        self._ready = True

    async def close(self) -> None:
        self._ready = False
        if not self._owns_client:
            return
        try:
            await self._client.aclose(close_connection_pool=True)
        except Exception as error:
            raise _failure("close", "close", error) from error

    async def set_if_absent(self, key: str | bytes, value: bytes, ttl_seconds: int) -> bool:
        self._validate_ttl(ttl_seconds)
        result = await self._execute(
            "set_if_absent",
            cast(Awaitable[object], self._client.set(key, value, nx=True, ex=ttl_seconds)),
        )
        if result is None:
            return False
        if result is not True:
            error = TypeError("invalid Redis SET response")
            raise _failure("set_if_absent", "response:set_if_absent", error)
        return True

    async def get_raw(self, key: str | bytes) -> bytes | None:
        result = await self._execute("get_raw", cast(Awaitable[object], self._client.get(key)))
        return self._raw_or_none("get_raw", result)

    async def consume(self, key: str | bytes) -> bytes | None:
        result = await self._execute(
            "consume",
            cast(Awaitable[object], self._client.eval(_CONSUME_SCRIPT, 1, key)),
        )
        return self._raw_or_none("consume", result)

    async def consume_if_exact(self, key: str | bytes, expected: bytes) -> bytes | None:
        result = await self._execute(
            "consume_if_exact",
            cast(
                Awaitable[object],
                self._client.eval(_CONSUME_IF_EXACT_SCRIPT, 1, key, expected),
            ),
        )
        return self._raw_or_none("consume_if_exact", result)

    async def increment_with_ttl(self, key: str | bytes, ttl_seconds: int) -> int:
        self._validate_ttl(ttl_seconds)
        result = await self._execute(
            "increment_with_ttl",
            cast(
                Awaitable[object],
                self._client.eval(_INCREMENT_WITH_TTL_SCRIPT, 1, key, ttl_seconds),
            ),
        )
        if isinstance(result, bool) or not isinstance(result, int) or result < 1:
            error = TypeError("invalid Redis rate-limit response")
            raise _failure("increment_with_ttl", "response:increment_with_ttl", error)
        return result

    async def _execute(self, operation: str, command: Awaitable[object]) -> object:
        if not self._ready:
            close = getattr(command, "close", None)
            if close is not None:
                close()
            error = RuntimeError("Redis client is not started")
            raise _failure(operation, f"not_ready:{operation}", error)
        try:
            return await command
        except Exception as error:
            self._ready = False
            raise _failure(operation, f"command:{operation}", error) from error

    async def _close_owned_client_safely(self) -> None:
        if self._owns_client:
            try:
                await self._client.aclose(close_connection_pool=True)
            except Exception as error:
                _diagnose("owned_client_cleanup", error)

    @staticmethod
    def _validate_ttl(ttl_seconds: int) -> None:
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("Redis TTL must be a positive integer")

    @staticmethod
    def _raw_or_none(operation: str, value: object) -> bytes | None:
        if value is None:
            return None
        if isinstance(value, bytes):
            return value
        error = TypeError("Redis did not return raw bytes")
        raise _failure(operation, f"response:{operation}", error)
