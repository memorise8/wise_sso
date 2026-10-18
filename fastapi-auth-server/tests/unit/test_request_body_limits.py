from __future__ import annotations

import asyncio
import zlib
from collections import deque
from collections.abc import Sequence
from typing import cast

import pytest
from starlette.types import Message, Receive, Scope

from wiseacct_sso.api.middleware import (
    _COMPRESSED_JSON_LIMIT_BYTES,
    _express_json_receive,
)


async def _parse_json_frames(
    frames: Sequence[bytes],
    *,
    content_encoding: str,
    extra_headers: Sequence[tuple[bytes, bytes]] = (),
) -> tuple[bool, list[Message], bytes | None]:
    pending = deque(
        {
            "type": "http.request",
            "body": frame,
            "more_body": index < len(frames) - 1,
        }
        for index, frame in enumerate(frames)
    )
    sent: list[Message] = []
    scope = cast(
        Scope,
        {
            "type": "http",
            "method": "PATCH",
            "path": "/admin/users/target/status",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-encoding", content_encoding.encode("ascii")),
                *extra_headers,
            ],
        },
    )

    async def receive() -> Message:
        if pending:
            return pending.popleft()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    replay, valid = await _express_json_receive(scope, cast(Receive, receive), send)
    replayed_body: bytes | None = None
    if valid:
        replayed = await replay()
        replayed_body = replayed.get("body", b"")
    return valid, sent, replayed_body


@pytest.mark.parametrize("content_encoding", ["gzip", "deflate"])
def test_compression_bomb_is_rejected_while_streaming(content_encoding: str) -> None:
    window_bits = 31 if content_encoding == "gzip" else zlib.MAX_WBITS
    bomb = zlib.compress(b'"' + (b"a" * (1024 * 1024)) + b'"', wbits=window_bits)
    frames = [bomb[index : index + 7] for index in range(0, len(bomb), 7)]

    valid, sent, replayed_body = asyncio.run(
        _parse_json_frames(frames, content_encoding=content_encoding)
    )

    assert valid is False
    assert replayed_body is None
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 500


@pytest.mark.parametrize("content_encoding", ["gzip", "deflate"])
def test_chunked_compressed_json_is_decoded_with_no_declared_length(
    content_encoding: str,
) -> None:
    body = b'{"status":"SUSPENDED"}'
    window_bits = 31 if content_encoding == "gzip" else zlib.MAX_WBITS
    compressed = zlib.compress(body, wbits=window_bits)
    frames = [compressed[index : index + 3] for index in range(0, len(compressed), 3)]
    frames.append(b"")

    valid, sent, replayed_body = asyncio.run(
        _parse_json_frames(
            frames,
            content_encoding=content_encoding,
            extra_headers=((b"transfer-encoding", b"chunked"),),
        )
    )

    assert valid is True
    assert sent == []
    assert replayed_body == body


def test_small_content_length_cannot_bypass_streamed_compressed_input_limit() -> None:
    valid_stream = zlib.compress(b"{}")
    oversized_trailing_data = b"x" * _COMPRESSED_JSON_LIMIT_BYTES
    frames = [valid_stream, oversized_trailing_data]

    valid, sent, replayed_body = asyncio.run(
        _parse_json_frames(
            frames,
            content_encoding="deflate",
            extra_headers=(
                (b"content-length", b"2"),
                (b"transfer-encoding", b"chunked"),
            ),
        )
    )

    assert valid is False
    assert replayed_body is None
    assert sent[0]["status"] == 500


def test_oversized_content_length_with_chunked_encoding_fails_closed() -> None:
    compressed = zlib.compress(b"{}", wbits=31)

    valid, sent, replayed_body = asyncio.run(
        _parse_json_frames(
            [compressed],
            content_encoding="gzip",
            extra_headers=(
                (b"content-length", str(_COMPRESSED_JSON_LIMIT_BYTES + 1).encode("ascii")),
                (b"transfer-encoding", b"chunked"),
            ),
        )
    )

    assert valid is False
    assert replayed_body is None
    assert sent[0]["status"] == 500
