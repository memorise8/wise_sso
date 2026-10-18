#!/usr/bin/env python3
"""Clear one explicitly selected isolated Redis logical database over RESP."""

from __future__ import annotations

import argparse
import socket


def command(stream: socket.SocketIO, *parts: str) -> object:
    payload = f"*{len(parts)}\r\n".encode()
    for part in parts:
        encoded = part.encode()
        payload += f"${len(encoded)}\r\n".encode() + encoded + b"\r\n"
    stream.write(payload)
    stream.flush()
    prefix = stream.read(1)
    line = stream.readline().removesuffix(b"\r\n")
    if prefix == b"+" or prefix == b":" or prefix == b"$":
        return line
    if prefix == b"*":
        return [command_bulk(stream) for _ in range(int(line))]
    raise RuntimeError("Redis rejected isolated cleanup")


def command_bulk(stream: socket.SocketIO) -> bytes:
    if stream.read(1) != b"$":
        raise RuntimeError("unexpected Redis response")
    length = int(stream.readline().removesuffix(b"\r\n"))
    value = stream.read(length)
    if stream.read(2) != b"\r\n":
        raise RuntimeError("invalid Redis response")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=int, choices=(13, 14))
    args = parser.parse_args()
    with socket.create_connection(("127.0.0.1", 6380), timeout=3) as connection:
        stream = connection.makefile("rwb", buffering=0)
        command(stream, "SELECT", str(args.database))
        keys = command(stream, "KEYS", "*")
        if not isinstance(keys, list):
            raise RuntimeError("unexpected Redis key response")
        if keys:
            command(stream, "UNLINK", *(key.decode() for key in keys))
        remaining = command(stream, "DBSIZE")
        if remaining != b"0":
            raise RuntimeError("isolated Redis database is not empty after cleanup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
