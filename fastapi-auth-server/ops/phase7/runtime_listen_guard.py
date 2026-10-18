#!/usr/bin/env python3
"""Prove that one exact process owns a TCP LISTEN socket on an expected port."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

SOCKET_LINK = re.compile(r"socket:\[(\d+)]")
LOOPBACK_ADDRESSES = {
    "tcp": {"0100007F"},
    "tcp6": {"00000000000000000000000001000000"},
}


def process_socket_inodes(pid: int) -> set[str]:
    inodes: set[str] = set()
    for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        match = SOCKET_LINK.fullmatch(target)
        if match:
            inodes.add(match.group(1))
    return inodes


def listening_inodes(pid: int, port: int) -> set[str]:
    expected_port = f"{port:04X}"
    found: set[str] = set()
    for table_name in ("tcp", "tcp6"):
        table = Path("/proc") / str(pid) / "net" / table_name
        for line in table.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            local_address, local_port = fields[1].rsplit(":", 1)
            state = fields[3]
            if (
                local_address in LOOPBACK_ADDRESSES[table_name]
                and local_port == expected_port
                and state == "0A"
            ):
                found.add(fields[9])
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    if args.pid <= 1 or not 1024 < args.port < 65536:
        return 2
    try:
        owned = process_socket_inodes(args.pid)
        listening = listening_inodes(args.pid, args.port)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return 1
    return 0 if owned & listening else 1


if __name__ == "__main__":
    raise SystemExit(main())
