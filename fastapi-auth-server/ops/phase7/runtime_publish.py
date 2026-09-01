#!/usr/bin/env python3
"""Atomically publish one complete evidence directory without replacement."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import stat
import sys
from pathlib import Path

AT_FDCWD = -100
RENAME_NOREPLACE = 1
EXPECTED_FILES = {
    "express-before.txt",
    "express-after.txt",
    "result.status",
    "provenance.txt",
}
FORBIDDEN = ("postgresql://", "postgres://", "redis://", "private key", "password=")


def validate_bundle(staging: Path) -> None:
    entries = list(staging.iterdir())
    if {entry.name for entry in entries} != EXPECTED_FILES:
        raise ValueError("evidence bundle has an unexpected file set")
    if stat.S_IMODE(staging.stat().st_mode) & 0o222:
        raise ValueError("evidence staging directory must be read-only")
    text: dict[str, str] = {}
    for entry in entries:
        if not entry.is_file() or entry.is_symlink() or stat.S_IMODE(entry.stat().st_mode) & 0o222:
            raise ValueError("evidence entries must be read-only regular non-link files")
        text[entry.name] = entry.read_text(encoding="utf-8")
    combined = "\n".join(text.values()).lower()
    if any(value in combined for value in FORBIDDEN):
        raise ValueError("evidence bundle contains a forbidden sensitive value")
    result = dict(
        line.split("=", 1) for line in text["result.status"].splitlines() if line and "=" in line
    )
    if result.get("status") not in {"PASS", "FAIL"}:
        raise ValueError("evidence status must fail closed")
    if result.get("overallReplacementReady") != "false":
        raise ValueError("runtime evidence cannot approve replacement")
    if result["status"] == "PASS" and (
        result.get("cleanup") != "PASS"
        or result.get("expressSnapshotUnchanged") != "true"
        or result.get("zeroCandidateResources") != "true"
        or result.get("privateTempRemoved") != "true"
        or text["express-before.txt"] != text["express-after.txt"]
    ):
        raise ValueError("PASS evidence requires every cleanup invariant")


def rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for fail-closed evidence publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(target),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--final", type=Path, required=True)
    args = parser.parse_args()
    staging = args.staging.resolve()
    final = args.final.absolute()
    if (
        final.parent.is_symlink()
        or staging.parent != final.parent.resolve()
        or not staging.is_dir()
        or staging.is_symlink()
    ):
        raise SystemExit("staging and final must be sibling directories")
    if not staging.name.startswith(f".{final.name}.tmp."):
        raise SystemExit("staging directory does not match the final run")
    try:
        validate_bundle(staging)
        rename_noreplace(staging, final)
    except (OSError, ValueError) as exc:
        print(f"evidence publication refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
