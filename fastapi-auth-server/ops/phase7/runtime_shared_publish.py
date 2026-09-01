#!/usr/bin/env python3
"""Atomically publish one sanitized shared-state runtime evidence bundle."""

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
    "cleanup.status",
    "result.status",
    "provenance.txt",
}
CLEANUP_KEYS = {
    "terminateExpress",
    "terminateFastapi",
    "dropSharedDatabase",
    "dropExpressRole",
    "dropFastapiRole",
    "redisProbe",
    "clearRedis13",
    "candidateComposeDown",
    "expressSnapshot",
    "candidateResources",
    "privateTempRemove",
}
FORBIDDEN = ("postgresql://", "postgres://", "redis://", "private key", "password=")
STEP_VALUES = {"PASS", "FAIL", "NOT_REQUIRED", "NOT_RUN", "PRESENT", "ERROR"}


def key_values(path: Path) -> dict[str, str]:
    pairs = [
        line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line
    ]
    if len(pairs) != len(dict(pairs)):
        raise ValueError("evidence keys must be unique")
    return dict(pairs)


def validate_bundle(staging: Path) -> None:
    entries = list(staging.iterdir())
    if {entry.name for entry in entries} != EXPECTED_FILES:
        raise ValueError("shared runtime evidence has an unexpected file set")
    if stat.S_IMODE(staging.stat().st_mode) & 0o222:
        raise ValueError("shared runtime evidence directory must be read-only")
    combined = ""
    for entry in entries:
        if not entry.is_file() or entry.is_symlink() or stat.S_IMODE(entry.stat().st_mode) & 0o222:
            raise ValueError("evidence entries must be read-only regular non-link files")
        combined += entry.read_text(encoding="utf-8").lower()
    if any(value in combined for value in FORBIDDEN):
        raise ValueError("shared runtime evidence contains a forbidden sensitive value")

    cleanup = key_values(staging / "cleanup.status")
    result = key_values(staging / "result.status")
    if set(cleanup) != CLEANUP_KEYS or any(value not in STEP_VALUES for value in cleanup.values()):
        raise ValueError("shared runtime evidence requires every exact cleanup step")
    cleanup_expected = (
        "PASS" if all(value in {"PASS", "NOT_REQUIRED"} for value in cleanup.values()) else "FAIL"
    )
    snapshot_expected = "true" if cleanup["expressSnapshot"] == "PASS" else "false"
    candidate_expected = {
        "PASS": "true",
        "PRESENT": "false",
    }.get(cleanup["candidateResources"], "unknown")
    private_expected = "true" if cleanup["privateTempRemove"] == "PASS" else "false"
    if (
        result.get("status") not in {"PASS", "FAIL"}
        or result.get("cleanup") != cleanup_expected
        or result.get("expressSnapshotUnchanged") != snapshot_expected
        or result.get("zeroCandidateResources") != candidate_expected
        or result.get("privateTempRemoved") != private_expected
        or result.get("overallReplacementReady") != "false"
    ):
        raise ValueError("shared runtime aggregate evidence is inconsistent")
    if result["status"] == "PASS" and (
        result.get("gateVerdict") != "PASS"
        or result.get("gateExit") != "0"
        or any(value != "PASS" for value in cleanup.values())
        or (staging / "express-before.txt").read_bytes()
        != (staging / "express-after.txt").read_bytes()
    ):
        raise ValueError("shared runtime PASS evidence requires every invariant")


def rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for fail-closed publication")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            AT_FDCWD,
            os.fsencode(source),
            AT_FDCWD,
            os.fsencode(target),
            RENAME_NOREPLACE,
        )
        != 0
    ):
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
        or not staging.name.startswith(f".{final.name}.tmp.")
    ):
        raise SystemExit("staging and final must be matching sibling directories")
    try:
        validate_bundle(staging)
        rename_noreplace(staging, final)
    except (OSError, ValueError) as exc:
        print(f"shared runtime evidence publication refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
