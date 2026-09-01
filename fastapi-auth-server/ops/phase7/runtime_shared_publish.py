#!/usr/bin/env python3
"""Atomically publish one sanitized shared-state runtime evidence bundle."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import re
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
RESULT_KEYS = {
    "status",
    "launcherExit",
    "gateVerdict",
    "gateExit",
    "integrity",
    "cleanup",
    "expressSnapshotUnchanged",
    "zeroCandidateResources",
    "privateTempRemoved",
    "resultCount",
    "concurrentTrialCount",
    "mixedRuntimeOverlapCount",
    "overlapMismatchCount",
    "fullPhase7SampleSatisfied",
    "overallReplacementReady",
}
PROVENANCE_KEYS = {"gitHead", "runId", "gateEvidenceSha256", "runtimeLauncherSha256"}
RUN_ID = re.compile(r"[a-z0-9][a-z0-9_]{0,63}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
STEP_VALUES = {"PASS", "FAIL", "NOT_REQUIRED", "NOT_RUN", "PRESENT", "ERROR"}


def key_values(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if any(not line or "=" not in line for line in lines):
        raise ValueError("evidence must contain only non-empty key-value lines")
    pairs = [line.split("=", 1) for line in lines]
    if len(pairs) != len(dict(pairs)):
        raise ValueError("evidence keys must be unique")
    return dict(pairs)


def validate_bundle(staging: Path, expected_run_id: str) -> None:
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
    provenance = key_values(staging / "provenance.txt")
    if set(cleanup) != CLEANUP_KEYS or any(value not in STEP_VALUES for value in cleanup.values()):
        raise ValueError("shared runtime evidence requires every exact cleanup step")
    if set(result) != RESULT_KEYS:
        raise ValueError("shared runtime result must contain the exact approved fields")
    if set(provenance) != PROVENANCE_KEYS:
        raise ValueError("shared runtime provenance must contain the exact approved fields")
    cleanup_expected = (
        "PASS" if all(value in {"PASS", "NOT_REQUIRED"} for value in cleanup.values()) else "FAIL"
    )
    snapshot_expected = "true" if cleanup["expressSnapshot"] == "PASS" else "false"
    candidate_expected = {"PASS": "true", "PRESENT": "false"}.get(
        cleanup["candidateResources"], "unknown"
    )
    private_expected = "true" if cleanup["privateTempRemove"] == "PASS" else "false"
    if (
        result.get("status") not in {"PASS", "FAIL"}
        or not result.get("launcherExit", "").isdigit()
        or result.get("integrity") not in {"PASS", "FAIL"}
        or result.get("cleanup") != cleanup_expected
        or result.get("expressSnapshotUnchanged") != snapshot_expected
        or result.get("zeroCandidateResources") != candidate_expected
        or result.get("privateTempRemoved") != private_expected
        or result.get("fullPhase7SampleSatisfied") != "false"
        or result.get("overallReplacementReady") != "false"
    ):
        raise ValueError("shared runtime aggregate fields do not match cleanup evidence")
    gate_passed = result.get("gateVerdict") == "PASS" and result.get("gateExit") == "0"
    overlap_proven = (
        result.get("resultCount") == "100"
        and result.get("concurrentTrialCount") == "70"
        and result.get("mixedRuntimeOverlapCount") == "70"
        and result.get("overlapMismatchCount") == "0"
    )
    overlap_unproven = all(
        result.get(key) == "NOT_PROVEN"
        for key in (
            "resultCount",
            "concurrentTrialCount",
            "mixedRuntimeOverlapCount",
            "overlapMismatchCount",
        )
    )
    snapshots_match = (staging / "express-before.txt").read_bytes() == (
        staging / "express-after.txt"
    ).read_bytes()
    if gate_passed != overlap_proven or (not gate_passed and not overlap_unproven):
        raise ValueError("gate result and overlap evidence do not correlate")
    if result["status"] == "PASS" and (
        result.get("launcherExit") != "0"
        or not gate_passed
        or result.get("integrity") != "PASS"
        or any(value != "PASS" for value in cleanup.values())
        or not snapshots_match
        or result.get("cleanup") != "PASS"
        or result.get("expressSnapshotUnchanged") != "true"
        or result.get("zeroCandidateResources") != "true"
        or result.get("privateTempRemoved") != "true"
    ):
        raise ValueError("shared runtime PASS evidence requires every invariant")
    if result["status"] == "FAIL" and result.get("launcherExit") == "0":
        raise ValueError("shared runtime FAIL evidence requires a non-zero final launcher exit")
    if (
        RUN_ID.fullmatch(expected_run_id) is None
        or provenance.get("runId") != expected_run_id
        or GIT_SHA.fullmatch(provenance.get("gitHead", "")) is None
        or SHA256.fullmatch(provenance.get("gateEvidenceSha256", "")) is None
        or SHA256.fullmatch(provenance.get("runtimeLauncherSha256", "")) is None
    ):
        raise ValueError("shared runtime provenance is missing or not linked to the final run")


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
        validate_bundle(staging, final.name)
        rename_noreplace(staging, final)
    except (OSError, ValueError) as exc:
        print(f"shared runtime evidence publication refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
