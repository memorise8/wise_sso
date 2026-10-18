#!/usr/bin/env python3
"""Run the bounded Phase 7 downstream validation gates without granting readiness."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
GIT_OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SAFE_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
GATES = ("performance", "security", "chaos", "backup-restore", "local-rollback")
IMPLEMENTED = ("security", "backup-restore")
PYTHON = "/usr/bin/python3"
TIMEOUT_SECONDS = 120
GIT_TIMEOUT_SECONDS = 60
MAX_RESULT_BYTES = 16 * 1024
STATUS_FIELDS = {"status", "overallReplacementReady", "reasonCodes"}
RESULT_FIELDS = {
    "schemaVersion",
    "gateId",
    "runId",
    "status",
    "sampleSatisfied",
    "readinessAssertionsSatisfied",
    "cleanupComplete",
    "expressSnapshotUnchanged",
    "overallReplacementReady",
}
CHILD_REASONS = {
    "CONTROLLED_COLLECTOR_REQUIRED",
    "TOOLCHAIN_LOCK_UNFROZEN",
    "POLICY_UNFROZEN",
    "MISSING_EVIDENCE",
    "UNSAFE_INPUT",
    "MALFORMED_INPUT",
    "POLICY_VIOLATION",
    "PUBLICATION_REFUSED",
}


class Refused(ValueError):
    """The request or downstream result cannot be safely accepted."""


@dataclass(frozen=True)
class GateStatus:
    gate: str
    status: str
    reason: str


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evidence-dir", type=Path, required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--source-tree", required=True)
    result.add_argument("--security-input", type=Path)
    result.add_argument("--backup-restore-input", type=Path)
    return result


def _safe_directory(path: Path, label: str, *, require_private: bool = True) -> Path:
    if not path.is_absolute():
        raise Refused(f"{label.upper()}_ABSOLUTE_REQUIRED")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise Refused(f"{label.upper()}_MISSING") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or path.resolve() != path
        or (require_private and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise Refused(f"{label.upper()}_UNSAFE")
    return path


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def validate_paths(
    evidence_dir: Path, inputs: dict[str, Path | None], repo: Path
) -> dict[str, Path | None]:
    evidence = _safe_directory(evidence_dir, "evidence_dir")
    resolved_repo = repo.resolve(strict=True)
    validated: dict[str, Path | None] = {}
    seen: list[Path] = []
    for gate, candidate in inputs.items():
        if candidate is None:
            validated[gate] = None
            continue
        source = _safe_directory(candidate, f"{gate.replace('-', '_')}_input")
        if _paths_overlap(source, evidence) or _paths_overlap(source, resolved_repo):
            raise Refused("INPUT_LOCATION_UNSAFE")
        if any(_paths_overlap(source, previous) for previous in seen):
            raise Refused("INPUT_REUSE_REFUSED")
        seen.append(source)
        validated[gate] = source
    for gate in GATES:
        if (evidence / f"{gate}.status").exists() or (evidence / f"{gate}.status").is_symlink():
            raise Refused("STATUS_PATH_REUSED")
    downstream = evidence / "downstream"
    if downstream.exists() or downstream.is_symlink():
        raise Refused("DOWNSTREAM_PATH_REUSED")
    return validated


def _git_environment() -> dict[str, str]:
    return {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def _git_object(repo: Path, expression: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed Git and bounded revision expression
        [
            "/usr/bin/git",
            "--no-replace-objects",
            "-C",
            str(repo),
            "rev-parse",
            "--verify",
            expression,
        ],
        env=_git_environment(),
        check=False,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    try:
        value = completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise Refused("SOURCE_BINDING_FAILED") from exc
    if completed.returncode != 0 or GIT_OBJECT.fullmatch(value) is None:
        raise Refused("SOURCE_BINDING_FAILED")
    return value


def _verify_source(repo: Path, revision: str, tree: str) -> None:
    if _git_object(repo, "HEAD") != revision or _git_object(repo, "HEAD^{tree}") != tree:
        raise Refused("SOURCE_BINDING_MISMATCH")


@contextmanager
def security_source_mirror(
    repo: Path, evidence_dir: Path, revision: str, tree: str
) -> Iterator[Path]:
    _verify_source(repo, revision, tree)
    try:
        with tempfile.TemporaryDirectory(
            prefix="wiseacct-phase7-security-source.", dir="/tmp"
        ) as private_name:
            private = Path(private_name)
            private.chmod(0o700)
            _safe_directory(private, "source_mirror")
            if _paths_overlap(private, repo) or _paths_overlap(private, evidence_dir):
                raise Refused("SOURCE_MIRROR_UNSAFE")
            clone = private / "repo"
            completed = subprocess.run(  # noqa: S603 - fixed Git clone from the bound repo
                [
                    "/usr/bin/git",
                    "--no-replace-objects",
                    "-c",
                    "protocol.file.allow=always",
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--no-checkout",
                    "--",
                    str(repo),
                    str(clone),
                ],
                cwd=private,
                env=_git_environment(),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=GIT_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                raise Refused("SOURCE_CLONE_FAILED")
            completed = subprocess.run(  # noqa: S603 - fixed detached checkout of validated SHA
                [
                    "/usr/bin/git",
                    "--no-replace-objects",
                    "-C",
                    str(clone),
                    "checkout",
                    "--detach",
                    "--force",
                    revision,
                ],
                env=_git_environment(),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=GIT_TIMEOUT_SECONDS,
            )
            if completed.returncode != 0:
                raise Refused("SOURCE_CHECKOUT_FAILED")
            _verify_source(clone, revision, tree)
            _verify_source(repo, revision, tree)
            yield clone
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refused("SOURCE_BINDING_FAILED") from exc


def _read_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise Refused("DOWNSTREAM_RESULT_MISSING") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o400
        or before.st_size > MAX_RESULT_BYTES
    ):
        raise Refused("DOWNSTREAM_RESULT_UNSAFE")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Refused("DOWNSTREAM_RESULT_CHANGED")
        data = os.read(descriptor, MAX_RESULT_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > MAX_RESULT_BYTES or any(
        getattr(before, field) != getattr(after, field)
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    ):
        raise Refused("DOWNSTREAM_RESULT_CHANGED")
    return data


def _parse_status(data: bytes) -> dict[str, str]:
    try:
        lines = data.decode("utf-8").splitlines()
        pairs = [line.split("=", 1) for line in lines]
        values = {key: value for key, value in pairs if key and value}
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refused("DOWNSTREAM_RESULT_MALFORMED") from exc
    if len(pairs) != len(values) or set(values) != STATUS_FIELDS:
        raise Refused("DOWNSTREAM_RESULT_MALFORMED")
    return values


def _parse_result(data: bytes) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise Refused("DOWNSTREAM_RESULT_MALFORMED")
            value[key] = child
        return value

    try:
        value: Any = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("DOWNSTREAM_RESULT_MALFORMED") from exc
    if not isinstance(value, dict) or set(value) != RESULT_FIELDS:
        raise Refused("DOWNSTREAM_RESULT_MALFORMED")
    return value


def verify_child_result(gate: str, run_id: str, root: Path, returncode: int) -> GateStatus:
    output = root / run_id
    try:
        output_meta = output.lstat()
    except OSError as exc:
        raise Refused("DOWNSTREAM_RESULT_MISSING") from exc
    if (
        stat.S_ISLNK(output_meta.st_mode)
        or not stat.S_ISDIR(output_meta.st_mode)
        or output_meta.st_uid != os.getuid()
        or output.resolve() != output
    ):
        raise Refused("DOWNSTREAM_RESULT_UNSAFE")
    status_doc = _parse_status(_read_regular(output / "result.status"))
    result_doc = _parse_result(_read_regular(output / "gate-result.json"))
    status = status_doc["status"]
    if status == "PASS" or result_doc.get("status") == "PASS" or returncode == 0:
        raise Refused("QUALIFYING_RESULT_REFUSED")
    expected_exit = {"INCOMPLETE": 3, "FAIL": 2}.get(status)
    if expected_exit is None or returncode != expected_exit:
        raise Refused("DOWNSTREAM_EXIT_MISMATCH")
    reasons = status_doc["reasonCodes"].split(",")
    if (
        not reasons
        or any(
            SAFE_REASON.fullmatch(reason) is None or reason not in CHILD_REASONS
            for reason in reasons
        )
        or status_doc["overallReplacementReady"] != "false"
        or type(result_doc["schemaVersion"]) is not int
        or result_doc["schemaVersion"] != 1
        or result_doc["gateId"] != gate
        or result_doc["runId"] != run_id
        or result_doc["status"] != status
        or any(
            result_doc[field] is not False
            for field in (
                "sampleSatisfied",
                "readinessAssertionsSatisfied",
                "cleanupComplete",
                "expressSnapshotUnchanged",
                "overallReplacementReady",
            )
        )
    ):
        raise Refused("DOWNSTREAM_RESULT_MALFORMED")
    return GateStatus(gate, status, ",".join(reasons))


def run_gate(
    gate: str,
    source: Path,
    evidence_dir: Path,
    run_id: str,
    repo: Path,
    source_revision: str,
    source_tree: str,
) -> GateStatus:
    root = evidence_dir / "downstream" / gate
    try:
        root.mkdir(mode=0o700)
    except OSError:
        return GateStatus(gate, "FAIL", "DOWNSTREAM_PUBLICATION_REFUSED")
    script = Path(__file__).resolve().parent
    arguments = [PYTHON, "-I"]
    if gate == "security":
        try:
            with security_source_mirror(repo, evidence_dir, source_revision, source_tree) as mirror:
                arguments.extend(
                    [
                        str(script / "security" / "security_gate.py"),
                        "--input",
                        str(source),
                        "--run-id",
                        run_id,
                        "--repo",
                        str(mirror),
                        "--evidence-root",
                        str(root),
                    ]
                )
                return _execute_gate(gate, arguments, root, run_id, repo)
        except Refused as exc:
            return GateStatus(gate, "FAIL", str(exc))
    else:
        arguments.extend(
            [
                str(script / "backup_restore" / "backup_restore_gate.py"),
                "--input",
                str(source),
                "--run-id",
                run_id,
                "--evidence-root",
                str(root),
            ]
        )
    return _execute_gate(gate, arguments, root, run_id, repo)


def _execute_gate(
    gate: str, arguments: list[str], root: Path, run_id: str, repo: Path
) -> GateStatus:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed interpreter, scripts, and options
            arguments,
            cwd=repo,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return GateStatus(gate, "FAIL", "DOWNSTREAM_TIMEOUT")
    except (OSError, subprocess.SubprocessError):
        return GateStatus(gate, "FAIL", "DOWNSTREAM_EXECUTION_ERROR")
    try:
        return verify_child_result(gate, run_id, root, completed.returncode)
    except Refused as exc:
        return GateStatus(gate, "FAIL", str(exc))


def _publish_statuses(evidence_dir: Path, statuses: list[GateStatus]) -> None:
    descriptors: list[int] = []
    paths: list[Path] = []
    try:
        for item in statuses:
            path = evidence_dir / f"{item.gate}.status"
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
            descriptors.append(descriptor)
            paths.append(path)
        for descriptor, item in zip(descriptors, statuses, strict=True):
            payload = (
                f"gate={item.gate}\nstatus={item.status}\nreason={item.reason}\n"
                "overallReplacementReady=false\n"
            ).encode()
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short status write")
                offset += written
            os.fsync(descriptor)
    except OSError as exc:
        for path in paths:
            try:
                path.unlink()
            except OSError:
                pass
        raise Refused("STATUS_PUBLICATION_REFUSED") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if (
        SAFE_ID.fullmatch(args.run_id) is None
        or GIT_OBJECT.fullmatch(args.source_revision) is None
        or GIT_OBJECT.fullmatch(args.source_tree) is None
    ):
        print("downstream gates refused: unsafe binding", file=sys.stderr)
        return 2
    repo = Path(__file__).resolve().parents[3]
    raw_inputs = {
        "security": args.security_input,
        "backup-restore": args.backup_restore_input,
    }
    try:
        inputs = validate_paths(args.evidence_dir, raw_inputs, repo)
        statuses = {gate: GateStatus(gate, "SKIP", "NOT_IMPLEMENTED") for gate in GATES}
        for gate in IMPLEMENTED:
            source = inputs[gate]
            statuses[gate] = (
                GateStatus(gate, "SKIP", "INPUT_REQUIRED")
                if source is None
                else GateStatus(gate, "INCOMPLETE", "DISPATCH_PENDING")
            )
        if any(inputs.values()):
            (args.evidence_dir / "downstream").mkdir(mode=0o700)
        for gate in IMPLEMENTED:
            source = inputs[gate]
            if source is not None:
                statuses[gate] = run_gate(
                    gate,
                    source,
                    args.evidence_dir,
                    args.run_id,
                    repo,
                    args.source_revision,
                    args.source_tree,
                )
        ordered = [statuses[gate] for gate in GATES]
        _publish_statuses(args.evidence_dir, ordered)
    except Refused as exc:
        print(f"downstream gates refused: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("downstream gates refused: IO_ERROR", file=sys.stderr)
        return 2
    return 2 if any(item.status == "FAIL" for item in ordered) else 3


if __name__ == "__main__":
    raise SystemExit(main())
