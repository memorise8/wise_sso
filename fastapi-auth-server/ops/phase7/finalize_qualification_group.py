#!/usr/bin/env python3
"""Fail-closed finalizer for one provisional Phase 7 qualification run group."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

REQUIRED_GATE_IDS = (
    "independent-contract",
    "shared-state-core",
    "performance",
    "security",
    "chaos",
    "backup-restore",
    "local-rollback",
)
MANIFEST_FIELDS = {"schemaVersion", "groupId", "gates"}
V1_GATE_FIELDS = {
    "gateId",
    "topology",
    "runId",
    "evidencePath",
    "evidenceAggregateSha256",
    "sourceRevision",
    "applicationTree",
    "schema",
    "lock",
    "config",
    "image",
    "status",
    "sampleSatisfied",
    "readinessAssertionsSatisfied",
    "resultEvidencePath",
    "resultEvidenceSha256",
    "cleanupEvidencePath",
    "cleanupEvidenceSha256",
    "expressBeforePath",
    "expressBeforeSha256",
    "expressAfterPath",
    "expressAfterSha256",
}
PROVENANCE_FIELDS = {
    "schemaVersion",
    "gateId",
    "topology",
    "runId",
    "sourceRevision",
    "gitTreeObject",
    "expressApplicationTreeSha256",
    "fastapiApplicationTreeSha256",
    "schemaSha256",
    "expressLockSha256",
    "fastapiLockSha256",
    "configSha256",
    "expressImageId",
    "fastapiImageId",
    "collectorAttestationSha256",
}
GROUP_PROVENANCE_FIELDS = (
    "sourceRevision",
    "gitTreeObject",
    "expressApplicationTreeSha256",
    "fastapiApplicationTreeSha256",
    "schemaSha256",
    "expressLockSha256",
    "fastapiLockSha256",
    "configSha256",
    "expressImageId",
    "fastapiImageId",
)
V2_GATE_FIELDS = (
    V1_GATE_FIELDS - {"applicationTree", "schema", "lock", "config", "image"}
    | (PROVENANCE_FIELDS - {"schemaVersion"})
    | {
        "provenanceEvidencePath",
        "provenanceEvidenceSha256",
        "collectorAttestationEvidencePath",
        "collectorAttestationEvidenceSha256",
    }
)
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
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SAFE_RELATIVE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
CLEANUP_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
REVISION = re.compile(r"[0-9a-f]{40,64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
GIT = "/usr/bin/git"
COLLECTOR_ATTESTATION_FIELDS = {
    "schemaVersion",
    "collectorId",
    "collectorRevision",
    "collectorTreeObject",
    "expressImageId",
    "fastapiImageId",
    "status",
}
EXPRESS_APPLICATION_FILES = {"auth-server/package.json", "auth-server/tsconfig.json"}
EXPRESS_APPLICATION_PREFIXES = (
    "auth-server/src/",
    "auth-server/public/",
    "auth-server/prisma/migrations/",
)
FASTAPI_APPLICATION_FILES = {
    "fastapi-auth-server/pyproject.toml",
    "fastapi-auth-server/README.md",
}
FASTAPI_APPLICATION_PREFIXES = ("fastapi-auth-server/src/",)
EXPRESS_LOCK_FILES = ("auth-server/package-lock.json",)
FASTAPI_LOCK_FILES = ("fastapi-auth-server/uv.lock",)
SCHEMA_FILES = ("auth-server/prisma/schema.prisma",)
CONFIG_FILES = (
    "auth-server/.dockerignore",
    "auth-server/.env.example",
    "auth-server/Dockerfile",
    "auth-server/docker-compose.yml",
    "fastapi-auth-server/.dockerignore",
    "fastapi-auth-server/.env.example",
    "fastapi-auth-server/Dockerfile",
    "fastapi-auth-server/docker-compose.dev.yml",
)
INDEPENDENT_CLEANUP_KEYS = {
    "terminateExpress",
    "terminateFastapi",
    "dropExpressDatabase",
    "dropFastapiDatabase",
    "dropExpressRole",
    "dropFastapiRole",
    "redisProbe",
    "clearRedis13",
    "clearRedis14",
    "candidateComposeDown",
    "expressSnapshot",
    "candidateResources",
    "privateTempRemove",
}
SHARED_CLEANUP_KEYS = {
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
DOWNSTREAM_CLEANUP_KEYS = {
    "runtimeCleanup",
    "databaseCleanup",
    "redisCleanup",
    "candidateResources",
    "expressSnapshot",
    "privateTempRemove",
}
CLEANUP_KEYS_BY_GATE = {
    "independent-contract": INDEPENDENT_CLEANUP_KEYS,
    "shared-state-core": SHARED_CLEANUP_KEYS,
    "performance": DOWNSTREAM_CLEANUP_KEYS,
    "security": DOWNSTREAM_CLEANUP_KEYS,
    "chaos": DOWNSTREAM_CLEANUP_KEYS,
    "backup-restore": DOWNSTREAM_CLEANUP_KEYS,
    "local-rollback": DOWNSTREAM_CLEANUP_KEYS,
}


class ManifestError(ValueError):
    """The run-group manifest or attached evidence is unsafe or malformed."""


def _regular_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ManifestError(f"missing evidence file: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ManifestError(f"input must be a regular non-symlink file: {path}")
    if before.st_nlink != 1:
        raise ManifestError(f"input must have exactly one hard link: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot safely open input: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino)
        stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or identity != (opened.st_dev, opened.st_ino)
            or stable != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        ):
            raise ManifestError(f"input changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read()
        after = os.fstat(descriptor)
        if (
            after.st_nlink != 1
            or identity != (after.st_dev, after.st_ino)
            or stable != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(data) != after.st_size
        ):
            raise ManifestError(f"input changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def _open_absolute_directory(path: Path, label: str) -> int:
    if not path.is_absolute():
        raise ManifestError(f"{label} must be an absolute path")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            if part in {"", ".", ".."}:
                raise ManifestError(f"{label} is not canonical")
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except (OSError, ManifestError) as exc:
        os.close(descriptor)
        if isinstance(exc, ManifestError):
            raise
        raise ManifestError(f"cannot safely open {label}: {path}") from exc


def _open_relative_directory(root_descriptor: int, raw: object, label: str) -> int:
    relative = _validated_relative_path(raw)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.dup(root_descriptor)
    try:
        for part in relative.parts:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ManifestError(f"cannot safely open {label}: {relative.as_posix()}") from exc


def _read_descriptor(descriptor: int, before: os.stat_result, label: str) -> bytes:
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ManifestError(f"input must be a single-link regular file: {label}")
    identity = (before.st_dev, before.st_ino)
    stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or identity != (opened.st_dev, opened.st_ino)
        or stable != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    ):
        raise ManifestError(f"input changed while opening: {label}")
    chunks: list[bytes] = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    data = b"".join(chunks)
    after = os.fstat(descriptor)
    if (
        after.st_nlink != 1
        or identity != (after.st_dev, after.st_ino)
        or stable != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        or len(data) != after.st_size
    ):
        raise ManifestError(f"input changed while reading: {label}")
    return data


def _snapshot_directory(descriptor: int) -> dict[str, tuple[bytes, tuple[int, int]]]:
    files: dict[str, tuple[bytes, tuple[int, int]]] = {}

    def visit(current_descriptor: int, prefix: PurePosixPath) -> None:
        before = os.fstat(current_descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise ManifestError("evidence bundle contains a non-directory")
        names = sorted(os.listdir(current_descriptor))
        for name in names:
            if not name or "/" in name or "\x00" in name:
                raise ManifestError("evidence bundle contains an unsafe entry name")
            try:
                name.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ManifestError("evidence bundle entry names must be UTF-8") from exc
            state = os.stat(name, dir_fd=current_descriptor, follow_symlinks=False)
            relative = (prefix / name).as_posix()
            if stat.S_ISLNK(state.st_mode):
                raise ManifestError(f"evidence bundle contains a symlink: {relative}")
            if stat.S_ISDIR(state.st_mode):
                flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
                child = os.open(name, flags, dir_fd=current_descriptor)
                try:
                    visit(child, prefix / name)
                finally:
                    os.close(child)
            elif stat.S_ISREG(state.st_mode):
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                child = os.open(name, flags, dir_fd=current_descriptor)
                try:
                    data = _read_descriptor(child, state, relative)
                finally:
                    os.close(child)
                files[relative] = (data, (state.st_dev, state.st_ino))
            else:
                raise ManifestError(f"evidence bundle contains a non-regular entry: {relative}")
        after = os.fstat(current_descriptor)
        stable = (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
        observed = (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
        if stable != observed or sorted(os.listdir(current_descriptor)) != names:
            raise ManifestError("evidence bundle changed while snapshotting")

    visit(descriptor, PurePosixPath())
    if not files:
        raise ManifestError("evidence bundle must contain at least one regular file")
    return files


def _snapshot_aggregate(snapshot: Mapping[str, tuple[bytes, tuple[int, int]]]) -> str:
    records = [
        path.encode("utf-8") + b"\0" + _sha256(data).encode() + b"\n"
        for path, (data, _) in snapshot.items()
    ]
    return _sha256(b"".join(sorted(records)))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validated_relative_path(raw: object) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ManifestError("evidence paths must be non-empty POSIX relative paths")
    relative = PurePosixPath(raw)
    if (
        SAFE_RELATIVE_PATH.fullmatch(raw) is None
        or relative.as_posix() != raw
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ManifestError(f"evidence path is not confined: {raw}")
    return relative


def _attachment_key(bundle_raw: object, attachment_raw: object) -> str:
    bundle = _validated_relative_path(bundle_raw)
    attachment = _validated_relative_path(attachment_raw)
    if (
        len(attachment.parts) <= len(bundle.parts)
        or attachment.parts[: len(bundle.parts)] != bundle.parts
    ):
        raise ManifestError("gate attachment is outside its evidence bundle")
    return PurePosixPath(*attachment.parts[len(bundle.parts) :]).as_posix()


def evidence_aggregate_sha256(directory: Path) -> str:
    """Hash sorted ``relative-path NUL file-sha256 LF`` evidence records."""
    descriptor = _open_absolute_directory(directory.absolute(), "evidence bundle")
    try:
        return _snapshot_aggregate(_snapshot_directory(descriptor))
    finally:
        os.close(descriptor)


def _exact_object(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ManifestError(f"{label} must contain the exact approved fields")
    return value


def _safe_id(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_ID.fullmatch(value) is None:
        raise ManifestError(f"{label} is not a safe identifier")
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ManifestError(f"{label} must be a lowercase SHA-256")
    return value


def _git(repo_descriptor: int, git_descriptor: int, *args: str) -> bytes:
    safe_environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        completed = subprocess.run(  # noqa: S603 - fixed git executable and arguments
            [
                GIT,
                f"--git-dir=/proc/self/fd/{git_descriptor}",
                f"--work-tree=/proc/self/fd/{repo_descriptor}",
                "-c",
                "core.fsmonitor=false",
                *args,
            ],
            cwd=f"/proc/self/fd/{repo_descriptor}",
            check=True,
            capture_output=True,
            env=safe_environment,
            pass_fds=(repo_descriptor, git_descriptor),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ManifestError(f"cannot verify repository with git {' '.join(args)}") from exc
    return completed.stdout


def _tracked_aggregate(
    repo_descriptor: int,
    git_descriptor: int,
    tracked: Mapping[str, tuple[str, str]],
    paths: tuple[str, ...],
    label: str,
) -> str:
    if not paths or any(path not in tracked for path in paths):
        raise ManifestError(f"repository is missing exact tracked {label} inputs")
    records = []
    for path in paths:
        mode, object_id = tracked[path]
        if mode not in {"100644", "100755"}:
            raise ManifestError(f"repository {label} input must be a regular tracked blob: {path}")
        data = _git(repo_descriptor, git_descriptor, "cat-file", "blob", object_id)
        records.append(path.encode() + b"\0" + _sha256(data).encode() + b"\n")
    return _sha256(b"".join(sorted(records)))


def _head_blobs(tree_data: bytes) -> dict[str, tuple[str, str]]:
    blobs: dict[str, tuple[str, str]] = {}
    for record in tree_data.rstrip(b"\0").split(b"\0"):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ManifestError("repository HEAD tree is malformed") from exc
        relative = PurePosixPath(path)
        if (
            object_type != "blob"
            or not path
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ManifestError(f"repository HEAD contains an unsupported tracked entry: {path}")
        blobs[path] = (mode, object_id)
    return blobs


def repository_provenance(repo_path: Path) -> dict[str, str]:
    """Derive the only accepted source provenance from one clean tracked repository."""
    if not repo_path.is_absolute():
        raise ManifestError("repo must be an absolute path")
    repo_descriptor = _open_absolute_directory(repo_path, "repo")
    try:
        identity = os.fstat(repo_descriptor)
        try:
            git_state = os.stat(".git", dir_fd=repo_descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(git_state.st_mode):
                raise ManifestError("repo must use a normal non-linked .git directory")
            git_descriptor = os.open(
                ".git",
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=repo_descriptor,
            )
        except OSError as exc:
            raise ManifestError("repo must use a normal non-linked .git directory") from exc
        try:
            git_identity = os.fstat(git_descriptor)
            if _git(repo_descriptor, git_descriptor, "rev-parse", "--show-prefix").strip():
                raise ManifestError("repo must name the Git worktree root")
            actual_work_tree = (
                _git(repo_descriptor, git_descriptor, "rev-parse", "--show-toplevel")
                .decode()
                .strip()
            )
            actual_git_dir = (
                _git(repo_descriptor, git_descriptor, "rev-parse", "--absolute-git-dir")
                .decode()
                .strip()
            )
            actual_common_dir = (
                _git(repo_descriptor, git_descriptor, "rev-parse", "--git-common-dir")
                .decode()
                .strip()
            )
            work_tree_state = os.stat(actual_work_tree)
            git_dir_state = os.stat(actual_git_dir)
            common_dir_state = os.stat(actual_common_dir)
            if (
                (work_tree_state.st_dev, work_tree_state.st_ino)
                != (identity.st_dev, identity.st_ino)
                or (git_dir_state.st_dev, git_dir_state.st_ino)
                != (git_identity.st_dev, git_identity.st_ino)
                or (common_dir_state.st_dev, common_dir_state.st_ino)
                != (git_identity.st_dev, git_identity.st_ino)
            ):
                raise ManifestError("repo has an unexpected Git metadata directory")
            try:
                alternate_state = os.stat(
                    "objects/info/alternates",
                    dir_fd=git_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                alternate_state = None
            if alternate_state is not None:
                raise ManifestError("repo must not use alternate object directories")
            if _git(
                repo_descriptor,
                git_descriptor,
                "for-each-ref",
                "--format=%(refname)",
                "refs/replace/",
            ):
                raise ManifestError("repo must not contain Git replace refs")
            if _git(
                repo_descriptor,
                git_descriptor,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ):
                raise ManifestError("repo must be clean")
            source_revision = (
                _git(repo_descriptor, git_descriptor, "rev-parse", "--verify", "HEAD")
                .decode()
                .strip()
            )
            git_tree_object = (
                _git(
                    repo_descriptor,
                    git_descriptor,
                    "rev-parse",
                    "--verify",
                    f"{source_revision}^{{tree}}",
                )
                .decode()
                .strip()
            )
            tracked = _head_blobs(
                _git(
                    repo_descriptor,
                    git_descriptor,
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    source_revision,
                )
            )
            if (
                REVISION.fullmatch(source_revision) is None
                or REVISION.fullmatch(git_tree_object) is None
            ):
                raise ManifestError("repository revision or tree object is invalid")
            express_application = tuple(
                sorted(
                    EXPRESS_APPLICATION_FILES
                    | {path for path in tracked if path.startswith(EXPRESS_APPLICATION_PREFIXES)}
                )
            )
            fastapi_application = tuple(
                sorted(
                    FASTAPI_APPLICATION_FILES
                    | {path for path in tracked if path.startswith(FASTAPI_APPLICATION_PREFIXES)}
                )
            )
            if not any(path.startswith(EXPRESS_APPLICATION_PREFIXES) for path in tracked):
                raise ManifestError("repository has no tracked Express application source inputs")
            if not any(path.startswith(FASTAPI_APPLICATION_PREFIXES) for path in tracked):
                raise ManifestError("repository has no tracked FastAPI application source inputs")
            result = {
                "sourceRevision": source_revision,
                "gitTreeObject": git_tree_object,
                "expressApplicationTreeSha256": _tracked_aggregate(
                    repo_descriptor,
                    git_descriptor,
                    tracked,
                    express_application,
                    "Express application",
                ),
                "fastapiApplicationTreeSha256": _tracked_aggregate(
                    repo_descriptor,
                    git_descriptor,
                    tracked,
                    fastapi_application,
                    "FastAPI application",
                ),
                "schemaSha256": _tracked_aggregate(
                    repo_descriptor, git_descriptor, tracked, SCHEMA_FILES, "Prisma schema"
                ),
                "expressLockSha256": _tracked_aggregate(
                    repo_descriptor,
                    git_descriptor,
                    tracked,
                    EXPRESS_LOCK_FILES,
                    "Express lock",
                ),
                "fastapiLockSha256": _tracked_aggregate(
                    repo_descriptor,
                    git_descriptor,
                    tracked,
                    FASTAPI_LOCK_FILES,
                    "FastAPI lock",
                ),
                "configSha256": _tracked_aggregate(
                    repo_descriptor,
                    git_descriptor,
                    tracked,
                    CONFIG_FILES,
                    "runtime configuration",
                ),
            }
            after = os.fstat(repo_descriptor)
            if (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino):
                raise ManifestError("repository identity changed while finalizing")
            if (
                _git(repo_descriptor, git_descriptor, "rev-parse", "--verify", "HEAD")
                .decode()
                .strip()
                != source_revision
            ):
                raise ManifestError("repository HEAD changed while finalizing")
            if _git(
                repo_descriptor,
                git_descriptor,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ):
                raise ManifestError("repository changed while finalizing")
            return result
        finally:
            os.close(git_descriptor)
    finally:
        os.close(repo_descriptor)


def _load_manifest(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(_regular_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest must be valid UTF-8 JSON") from exc
    return _exact_object(document, MANIFEST_FIELDS, "manifest")


def _provenance_document(data: bytes, gate_id: str) -> Mapping[str, Any]:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"provenance evidence is not valid UTF-8 JSON: {gate_id}") from exc
    provenance = _exact_object(document, PROVENANCE_FIELDS, f"provenance {gate_id}")
    if type(provenance["schemaVersion"]) is not int or provenance["schemaVersion"] != 2:
        raise ManifestError(f"provenance schemaVersion is unsupported: {gate_id}")
    for field in ("gateId", "topology", "runId"):
        _safe_id(provenance[field], f"provenance {gate_id}.{field}")
    if (
        not isinstance(provenance["sourceRevision"], str)
        or REVISION.fullmatch(provenance["sourceRevision"]) is None
        or not isinstance(provenance["gitTreeObject"], str)
        or REVISION.fullmatch(provenance["gitTreeObject"]) is None
    ):
        raise ManifestError(f"provenance revisions are invalid: {gate_id}")
    for field in GROUP_PROVENANCE_FIELDS[2:8]:
        _hash(provenance[field], f"provenance {gate_id}.{field}")
    for field in ("expressImageId", "fastapiImageId"):
        value = provenance[field]
        if not isinstance(value, str) or IMAGE.fullmatch(value) is None:
            raise ManifestError(f"provenance {gate_id}.{field} must be a pinned image ID")
    _hash(
        provenance["collectorAttestationSha256"],
        f"provenance {gate_id}.collectorAttestationSha256",
    )
    return provenance


def _collector_attestation_document(data: bytes, gate_id: str) -> Mapping[str, Any]:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"collector attestation is not valid UTF-8 JSON: {gate_id}") from exc
    attestation = _exact_object(
        document, COLLECTOR_ATTESTATION_FIELDS, f"collector attestation {gate_id}"
    )
    if (
        type(attestation["schemaVersion"]) is not int
        or attestation["schemaVersion"] != 1
        or attestation["status"] != "UNVERIFIED"
    ):
        raise ManifestError(f"collector attestation is not an exact unverified record: {gate_id}")
    _safe_id(attestation["collectorId"], f"collector attestation {gate_id}.collectorId")
    for field in ("collectorRevision", "collectorTreeObject"):
        value = attestation[field]
        if not isinstance(value, str) or REVISION.fullmatch(value) is None:
            raise ManifestError(f"collector attestation {gate_id}.{field} is invalid")
    for field in ("expressImageId", "fastapiImageId"):
        value = attestation[field]
        if not isinstance(value, str) or IMAGE.fullmatch(value) is None:
            raise ManifestError(f"collector attestation {gate_id}.{field} is invalid")
    return attestation


def _cleanup_passes(data: bytes, gate_id: str) -> bool:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    pairs = [line.split("=", 1) for line in lines]
    keys = [pair[0] for pair in pairs if len(pair) == 2]
    return (
        bool(pairs)
        and len(keys) == len(pairs)
        and len(set(keys)) == len(keys)
        and set(keys) == CLEANUP_KEYS_BY_GATE[gate_id]
        and all(CLEANUP_KEY.fullmatch(pair[0]) and pair[1] == "PASS" for pair in pairs)
    )


def _result_document(data: bytes, gate_id: str, run_id: str) -> Mapping[str, Any]:
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"gate result evidence is not valid UTF-8 JSON: {gate_id}") from exc
    result = _exact_object(document, RESULT_FIELDS, f"gate result {gate_id}")
    if (
        type(result["schemaVersion"]) is not int
        or result["schemaVersion"] != 1
        or result["gateId"] != gate_id
        or result["runId"] != run_id
        or result["status"] not in {"PASS", "FAIL", "INCOMPLETE"}
        or type(result["sampleSatisfied"]) is not bool
        or type(result["readinessAssertionsSatisfied"]) is not bool
        or type(result["cleanupComplete"]) is not bool
        or type(result["expressSnapshotUnchanged"]) is not bool
        or result["overallReplacementReady"] is not False
    ):
        raise ManifestError(f"gate result evidence violates its exact contract: {gate_id}")
    return result


def finalize(
    manifest_path: Path, evidence_root: Path, repo_path: Path
) -> tuple[dict[str, Any], bool]:
    manifest = _load_manifest(manifest_path)
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] not in {1, 2}:
        raise ManifestError("unsupported schemaVersion")
    group_id = _safe_id(manifest["groupId"], "groupId")
    raw_gates = manifest["gates"]
    if not isinstance(raw_gates, list):
        raise ManifestError("gates must be an array")
    if manifest["schemaVersion"] == 1:
        seen_v1: set[str] = set()
        for index, raw_gate in enumerate(raw_gates):
            gate = _exact_object(raw_gate, V1_GATE_FIELDS, f"gate[{index}]")
            gate_id = _safe_id(gate["gateId"], f"gate[{index}].gateId")
            if gate_id not in REQUIRED_GATE_IDS:
                raise ManifestError(f"unknown gateId: {gate_id}")
            if gate_id in seen_v1:
                raise ManifestError(f"duplicate gateId: {gate_id}")
            seen_v1.add(gate_id)
        return (
            {
                "schemaVersion": 2,
                "groupId": group_id,
                "status": "INCOMPLETE",
                "overallReplacementReady": False,
                "requiredGateIds": list(REQUIRED_GATE_IDS),
                "gateCount": 0,
                "gates": [],
                "provenanceGroup": {field: None for field in GROUP_PROVENANCE_FIELDS},
                "reasons": ["migration-required:schemaVersion-1"],
            },
            False,
        )

    expected_repository_provenance = repository_provenance(repo_path)
    evidence_descriptor = _open_absolute_directory(evidence_root.absolute(), "evidence root")

    reasons: set[str] = set()
    reasons.add("controlled-collector-required")
    seen: set[str] = set()
    provenances: dict[str, set[str]] = {field: set() for field in GROUP_PROVENANCE_FIELDS}
    normalized_gates: list[dict[str, Any]] = []
    required = set(REQUIRED_GATE_IDS)

    for index, raw_gate in enumerate(raw_gates):
        gate = _exact_object(raw_gate, V2_GATE_FIELDS, f"gate[{index}]")
        gate_id = _safe_id(gate["gateId"], f"gate[{index}].gateId")
        if gate_id not in required:
            raise ManifestError(f"unknown gateId: {gate_id}")
        if gate_id in seen:
            raise ManifestError(f"duplicate gateId: {gate_id}")
        seen.add(gate_id)
        _safe_id(gate["topology"], f"gate[{index}].topology")
        run_id = _safe_id(gate["runId"], f"gate[{index}].runId")
        if gate["status"] not in {"PASS", "FAIL", "INCOMPLETE"}:
            raise ManifestError(f"gate[{index}].status is invalid")
        if (
            type(gate["sampleSatisfied"]) is not bool
            or type(gate["readinessAssertionsSatisfied"]) is not bool
        ):
            raise ManifestError("sample and readiness assertions must be booleans")
        bundle_descriptor = _open_relative_directory(
            evidence_descriptor, gate["evidencePath"], f"evidence bundle {gate_id}"
        )
        try:
            snapshot = _snapshot_directory(bundle_descriptor)
        except Exception:
            os.close(bundle_descriptor)
            raise
        expected_aggregate = _hash(gate["evidenceAggregateSha256"], "evidenceAggregateSha256")
        if _snapshot_aggregate(snapshot) != expected_aggregate:
            os.close(bundle_descriptor)
            raise ManifestError(f"evidence aggregate hash mismatch for {gate_id}")

        attachments: dict[str, bytes] = {}
        attachment_paths: set[str] = set()
        attachment_inodes: set[tuple[int, int]] = set()
        for path_field, hash_field in (
            ("provenanceEvidencePath", "provenanceEvidenceSha256"),
            (
                "collectorAttestationEvidencePath",
                "collectorAttestationEvidenceSha256",
            ),
            ("resultEvidencePath", "resultEvidenceSha256"),
            ("cleanupEvidencePath", "cleanupEvidenceSha256"),
            ("expressBeforePath", "expressBeforeSha256"),
            ("expressAfterPath", "expressAfterSha256"),
        ):
            attachment_key = _attachment_key(gate["evidencePath"], gate[path_field])
            if attachment_key in attachment_paths:
                os.close(bundle_descriptor)
                raise ManifestError(f"gate attachment roles must use distinct paths: {gate_id}")
            attachment_paths.add(attachment_key)
            try:
                content, inode = snapshot[attachment_key]
            except KeyError as exc:
                os.close(bundle_descriptor)
                raise ManifestError(f"missing evidence attachment: {gate_id}.{path_field}") from exc
            if inode in attachment_inodes:
                os.close(bundle_descriptor)
                raise ManifestError(f"gate attachment roles must use distinct inodes: {gate_id}")
            attachment_inodes.add(inode)
            if _sha256(content) != _hash(gate[hash_field], hash_field):
                os.close(bundle_descriptor)
                raise ManifestError(f"attachment hash mismatch for {gate_id}: {path_field}")
            attachments[path_field] = content
        second_snapshot = _snapshot_directory(bundle_descriptor)
        os.close(bundle_descriptor)
        if (
            second_snapshot != snapshot
            or _snapshot_aggregate(second_snapshot) != expected_aggregate
        ):
            raise ManifestError(f"evidence bundle changed while finalizing {gate_id}")

        provenance = _provenance_document(attachments["provenanceEvidencePath"], gate_id)
        for field in PROVENANCE_FIELDS - {"schemaVersion"}:
            if gate[field] != provenance[field]:
                raise ManifestError(
                    f"manifest provenance does not match attached evidence: {gate_id}.{field}"
                )
        for field, expected_value in expected_repository_provenance.items():
            if provenance[field] != expected_value:
                raise ManifestError(
                    f"attached provenance does not match repository: {gate_id}.{field}"
                )
        collector_attestation = _collector_attestation_document(
            attachments["collectorAttestationEvidencePath"], gate_id
        )
        if provenance["collectorAttestationSha256"] != gate["collectorAttestationEvidenceSha256"]:
            raise ManifestError(f"collector attestation is not bound to provenance: {gate_id}")
        for field in ("expressImageId", "fastapiImageId"):
            if collector_attestation[field] != provenance[field]:
                raise ManifestError(
                    f"collector attestation image does not match provenance: {gate_id}.{field}"
                )
        for field in GROUP_PROVENANCE_FIELDS:
            provenances[field].add(provenance[field])

        result_evidence = _result_document(attachments["resultEvidencePath"], gate_id, run_id)
        for field in ("status", "sampleSatisfied", "readinessAssertionsSatisfied"):
            if gate[field] != result_evidence[field]:
                raise ManifestError(f"manifest claim does not match gate result: {gate_id}.{field}")

        if gate["status"] != "PASS":
            reasons.add(f"gate-not-pass:{gate_id}")
        if not gate["sampleSatisfied"]:
            reasons.add(f"sample-unsatisfied:{gate_id}")
        if not gate["readinessAssertionsSatisfied"]:
            reasons.add(f"readiness-unsatisfied:{gate_id}")
        cleanup_passes = _cleanup_passes(attachments["cleanupEvidencePath"], gate_id)
        snapshots_match = attachments["expressBeforePath"] == attachments["expressAfterPath"]
        if result_evidence["cleanupComplete"] != cleanup_passes:
            raise ManifestError(f"cleanup claim does not match attached evidence: {gate_id}")
        if result_evidence["expressSnapshotUnchanged"] != snapshots_match:
            raise ManifestError(f"Express invariance claim does not match evidence: {gate_id}")
        if not cleanup_passes:
            reasons.add(f"cleanup-not-pass:{gate_id}")
        if not snapshots_match:
            reasons.add(f"express-invariance-failed:{gate_id}")
        normalized_gates.append(
            {
                "gateId": gate_id,
                "runId": gate["runId"],
                "status": gate["status"],
                "topology": gate["topology"],
                "evidenceAggregateSha256": expected_aggregate,
            }
        )

    for missing in sorted(required - seen):
        reasons.add(f"missing-gate:{missing}")
    for field, values in provenances.items():
        if len(values) > 1:
            reasons.add(f"mixed-provenance:{field}")

    # Image IDs are not authenticated until a reviewed controlled collector exists.
    complete = False
    os.close(evidence_descriptor)
    output = {
        "schemaVersion": 2,
        "groupId": group_id,
        "status": "INCOMPLETE",
        "overallReplacementReady": False,
        "requiredGateIds": list(REQUIRED_GATE_IDS),
        "gateCount": len(normalized_gates),
        "gates": sorted(normalized_gates, key=lambda gate: REQUIRED_GATE_IDS.index(gate["gateId"])),
        "provenanceGroup": {
            field: next(iter(values)) if len(values) == 1 else None
            for field, values in provenances.items()
        },
        "reasons": sorted(reasons),
    }
    return output, complete


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    try:
        result, complete = finalize(args.manifest, args.evidence_root, args.repo)
    except (ManifestError, OSError) as exc:
        print(f"qualification group refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
