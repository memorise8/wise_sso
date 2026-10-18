#!/usr/bin/env python3
"""Validate and atomically publish sanitized Phase 7 security evidence."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LEGACY_INPUTS = {
    "provenance.txt",
    "dependency-python.json",
    "dependency-node-runtime.json",
    "dependency-node-build.json",
    "sast.sarif",
    "secrets.sarif",
    "image-vulns.json",
    "image-high-critical.json",
    "image-misconfig.json",
    "sbom.cdx.json",
    "licenses.json",
    "hardening.status",
    "negative-tests.xml",
    "negative-tests.status",
    "sanitization.status",
    "cleanup.status",
    "express-before.txt",
    "express-after.txt",
    "candidate-inventory.json",
}
CONTROL_ATTACHMENTS = {
    "collector-contract.json",
    "qualification-provenance.json",
    "collector-attestation.json",
    "image-metadata.json",
}
EXPECTED_INPUTS = LEGACY_INPUTS | CONTROL_ATTACHMENTS
JSON_REPORTS = {
    "dependency-python.json",
    "dependency-node-runtime.json",
    "dependency-node-build.json",
    "image-vulns.json",
    "image-high-critical.json",
    "image-misconfig.json",
}
DEPENDENCY_REPORTS = {
    "dependency-python.json": ("pip-audit", "python"),
    "dependency-node-runtime.json": ("npm-audit", "node-runtime"),
    "dependency-node-build.json": ("npm-audit", "node-build"),
}
IMAGE_REPORTS = {
    "image-vulns.json": "vulnerabilities",
    "image-high-critical.json": "high-critical",
    "image-misconfig.json": "misconfiguration",
}
SCANNER_NAMES = {"pip-audit", "npm-audit", "ruff", "semgrep", "gitleaks", "trivy"}
REPORT_FIELDS = {"schemaVersion", "scanner", "subject", "findings"}
SCANNER_FIELDS = {
    "name",
    "version",
    "imageDigest",
    "databaseUpdatedAt",
    "mode",
    "scope",
    "ruleSha256",
}
SUBJECT_FIELDS = {"sourceRevision", "applicationTree", "imageId", "imageConfig", "baseImage"}
FINDING_FIELDS = {"id", "severity", "domain", "path", "reachability", "waiver"}
WAIVER_FIELDS = {"owner", "rationale", "compensatingControl", "expiresAt"}
PROVENANCE_KEYS = {
    "schemaVersion",
    "runId",
    "sourceRevision",
    "applicationTree",
    "runnerSha256",
    "policySha256",
    "ruleSha256",
    "pythonLockSha256",
    "nodeLockSha256",
    "nodeBuildLockSha256",
    "dockerfileSha256",
    "toolchainLockSha256",
    "imageId",
    "imageConfig",
    "baseImage",
    "scannerImages",
    "scannerVersions",
    "scannerDatabaseUpdatedAt",
    "network",
    "sockets",
    "reportHashes",
    "expressBeforeSha256",
    "expressAfterSha256",
    "candidateInventorySha256",
    "cleanupInventorySha256",
}
CLEANUP_KEYS = {
    "runtimeCleanup",
    "databaseCleanup",
    "redisCleanup",
    "candidateResources",
    "expressSnapshot",
    "privateTempRemove",
}
HARDENING_KEYS = {"nonroot", "readOnlyRootfs", "capDropAll", "noNewPrivileges", "tmpfs"}
BLOCKING_MEDIUM_DOMAINS = {"auth", "crypto", "redirect", "network-reachable"}
ALLOWED_FINDING_DOMAINS = BLOCKING_MEDIUM_DOMAINS | {
    "dependency",
    "sast",
    "secrets",
    "image",
    "misconfiguration",
    "license",
}
FORBIDDEN_LICENSES = {"AGPL-3.0", "SSPL-1.0", "BUSL-1.1", "Commons-Clause", "Noncommercial"}
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TREE = re.compile(r"[0-9a-f]{40,64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
EXPECTED_POLICY = {
    "schemaVersion": 1,
    "blockingMediumDomains": ["auth", "crypto", "redirect", "network-reachable"],
    "forbiddenLicenses": [
        "AGPL",
        "BUSL",
        "Commons-Clause",
        "Noncommercial",
        "SSPL",
        "UNLICENSED",
        "UNKNOWN",
    ],
    "manualReviewLicenses": ["GPL", "LGPL"],
    "maximumScannerDatabaseAgeHours": 24,
    "maximumBuildOnlyWaiverDays": 30,
    "criticalWaiversAllowed": False,
    "runtimeWaiversAllowed": False,
    "allowedFindingDomains": sorted(ALLOWED_FINDING_DOMAINS),
}
REQUIRED_NEGATIVE_TESTS = {
    "jwt.wrong-alg",
    "jwt.issuer",
    "jwt.audience",
    "jwt.expiry",
    "jwt.token-type",
    "redirect.exact-binding",
    "pkce.exact-binding",
    "oauth.state-provider-binding",
    "admin.unauthorized-self-protection",
    "failure.db-redis-fail-closed",
    "password.enumeration-dummy-password",
    "failure.queued-replay-zero",
}
ALLOWED_REASON_CODES = {
    "CONTROLLED_COLLECTOR_REQUIRED",
    "TOOLCHAIN_LOCK_UNFROZEN",
    "MISSING_EVIDENCE",
    "UNSAFE_INPUT",
    "MALFORMED_INPUT",
    "POLICY_VIOLATION",
    "PUBLICATION_REFUSED",
}
SENSITIVE_KEYS = {"accesstoken", "refreshtoken", "apikey", "clientsecret", "authorization"}
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
TOKEN_PREFIX = re.compile(
    r"\b(?:ghp|github_pat|glpat|xox[baprs]|sk_live|sk_test)_[A-Za-z0-9_-]+", re.I
)
PINNED_FILES = {
    "runnerSha256": "fastapi-auth-server/ops/phase7/security/security_gate.py",
    "policySha256": "fastapi-auth-server/ops/phase7/security/security-policy.json",
    "ruleSha256": "fastapi-auth-server/ops/phase7/security/semgrep-rules.yml",
    "pythonLockSha256": "fastapi-auth-server/uv.lock",
    "nodeLockSha256": "auth-server/package-lock.json",
    "nodeBuildLockSha256": "auth-server/package-lock.json",
    "dockerfileSha256": "fastapi-auth-server/Dockerfile",
    "toolchainLockSha256": (
        "fastapi-auth-server/ops/phase7/security/controlled-toolchain-lock.json"
    ),
}


def _empty_image_lock() -> dict[str, object]:
    return {
        "repository": None,
        "version": None,
        "indexDigest": None,
        "platformDigests": {"linux/amd64": None, "linux/arm64/v8": None},
        "configDigests": {"linux/amd64": None, "linux/arm64/v8": None},
    }


def _empty_trivy_artifact_lock() -> dict[str, object]:
    return {
        "repository": None,
        "version": None,
        "manifestDigest": None,
        "payloadSha256": None,
    }


def _empty_signature_policy() -> dict[str, object]:
    return {"issuer": None, "subject": None, "rekorRequired": None}


TOOLCHAIN_LOCK = {
    "schemaVersion": 2,
    "status": "UNFROZEN",
    "collectionNetwork": "disabled",
    "stagingNetwork": "default-deny",
    "daemonPolicy": "isolated-disposable",
    "bootstrapBinary": {"path": None, "sha256": None},
    "targetPlatforms": [
        {"os": "linux", "architecture": "amd64", "variant": None},
        {"os": "linux", "architecture": "arm64", "variant": "v8"},
    ],
    "images": {name: _empty_image_lock() for name in ("builder", "collector")},
    "scanners": {name: _empty_image_lock() for name in sorted(SCANNER_NAMES)},
    "trivyArtifacts": {
        name: _empty_trivy_artifact_lock()
        for name in ("vulnerability-db", "java-db", "checks-bundle")
    },
    "signaturePolicies": {
        "images": {name: _empty_signature_policy() for name in ("builder", "collector")},
        "scanners": {name: _empty_signature_policy() for name in sorted(SCANNER_NAMES)},
        "trivyArtifacts": {
            name: _empty_signature_policy()
            for name in ("vulnerability-db", "java-db", "checks-bundle")
        },
    },
    "advisoryOrigins": {"pip": None, "npm": None},
    "destinationAllowlist": [],
}
QUALIFICATION_PROVENANCE_FIELDS = {
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
COLLECTOR_ATTESTATION_FIELDS = {
    "schemaVersion",
    "collectorId",
    "collectorRevision",
    "collectorTreeObject",
    "expressImageId",
    "fastapiImageId",
    "status",
}
IMAGE_METADATA_FIELDS = {
    "schemaVersion",
    "gateId",
    "runId",
    "status",
    "sourceRevision",
    "gitTreeObject",
    "imageId",
    "imageConfig",
    "baseImage",
    "securityProvenanceSha256",
    "qualificationProvenanceSha256",
    "collectorAttestationSha256",
    "toolchainLockSha256",
}
COLLECTOR_CONTRACT_FIELDS = {
    "schemaVersion",
    "gateId",
    "topology",
    "runId",
    "status",
    "sourceRevision",
    "gitTreeObject",
    "securityProvenanceSha256",
    "qualificationProvenanceSha256",
    "collectorAttestationSha256",
    "imageMetadataSha256",
    "toolchainLockSha256",
    "reportAggregateSha256",
    "bundleAggregateSha256",
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
REPOSITORY_INPUT_GROUPS = {
    "expressApplicationTreeSha256": (EXPRESS_APPLICATION_FILES, EXPRESS_APPLICATION_PREFIXES),
    "fastapiApplicationTreeSha256": (FASTAPI_APPLICATION_FILES, FASTAPI_APPLICATION_PREFIXES),
    "schemaSha256": ({"auth-server/prisma/schema.prisma"}, ()),
    "expressLockSha256": ({"auth-server/package-lock.json"}, ()),
    "fastapiLockSha256": ({"fastapi-auth-server/uv.lock"}, ()),
    "configSha256": (
        {
            "auth-server/.dockerignore",
            "auth-server/.env.example",
            "auth-server/Dockerfile",
            "auth-server/docker-compose.yml",
            "fastapi-auth-server/.dockerignore",
            "fastapi-auth-server/.env.example",
            "fastapi-auth-server/Dockerfile",
            "fastapi-auth-server/docker-compose.dev.yml",
        },
        (),
    ),
}
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(rb"(?:postgres(?:ql)?|redis)://", re.I),
    re.compile(rb"(?:password|secret|token|authorization)\s*[:=]\s*[^\s,]{4,}", re.I),
    re.compile(rb'"(?:password|secret|token|authorization)"\s*:\s*"[^"\s]{1,}"', re.I),
    re.compile(rb"\b(?:ghp|github_pat|glpat|xox[baprs]|sk_live|sk_test)_[A-Za-z0-9_-]+", re.I),
    re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.I),
    re.compile(rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    re.compile(rb"https?://", re.I),
)


class Incomplete(ValueError):
    """Required external evidence or tooling is absent."""


class Failed(ValueError):
    """Evidence is malformed, unsafe, inconsistent, or violates policy."""


@dataclass(frozen=True)
class RepositorySnapshot:
    """Immutable HEAD-derived repository inputs bound to one real worktree."""

    provenance: dict[str, str]
    pinned_blobs: dict[str, bytes]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise Failed(f"{label}:exact-fields")
    return value


def type_exact_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict) or set(actual) != set(expected):
            return False
        return all(type_exact_equal(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return False
        return all(
            type_exact_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Failed(f"{label}:timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Failed(f"{label}:timestamp") from exc
    return parsed


def regular_bytes(path: Path, *, missing: bool = True) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        error = Incomplete if missing else Failed
        raise error(f"missing:{path.name}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
    ):
        raise Failed(f"unsafe-file:{path.name}")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise Failed(f"unsafe-permissions:{path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise Failed(f"unsafe-open:{path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise Failed(f"changed-input:{path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise Failed(f"changed-input:{path.name}")
    finally:
        os.close(descriptor)
    if len(data) > 32 * 1024 * 1024:
        raise Failed(f"oversize:{path.name}")
    scanned = data.replace(b"https://json.schemastore.org/sarif-2.1.0.json", b"")
    if any(pattern.search(scanned) for pattern in SECRET_PATTERNS):
        raise Failed(f"secret-material:{path.name}")
    return data


def parse_pairs(data: bytes, keys: set[str], label: str) -> dict[str, str]:
    try:
        lines = data.decode().splitlines()
    except UnicodeDecodeError as exc:
        raise Failed(f"{label}:utf8") from exc
    pairs = [line.split("=", 1) for line in lines]
    if any(len(pair) != 2 for pair in pairs) or len(pairs) != len(keys):
        raise Failed(f"{label}:exact-lines")
    result = dict(pairs)
    if len(result) != len(pairs) or set(result) != keys:
        raise Failed(f"{label}:exact-keys")
    return result


def load_json(data: bytes, label: str) -> Any:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Failed(f"{label}:json") from exc
    scan_structured(value, label)
    return value


def scan_structured(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in SENSITIVE_KEYS and child is not None and child != "":
                raise Failed(f"secret-material:{label}")
            scan_structured(child, label)
    elif isinstance(value, list):
        for child in value:
            scan_structured(child, label)
    elif isinstance(value, str) and (EMAIL.search(value) or TOKEN_PREFIX.search(value)):
        raise Failed(f"secret-material:{label}")


def validate_policy(data: bytes) -> None:
    if load_json(data, "security-policy") != EXPECTED_POLICY:
        raise Failed("security-policy:exact-contract")


def aggregate_hash(blobs: dict[str, bytes], names: set[str]) -> str:
    records = [name.encode() + b"\0" + sha256(blobs[name]).encode() + b"\n" for name in names]
    return sha256(b"".join(sorted(records)))


def git(
    repo_descriptor: int,
    git_descriptor: int,
    *arguments: str,
    allow_no_match: bool = False,
) -> bytes:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(  # noqa: S603 - fixed Git binary and sanitized environment
        [
            "/usr/bin/git",
            "--no-replace-objects",
            f"--git-dir=/proc/self/fd/{git_descriptor}",
            f"--work-tree=/proc/self/fd/{repo_descriptor}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        ],
        cwd=f"/proc/self/fd/{repo_descriptor}",
        check=False,
        capture_output=True,
        env=environment,
        pass_fds=(repo_descriptor, git_descriptor),
    )
    if completed.returncode != 0 and not (allow_no_match and completed.returncode == 1):
        raise subprocess.CalledProcessError(
            completed.returncode, completed.args, completed.stdout, completed.stderr
        )
    return completed.stdout


def _regular_metadata_file(path: Path, label: str) -> bytes:
    state = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
        raise Failed(f"repo:{label}")
    return path.read_bytes()


def _config_is_unsafe(data: bytes) -> bool:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise Failed("repo:git-config") from exc
    for line in lines:
        key = line.split(maxsplit=1)[0].lower()
        if (
            key == "core.worktree"
            or key == "extensions.partialclone"
            or key == "include.path"
            or (key.startswith("includeif.") and key.endswith(".path"))
            or "promisor" in key
            or "alternate" in key
        ):
            return True
    return False


def repository_snapshot(repo: Path) -> RepositorySnapshot:
    if not repo.is_absolute() or repo.resolve() != repo or repo.is_symlink() or not repo.is_dir():
        raise Failed("repo:unsafe")
    repo_descriptor = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        repo_identity = os.fstat(repo_descriptor)
        dotgit = repo / ".git"
        dotgit_state = dotgit.lstat()
        if stat.S_ISDIR(dotgit_state.st_mode) and not dotgit.is_symlink():
            git_dir = dotgit
            common_dir = dotgit
        elif stat.S_ISREG(dotgit_state.st_mode) and not dotgit.is_symlink():
            lines = _regular_metadata_file(dotgit, "gitfile").decode("utf-8").splitlines()
            if len(lines) != 1 or not lines[0].startswith("gitdir: "):
                raise Failed("repo:gitfile")
            git_dir = Path(lines[0][8:])
            if (
                not git_dir.is_absolute()
                or git_dir.resolve() != git_dir
                or git_dir.is_symlink()
                or not git_dir.is_dir()
            ):
                raise Failed("repo:gitfile-target")
            commondir = _regular_metadata_file(git_dir / "commondir", "commondir")
            backlink = _regular_metadata_file(git_dir / "gitdir", "gitdir")
            if commondir.decode("utf-8").strip() != "../.." or backlink.decode(
                "utf-8"
            ).strip() != str(dotgit):
                raise Failed("repo:linked-worktree-binding")
            common_dir = (git_dir / "../..").resolve()
            if git_dir.parent != common_dir / "worktrees":
                raise Failed("repo:linked-worktree-namespace")
        else:
            raise Failed("repo:git-metadata")
        if common_dir.is_symlink() or not common_dir.is_dir():
            raise Failed("repo:common-dir")
        git_descriptor = os.open(
            git_dir, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        common_descriptor = os.open(
            common_dir, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            git_identity = os.fstat(git_descriptor)
            common_identity = os.fstat(common_descriptor)
            for relative in ("objects/info/alternates", "objects/info/http-alternates"):
                try:
                    os.stat(relative, dir_fd=common_descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise Failed("repo:object-alternates")
            for relative in ("HEAD", "index"):
                state = os.stat(relative, dir_fd=git_descriptor, follow_symlinks=False)
                if not stat.S_ISREG(state.st_mode):
                    raise Failed(f"repo:{relative}")
            local_config = git(
                repo_descriptor,
                git_descriptor,
                "config",
                "--no-includes",
                "--local",
                "--get-regexp",
                ".*",
                allow_no_match=True,
            )
            if _config_is_unsafe(local_config):
                raise Failed("repo:unsafe-local-config")
            worktree_enabled = git(
                repo_descriptor,
                git_descriptor,
                "config",
                "--no-includes",
                "--local",
                "--type=bool",
                "--get",
                "extensions.worktreeConfig",
                allow_no_match=True,
            ).strip()
            if worktree_enabled == b"true":
                worktree_config = git(
                    repo_descriptor,
                    git_descriptor,
                    "config",
                    "--no-includes",
                    "--worktree",
                    "--get-regexp",
                    ".*",
                    allow_no_match=True,
                )
                if _config_is_unsafe(worktree_config):
                    raise Failed("repo:unsafe-worktree-config")
            if git(
                repo_descriptor,
                git_descriptor,
                "for-each-ref",
                "--format=%(refname)",
                "refs/replace/",
            ):
                raise Failed("repo:replace-refs")
            top = (
                git(repo_descriptor, git_descriptor, "rev-parse", "--show-toplevel")
                .decode()
                .strip()
            )
            if (
                os.stat(top).st_dev != repo_identity.st_dev
                or os.stat(top).st_ino != repo_identity.st_ino
            ):
                raise Failed("repo:worktree-binding")
            actual_git = (
                git(repo_descriptor, git_descriptor, "rev-parse", "--absolute-git-dir")
                .decode()
                .strip()
            )
            if (
                os.stat(actual_git).st_dev != git_identity.st_dev
                or os.stat(actual_git).st_ino != git_identity.st_ino
            ):
                raise Failed("repo:git-dir-binding")
            common_value = (
                git(repo_descriptor, git_descriptor, "rev-parse", "--git-common-dir")
                .decode()
                .strip()
            )
            actual_common = Path(common_value)
            if not actual_common.is_absolute():
                actual_common = repo / actual_common
            common_state = actual_common.stat()
            if (common_state.st_dev, common_state.st_ino) != (
                common_identity.st_dev,
                common_identity.st_ino,
            ):
                raise Failed("repo:common-dir-binding")
            index_path = Path(
                git(repo_descriptor, git_descriptor, "rev-parse", "--git-path", "index")
                .decode()
                .strip()
            )
            index_state = index_path.stat()
            expected_index = os.stat("index", dir_fd=git_descriptor, follow_symlinks=False)
            if (index_state.st_dev, index_state.st_ino) != (
                expected_index.st_dev,
                expected_index.st_ino,
            ):
                raise Failed("repo:index-binding")
            if git(
                repo_descriptor, git_descriptor, "status", "--porcelain=v1", "--untracked-files=all"
            ):
                raise Failed("source:dirty")
            revision = (
                git(repo_descriptor, git_descriptor, "rev-parse", "--verify", "HEAD")
                .decode()
                .strip()
            )
            tree = (
                git(
                    repo_descriptor, git_descriptor, "rev-parse", "--verify", f"{revision}^{{tree}}"
                )
                .decode()
                .strip()
            )
            if TREE.fullmatch(revision) is None or TREE.fullmatch(tree) is None:
                raise Failed("repo:revision")
            tracked: dict[str, tuple[str, str]] = {}
            tree_data = git(
                repo_descriptor, git_descriptor, "ls-tree", "-r", "-z", "--full-tree", revision
            )
            for record in tree_data.rstrip(b"\0").split(b"\0"):
                try:
                    metadata, raw_path = record.split(b"\t", 1)
                    mode, object_type, object_id = metadata.decode("ascii").split(" ")
                    path = raw_path.decode("utf-8")
                except (UnicodeDecodeError, ValueError) as exc:
                    raise Failed("repo:tree") from exc
                if object_type != "blob" or mode not in {"100644", "100755"} or not path:
                    raise Failed("repo:tree")
                tracked[path] = (mode, object_id)
            pinned_blobs: dict[str, bytes] = {}
            for relative in set(PINNED_FILES.values()):
                if relative not in tracked:
                    raise Incomplete(f"missing-pinned-input:{relative}")
                pinned_blobs[relative] = git(
                    repo_descriptor, git_descriptor, "cat-file", "blob", tracked[relative][1]
                )
            result = {"sourceRevision": revision, "gitTreeObject": tree}
            for field, (exact_paths, prefixes) in REPOSITORY_INPUT_GROUPS.items():
                paths = set(exact_paths) | {
                    path for path in tracked if any(path.startswith(prefix) for prefix in prefixes)
                }
                if not paths or any(path not in tracked for path in paths):
                    raise Failed(f"repo:missing-{field}")
                records = []
                for path in paths:
                    blob = git(
                        repo_descriptor, git_descriptor, "cat-file", "blob", tracked[path][1]
                    )
                    records.append(path.encode() + b"\0" + sha256(blob).encode() + b"\n")
                result[field] = sha256(b"".join(sorted(records)))
            if (
                git(repo_descriptor, git_descriptor, "rev-parse", "--verify", "HEAD")
                .decode()
                .strip()
                != revision
                or git(
                    repo_descriptor,
                    git_descriptor,
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                )
                or (
                    os.fstat(repo_descriptor).st_dev,
                    os.fstat(repo_descriptor).st_ino,
                )
                != (repo_identity.st_dev, repo_identity.st_ino)
            ):
                raise Failed("source:changed")
            return RepositorySnapshot(result, pinned_blobs)
        finally:
            os.close(common_descriptor)
            os.close(git_descriptor)
    finally:
        os.close(repo_descriptor)


def repository_provenance(repo: Path) -> dict[str, str]:
    return repository_snapshot(repo).provenance


def validate_control_attachments(
    blobs: dict[str, bytes],
    run_id: str,
    repo_snapshot: RepositorySnapshot,
    security_provenance: dict[str, str],
) -> None:
    lock_bytes = repo_snapshot.pinned_blobs[PINNED_FILES["toolchainLockSha256"]]
    lock = exact(load_json(lock_bytes, "toolchain-lock"), set(TOOLCHAIN_LOCK), "toolchain-lock")
    if (
        type(lock["schemaVersion"]) is not int
        or lock["schemaVersion"] != 2
        or not isinstance(lock["status"], str)
        or lock["status"] != "UNFROZEN"
        or not isinstance(lock["collectionNetwork"], str)
        or lock["collectionNetwork"] != "disabled"
        or not isinstance(lock["stagingNetwork"], str)
        or lock["stagingNetwork"] != "default-deny"
        or not isinstance(lock["daemonPolicy"], str)
        or lock["daemonPolicy"] != "isolated-disposable"
        or not type_exact_equal(lock, TOOLCHAIN_LOCK)
    ):
        raise Failed("toolchain-lock:exact-unfrozen-contract")
    lock_hash = sha256(lock_bytes)
    if security_provenance["toolchainLockSha256"] != lock_hash:
        raise Failed("provenance:toolchain-lock")

    attestation = exact(
        load_json(blobs["collector-attestation.json"], "collector-attestation"),
        COLLECTOR_ATTESTATION_FIELDS,
        "collector-attestation",
    )
    if (
        type(attestation["schemaVersion"]) is not int
        or attestation["schemaVersion"] != 1
        or not isinstance(attestation["status"], str)
        or attestation["status"] != "UNVERIFIED"
        or not isinstance(attestation["collectorId"], str)
        or SAFE_ID.fullmatch(attestation["collectorId"]) is None
        or not isinstance(attestation["collectorRevision"], str)
        or TREE.fullmatch(attestation["collectorRevision"]) is None
        or not isinstance(attestation["collectorTreeObject"], str)
        or TREE.fullmatch(attestation["collectorTreeObject"]) is None
        or not isinstance(attestation["expressImageId"], str)
        or IMAGE.fullmatch(attestation["expressImageId"]) is None
        or not isinstance(attestation["fastapiImageId"], str)
        or IMAGE.fullmatch(attestation["fastapiImageId"]) is None
    ):
        raise Failed("collector-attestation:exact-unverified-contract")

    qualification = exact(
        load_json(blobs["qualification-provenance.json"], "qualification-provenance"),
        QUALIFICATION_PROVENANCE_FIELDS,
        "qualification-provenance",
    )
    expected_repo = repo_snapshot.provenance
    if (
        type(qualification["schemaVersion"]) is not int
        or qualification["schemaVersion"] != 2
        or qualification["gateId"] != "security"
        or qualification["topology"] != "controlled-security-v1"
        or qualification["runId"] != run_id
    ):
        raise Failed("qualification-provenance:identity")
    for field, expected in expected_repo.items():
        if qualification[field] != expected:
            raise Failed(f"qualification-provenance:repo-{field}")
    for field in (
        "expressApplicationTreeSha256",
        "fastapiApplicationTreeSha256",
        "schemaSha256",
        "expressLockSha256",
        "fastapiLockSha256",
        "configSha256",
        "collectorAttestationSha256",
    ):
        if SHA256.fullmatch(str(qualification[field])) is None:
            raise Failed(f"qualification-provenance:{field}")
    if qualification["collectorAttestationSha256"] != sha256(blobs["collector-attestation.json"]):
        raise Failed("qualification-provenance:collector-attestation-hash")
    for field in ("expressImageId", "fastapiImageId"):
        if qualification[field] != attestation[field]:
            raise Failed(f"collector-attestation:image-{field}")
    if qualification["fastapiImageId"] != security_provenance["imageId"]:
        raise Failed("qualification-provenance:fastapi-image")
    if (
        qualification["sourceRevision"] != security_provenance["sourceRevision"]
        or qualification["gitTreeObject"] != security_provenance["applicationTree"]
    ):
        raise Failed("qualification-provenance:legacy-source")

    image_metadata = exact(
        load_json(blobs["image-metadata.json"], "image-metadata"),
        IMAGE_METADATA_FIELDS,
        "image-metadata",
    )
    if (
        type(image_metadata["schemaVersion"]) is not int
        or image_metadata["schemaVersion"] != 1
        or image_metadata["gateId"] != "security"
        or image_metadata["runId"] != run_id
        or image_metadata["status"] != "UNVERIFIED"
    ):
        raise Failed("image-metadata:exact-unverified-contract")
    image_expected = {
        "sourceRevision": qualification["sourceRevision"],
        "gitTreeObject": qualification["gitTreeObject"],
        "imageId": security_provenance["imageId"],
        "imageConfig": security_provenance["imageConfig"],
        "baseImage": security_provenance["baseImage"],
        "securityProvenanceSha256": sha256(blobs["provenance.txt"]),
        "qualificationProvenanceSha256": sha256(blobs["qualification-provenance.json"]),
        "collectorAttestationSha256": sha256(blobs["collector-attestation.json"]),
        "toolchainLockSha256": lock_hash,
    }
    if any(image_metadata[field] != value for field, value in image_expected.items()):
        raise Failed("image-metadata:hash-or-image-binding")

    contract = exact(
        load_json(blobs["collector-contract.json"], "collector-contract"),
        COLLECTOR_CONTRACT_FIELDS,
        "collector-contract",
    )
    if (
        type(contract["schemaVersion"]) is not int
        or contract["schemaVersion"] != 1
        or contract["gateId"] != "security"
        or contract["topology"] != qualification["topology"]
        or contract["runId"] != run_id
        or contract["status"] != "UNVERIFIED"
    ):
        raise Failed("collector-contract:exact-unverified-contract")
    contract_expected = {
        "sourceRevision": qualification["sourceRevision"],
        "gitTreeObject": qualification["gitTreeObject"],
        "securityProvenanceSha256": sha256(blobs["provenance.txt"]),
        "qualificationProvenanceSha256": sha256(blobs["qualification-provenance.json"]),
        "collectorAttestationSha256": sha256(blobs["collector-attestation.json"]),
        "imageMetadataSha256": sha256(blobs["image-metadata.json"]),
        "toolchainLockSha256": lock_hash,
        "reportAggregateSha256": aggregate_hash(blobs, LEGACY_INPUTS),
        "bundleAggregateSha256": aggregate_hash(
            blobs, EXPECTED_INPUTS - {"collector-contract.json"}
        ),
    }
    if any(contract[field] != value for field, value in contract_expected.items()):
        raise Failed("collector-contract:hash-binding")


def validate_scanner(
    value: object,
    expected: str,
    expected_scope: str,
    now: dt.datetime,
    provenance: dict[str, str],
) -> None:
    scanner = exact(value, SCANNER_FIELDS, "scanner")
    versions = load_json(provenance["scannerVersions"].encode(), "scannerVersions")
    images = load_json(provenance["scannerImages"].encode(), "scannerImages")
    if not isinstance(versions, dict) or set(versions) != SCANNER_NAMES:
        raise Failed("scanner:provenance-versions")
    if (
        scanner["name"] != expected
        or not isinstance(scanner["version"], str)
        or scanner["version"] != versions[expected]
    ):
        raise Failed("scanner:identity")
    if scanner["imageDigest"] != images[expected]:
        raise Failed("scanner:image-identity")
    if VERSION.fullmatch(str(scanner["version"])) is None:
        raise Failed("scanner:version")
    if scanner["scope"] != expected_scope:
        raise Failed("scanner:scope")
    if scanner["mode"] != "offline" or scanner["ruleSha256"] != provenance["ruleSha256"]:
        raise Failed("scanner:mode-or-rules")
    updated = timestamp(scanner["databaseUpdatedAt"], "scanner-database")
    if scanner["databaseUpdatedAt"] != provenance["scannerDatabaseUpdatedAt"]:
        raise Failed("scanner:database-provenance")
    age = now - updated
    if age < dt.timedelta(0) or age > dt.timedelta(hours=24):
        raise Failed("scanner:database-stale")


def validate_subject(value: object, provenance: dict[str, str]) -> None:
    subject = exact(value, SUBJECT_FIELDS, "subject")
    for key in SUBJECT_FIELDS:
        if subject[key] != provenance[key]:
            raise Failed(f"subject-mismatch:{key}")


def validate_findings(value: object, category: str, now: dt.datetime) -> None:
    if not isinstance(value, list):
        raise Failed(f"{category}:findings")
    seen: set[str] = set()
    for raw in value:
        finding = exact(raw, FINDING_FIELDS, f"{category}:finding")
        finding_id = finding["id"]
        severity = finding["severity"]
        domain = finding["domain"]
        if not isinstance(finding_id, str) or not finding_id or finding_id in seen:
            raise Failed(f"{category}:finding-id")
        seen.add(finding_id)
        if not isinstance(severity, str) or severity not in {
            "UNKNOWN",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            raise Failed(f"{category}:severity")
        if not all(
            isinstance(finding[key], str) and finding[key]
            for key in ("domain", "path", "reachability")
        ):
            raise Failed(f"{category}:finding-fields")
        if domain not in ALLOWED_FINDING_DOMAINS:
            raise Failed(f"{category}:finding-domain")
        waiver = finding["waiver"]
        if severity == "MEDIUM" and domain in BLOCKING_MEDIUM_DOMAINS:
            raise Failed(f"blocking-medium:{finding_id}")
        if severity in {"CRITICAL", "HIGH"}:
            if severity == "CRITICAL" or category != "node-build" or waiver is None:
                raise Failed(f"unapproved-{severity.lower()}:{finding_id}")
            approved = exact(waiver, WAIVER_FIELDS, f"waiver:{finding_id}")
            if not all(isinstance(approved[key], str) and approved[key] for key in WAIVER_FIELDS):
                raise Failed(f"waiver:{finding_id}:fields")
            expires = timestamp(approved["expiresAt"], f"waiver:{finding_id}:expiry")
            if expires <= now or expires - now > dt.timedelta(days=30):
                raise Failed(f"waiver:{finding_id}:bounds")
            if finding["reachability"] not in {"unreachable-build-only", "build-tool-only"}:
                raise Failed(f"waiver:{finding_id}:reachability")
        elif waiver is not None:
            raise Failed(f"unnecessary-waiver:{finding_id}")


def validate_report(
    data: bytes, expected_scanner: str, category: str, provenance: dict[str, str], now: dt.datetime
) -> None:
    report = exact(load_json(data, category), REPORT_FIELDS, category)
    if type(report["schemaVersion"]) is not int or report["schemaVersion"] != 1:
        raise Failed(f"{category}:schema")
    scope = "image" if expected_scanner == "trivy" else category
    validate_scanner(report["scanner"], expected_scanner, scope, now, provenance)
    validate_subject(report["subject"], provenance)
    validate_findings(report["findings"], category, now)


def validate_sarif(
    data: bytes, expected_tools: set[str], provenance: dict[str, str], now: dt.datetime, label: str
) -> None:
    document = load_json(data, label)
    if (
        not isinstance(document, dict)
        or set(document) != {"$schema", "version", "runs"}
        or document["version"] != "2.1.0"
    ):
        raise Failed(f"{label}:sarif-envelope")
    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) != len(expected_tools):
        raise Failed(f"{label}:runs")
    found: set[str] = set()
    for run in runs:
        if not isinstance(run, dict) or set(run) != {"tool", "properties", "results"}:
            raise Failed(f"{label}:run-fields")
        driver = exact(exact(run["tool"], {"driver"}, label)["driver"], {"name", "version"}, label)
        name = driver["name"]
        if (
            name not in expected_tools
            or name in found
            or VERSION.fullmatch(str(driver["version"])) is None
        ):
            raise Failed(f"{label}:tool-identity")
        found.add(name)
        props = exact(
            run["properties"],
            {"databaseUpdatedAt", "imageDigest", "mode", "scope", "ruleSha256", "subject"},
            label,
        )
        validate_scanner(
            {
                "name": name,
                "version": driver["version"],
                **{
                    key: props[key]
                    for key in (
                        "databaseUpdatedAt",
                        "imageDigest",
                        "mode",
                        "scope",
                        "ruleSha256",
                    )
                },
            },
            name,
            (
                "full-history"
                if label == "secrets.sarif" and name == "gitleaks"
                else "filesystem"
                if label == "secrets.sarif"
                else "source-security"
            ),
            now,
            provenance,
        )
        validate_subject(props["subject"], provenance)
        if label == "secrets.sarif" and run["results"]:
            raise Failed("secrets:finding-present")
        validate_findings(run["results"], "sast" if label == "sast.sarif" else "secrets", now)


def validate_provenance(
    data: bytes, run_id: str, repo_snapshot: RepositorySnapshot, now: dt.datetime
) -> dict[str, str]:
    values = parse_pairs(data, PROVENANCE_KEYS, "provenance")
    if values["schemaVersion"] != "1" or values["runId"] != run_id:
        raise Failed("provenance:identity")
    if values["network"] != "disabled" or values["sockets"] != "none":
        raise Failed("provenance:network")
    hash_keys = {key for key in PROVENANCE_KEYS if key.endswith("Sha256")}
    hash_keys.update({"imageConfig", "baseImage"})
    if any(SHA256.fullmatch(values[key]) is None for key in hash_keys):
        raise Failed("provenance:hash")
    if TREE.fullmatch(values["applicationTree"]) is None:
        raise Failed("provenance:tree")
    if IMAGE.fullmatch(values["imageId"]) is None:
        raise Failed("provenance:image")
    images = load_json(values["scannerImages"].encode(), "scannerImages")
    versions = load_json(values["scannerVersions"].encode(), "scannerVersions")
    if (
        not isinstance(images, dict)
        or set(images) != SCANNER_NAMES
        or any(IMAGE.fullmatch(str(value)) is None for value in images.values())
        or not isinstance(versions, dict)
        or set(versions) != SCANNER_NAMES
        or any(
            not isinstance(value, str) or VERSION.fullmatch(value) is None
            for value in versions.values()
        )
    ):
        raise Failed("provenance:scanner-pins")
    updated = timestamp(values["scannerDatabaseUpdatedAt"], "scanner-database")
    age = now - updated
    if age < dt.timedelta(0) or age > dt.timedelta(hours=24):
        raise Failed("provenance:scanner-database-stale")
    for key, relative in PINNED_FILES.items():
        if sha256(repo_snapshot.pinned_blobs[relative]) != values[key]:
            raise Failed(f"provenance:pinned-input:{key}")
    validate_policy(repo_snapshot.pinned_blobs[PINNED_FILES["policySha256"]])
    if (
        values["sourceRevision"] != repo_snapshot.provenance["sourceRevision"]
        or values["applicationTree"] != repo_snapshot.provenance["gitTreeObject"]
    ):
        raise Failed("provenance:source-mismatch")
    return values


def validate_bundle(
    source: Path, run_id: str, repo: Path, now: dt.datetime
) -> tuple[dict[str, bytes], list[str]]:
    if source.is_symlink():
        raise Failed("input-directory:unsafe")
    if not source.exists():
        raise Incomplete("missing:input-directory")
    if (
        not source.is_absolute()
        or source.resolve() != source
        or source.is_symlink()
        or stat.S_IMODE(source.stat().st_mode) != 0o700
        or source.stat().st_uid != os.getuid()
    ):
        raise Failed("input-directory:unsafe")
    source_identity = source.stat()
    names = {entry.name for entry in source.iterdir()}
    unexpected = names - EXPECTED_INPUTS
    if unexpected:
        raise Failed("input-directory:unexpected-files")
    missing = EXPECTED_INPUTS - names
    if missing:
        raise Incomplete("missing:" + ",".join(sorted(missing)))
    blobs = {name: regular_bytes(source / name) for name in EXPECTED_INPUTS}
    after = source.stat()
    if (source_identity.st_dev, source_identity.st_ino) != (after.st_dev, after.st_ino) or {
        entry.name for entry in source.iterdir()
    } != EXPECTED_INPUTS:
        raise Failed("input-directory:changed")
    repo_snapshot = repository_snapshot(repo)
    provenance = validate_provenance(blobs["provenance.txt"], run_id, repo_snapshot, now)
    expected_hashes = ",".join(
        f"{name}:{sha256(blobs[name])}" for name in sorted(LEGACY_INPUTS - {"provenance.txt"})
    )
    if provenance["reportHashes"] != expected_hashes:
        raise Failed("provenance:report-hashes")
    linked_hashes = {
        "expressBeforeSha256": "express-before.txt",
        "expressAfterSha256": "express-after.txt",
        "candidateInventorySha256": "candidate-inventory.json",
        "cleanupInventorySha256": "cleanup.status",
    }
    if any(provenance[key] != sha256(blobs[name]) for key, name in linked_hashes.items()):
        raise Failed("provenance:runtime-evidence-hash")
    validate_control_attachments(blobs, run_id, repo_snapshot, provenance)
    for name, (scanner, category) in DEPENDENCY_REPORTS.items():
        validate_report(blobs[name], scanner, category, provenance, now)
    for name, category in IMAGE_REPORTS.items():
        validate_report(blobs[name], "trivy", category, provenance, now)
    validate_sarif(blobs["sast.sarif"], {"ruff", "semgrep"}, provenance, now, "sast.sarif")
    validate_sarif(blobs["secrets.sarif"], {"gitleaks", "trivy"}, provenance, now, "secrets.sarif")
    sbom = load_json(blobs["sbom.cdx.json"], "sbom")
    if (
        not isinstance(sbom, dict)
        or set(sbom)
        != {"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components"}
        or sbom["bomFormat"] != "CycloneDX"
        or not isinstance(sbom["components"], list)
    ):
        raise Failed("sbom:exact-cyclonedx")
    metadata = exact(sbom["metadata"], {"timestamp", "scanner", "subject"}, "sbom-metadata")
    timestamp(metadata["timestamp"], "sbom-timestamp")
    validate_scanner(metadata["scanner"], "trivy", "image", now, provenance)
    validate_subject(metadata["subject"], provenance)
    sbom_packages: dict[str, tuple[str, str, set[str]]] = {}
    for component in sbom["components"]:
        item = exact(component, {"name", "version", "purl", "licenses"}, "sbom-component")
        if not all(isinstance(item[key], str) and item[key] for key in ("name", "version", "purl")):
            raise Failed("sbom:component-identity")
        if (
            not isinstance(item["licenses"], list)
            or not item["licenses"]
            or not all(isinstance(value, str) and value for value in item["licenses"])
        ):
            raise Failed("sbom:component-licenses")
        if len(set(item["licenses"])) != len(item["licenses"]) or item["purl"] in sbom_packages:
            raise Failed("sbom:duplicate-component-or-license")
        sbom_packages[item["purl"]] = (item["name"], item["version"], set(item["licenses"]))
    licenses = load_json(blobs["licenses.json"], "licenses")
    licenses = exact(
        licenses,
        {"schemaVersion", "scanner", "subject", "manualReview", "packages"},
        "licenses",
    )
    if (
        type(licenses["schemaVersion"]) is not int
        or licenses["schemaVersion"] != 1
        or not isinstance(licenses["packages"], list)
        or not isinstance(licenses["manualReview"], list)
    ):
        raise Failed("licenses:schema")
    validate_scanner(licenses["scanner"], "trivy", "image", now, provenance)
    validate_subject(licenses["subject"], provenance)
    if not all(isinstance(value, str) and value for value in licenses["manualReview"]):
        raise Failed("licenses:manual-review")
    reviews = set(licenses["manualReview"])
    license_packages: dict[str, tuple[str, str, set[str]]] = {}
    for package in licenses["packages"]:
        item = exact(package, {"name", "version", "purl", "licenses"}, "license-package")
        if not all(isinstance(item[key], str) and item[key] for key in ("name", "version", "purl")):
            raise Failed("license:package-identity")
        if (
            not isinstance(item["licenses"], list)
            or not item["licenses"]
            or not all(isinstance(value, str) and value for value in item["licenses"])
        ):
            raise Failed("license:package-licenses")
        package_licenses = set(item["licenses"])
        if len(package_licenses) != len(item["licenses"]) or item["purl"] in license_packages:
            raise Failed("license:duplicate-package-or-license")
        license_packages[item["purl"]] = (item["name"], item["version"], package_licenses)
        for license_id in package_licenses:
            normalized_license = license_id.upper()
            if (
                normalized_license in {"", "UNKNOWN", "UNLICENSED"}
                or license_id in FORBIDDEN_LICENSES
                or any(
                    token in license_id.lower()
                    for token in ("agpl", "sspl", "busl", "commons", "noncommercial")
                )
            ):
                raise Failed(f"license:forbidden:{item['purl']}")
            if "GPL" in normalized_license and item["purl"] not in reviews:
                raise Failed(f"license:manual-review:{item['purl']}")
    if sbom_packages != license_packages:
        raise Failed("license:sbom-reconciliation")
    hardening = parse_pairs(blobs["hardening.status"], HARDENING_KEYS, "hardening")
    if any(value != "PASS" for value in hardening.values()):
        raise Failed("hardening:failed")
    cleanup = parse_pairs(blobs["cleanup.status"], CLEANUP_KEYS, "cleanup")
    if any(value != "PASS" for value in cleanup.values()):
        raise Failed("cleanup:failed")
    inventory = exact(
        load_json(blobs["candidate-inventory.json"], "candidate-inventory"),
        {"schemaVersion", "imageId", "resources"},
        "candidate-inventory",
    )
    if inventory != {"schemaVersion": 1, "imageId": provenance["imageId"], "resources": []}:
        raise Failed("candidate-inventory:not-empty-or-unlinked")
    negative = parse_pairs(
        blobs["negative-tests.status"],
        {"status", "tests", "failures", "errors", "skipped"},
        "negative-tests",
    )
    if (
        negative["status"] != "PASS"
        or negative["failures"] != "0"
        or negative["errors"] != "0"
        or negative["skipped"] != "0"
        or not negative["tests"].isdigit()
        or int(negative["tests"]) != len(REQUIRED_NEGATIVE_TESTS)
    ):
        raise Failed("negative-tests:failed")
    if b"<!" in blobs["negative-tests.xml"]:
        raise Failed("negative-tests:xml-declaration")
    try:
        suite = ET.fromstring(  # noqa: S314 - bounded input rejects DTD/entity declarations
            blobs["negative-tests.xml"]
        )
    except ET.ParseError as exc:
        raise Failed("negative-tests:xml") from exc
    if (
        suite.tag != "testsuite"
        or any(
            suite.attrib.get(key) != negative[value]
            for key, value in (
                ("tests", "tests"),
                ("failures", "failures"),
                ("errors", "errors"),
                ("skipped", "skipped"),
            )
        )
        or any(element.tag in {"failure", "error", "skipped"} for element in suite.iter())
    ):
        raise Failed("negative-tests:xml")
    cases = list(suite)
    if (
        any(
            case.tag != "testcase"
            or set(case.attrib) != {"classname", "name", "time"}
            or case.attrib["classname"] != "phase7-security"
            or not re.fullmatch(
                r"(?:0\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(?:\.[0-9]+)?)", case.attrib["time"]
            )
            or len(case) != 1
            or case[0].tag != "properties"
            or len(case[0]) != 1
            or case[0][0].tag != "property"
            or set(case[0][0].attrib) != {"name", "value"}
            or case[0][0].attrib["name"] != "evidenceSha256"
            or SHA256.fullmatch(case[0][0].attrib["value"]) is None
            for case in cases
        )
        or len(cases) != len(REQUIRED_NEGATIVE_TESTS)
        or {case.attrib["name"] for case in cases} != REQUIRED_NEGATIVE_TESTS
    ):
        raise Failed("negative-tests:required-cases")
    sanitization = parse_pairs(
        blobs["sanitization.status"],
        {"status", "secretPatterns", "piiPatterns", "unsafePaths"},
        "sanitization",
    )
    if sanitization != {
        "status": "PASS",
        "secretPatterns": "0",
        "piiPatterns": "0",
        "unsafePaths": "0",
    }:
        raise Failed("sanitization:failed")
    if blobs["express-before.txt"] != blobs["express-after.txt"]:
        raise Failed("express-snapshot:changed")
    return blobs, []


def snapshot_inputs(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise Failed("input-directory:unsafe")
    if not source.exists():
        raise Incomplete("missing:input-directory")
    if (
        not source.is_absolute()
        or source.resolve() != source
        or stat.S_IMODE(source.stat().st_mode) != 0o700
        or source.stat().st_uid != os.getuid()
    ):
        raise Failed("input-directory:unsafe")
    identity = source.stat()
    names = {entry.name for entry in source.iterdir()}
    if names - EXPECTED_INPUTS:
        raise Failed("input-directory:unexpected-files")
    if EXPECTED_INPUTS - names:
        raise Incomplete("missing:" + ",".join(sorted(EXPECTED_INPUTS - names)))
    for name in EXPECTED_INPUTS:
        target = destination / name
        target.write_bytes(regular_bytes(source / name))
        os.chmod(target, 0o600)
        fsync_path(target)
    after = source.stat()
    if (identity.st_dev, identity.st_ino, identity.st_mtime_ns, identity.st_ctime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or {entry.name for entry in source.iterdir()} != EXPECTED_INPUTS:
        raise Failed("input-directory:changed")
    fsync_path(destination)


def rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise OSError(errno.ENOSYS, "renameat2 required")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), target)


def fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | (os.O_DIRECTORY if path.is_dir() else 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reason_code(error: BaseException) -> str:
    if isinstance(error, Incomplete):
        return "MISSING_EVIDENCE"
    message = str(error)
    if any(token in message for token in ("unsafe", "symlink", "changed-input", "hardlink")):
        return "UNSAFE_INPUT"
    if any(
        token in message
        for token in (
            "finding",
            "unapproved",
            "license",
            "secret",
            "policy",
            "hardening",
            "snapshot",
        )
    ):
        return "POLICY_VIOLATION"
    return "MALFORMED_INPUT"


def publish(
    evidence_root: Path, run_id: str, blobs: dict[str, bytes], status: str, reasons: list[str]
) -> Path:
    if status == "PASS":
        status = "INCOMPLETE"
        reasons = ["TOOLCHAIN_LOCK_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"]
    # Until a controlled collector can authenticate opaque runtime/test artifacts,
    # never republish caller-authored bytes, even after structural validation.
    blobs = {}
    if not reasons or any(reason not in ALLOWED_REASON_CODES for reason in reasons):
        raise Failed("reason-code:invalid")
    root_created = not evidence_root.exists()
    evidence_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (
        evidence_root.resolve() != evidence_root
        or evidence_root.is_symlink()
        or stat.S_IMODE(evidence_root.stat().st_mode) != 0o700
    ):
        raise Failed("evidence-root:unsafe")
    if root_created:
        fsync_path(evidence_root.parent)
    target = evidence_root / run_id
    if target.exists() or target.is_symlink():
        raise Failed("evidence:collision")
    staging = Path(tempfile.mkdtemp(prefix=f".{run_id}.tmp.", dir=evidence_root))
    try:
        os.chmod(staging, 0o700)
        for name, data in blobs.items():
            path = staging / name
            path.write_bytes(data)
            os.chmod(path, 0o400)
        result = {
            "schemaVersion": 1,
            "gateId": "security",
            "runId": run_id,
            "status": status,
            "sampleSatisfied": status == "PASS",
            "readinessAssertionsSatisfied": status == "PASS",
            "cleanupComplete": status == "PASS",
            "expressSnapshotUnchanged": status == "PASS",
            "overallReplacementReady": False,
        }
        result_bytes = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (staging / "result.status").write_text(
            "status="
            f"{status}\noverallReplacementReady=false\nreasonCodes=" + ",".join(reasons) + "\n",
            encoding="utf-8",
        )
        (staging / "gate-result.json").write_bytes(result_bytes)
        for name in ("result.status", "gate-result.json"):
            os.chmod(staging / name, 0o400)
        for entry in staging.iterdir():
            fsync_path(entry)
        os.chmod(staging, 0o500)
        fsync_path(staging)
        rename_noreplace(staging, target)
        fsync_path(evidence_root)
        return target
    except Exception as error:
        if staging.exists():
            os.chmod(staging, 0o700)
            for entry in staging.iterdir():
                if entry.is_file() and not entry.is_symlink():
                    os.chmod(entry, 0o600)
            shutil.rmtree(staging)
        if staging.exists():
            raise Failed("publication:staging-debris") from error
        raise


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--now", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if SAFE_ID.fullmatch(args.run_id) is None:
        print("security gate refused: unsafe run id", file=sys.stderr)
        return 2
    blobs: dict[str, bytes] = {}
    try:
        now = timestamp(args.now, "now") if args.now else dt.datetime.now(dt.UTC)
        with tempfile.TemporaryDirectory(prefix="wiseacct-phase7-security-input.") as private:
            snapshot = Path(private)
            os.chmod(snapshot, 0o700)
            snapshot_inputs(args.input, snapshot)
            blobs, reasons = validate_bundle(snapshot, args.run_id, args.repo.resolve(), now)
        status, reasons = (
            "INCOMPLETE",
            [
                "TOOLCHAIN_LOCK_UNFROZEN",
                "CONTROLLED_COLLECTOR_REQUIRED",
            ],
        )
    except Incomplete as exc:
        status, reasons = "INCOMPLETE", [reason_code(exc)]
    except (Failed, OSError, subprocess.SubprocessError) as exc:
        status, reasons = "FAIL", [reason_code(exc)]
    except Exception:
        status, reasons = "FAIL", ["MALFORMED_INPUT"]
    try:
        output = publish(args.evidence_root.absolute(), args.run_id, blobs, status, reasons)
    except (Failed, OSError) as exc:
        print(f"security gate publication refused: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0 if status == "PASS" else (3 if status == "INCOMPLETE" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
