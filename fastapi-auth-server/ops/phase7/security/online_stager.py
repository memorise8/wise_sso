#!/usr/bin/env python3
"""Fail-closed controller preflight for the Phase 7 restricted online stager."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

LOCK_RELATIVE = "fastapi-auth-server/ops/phase7/security/controlled-toolchain-lock.json"
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._/-]{0,254}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
ORIGIN = re.compile(r"https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?:443")
PLATFORMS = {
    "linux/amd64": {"os": "linux", "architecture": "amd64", "variant": None},
    "linux/arm64/v8": {"os": "linux", "architecture": "arm64", "variant": "v8"},
}
IMAGE_NAMES = {"builder", "collector"}
SCANNER_NAMES = {"gitleaks", "npm-audit", "pip-audit", "ruff", "semgrep", "trivy"}
TRIVY_KINDS = {"vulnerability-db", "java-db", "checks-bundle"}
TOP_FIELDS = {
    "schemaVersion",
    "status",
    "collectionNetwork",
    "stagingNetwork",
    "daemonPolicy",
    "bootstrapBinary",
    "targetPlatforms",
    "images",
    "scanners",
    "trivyArtifacts",
    "signaturePolicies",
    "advisoryOrigins",
    "destinationAllowlist",
}
IMAGE_FIELDS = {"repository", "version", "indexDigest", "platformDigests", "configDigests"}
TRIVY_FIELDS = {"repository", "version", "manifestDigest", "payloadSha256"}


class Refused(ValueError):
    """The controller cannot safely stage with this repository or lock."""


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise Refused(f"{label}:exact-fields")
    return value


def load_security_gate() -> ModuleType:
    path = Path(__file__).with_name("security_gate.py")
    spec = importlib.util.spec_from_file_location("phase7_security_gate_for_online_stager", path)
    if spec is None or spec.loader is None:
        raise Refused("repository-snapshot:unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(spec.name, None)
        raise Refused("repository-snapshot:unavailable") from exc
    return module


def validate_image(value: object, label: str, status: str) -> dict[str, Any]:
    image = exact(value, IMAGE_FIELDS, label)
    platform_digests = exact(image["platformDigests"], set(PLATFORMS), f"{label}:platform")
    config_digests = exact(image["configDigests"], set(PLATFORMS), f"{label}:config")
    scalars = [image["repository"], image["version"], image["indexDigest"]]
    pins = [*platform_digests.values(), *config_digests.values()]
    if status == "UNFROZEN":
        if any(value is not None for value in [*scalars, *pins]):
            raise Refused(f"{label}:unfrozen-pins")
        return image
    repository, version, index_digest = scalars
    if (
        not isinstance(repository, str)
        or REPOSITORY.fullmatch(repository) is None
        or ":" in repository
        or "@" in repository
        or not isinstance(version, str)
        or VERSION.fullmatch(version) is None
        or version.lower() == "latest"
        or not isinstance(index_digest, str)
        or DIGEST.fullmatch(index_digest) is None
        or any(not isinstance(pin, str) or DIGEST.fullmatch(pin) is None for pin in pins)
    ):
        raise Refused(f"{label}:frozen-pins")
    return image


def validate_lock(lock: object) -> dict[str, Any]:
    item = exact(lock, TOP_FIELDS, "toolchain-lock")
    status = item["status"]
    if (
        type(item["schemaVersion"]) is not int
        or item["schemaVersion"] != 2
        or not isinstance(status, str)
        or status not in {"UNFROZEN", "FROZEN"}
        or item["collectionNetwork"] != "disabled"
        or item["stagingNetwork"] != "default-deny"
        or item["daemonPolicy"] != "isolated-disposable"
        or item["targetPlatforms"] != list(PLATFORMS.values())
    ):
        raise Refused("toolchain-lock:fixed-policy")
    images = exact(item["images"], IMAGE_NAMES, "toolchain-lock:images")
    scanners = exact(item["scanners"], SCANNER_NAMES, "toolchain-lock:scanners")
    for name, value in images.items():
        validate_image(value, f"toolchain-lock:images:{name}", status)
    for name, value in scanners.items():
        validate_image(value, f"toolchain-lock:scanners:{name}", status)
    artifacts = exact(item["trivyArtifacts"], TRIVY_KINDS, "toolchain-lock:trivy")
    for name, value in artifacts.items():
        artifact = exact(value, TRIVY_FIELDS, f"toolchain-lock:trivy:{name}")
        values = list(artifact.values())
        if status == "UNFROZEN":
            if any(value is not None for value in values):
                raise Refused(f"toolchain-lock:trivy:{name}:unfrozen-pins")
        elif (
            not isinstance(artifact["repository"], str)
            or REPOSITORY.fullmatch(artifact["repository"]) is None
            or ":" in artifact["repository"]
            or "@" in artifact["repository"]
            or not isinstance(artifact["version"], str)
            or VERSION.fullmatch(artifact["version"]) is None
            or artifact["version"].lower() == "latest"
            or not isinstance(artifact["manifestDigest"], str)
            or DIGEST.fullmatch(artifact["manifestDigest"]) is None
            or not isinstance(artifact["payloadSha256"], str)
            or SHA256.fullmatch(artifact["payloadSha256"]) is None
        ):
            raise Refused(f"toolchain-lock:trivy:{name}:frozen-pins")
    bootstrap = exact(item["bootstrapBinary"], {"path", "sha256"}, "toolchain-lock:bootstrap")
    policies = exact(
        item["signaturePolicies"],
        {"images", "scanners", "trivyArtifacts"},
        "toolchain-lock:signature-policies",
    )
    policy_groups = {
        "images": exact(
            policies["images"], IMAGE_NAMES, "toolchain-lock:signature-policies:images"
        ),
        "scanners": exact(
            policies["scanners"], SCANNER_NAMES, "toolchain-lock:signature-policies:scanners"
        ),
        "trivyArtifacts": exact(
            policies["trivyArtifacts"], TRIVY_KINDS, "toolchain-lock:signature-policies:trivy"
        ),
    }
    for group, policies_by_name in policy_groups.items():
        for name, value in policies_by_name.items():
            exact(
                value,
                {"issuer", "subject", "rekorRequired"},
                f"toolchain-lock:signature-policy:{group}:{name}",
            )
    origins = exact(item["advisoryOrigins"], {"pip", "npm"}, "toolchain-lock:origins")
    allowlist = item["destinationAllowlist"]
    if not isinstance(allowlist, list) or len(set(map(str, allowlist))) != len(allowlist):
        raise Refused("toolchain-lock:allowlist")
    if status == "UNFROZEN":
        if (
            bootstrap != {"path": None, "sha256": None}
            or any(
                value != {"issuer": None, "subject": None, "rekorRequired": None}
                for values in policy_groups.values()
                for value in values.values()
            )
            or origins != {"pip": None, "npm": None}
            or allowlist
        ):
            raise Refused("toolchain-lock:unfrozen-policy-pins")
        return item
    if (
        bootstrap["path"] != "/usr/bin/docker"
        or not isinstance(bootstrap["sha256"], str)
        or SHA256.fullmatch(bootstrap["sha256"]) is None
        or any(
            not isinstance(value["issuer"], str)
            or not value["issuer"]
            or not isinstance(value["subject"], str)
            or not value["subject"]
            or type(value["rekorRequired"]) is not bool
            or value["rekorRequired"] is not True
            for values in policy_groups.values()
            for value in values.values()
        )
        or any(
            not isinstance(origin, str) or ORIGIN.fullmatch(origin) is None
            for origin in origins.values()
        )
        or any(
            not isinstance(origin, str) or ORIGIN.fullmatch(origin) is None for origin in allowlist
        )
        or set(origins.values()) - set(allowlist)
    ):
        raise Refused("toolchain-lock:frozen-policy-pins")
    required_origins = {
        f"https://{value['repository'].split('/', 1)[0]}:443"
        for value in [*images.values(), *scanners.values(), *artifacts.values()]
    }
    if set(allowlist) != required_origins | set(origins.values()):
        raise Refused("toolchain-lock:destination-projection")
    return item


@dataclass(frozen=True)
class StagingSubject:
    role: str
    requested_reference: str
    platform: str
    platform_digest: str
    config_digest: str


def collection_plan(lock: dict[str, Any], platform: str) -> tuple[StagingSubject, ...]:
    """Describe pinned subjects without producing any executable command."""
    validate_lock(lock)
    if lock["status"] != "FROZEN" or platform not in PLATFORMS:
        raise Refused("collection-plan:not-frozen")
    subjects = []
    for role, image in lock["images"].items():
        subjects.append(
            StagingSubject(
                role=role,
                requested_reference=f"{image['repository']}@{image['indexDigest']}",
                platform=platform,
                platform_digest=image["platformDigests"][platform],
                config_digest=image["configDigests"][platform],
            )
        )
    for scanner, image in lock["scanners"].items():
        subjects.append(
            StagingSubject(
                role=f"scanner-{scanner}",
                requested_reference=f"{image['repository']}@{image['indexDigest']}",
                platform=platform,
                platform_digest=image["platformDigests"][platform],
                config_digest=image["configDigests"][platform],
            )
        )
    return tuple(subjects)


def rename_noreplace(directory_fd: int, source: str, target: str) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise Refused("publication:no-atomic-noreplace")
    if function(directory_fd, os.fsencode(source), directory_fd, os.fsencode(target), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Refused("publication:collision")
        raise OSError(code, os.strerror(code))


def same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def publish(
    parent: Path,
    run_id: str,
    mode: str,
    revision: str | None,
    tree: str | None,
    lock_hash: str,
) -> Path:
    if not parent.is_absolute() or Path(os.path.normpath(str(parent))) != parent:
        raise Refused("output-parent:unsafe")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    staging_name = f".{run_id}.tmp.{secrets.token_hex(12)}"
    staging_fd = -1
    staging_identity: os.stat_result | None = None
    outputs: dict[str, bytes] = {}
    try:
        identity = os.fstat(parent_fd)
        if identity.st_uid != os.getuid() or stat.S_IMODE(identity.st_mode) != 0o700:
            raise Refused("output-parent:unsafe")
        try:
            os.stat(run_id, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise Refused("publication:collision")
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        staging_fd = os.open(
            staging_name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        staging_identity = os.fstat(staging_fd)
        result = {
            "schemaVersion": 1,
            "gateId": "security-online-stager-controller",
            "runId": run_id,
            "mode": mode,
            "status": "INCOMPLETE",
            "preflightValidated": True,
            "toolchainFrozen": False,
            "sourceRevision": revision,
            "gitTreeObject": tree,
            "toolchainLockSha256": lock_hash,
            "reasonCodes": ["TOOLCHAIN_LOCK_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"],
            "readinessAssertionsSatisfied": False,
            "overallReplacementReady": False,
        }
        outputs = {
            "gate-result.json": (
                json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode(),
            "result.status": (
                b"status=INCOMPLETE\n"
                b"preflightValidated=true\n"
                b"toolchainFrozen=false\n"
                b"overallReplacementReady=false\n"
                b"reasonCodes=TOOLCHAIN_LOCK_UNFROZEN,CONTROLLED_COLLECTOR_REQUIRED\n"
            ),
        }
        for name, data in outputs.items():
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400, dir_fd=staging_fd
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fchmod(staging_fd, 0o500)
        os.fsync(staging_fd)
        named_staging = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
        if not same_inode(named_staging, staging_identity):
            raise Refused("publication:staging-name-replaced")
        rename_noreplace(parent_fd, staging_name, run_id)
        published = os.stat(run_id, dir_fd=parent_fd, follow_symlinks=False)
        if not same_inode(published, staging_identity):
            quarantine = f".{run_id}.rejected.{secrets.token_hex(12)}"
            rename_noreplace(parent_fd, run_id, quarantine)
            quarantined = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
            if not same_inode(quarantined, published):
                raise Refused("publication:post-rename-race")
            raise Refused("publication:renamed-inode-mismatch")
        os.fsync(parent_fd)
        os.close(staging_fd)
        staging_fd = -1
        return parent / run_id
    except Exception:
        if staging_fd >= 0:
            os.fchmod(staging_fd, 0o700)
            for name in outputs:
                try:
                    os.unlink(name, dir_fd=staging_fd)
                except FileNotFoundError:
                    pass
            os.close(staging_fd)
        if staging_identity is not None:
            for owned_name in (staging_name, run_id):
                try:
                    named = os.stat(owned_name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if same_inode(named, staging_identity):
                    os.rmdir(owned_name, dir_fd=parent_fd)
        raise
    finally:
        os.close(parent_fd)


def run(
    mode: str,
    run_id: str,
    platform: str,
    output_parent: Path,
    repo: Path,
) -> int:
    if (
        mode not in {"check", "collect"}
        or SAFE_ID.fullmatch(run_id) is None
        or platform not in PLATFORMS
    ):
        return 2
    try:
        gate = load_security_gate()
        if output_parent == repo or output_parent.is_relative_to(repo):
            raise Refused("output-parent:inside-repository")
        snapshot = gate.repository_snapshot(repo)
        lock_bytes = snapshot.pinned_blobs[LOCK_RELATIVE]
        lock = validate_lock(json.loads(lock_bytes))
        if lock["status"] != "UNFROZEN" or not gate.type_exact_equal(lock, gate.TOOLCHAIN_LOCK):
            raise Refused("check-only-controller:frozen-collection-not-implemented")
        output = publish(
            output_parent,
            run_id,
            mode,
            snapshot.provenance["sourceRevision"],
            snapshot.provenance["gitTreeObject"],
            hashlib.sha256(lock_bytes).hexdigest(),
        )
    except (Refused, OSError, json.JSONDecodeError, KeyError, ValueError):
        return 2
    print(output)
    return 3


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "collect"))
    parser.add_argument("run_id")
    parser.add_argument("platform")
    parser.add_argument("output_parent", type=Path)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    return run(args.mode, args.run_id, args.platform, args.output_parent, args.repo)


if __name__ == "__main__":
    raise SystemExit(main())
