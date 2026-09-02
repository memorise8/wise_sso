#!/usr/bin/env python3
"""Validate an untrusted online-stager bundle without executing its contents."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

MANIFEST_NAME = "online-stager-manifest.json"
TOP_FIELDS = {
    "schemaVersion",
    "kind",
    "runId",
    "status",
    "createdAt",
    "expiresAt",
    "sourceRevision",
    "gitTreeObject",
    "toolchainLockSha256",
    "targetPlatform",
    "networkScope",
    "images",
    "trivyArtifacts",
    "advisoryReports",
    "aggregateSha256",
}
BLOB_FIELDS = {"path", "sha256", "sizeBytes"}
PLATFORM_FIELDS = {"os", "architecture", "variant"}
IMAGE_FIELDS = {
    "role",
    "repository",
    "requestedReference",
    "indexDigest",
    "platformDigest",
    "configDigest",
    "archive",
    "signatures",
    "attestations",
    "fetchedAt",
}
SUBJECT_FIELDS = {"status", "subjectDigest", "rawArtifact", "descriptor"}
ATTESTATION_FIELDS = {
    "status",
    "subjectDigest",
    "predicateType",
    "rawArtifact",
    "descriptor",
}
EVIDENCE_FIELDS = {"rawArtifact", "descriptor"}
TRIVY_FIELDS = {
    "kind",
    "repository",
    "manifestDigest",
    "payload",
    "updatedAt",
    "nextUpdateAt",
    "signatures",
    "attestations",
}
ADVISORY_FIELDS = {
    "ecosystem",
    "producer",
    "serviceOrigin",
    "lockSha256",
    "request",
    "response",
    "observedAt",
}
DESTINATION_FIELDS = {"scheme", "host", "port"}
NETWORK_FIELDS = {"mode", "observationStatus", "destinations", "evidence"}
IMAGE_ROLES = {
    "builder",
    "collector",
    "scanner-gitleaks",
    "scanner-npm-audit",
    "scanner-pip-audit",
    "scanner-ruff",
    "scanner-semgrep",
    "scanner-trivy",
}
TRIVY_KINDS = {"vulnerability-db", "java-db", "checks-bundle"}
ECOSYSTEMS = {"pip", "npm"}
PREDICATES = {"https://slsa.dev/provenance/v1", "https://spdx.dev/Document"}
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SAFE_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
REPOSITORY = re.compile(r"[a-z0-9][a-z0-9._/-]{0,254}")
SHA256 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40,64}")
RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z")
MAX_FILE_SIZE = 268435456
MAX_TOTAL_SIZE = 536870912
LOCK_RELATIVE = "fastapi-auth-server/ops/phase7/security/controlled-toolchain-lock.json"
ALLOWED_REASONS = {
    "TOOLCHAIN_LOCK_UNFROZEN",
    "CONTROLLED_COLLECTOR_REQUIRED",
    "MISSING_EVIDENCE",
    "UNSAFE_INPUT",
    "MALFORMED_INPUT",
    "PUBLICATION_REFUSED",
}


class Incomplete(ValueError):
    """The staged bundle is absent or incomplete."""


class Failed(ValueError):
    """The staged bundle is unsafe or malformed."""


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise Failed(f"{label}:exact-fields")
    return value


def timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise Failed(f"{label}:timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Failed(f"{label}:timestamp") from exc
    if parsed.tzinfo is None:
        raise Failed(f"{label}:timestamp")
    return parsed


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_exact_json(data: bytes, fields: set[str], label: str) -> dict[str, Any]:
    try:
        return exact(json.loads(data), fields, label)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Failed(f"{label}:json") from exc


def type_exact_equal(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return set(actual) == set(expected) and all(
            type_exact_equal(actual[key], value) for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list):
            return False
        return len(actual) == len(expected) and all(
            type_exact_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    return actual == expected


def load_security_gate() -> ModuleType:
    path = Path(__file__).with_name("security_gate.py")
    spec = importlib.util.spec_from_file_location("phase7_security_gate_for_stager", path)
    if spec is None or spec.loader is None:
        raise Failed("repository-snapshot:unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(spec.name, None)
        raise Failed("repository-snapshot:unavailable") from exc
    return module


def regular_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise Incomplete(f"missing:{path.name}") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size < 1
        or before.st_size > MAX_FILE_SIZE
    ):
        raise Failed(f"artifact:unsafe:{path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise Failed(f"artifact:changed:{path.name}")
        chunks: list[bytes] = []
        remaining = MAX_FILE_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(1048576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) != before.st_size or (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
        after.st_uid,
        stat.S_IMODE(after.st_mode),
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
        before.st_uid,
        stat.S_IMODE(before.st_mode),
    ):
        raise Failed(f"artifact:changed:{path.name}")
    return data


def blob(value: object, label: str, paths: dict[str, tuple[str, int]]) -> dict[str, Any]:
    item = exact(value, BLOB_FIELDS, label)
    path = item["path"]
    digest = item["sha256"]
    size = item["sizeBytes"]
    if (
        not isinstance(path, str)
        or SAFE_PATH.fullmatch(path) is None
        or path == MANIFEST_NAME
        or not isinstance(digest, str)
        or SHA256.fullmatch(digest) is None
        or type(size) is not int
        or not 1 <= size <= MAX_FILE_SIZE
        or path in paths
    ):
        raise Failed(f"{label}:blob")
    paths[path] = (digest, size)
    return item


def destination(value: object, label: str) -> tuple[str, int]:
    item = exact(value, DESTINATION_FIELDS, label)
    if (
        item["scheme"] != "https"
        or type(item["port"]) is not int
        or item["port"] != 443
        or not isinstance(item["host"], str)
        or HOST.fullmatch(item["host"]) is None
        or item["host"].startswith(".")
        or ".." in item["host"]
    ):
        raise Failed(f"{label}:https-443")
    return item["host"], item["port"]


def validate_manifest(
    raw: bytes, source: Path, run_id: str, repo: Path, now: dt.datetime
) -> dict[str, Any]:
    try:
        manifest = exact(json.loads(raw), TOP_FIELDS, "manifest")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Failed("manifest:json") from exc
    if (
        type(manifest["schemaVersion"]) is not int
        or manifest["schemaVersion"] != 1
        or manifest["kind"] != "phase7-online-stager-manifest"
        or manifest["runId"] != run_id
        or manifest["status"] != "STAGED_UNVERIFIED"
        or SAFE_ID.fullmatch(run_id) is None
        or not isinstance(manifest["sourceRevision"], str)
        or REVISION.fullmatch(manifest["sourceRevision"]) is None
        or not isinstance(manifest["gitTreeObject"], str)
        or REVISION.fullmatch(manifest["gitTreeObject"]) is None
        or not isinstance(manifest["toolchainLockSha256"], str)
        or SHA256.fullmatch(manifest["toolchainLockSha256"]) is None
        or not isinstance(manifest["aggregateSha256"], str)
        or SHA256.fullmatch(manifest["aggregateSha256"]) is None
    ):
        raise Failed("manifest:identity")
    created = timestamp(manifest["createdAt"], "createdAt")
    expires = timestamp(manifest["expiresAt"], "expiresAt")
    if created > now + dt.timedelta(minutes=5) or now - created > dt.timedelta(hours=24):
        raise Failed("manifest:stale")
    if expires <= now or expires <= created or expires - created > dt.timedelta(hours=24):
        raise Failed("manifest:expired-or-overlong")
    platform = exact(manifest["targetPlatform"], PLATFORM_FIELDS, "targetPlatform")
    expected_variant = None if platform["architecture"] == "amd64" else "v8"
    if (
        platform["os"] != "linux"
        or not isinstance(platform["architecture"], str)
        or platform["architecture"] not in {"amd64", "arm64"}
        or platform["variant"] != expected_variant
    ):
        raise Failed("targetPlatform:unsupported")

    security_gate = load_security_gate()
    snapshot = security_gate.repository_snapshot(repo)
    provenance = snapshot.provenance
    if (
        manifest["sourceRevision"] != provenance["sourceRevision"]
        or manifest["gitTreeObject"] != provenance["gitTreeObject"]
    ):
        raise Failed("manifest:repository-mismatch")
    lock_bytes = snapshot.pinned_blobs[LOCK_RELATIVE]
    try:
        lock = json.loads(lock_bytes)
    except json.JSONDecodeError as exc:
        raise Failed("toolchain-lock:json") from exc
    if (
        manifest["toolchainLockSha256"] != hash_bytes(lock_bytes)
        or not isinstance(lock, dict)
        or lock != security_gate.TOOLCHAIN_LOCK
    ):
        raise Failed("toolchain-lock:binding")

    paths: dict[str, tuple[str, int]] = {}
    payload_contracts: list[tuple[str, dict[str, object]]] = []
    network = exact(manifest["networkScope"], NETWORK_FIELDS, "networkScope")
    if (
        network["mode"] != "default-deny"
        or network["observationStatus"] != "STAGED_UNVERIFIED"
        or not isinstance(network["destinations"], list)
    ):
        raise Failed("networkScope:default-deny")
    declared = [destination(item, "networkScope.destination") for item in network["destinations"]]
    if not declared or len(set(declared)) != len(declared) or len(declared) > 16:
        raise Failed("networkScope:destinations")
    network_evidence = exact(network["evidence"], EVIDENCE_FIELDS, "networkScope.evidence")
    network_raw = blob(network_evidence["rawArtifact"], "networkScope.evidence.rawArtifact", paths)
    network_descriptor = blob(
        network_evidence["descriptor"], "networkScope.evidence.descriptor", paths
    )
    payload_contracts.append(
        (
            network_descriptor["path"],
            {
                "schemaVersion": 1,
                "kind": "network-observation",
                "status": "STAGED_UNVERIFIED",
                "defaultDeny": True,
                "destinations": network["destinations"],
                "rawArtifactSha256": network_raw["sha256"],
            },
        )
    )

    if not isinstance(manifest["images"], list) or len(manifest["images"]) != len(IMAGE_ROLES):
        raise Failed("images:count")
    roles: set[str] = set()
    for value in manifest["images"]:
        image = exact(value, IMAGE_FIELDS, "image")
        role, image_digest = image["role"], image["indexDigest"]
        if (
            not isinstance(role, str)
            or role not in IMAGE_ROLES
            or role in roles
            or not isinstance(image_digest, str)
            or DIGEST.fullmatch(image_digest) is None
            or not isinstance(image["platformDigest"], str)
            or DIGEST.fullmatch(image["platformDigest"]) is None
            or not isinstance(image["configDigest"], str)
            or DIGEST.fullmatch(image["configDigest"]) is None
            or not isinstance(image["repository"], str)
            or REPOSITORY.fullmatch(image["repository"]) is None
            or image["requestedReference"] != f"{image['repository']}@{image_digest}"
        ):
            raise Failed("image:role-or-digest")
        roles.add(role)
        repository_host = image["repository"].split("/", 1)[0]
        if HOST.fullmatch(repository_host) is None or (repository_host, 443) not in declared:
            raise Failed("image:undeclared-registry")
        fetched = timestamp(image["fetchedAt"], "image.fetchedAt")
        if fetched > now + dt.timedelta(minutes=5) or now - fetched > dt.timedelta(hours=24):
            raise Failed("image:stale")
        archive = blob(image["archive"], "image.archive", paths)
        for field, exact_fields in (
            ("signatures", SUBJECT_FIELDS),
            ("attestations", ATTESTATION_FIELDS),
        ):
            values = image[field]
            if not isinstance(values, list) or not values:
                raise Failed(f"image.{field}:empty")
            predicates: set[str] = set()
            for value2 in values:
                subject = exact(value2, exact_fields, f"image.{field}")
                if subject["status"] != "UNVERIFIED" or subject["subjectDigest"] != image_digest:
                    raise Failed(f"image.{field}:subject")
                if field == "attestations":
                    predicate = subject["predicateType"]
                    if (
                        not isinstance(predicate, str)
                        or predicate not in PREDICATES
                        or predicate in predicates
                    ):
                        raise Failed("image.attestations:predicate")
                    predicates.add(predicate)
                raw_artifact = blob(subject["rawArtifact"], f"image.{field}.rawArtifact", paths)
                descriptor = blob(subject["descriptor"], f"image.{field}.descriptor", paths)
                contract: dict[str, object] = {
                    "schemaVersion": 1,
                    "kind": "signature" if field == "signatures" else "attestation",
                    "status": "UNVERIFIED",
                    "repository": image["repository"],
                    "subjectDigest": image_digest,
                    "rawArtifactSha256": raw_artifact["sha256"],
                }
                if field == "attestations":
                    contract["predicateType"] = subject["predicateType"]
                    contract.update(
                        {
                            "role": role,
                            "archiveSha256": archive["sha256"],
                            "platformDigest": image["platformDigest"],
                            "configDigest": image["configDigest"],
                            "targetPlatform": manifest["targetPlatform"],
                        }
                    )
                payload_contracts.append((descriptor["path"], contract))
    if roles != IMAGE_ROLES:
        raise Failed("images:roles")

    if not isinstance(manifest["trivyArtifacts"], list) or len(manifest["trivyArtifacts"]) != 3:
        raise Failed("trivyArtifacts:count")
    trivy_kinds: set[str] = set()
    for value in manifest["trivyArtifacts"]:
        item = exact(value, TRIVY_FIELDS, "trivyArtifact")
        if (
            not isinstance(item["kind"], str)
            or item["kind"] not in TRIVY_KINDS
            or item["kind"] in trivy_kinds
        ):
            raise Failed("trivyArtifact:kind")
        trivy_kinds.add(item["kind"])
        updated = timestamp(item["updatedAt"], "trivyArtifact.updatedAt")
        next_update = timestamp(item["nextUpdateAt"], "trivyArtifact.nextUpdateAt")
        if (
            updated > now + dt.timedelta(minutes=5)
            or now - updated > dt.timedelta(hours=24)
            or next_update <= now
            or next_update <= updated
        ):
            raise Failed("trivyArtifact:stale")
        if (
            not isinstance(item["repository"], str)
            or REPOSITORY.fullmatch(item["repository"]) is None
            or not isinstance(item["manifestDigest"], str)
            or DIGEST.fullmatch(item["manifestDigest"]) is None
        ):
            raise Failed("trivyArtifact:repository-or-digest")
        repository_host = item["repository"].split("/", 1)[0]
        if HOST.fullmatch(repository_host) is None or (repository_host, 443) not in declared:
            raise Failed("trivyArtifact:undeclared-registry")
        payload = blob(item["payload"], "trivyArtifact.payload", paths)
        for field, exact_fields in (
            ("signatures", SUBJECT_FIELDS),
            ("attestations", ATTESTATION_FIELDS),
        ):
            values = item[field]
            if not isinstance(values, list) or not values:
                raise Failed(f"trivyArtifact.{field}:empty")
            for value2 in values:
                subject = exact(value2, exact_fields, f"trivyArtifact.{field}")
                if (
                    subject["status"] != "UNVERIFIED"
                    or subject["subjectDigest"] != item["manifestDigest"]
                ):
                    raise Failed(f"trivyArtifact.{field}:subject")
                contract = {
                    "schemaVersion": 1,
                    "kind": "signature" if field == "signatures" else "attestation",
                    "status": "UNVERIFIED",
                    "repository": item["repository"],
                    "subjectDigest": item["manifestDigest"],
                }
                if field == "attestations":
                    predicate = subject["predicateType"]
                    if not isinstance(predicate, str) or predicate not in PREDICATES:
                        raise Failed("trivyArtifact.attestations:predicate")
                    contract["predicateType"] = predicate
                    contract.update(
                        {
                            "artifactKind": item["kind"],
                            "payloadSha256": payload["sha256"],
                            "updatedAt": item["updatedAt"],
                            "nextUpdateAt": item["nextUpdateAt"],
                        }
                    )
                raw_artifact = blob(
                    subject["rawArtifact"], f"trivyArtifact.{field}.rawArtifact", paths
                )
                descriptor = blob(subject["descriptor"], f"trivyArtifact.{field}.descriptor", paths)
                contract["rawArtifactSha256"] = raw_artifact["sha256"]
                payload_contracts.append((descriptor["path"], contract))
    if trivy_kinds != TRIVY_KINDS:
        raise Failed("trivyArtifacts:kinds")

    if not isinstance(manifest["advisoryReports"], list) or len(manifest["advisoryReports"]) != 2:
        raise Failed("advisoryReports:count")
    ecosystems: set[str] = set()
    for value in manifest["advisoryReports"]:
        item = exact(value, ADVISORY_FIELDS, "advisoryReport")
        ecosystem = item["ecosystem"]
        if not isinstance(ecosystem, str) or ecosystem not in ECOSYSTEMS or ecosystem in ecosystems:
            raise Failed("advisoryReport:ecosystem")
        ecosystems.add(ecosystem)
        producer = "pip-audit" if ecosystem == "pip" else "npm-audit"
        if item["producer"] != producer:
            raise Failed("advisoryReport:producer")
        if not isinstance(item["serviceOrigin"], str):
            raise Failed("advisoryReport:origin")
        origin = item["serviceOrigin"]
        if not origin.startswith("https://") or not origin.endswith(":443"):
            raise Failed("advisoryReport:origin")
        host = origin[len("https://") : -len(":443")]
        if (host, 443) not in declared:
            raise Failed("advisoryReport:undeclared-destination")
        if not isinstance(item["lockSha256"], str) or SHA256.fullmatch(item["lockSha256"]) is None:
            raise Failed("advisoryReport:lock")
        expected_lock = (
            provenance["fastapiLockSha256"]
            if ecosystem == "pip"
            else provenance["expressLockSha256"]
        )
        if item["lockSha256"] != expected_lock:
            raise Failed("advisoryReport:lock-binding")
        observed = timestamp(item["observedAt"], "advisoryReport.observedAt")
        if observed > now + dt.timedelta(minutes=5) or now - observed > dt.timedelta(hours=24):
            raise Failed("advisoryReport:stale")
        request = exact(item["request"], EVIDENCE_FIELDS, "advisoryReport.request")
        response = exact(item["response"], EVIDENCE_FIELDS, "advisoryReport.response")
        request_raw = blob(request["rawArtifact"], "advisoryReport.request.rawArtifact", paths)
        request_descriptor = blob(request["descriptor"], "advisoryReport.request.descriptor", paths)
        response_raw = blob(response["rawArtifact"], "advisoryReport.response.rawArtifact", paths)
        response_descriptor = blob(
            response["descriptor"], "advisoryReport.response.descriptor", paths
        )
        request_contract = {
            "schemaVersion": 1,
            "kind": "advisory-request",
            "ecosystem": ecosystem,
            "producer": producer,
            "serviceOrigin": origin,
            "lockSha256": expected_lock,
            "rawArtifactSha256": request_raw["sha256"],
        }
        response_contract = {
            "schemaVersion": 1,
            "kind": "advisory-response",
            "status": "STAGED_UNVERIFIED",
            "ecosystem": ecosystem,
            "producer": producer,
            "serviceOrigin": origin,
            "lockSha256": expected_lock,
            "requestRawArtifactSha256": request_raw["sha256"],
            "responseRawArtifactSha256": response_raw["sha256"],
            "observedAt": item["observedAt"],
        }
        payload_contracts.extend(
            [
                (request_descriptor["path"], request_contract),
                (response_descriptor["path"], response_contract),
            ]
        )
    if ecosystems != ECOSYSTEMS:
        raise Failed("advisoryReports:ecosystems")

    expected_names = set(paths) | {MANIFEST_NAME}
    actual_names = {entry.name for entry in source.iterdir()}
    if actual_names - expected_names:
        raise Failed("input-directory:unexpected-files")
    if expected_names - actual_names:
        raise Incomplete("missing:" + ",".join(sorted(expected_names - actual_names)))
    if sum(size for _, size in paths.values()) > MAX_TOTAL_SIZE:
        raise Failed("artifacts:total-size")
    verified: dict[str, bytes] = {}
    for path, (expected_hash, expected_size) in paths.items():
        data = regular_bytes(source / path)
        if len(data) != expected_size or hash_bytes(data) != expected_hash:
            raise Failed(f"artifact:hash-or-size:{path}")
        verified[path] = data
    for path, expected in payload_contracts:
        actual = load_exact_json(verified[path], set(expected), f"artifact-payload:{path}")
        if not type_exact_equal(actual, expected):
            raise Failed(f"artifact-payload:binding:{path}")
    aggregate = hash_bytes(
        b"".join(
            f"{path}\0{digest}\0{size}\n".encode() for path, (digest, size) in sorted(paths.items())
        )
    )
    if manifest["aggregateSha256"] != aggregate:
        raise Failed("manifest:aggregate")
    return manifest


def fsync_path(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if path.is_dir() else 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_noreplace(source: Path, target: Path) -> None:
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise Failed("publication:no-atomic-noreplace")
    if function(-100, os.fsencode(source), -100, os.fsencode(target), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Failed("evidence:collision")
        raise OSError(code, os.strerror(code))


def publish(
    evidence_root: Path, run_id: str, status: str, reasons: list[str], validated: bool
) -> Path:
    if (
        status not in {"INCOMPLETE", "FAIL"}
        or not reasons
        or any(reason not in ALLOWED_REASONS for reason in reasons)
    ):
        raise Failed("publication:status-or-reason")
    created = not evidence_root.exists()
    evidence_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if (
        evidence_root.is_symlink()
        or evidence_root.resolve() != evidence_root
        or stat.S_IMODE(evidence_root.stat().st_mode) != 0o700
    ):
        raise Failed("evidence-root:unsafe")
    if created:
        fsync_path(evidence_root.parent)
    target = evidence_root / run_id
    if target.exists() or target.is_symlink():
        raise Failed("evidence:collision")
    staging = Path(tempfile.mkdtemp(prefix=f".{run_id}.tmp.", dir=evidence_root))
    try:
        result = {
            "schemaVersion": 1,
            "gateId": "security-stager-intake",
            "runId": run_id,
            "status": status,
            "intakeValidated": validated,
            "sampleSatisfied": False,
            "readinessAssertionsSatisfied": False,
            "overallReplacementReady": False,
        }
        outputs = {
            "gate-result.json": (
                json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode(),
            "result.status": (
                f"status={status}\nintakeValidated={str(validated).lower()}\n"
                f"overallReplacementReady=false\nreasonCodes={','.join(reasons)}\n"
            ).encode(),
        }
        for name, data in outputs.items():
            path = staging / name
            path.write_bytes(data)
            os.chmod(path, 0o400)
            fsync_path(path)
        os.chmod(staging, 0o500)
        fsync_path(staging)
        rename_noreplace(staging, target)
        fsync_path(evidence_root)
        return target
    except Exception:
        if staging.exists():
            os.chmod(staging, 0o700)
            for entry in staging.iterdir():
                if entry.is_file() and not entry.is_symlink():
                    os.chmod(entry, 0o600)
            shutil.rmtree(staging)
        raise


def reason_code(error: BaseException) -> str:
    if isinstance(error, Incomplete):
        return "MISSING_EVIDENCE"
    if any(token in str(error) for token in ("unsafe", "changed", "hardlink", "symlink")):
        return "UNSAFE_INPUT"
    return "MALFORMED_INPUT"


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    if SAFE_ID.fullmatch(args.run_id) is None:
        print("security stager intake refused: unsafe run id", file=sys.stderr)
        return 2
    status, reasons, validated = "FAIL", ["MALFORMED_INPUT"], False
    try:
        source = args.input
        if not source.exists():
            raise Incomplete("missing:input-directory")
        if (
            not source.is_absolute()
            or source.resolve() != source
            or source.is_symlink()
            or not source.is_dir()
            or source.stat().st_uid != os.getuid()
            or stat.S_IMODE(source.stat().st_mode) != 0o700
        ):
            raise Failed("input-directory:unsafe")
        identity = source.stat()
        manifest_bytes = regular_bytes(source / MANIFEST_NAME)
        validate_manifest(manifest_bytes, source, args.run_id, args.repo, dt.datetime.now(dt.UTC))
        after = source.stat()
        if (identity.st_dev, identity.st_ino, identity.st_mtime_ns, identity.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise Failed("input-directory:changed")
        status = "INCOMPLETE"
        reasons = ["TOOLCHAIN_LOCK_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"]
        validated = True
    except (Incomplete, Failed, OSError) as exc:
        status = "INCOMPLETE" if isinstance(exc, Incomplete) else "FAIL"
        reasons = [reason_code(exc)]
    except Exception:
        status, reasons = "FAIL", ["MALFORMED_INPUT"]
    try:
        output = publish(args.evidence_root.absolute(), args.run_id, status, reasons, validated)
    except (Failed, OSError) as exc:
        print(f"security stager intake publication refused: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 3 if status == "INCOMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
