#!/usr/bin/env python3
"""Validate and safely publish a Phase 7 backup/restore controller result."""

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
import sys
import tempfile
from pathlib import Path
from typing import Any

INPUT_NAME = "backup-restore-evidence.json"
PROVENANCE_NAME = "provenance.json"
ATTESTATION_NAME = "collector-attestation.json"
EXPECTED_INPUTS = {INPUT_NAME, PROVENANCE_NAME, ATTESTATION_NAME}
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SAFE_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40,64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
TEST_DATABASE = re.compile(r"[a-z][a-z0-9_]{2,62}_test_[a-z0-9_]{1,48}")
FORBIDDEN_DB_WORDS = re.compile(r"(?:^|_)(?:prod|production|live|primary)(?:_|$)", re.I)
URL = re.compile(r"(?:https?|postgres(?:ql)?|redis)://", re.I)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
TOKEN = re.compile(
    r"\b(?:Bearer\s+|eyJ[A-Za-z0-9_-]*\.|ghp_|github_pat_|glpat-|xox[baprs]-|sk_(?:live|test)_)",
    re.I,
)
SECRET_VALUE = re.compile(
    r"(?:password|secret|token|authorization|private.?key|raw.?key)\s*[:=]", re.I
)
SENSITIVE_KEYS = {
    "accesstoken",
    "refreshtoken",
    "password",
    "secret",
    "clientsecret",
    "authorization",
    "databaseurl",
    "rawkey",
    "privatekey",
}
ENCRYPTION_ALGORITHM = "AES-256-GCM"
MAX_PLAINTEXT_BYTES = 67108864
KEY_OWNER = "phase7-local-qualification-runner"
KEY_REFERENCE_TEMPLATE = "urn:wiseacct:phase7:backup-restore:ephemeral:{runId}"
POLICY: dict[str, object] = {
    "encryptionAlgorithm": ENCRYPTION_ALGORITHM,
    "keyOwner": KEY_OWNER,
    "keyReferenceTemplate": KEY_REFERENCE_TEMPLATE,
    "maxArtifactRetentionSeconds": None,
    "maxPlaintextBytes": MAX_PLAINTEXT_BYTES,
    "redisDisposition": "ephemeral-not-backed-up",
    "rpoSeconds": None,
    "rtoSeconds": None,
    "schemaVersion": 1,
    "sourceScope": "synthetic-only",
    "status": "UNFROZEN",
}
TOP_FIELDS = {
    "schemaVersion",
    "gateId",
    "runId",
    "collector",
    "policySha256",
    "source",
    "restore",
    "tools",
    "encryptedArtifact",
    "plaintext",
    "timing",
    "verification",
    "fastapiSmoke",
    "expressInvariance",
    "accessAndRetention",
    "cleanup",
}
DATABASE_PROVENANCE_FIELDS = {
    "schemaVersion",
    "databaseName",
    "databaseFingerprint",
    "syntheticOnly",
    "productionData",
}
REQUIRED_TABLES = {
    "User",
    "PasswordCredential",
    "PendingPasswordCredential",
    "SubjectReservation",
    "SocialAccount",
    "RefreshToken",
    "EmailVerificationToken",
    "PasswordResetToken",
    "AuditLog",
    "Role",
    "UserRole",
}
REQUIRED_SMOKE = {"health", "user-read", "session-read", "role-read"}
ALLOWED_REASONS = {
    "CONTROLLED_COLLECTOR_REQUIRED",
    "POLICY_UNFROZEN",
    "MISSING_EVIDENCE",
    "UNSAFE_INPUT",
    "MALFORMED_INPUT",
    "POLICY_VIOLATION",
    "PUBLICATION_REFUSED",
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
ATTESTATION_FIELDS = {
    "schemaVersion",
    "collectorId",
    "collectorRevision",
    "collectorTreeObject",
    "expressImageId",
    "fastapiImageId",
    "status",
}
FIXTURE_FIELDS = {"schemaVersion", "fixtureId", "sentinels"}
SENTINEL_FIELDS = {"id", "table", "recordId", "count", "digest"}
SENTINEL_PROOF_FIELDS = {
    "id",
    "table",
    "sourceCount",
    "restoreCount",
    "sourceDigest",
    "restoreDigest",
}


class Incomplete(ValueError):
    """Required evidence is absent."""


class Failed(ValueError):
    """Evidence is unsafe, malformed, inconsistent, or violates policy."""


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise Failed(f"{label}:exact-fields")
    return value


def timestamp(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Failed(f"{label}:timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Failed(f"{label}:timestamp") from exc
    if parsed.tzinfo is None:
        raise Failed(f"{label}:timestamp")
    return parsed


def sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise Failed(f"{label}:sha256")
    return value


def safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_WORD.fullmatch(value) is None:
        raise Failed(f"{label}:unsafe-text")
    if (
        URL.search(value)
        or EMAIL.search(value)
        or TOKEN.search(value)
        or SECRET_VALUE.search(value)
    ):
        raise Failed(f"{label}:secret-or-url")
    return value


def scan(value: object, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in SENSITIVE_KEYS and child not in (None, "", False):
                raise Failed(f"secret-material:{label}")
            scan(child, label)
    elif isinstance(value, list):
        for child in value:
            scan(child, label)
    elif isinstance(value, str) and (
        URL.search(value)
        or EMAIL.search(value)
        or TOKEN.search(value)
        or SECRET_VALUE.search(value)
    ):
        raise Failed(f"secret-material:{label}")


def load_json(data: bytes, label: str) -> Any:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Failed(f"{label}:json") from exc
    scan(value, label)
    return value


def regular_bytes(path: Path, expected_mode: int = 0o600) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise Incomplete(f"missing:{path.name}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
    ):
        raise Failed(f"unsafe-file:{path.name}")
    if stat.S_IMODE(before.st_mode) != expected_mode:
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
        chunks: list[bytes] = []
        remaining = 4 * 1024 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise Failed(f"changed-input:{path.name}")
        if len(data) > 4 * 1024 * 1024 or len(data) != before.st_size:
            raise Failed(f"{path.name}:size")
        return data
    finally:
        os.close(descriptor)


def snapshot_inputs(source: Path, target: Path) -> None:
    if not source.is_absolute():
        raise Failed("input:absolute-required")
    try:
        source_stat = source.lstat()
    except OSError as exc:
        raise Incomplete("missing:input-directory") from exc
    if (
        stat.S_ISLNK(source_stat.st_mode)
        or not stat.S_ISDIR(source_stat.st_mode)
        or source.resolve() != source
        or source_stat.st_uid != os.getuid()
        or stat.S_IMODE(source_stat.st_mode) != 0o700
    ):
        raise Failed("input-directory:unsafe")
    names = {entry.name for entry in source.iterdir()}
    unexpected = names - EXPECTED_INPUTS
    if unexpected:
        raise Failed("input-directory:unexpected-files")
    missing = EXPECTED_INPUTS - names
    if missing:
        raise Incomplete("missing:evidence")
    for name in sorted(EXPECTED_INPUTS):
        data = regular_bytes(source / name)
        destination = target / name
        destination.write_bytes(data)
        os.chmod(destination, 0o600)
    after = source.lstat()
    stable = ("st_dev", "st_ino", "st_uid", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(source_stat, field) != getattr(after, field) for field in stable):
        raise Failed("input-directory:changed-input")


def validate_provenance(value: object, label: str) -> dict[str, Any]:
    item = exact(value, DATABASE_PROVENANCE_FIELDS, label)
    if (
        item["schemaVersion"] != 2
        or item["syntheticOnly"] is not True
        or item["productionData"] is not False
    ):
        raise Failed(f"{label}:synthetic-policy")
    name = item["databaseName"]
    if (
        not isinstance(name, str)
        or TEST_DATABASE.fullmatch(name) is None
        or len(name.encode("ascii")) > 63
        or FORBIDDEN_DB_WORDS.search(name)
    ):
        raise Failed(f"{label}:test-database-required")
    sha(item["databaseFingerprint"], f"{label}:fingerprint")
    return item


def validate_tool(value: object, expected_name: str) -> None:
    tool = exact(value, {"name", "version", "executableSha256"}, expected_name)
    if (
        tool["name"] != expected_name
        or not isinstance(tool["version"], str)
        or VERSION.fullmatch(tool["version"]) is None
    ):
        raise Failed(f"tool:{expected_name}:identity")
    sha(tool["executableSha256"], f"tool:{expected_name}")


def validate_timing(value: object) -> None:
    fields = {
        "backupStartedAt",
        "backupEndedAt",
        "backupDurationMs",
        "restoreStartedAt",
        "restoreEndedAt",
        "restoreDurationMs",
        "rpoSeconds",
        "rtoSeconds",
    }
    timing = exact(value, fields, "timing")
    backup_start = timestamp(timing["backupStartedAt"], "backup-start")
    backup_end = timestamp(timing["backupEndedAt"], "backup-end")
    restore_start = timestamp(timing["restoreStartedAt"], "restore-start")
    restore_end = timestamp(timing["restoreEndedAt"], "restore-end")
    for key in ("backupDurationMs", "restoreDurationMs", "rpoSeconds", "rtoSeconds"):
        if not isinstance(timing[key], int) or isinstance(timing[key], bool) or timing[key] < 0:
            raise Failed(f"timing:{key}")
    if backup_end > restore_start or backup_start > backup_end or restore_start > restore_end:
        raise Failed("timing:order")
    expected_backup = round((backup_end - backup_start).total_seconds() * 1000)
    expected_restore = round((restore_end - restore_start).total_seconds() * 1000)
    if (
        timing["backupDurationMs"] != expected_backup
        or timing["restoreDurationMs"] != expected_restore
    ):
        raise Failed("timing:duration-mismatch")


def validate_attachments(
    provenance_data: bytes,
    attestation_data: bytes,
    run_id: str,
    document: dict[str, Any],
) -> None:
    provenance = exact(load_json(provenance_data, PROVENANCE_NAME), PROVENANCE_FIELDS, "provenance")
    attestation = exact(
        load_json(attestation_data, ATTESTATION_NAME), ATTESTATION_FIELDS, "collector-attestation"
    )
    if (
        provenance["schemaVersion"] != 2
        or provenance["gateId"] != "backup-restore"
        or provenance["topology"] != "backup-restore-disposable-v1"
        or provenance["runId"] != run_id
    ):
        raise Failed("provenance:identity")
    for field in ("sourceRevision", "gitTreeObject"):
        if not isinstance(provenance[field], str) or REVISION.fullmatch(provenance[field]) is None:
            raise Failed(f"provenance:{field}")
    for field in (
        "expressApplicationTreeSha256",
        "fastapiApplicationTreeSha256",
        "schemaSha256",
        "expressLockSha256",
        "fastapiLockSha256",
        "configSha256",
        "collectorAttestationSha256",
    ):
        sha(provenance[field], f"provenance:{field}")
    for field in ("expressImageId", "fastapiImageId"):
        if not isinstance(provenance[field], str) or IMAGE_ID.fullmatch(provenance[field]) is None:
            raise Failed(f"provenance:{field}")
    if (
        attestation["schemaVersion"] != 1
        or attestation["status"] != "UNVERIFIED"
        or not isinstance(attestation["collectorId"], str)
        or SAFE_ID.fullmatch(attestation["collectorId"]) is None
        or attestation["collectorId"] != document["collector"]["identity"]
    ):
        raise Failed("collector-attestation:identity")
    for field in ("collectorRevision", "collectorTreeObject"):
        if (
            not isinstance(attestation[field], str)
            or REVISION.fullmatch(attestation[field]) is None
        ):
            raise Failed(f"collector-attestation:{field}")
    for field in ("expressImageId", "fastapiImageId"):
        if (
            not isinstance(attestation[field], str)
            or IMAGE_ID.fullmatch(attestation[field]) is None
            or attestation[field] != provenance[field]
        ):
            raise Failed(f"collector-attestation:{field}:provenance-mismatch")
    if provenance["collectorAttestationSha256"] != hashlib.sha256(attestation_data).hexdigest():
        raise Failed("collector-attestation:hash-mismatch")
    express = exact(document["expressInvariance"], {"before", "after"}, "express-invariance")
    before = exact(
        express["before"],
        {"containerId", "imageId", "state", "restartCount", "startedAt"},
        "express-before",
    )
    if before["imageId"] != provenance["expressImageId"]:
        raise Failed("provenance:express-image-mismatch")


def validate_fixture_manifest(data: bytes) -> tuple[str, dict[str, dict[str, Any]]]:
    manifest = exact(load_json(data, "fixture-manifest"), FIXTURE_FIELDS, "fixture-manifest")
    if (
        manifest["schemaVersion"] != 1
        or manifest["fixtureId"] != "phase7-backup-restore-synthetic-v1"
    ):
        raise Failed("fixture-manifest:identity")
    raw_sentinels = manifest["sentinels"]
    if not isinstance(raw_sentinels, list) or len(raw_sentinels) != 4:
        raise Failed("fixture-manifest:sentinels")
    sentinels: dict[str, dict[str, Any]] = {}
    for raw in raw_sentinels:
        sentinel = exact(raw, SENTINEL_FIELDS, "fixture-sentinel")
        identifier = sentinel["id"]
        if (
            identifier not in {"user", "credential", "role", "session"}
            or identifier in sentinels
            or sentinel["table"] not in REQUIRED_TABLES
            or not isinstance(sentinel["count"], int)
            or isinstance(sentinel["count"], bool)
            or sentinel["count"] <= 0
        ):
            raise Failed("fixture-manifest:sentinels")
        record_id = safe_text(sentinel["recordId"], "fixture-sentinel:record-id")
        expected_digest = hashlib.sha256(
            canonical({"table": sentinel["table"], "recordId": record_id})
        ).hexdigest()
        if sha(sentinel["digest"], "fixture-sentinel:digest") != expected_digest:
            raise Failed("fixture-manifest:sentinel-digest")
        sentinels[identifier] = sentinel
    expected_tables = {
        "user": "User",
        "credential": "PasswordCredential",
        "role": "Role",
        "session": "RefreshToken",
    }
    if {identifier: item["table"] for identifier, item in sentinels.items()} != expected_tables:
        raise Failed("fixture-manifest:sentinels")
    return hashlib.sha256(data).hexdigest(), sentinels


def validate_verification(
    value: object, fixture_hash: str, fixture_sentinels: dict[str, dict[str, Any]]
) -> None:
    verification = exact(
        value,
        {"schemaCatalog", "rowCounts", "coreAuthState", "fixtureManifestSha256", "sentinels"},
        "verification",
    )
    if sha(verification["fixtureManifestSha256"], "fixture-manifest") != fixture_hash:
        raise Failed("verification:fixture-manifest-hash")
    catalog = exact(
        verification["schemaCatalog"], {"status", "sourceSha256", "restoreSha256"}, "schema-catalog"
    )
    if catalog["status"] != "PASS" or sha(catalog["sourceSha256"], "schema-source") != sha(
        catalog["restoreSha256"], "schema-restore"
    ):
        raise Failed("verification:schema-catalog")
    rows = verification["rowCounts"]
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_TABLES):
        raise Failed("verification:row-count-set")
    seen: set[str] = set()
    row_counts: dict[str, int] = {}
    for raw in rows:
        row = exact(
            raw,
            {"table", "sourceCount", "restoreCount", "sourceDigest", "restoreDigest"},
            "row-count",
        )
        table = row["table"]
        if table not in REQUIRED_TABLES or table in seen:
            raise Failed("verification:row-count-set")
        seen.add(table)
        if (
            not isinstance(row["sourceCount"], int)
            or isinstance(row["sourceCount"], bool)
            or row["sourceCount"] < 0
            or row["sourceCount"] != row["restoreCount"]
            or sha(row["sourceDigest"], "row-source") != sha(row["restoreDigest"], "row-restore")
        ):
            raise Failed("verification:row-count-mismatch")
        row_counts[table] = row["sourceCount"]
    if seen != REQUIRED_TABLES:
        raise Failed("verification:row-count-set")
    proofs = verification["sentinels"]
    if not isinstance(proofs, list) or len(proofs) != len(fixture_sentinels):
        raise Failed("verification:sentinel-set")
    seen_sentinels: set[str] = set()
    for raw in proofs:
        proof = exact(raw, SENTINEL_PROOF_FIELDS, "sentinel-proof")
        identifier = proof["id"]
        expected = fixture_sentinels.get(identifier) if isinstance(identifier, str) else None
        if expected is None or identifier in seen_sentinels or proof["table"] != expected["table"]:
            raise Failed("verification:sentinel-set")
        seen_sentinels.add(identifier)
        if (
            proof["sourceCount"] != expected["count"]
            or proof["restoreCount"] != expected["count"]
            or row_counts[proof["table"]] < expected["count"]
            or sha(proof["sourceDigest"], "sentinel-source") != expected["digest"]
            or sha(proof["restoreDigest"], "sentinel-restore") != expected["digest"]
        ):
            raise Failed("verification:sentinel-mismatch")
    if seen_sentinels != set(fixture_sentinels):
        raise Failed("verification:sentinel-set")
    core = exact(
        verification["coreAuthState"],
        {"status", "sourceSha256", "restoreSha256", "foreignKeyViolations", "sequenceMismatches"},
        "core-auth-state",
    )
    if (
        core["status"] != "PASS"
        or core["foreignKeyViolations"] != 0
        or core["sequenceMismatches"] != 0
        or sha(core["sourceSha256"], "core-source") != sha(core["restoreSha256"], "core-restore")
    ):
        raise Failed("verification:core-auth-state")


def validate_smoke(value: object, restore_name: str) -> None:
    smoke = exact(value, {"mode", "databaseName", "mutations", "checks"}, "fastapi-smoke")
    if (
        smoke["mode"] != "read-only-synthetic"
        or smoke["databaseName"] != restore_name
        or smoke["mutations"] != 0
    ):
        raise Failed("fastapi-smoke:read-only")
    checks = smoke["checks"]
    if not isinstance(checks, list):
        raise Failed("fastapi-smoke:checks")
    parsed = [exact(item, {"id", "status"}, "fastapi-smoke-check") for item in checks]
    if (
        {item["id"] for item in parsed} != REQUIRED_SMOKE
        or len(parsed) != len(REQUIRED_SMOKE)
        or any(item["status"] != "PASS" for item in parsed)
    ):
        raise Failed("fastapi-smoke:checks")


def validate_document(
    data: bytes, run_id: str, policy_path: Path, fixture_path: Path
) -> dict[str, Any]:
    policy = load_json(regular_bytes(policy_path, 0o644), "backup-restore-policy")
    if policy != POLICY:
        raise Failed("policy:exact-contract")
    fixture_hash, fixture_sentinels = validate_fixture_manifest(regular_bytes(fixture_path, 0o644))
    document = exact(load_json(data, INPUT_NAME), TOP_FIELDS, "evidence")
    if (
        document["schemaVersion"] != 1
        or document["gateId"] != "backup-restore"
        or document["runId"] != run_id
    ):
        raise Failed("evidence:identity")
    if document["policySha256"] != hashlib.sha256(canonical(POLICY)).hexdigest():
        raise Failed("policy:hash")
    collector = exact(document["collector"], {"kind", "identity", "version"}, "collector")
    if collector["kind"] != "controlled-disposable-v1":
        raise Failed("collector:kind")
    safe_text(collector["identity"], "collector-identity")
    if not isinstance(collector["version"], str) or VERSION.fullmatch(collector["version"]) is None:
        raise Failed("collector:version")
    source = validate_provenance(document["source"], "source-provenance-v2")
    restore = validate_provenance(document["restore"], "restore-provenance-v2")
    if (
        source["databaseName"].encode("ascii")[:63] == restore["databaseName"].encode("ascii")[:63]
        or source["databaseFingerprint"] == restore["databaseFingerprint"]
    ):
        raise Failed("provenance:source-restore-not-distinct")
    tools = exact(document["tools"], {"pgDump", "pgRestore"}, "tools")
    validate_tool(tools["pgDump"], "pg_dump")
    validate_tool(tools["pgRestore"], "pg_restore")
    artifact = exact(
        document["encryptedArtifact"],
        {
            "format",
            "algorithm",
            "ciphertextSha256",
            "ciphertextSizeBytes",
            "plaintextDumpSha256",
            "plaintextDumpSizeBytes",
            "decryptedRestoreInputSha256",
            "rawKeyPresent",
            "keyOwner",
            "keyReference",
        },
        "encrypted-artifact",
    )
    ciphertext_sha = sha(artifact["ciphertextSha256"], "ciphertext")
    plaintext_sha = sha(artifact["plaintextDumpSha256"], "plaintext-dump")
    decrypted_sha = sha(artifact["decryptedRestoreInputSha256"], "decrypted-restore-input")
    if (
        artifact["format"] != "postgres-custom"
        or artifact["algorithm"] != ENCRYPTION_ALGORITHM
        or not isinstance(artifact["ciphertextSizeBytes"], int)
        or isinstance(artifact["ciphertextSizeBytes"], bool)
        or artifact["ciphertextSizeBytes"] <= 0
        or not isinstance(artifact["plaintextDumpSizeBytes"], int)
        or isinstance(artifact["plaintextDumpSizeBytes"], bool)
        or not 0 < artifact["plaintextDumpSizeBytes"] <= MAX_PLAINTEXT_BYTES
        or artifact["rawKeyPresent"] is not False
        or plaintext_sha != decrypted_sha
        or ciphertext_sha == plaintext_sha
    ):
        raise Failed("encrypted-artifact:policy")
    if safe_text(artifact["keyOwner"], "key-owner") != KEY_OWNER:
        raise Failed("key-owner:policy")
    reference = safe_text(artifact["keyReference"], "key-reference")
    if reference != KEY_REFERENCE_TEMPLATE.format(runId=run_id):
        raise Failed("key-reference:policy")
    plaintext = exact(
        document["plaintext"], {"published", "retained", "discoveredCount"}, "plaintext"
    )
    if plaintext != {"published": False, "retained": False, "discoveredCount": 0}:
        raise Failed("plaintext:published-or-retained")
    validate_timing(document["timing"])
    validate_verification(document["verification"], fixture_hash, fixture_sentinels)
    validate_smoke(document["fastapiSmoke"], restore["databaseName"])
    express = exact(document["expressInvariance"], {"before", "after"}, "express-invariance")
    snapshot_fields = {"containerId", "imageId", "state", "restartCount", "startedAt"}
    before = exact(express["before"], snapshot_fields, "express-before")
    after = exact(express["after"], snapshot_fields, "express-after")
    for key in ("containerId",):
        sha(before[key], f"express-before:{key}")
    safe_text(before["imageId"], "express-image")
    timestamp(before["startedAt"], "express-started")
    if (
        before != after
        or before["state"] != "running"
        or not isinstance(before["restartCount"], int)
        or isinstance(before["restartCount"], bool)
        or before["restartCount"] < 0
    ):
        raise Failed("express-invariance:changed")
    access = exact(
        document["accessAndRetention"],
        {"accessors", "createdAt", "expiresAt", "retentionSeconds", "deletionConfirmedAt"},
        "access-retention",
    )
    if (
        access["accessors"] != ["controlled-collector"]
        or not isinstance(access["retentionSeconds"], int)
        or isinstance(access["retentionSeconds"], bool)
        or access["retentionSeconds"] <= 0
    ):
        raise Failed("policy:access-retention")
    created = timestamp(access["createdAt"], "retention-created")
    expires = timestamp(access["expiresAt"], "retention-expires")
    deleted = timestamp(access["deletionConfirmedAt"], "retention-deleted")
    if (
        round((expires - created).total_seconds()) != access["retentionSeconds"]
        or deleted < created
        or deleted > expires
    ):
        raise Failed("policy:retention-expiry")
    cleanup = exact(
        document["cleanup"],
        {
            "sourceDatabaseDropped",
            "restoreDatabaseDropped",
            "artifactRemoved",
            "privateTempRemoved",
            "deletionConfirmed",
            "deletedCiphertextSha256",
            "candidateInventory",
        },
        "cleanup",
    )
    required_true = (
        "sourceDatabaseDropped",
        "restoreDatabaseDropped",
        "artifactRemoved",
        "privateTempRemoved",
        "deletionConfirmed",
    )
    if (
        any(cleanup[key] is not True for key in required_true)
        or cleanup["candidateInventory"] != []
        or sha(cleanup["deletedCiphertextSha256"], "deleted-ciphertext")
        != artifact["ciphertextSha256"]
    ):
        raise Failed("cleanup:incomplete")
    return document


def validate_bundle(
    source: Path, run_id: str, policy_path: Path, fixture_path: Path | None = None
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="wiseacct-phase7-backup-restore-input.") as private:
        snapshot = Path(private)
        os.chmod(snapshot, 0o700)
        snapshot_inputs(source, snapshot)
        if fixture_path is None:
            fixture_path = Path(__file__).with_name("backup-restore-fixture-manifest.json")
        document = validate_document(
            regular_bytes(snapshot / INPUT_NAME), run_id, policy_path, fixture_path
        )
        validate_attachments(
            regular_bytes(snapshot / PROVENANCE_NAME),
            regular_bytes(snapshot / ATTESTATION_NAME),
            run_id,
            document,
        )
        return document


def reason_code(error: BaseException) -> str:
    if isinstance(error, Incomplete):
        return "MISSING_EVIDENCE"
    message = str(error)
    if any(term in message for term in ("unsafe", "changed-input", "permissions")):
        return "UNSAFE_INPUT"
    if any(
        term in message
        for term in (
            "policy",
            "plaintext",
            "secret",
            "verification",
            "smoke",
            "invariance",
            "cleanup",
            "provenance",
            "artifact",
            "retention",
        )
    ):
        return "POLICY_VIOLATION"
    return "MALFORMED_INPUT"


def fsync_path(path: Path) -> None:
    flags = os.O_RDONLY | (getattr(os, "O_DIRECTORY", 0) if path.is_dir() else 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def rename_noreplace(source: Path, target: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise Failed("publication:no-atomic-noreplace")
    result = renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise Failed("evidence:collision")
        raise OSError(code, os.strerror(code))


def publish(evidence_root: Path, run_id: str, status: str, reasons: list[str]) -> Path:
    if status == "PASS":
        status, reasons = "INCOMPLETE", ["POLICY_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"]
    if (
        status not in {"INCOMPLETE", "FAIL"}
        or not reasons
        or any(reason not in ALLOWED_REASONS for reason in reasons)
    ):
        raise Failed("publication:status-or-reason")
    root_created = not evidence_root.exists()
    evidence_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if (
        evidence_root.is_symlink()
        or evidence_root.resolve() != evidence_root
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
        result = {
            "schemaVersion": 1,
            "gateId": "backup-restore",
            "runId": run_id,
            "status": status,
            "sampleSatisfied": False,
            "readinessAssertionsSatisfied": False,
            "cleanupComplete": False,
            "expressSnapshotUnchanged": False,
            "overallReplacementReady": False,
        }
        files = {
            "gate-result.json": canonical(result),
            "result.status": (
                f"status={status}\noverallReplacementReady=false\nreasonCodes={','.join(reasons)}\n"
            ).encode(),
        }
        for name, data in files.items():
            path = staging / name
            path.write_bytes(data)
            os.chmod(path, 0o400)
            fsync_path(path)
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
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    if SAFE_ID.fullmatch(args.run_id) is None:
        print("backup/restore gate refused: unsafe run id", file=sys.stderr)
        return 2
    policy_path = Path(__file__).with_name("backup-restore-policy.json")
    try:
        validate_bundle(args.input, args.run_id, policy_path)
        status, reasons = "INCOMPLETE", ["POLICY_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"]
    except Incomplete as exc:
        status, reasons = "INCOMPLETE", [reason_code(exc)]
    except (Failed, OSError) as exc:
        status, reasons = "FAIL", [reason_code(exc)]
    except Exception:
        status, reasons = "FAIL", ["MALFORMED_INPUT"]
    try:
        output = publish(args.evidence_root.absolute(), args.run_id, status, reasons)
    except (Failed, OSError) as exc:
        print(f"backup/restore gate publication refused: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 3 if status == "INCOMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
