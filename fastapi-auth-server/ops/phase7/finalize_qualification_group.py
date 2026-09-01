#!/usr/bin/env python3
"""Fail-closed finalizer for one provisional Phase 7 qualification run group."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
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
GATE_FIELDS = {
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
PROVENANCE_FIELDS = (
    "sourceRevision",
    "applicationTree",
    "schema",
    "lock",
    "config",
    "image",
)
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
SAFE_RELATIVE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*")
CLEANUP_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
REVISION = re.compile(r"[0-9a-f]{40,64}")
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot safely open input: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise ManifestError(f"input changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative_evidence_path(root: Path, raw: object, *, directory: bool) -> Path:
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
    current = root
    for part in relative.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ManifestError(f"missing evidence path: {raw}") from exc
        if stat.S_ISLNK(mode):
            raise ManifestError(f"evidence path contains a symlink: {raw}")
    mode = current.lstat().st_mode
    if directory and not stat.S_ISDIR(mode):
        raise ManifestError(f"evidence bundle must be a directory: {raw}")
    if not directory and not stat.S_ISREG(mode):
        raise ManifestError(f"evidence attachment must be a regular file: {raw}")
    return current


def evidence_aggregate_sha256(directory: Path) -> str:
    """Hash sorted ``relative-path NUL file-sha256 LF`` evidence records."""
    records: list[bytes] = []

    def visit(current: Path) -> None:
        for entry in sorted(current.iterdir(), key=lambda item: item.name):
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ManifestError(f"evidence bundle contains a symlink: {entry}")
            if stat.S_ISDIR(mode):
                visit(entry)
            elif stat.S_ISREG(mode):
                relative = entry.relative_to(directory).as_posix().encode("utf-8")
                records.append(relative + b"\0" + _sha256(_regular_bytes(entry)).encode() + b"\n")
            else:
                raise ManifestError(f"evidence bundle contains a non-regular entry: {entry}")

    visit(directory)
    if not records:
        raise ManifestError("evidence bundle must contain at least one regular file")
    return _sha256(b"".join(sorted(records)))


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


def _load_manifest(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(_regular_bytes(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest must be valid UTF-8 JSON") from exc
    return _exact_object(document, MANIFEST_FIELDS, "manifest")


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


def finalize(manifest_path: Path, evidence_root: Path) -> tuple[dict[str, Any], bool]:
    root_mode = evidence_root.lstat().st_mode
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode):
        raise ManifestError("evidence root must be a regular non-symlink directory")
    manifest = _load_manifest(manifest_path)
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1:
        raise ManifestError("unsupported schemaVersion")
    group_id = _safe_id(manifest["groupId"], "groupId")
    raw_gates = manifest["gates"]
    if not isinstance(raw_gates, list):
        raise ManifestError("gates must be an array")

    reasons: set[str] = set()
    seen: set[str] = set()
    provenances: dict[str, set[str]] = {field: set() for field in PROVENANCE_FIELDS}
    normalized_gates: list[dict[str, Any]] = []
    required = set(REQUIRED_GATE_IDS)

    for index, raw_gate in enumerate(raw_gates):
        gate = _exact_object(raw_gate, GATE_FIELDS, f"gate[{index}]")
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
        if (
            not isinstance(gate["sourceRevision"], str)
            or REVISION.fullmatch(gate["sourceRevision"]) is None
        ):
            raise ManifestError("sourceRevision must be a lowercase revision hash")
        for field in ("applicationTree", "schema", "lock", "config"):
            _hash(gate[field], field)
        if not isinstance(gate["image"], str) or IMAGE.fullmatch(gate["image"]) is None:
            raise ManifestError("image must be a pinned sha256 digest")
        for field in PROVENANCE_FIELDS:
            provenances[field].add(gate[field])

        bundle = _relative_evidence_path(
            root=evidence_root, raw=gate["evidencePath"], directory=True
        )
        expected_aggregate = _hash(gate["evidenceAggregateSha256"], "evidenceAggregateSha256")
        if evidence_aggregate_sha256(bundle) != expected_aggregate:
            raise ManifestError(f"evidence aggregate hash mismatch for {gate_id}")

        attachments: dict[str, bytes] = {}
        for path_field, hash_field in (
            ("resultEvidencePath", "resultEvidenceSha256"),
            ("cleanupEvidencePath", "cleanupEvidenceSha256"),
            ("expressBeforePath", "expressBeforeSha256"),
            ("expressAfterPath", "expressAfterSha256"),
        ):
            attachment = _relative_evidence_path(
                root=evidence_root, raw=gate[path_field], directory=False
            )
            if not attachment.is_relative_to(bundle):
                raise ManifestError(f"gate attachment is outside its evidence bundle: {gate_id}")
            content = _regular_bytes(attachment)
            if _sha256(content) != _hash(gate[hash_field], hash_field):
                raise ManifestError(f"attachment hash mismatch for {gate_id}: {path_field}")
            attachments[path_field] = content

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

    complete = not reasons and seen == required
    output = {
        "schemaVersion": 1,
        "groupId": group_id,
        "status": "PROVISIONAL_READY_FOR_REVIEW" if complete else "INCOMPLETE",
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
    args = parser.parse_args()
    try:
        result, complete = finalize(args.manifest, args.evidence_root)
    except (ManifestError, OSError) as exc:
        print(f"qualification group refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
