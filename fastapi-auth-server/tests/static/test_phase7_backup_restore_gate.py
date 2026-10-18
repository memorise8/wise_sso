from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "ops" / "phase7" / "backup_restore" / "backup_restore_gate.py"
POLICY = ROOT / "ops" / "phase7" / "backup_restore" / "backup-restore-policy.json"
FIXTURE = ROOT / "ops" / "phase7" / "backup_restore" / "backup-restore-fixture-manifest.json"
SCHEMA = ROOT / "ops" / "phase7" / "backup_restore" / "backup-restore-evidence.schema.json"
WRAPPER = ROOT / "ops" / "phase7" / "run-backup-restore-gate.sh"
SPEC = importlib.util.spec_from_file_location("phase7_backup_restore_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
RUN_ID = "backup-restore-test"


def evidence() -> dict[str, Any]:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    rows = [
        {
            "table": table,
            "sourceCount": 2,
            "restoreCount": 2,
            "sourceDigest": HASH_A,
            "restoreDigest": HASH_A,
        }
        for table in sorted(gate.REQUIRED_TABLES)
    ]
    snapshot = {
        "containerId": HASH_C,
        "imageId": f"sha256:{HASH_B}",
        "state": "running",
        "restartCount": 0,
        "startedAt": "2026-09-02T00:00:00Z",
    }
    return {
        "schemaVersion": 1,
        "gateId": "backup-restore",
        "runId": RUN_ID,
        "collector": {
            "kind": "controlled-disposable-v1",
            "identity": "phase7-collector",
            "version": "1.0.0",
        },
        "policySha256": hashlib.sha256(gate.canonical(gate.POLICY)).hexdigest(),
        "source": {
            "schemaVersion": 2,
            "databaseName": "wiseacct_test_backup_source",
            "databaseFingerprint": HASH_A,
            "syntheticOnly": True,
            "productionData": False,
        },
        "restore": {
            "schemaVersion": 2,
            "databaseName": "wiseacct_test_restore_target",
            "databaseFingerprint": HASH_B,
            "syntheticOnly": True,
            "productionData": False,
        },
        "tools": {
            "pgDump": {"name": "pg_dump", "version": "17.2", "executableSha256": HASH_A},
            "pgRestore": {
                "name": "pg_restore",
                "version": "17.2",
                "executableSha256": HASH_B,
            },
        },
        "encryptedArtifact": {
            "format": "postgres-custom",
            "algorithm": "AES-256-GCM",
            "ciphertextSha256": HASH_C,
            "ciphertextSizeBytes": 4096,
            "plaintextDumpSha256": HASH_A,
            "plaintextDumpSizeBytes": 2048,
            "decryptedRestoreInputSha256": HASH_A,
            "rawKeyPresent": False,
            "keyOwner": "phase7-local-qualification-runner",
            "keyReference": f"urn:wiseacct:phase7:backup-restore:ephemeral:{RUN_ID}",
        },
        "plaintext": {"published": False, "retained": False, "discoveredCount": 0},
        "timing": {
            "backupStartedAt": "2026-09-02T00:00:00Z",
            "backupEndedAt": "2026-09-02T00:00:02Z",
            "backupDurationMs": 2000,
            "restoreStartedAt": "2026-09-02T00:00:03Z",
            "restoreEndedAt": "2026-09-02T00:00:08Z",
            "restoreDurationMs": 5000,
            "rpoSeconds": 10,
            "rtoSeconds": 8,
        },
        "verification": {
            "fixtureManifestSha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
            "sentinels": [
                {
                    "id": sentinel["id"],
                    "table": sentinel["table"],
                    "sourceCount": sentinel["count"],
                    "restoreCount": sentinel["count"],
                    "sourceDigest": sentinel["digest"],
                    "restoreDigest": sentinel["digest"],
                }
                for sentinel in fixture["sentinels"]
            ],
            "schemaCatalog": {
                "status": "PASS",
                "sourceSha256": HASH_A,
                "restoreSha256": HASH_A,
            },
            "rowCounts": rows,
            "coreAuthState": {
                "status": "PASS",
                "sourceSha256": HASH_B,
                "restoreSha256": HASH_B,
                "foreignKeyViolations": 0,
                "sequenceMismatches": 0,
            },
        },
        "fastapiSmoke": {
            "mode": "read-only-synthetic",
            "databaseName": "wiseacct_test_restore_target",
            "mutations": 0,
            "checks": [{"id": check, "status": "PASS"} for check in sorted(gate.REQUIRED_SMOKE)],
        },
        "expressInvariance": {"before": snapshot, "after": copy.deepcopy(snapshot)},
        "accessAndRetention": {
            "accessors": ["controlled-collector"],
            "createdAt": "2026-09-02T00:00:00Z",
            "expiresAt": "2026-09-02T01:00:00Z",
            "retentionSeconds": 3600,
            "deletionConfirmedAt": "2026-09-02T00:01:00Z",
        },
        "cleanup": {
            "sourceDatabaseDropped": True,
            "restoreDatabaseDropped": True,
            "artifactRemoved": True,
            "privateTempRemoved": True,
            "deletionConfirmed": True,
            "deletedCiphertextSha256": HASH_C,
            "candidateInventory": [],
        },
    }


def write_private(path: Path, value: object) -> None:
    path.write_bytes(gate.canonical(value))
    path.chmod(0o600)


def attachments(document: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    attestation = {
        "schemaVersion": 1,
        "collectorId": document["collector"]["identity"],
        "collectorRevision": "d" * 40,
        "collectorTreeObject": "e" * 40,
        "expressImageId": document["expressInvariance"]["before"]["imageId"],
        "fastapiImageId": f"sha256:{HASH_C}",
        "status": "UNVERIFIED",
    }
    provenance = {
        "schemaVersion": 2,
        "gateId": "backup-restore",
        "topology": "backup-restore-disposable-v1",
        "runId": document["runId"],
        "sourceRevision": "f" * 40,
        "gitTreeObject": "1" * 40,
        "expressApplicationTreeSha256": HASH_A,
        "fastapiApplicationTreeSha256": HASH_B,
        "schemaSha256": HASH_C,
        "expressLockSha256": HASH_A,
        "fastapiLockSha256": HASH_B,
        "configSha256": HASH_C,
        "expressImageId": attestation["expressImageId"],
        "fastapiImageId": attestation["fastapiImageId"],
        "collectorAttestationSha256": hashlib.sha256(gate.canonical(attestation)).hexdigest(),
    }
    return provenance, attestation


def make_input(tmp_path: Path, document: object | None = None) -> Path:
    source = tmp_path / "input"
    source.mkdir(mode=0o700)
    actual = evidence() if document is None else document
    write_private(source / gate.INPUT_NAME, actual)
    if isinstance(actual, dict):
        provenance, attestation = attachments(actual)
        write_private(source / gate.PROVENANCE_NAME, provenance)
        write_private(source / gate.ATTESTATION_NAME, attestation)
    return source


def validate(document: object, tmp_path: Path) -> None:
    gate.validate_bundle(make_input(tmp_path, document), RUN_ID, POLICY)


def test_contract_files_and_wrapper_are_static_and_executable() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert policy == gate.POLICY
    assert policy["status"] == "UNFROZEN"
    assert policy["rpoSeconds"] is None
    assert policy["rtoSeconds"] is None
    assert policy["maxArtifactRetentionSeconds"] is None
    assert policy["maxPlaintextBytes"] == 67108864
    assert policy["encryptionAlgorithm"] == "AES-256-GCM"
    assert policy["keyOwner"] == "phase7-local-qualification-runner"
    assert policy["sourceScope"] == "synthetic-only"
    assert policy["redisDisposition"] == "ephemeral-not-backed-up"
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert {item["id"] for item in fixture["sentinels"]} == {
        "user",
        "credential",
        "role",
        "session",
    }
    for sentinel in fixture["sentinels"]:
        projection = {"table": sentinel["table"], "recordId": sentinel["recordId"]}
        assert sentinel["digest"] == hashlib.sha256(gate.canonical(projection)).hexdigest()
    definitions = schema["$defs"]
    assert definitions["provenance"]["properties"]["databaseName"]["maxLength"] == 63
    assert definitions["pgDumpTool"]["properties"]["name"] == {"const": "pg_dump"}
    assert definitions["pgRestoreTool"]["properties"]["name"] == {"const": "pg_restore"}
    assert definitions["artifact"]["properties"]["algorithm"] == {"const": "AES-256-GCM"}
    assert definitions["verification"]["properties"]["rowCounts"]["minItems"] == len(
        gate.REQUIRED_TABLES
    )
    assert definitions["verification"]["properties"]["sentinels"]["minItems"] == 4
    assert definitions["smoke"]["properties"]["checks"]["minItems"] == len(gate.REQUIRED_SMOKE)
    assert definitions["access"]["properties"]["accessors"] == {"const": ["controlled-collector"]}
    assert os.access(WRAPPER, os.X_OK)
    wrapper = WRAPPER.read_text(encoding="utf-8")
    assert "docker" not in wrapper.lower()
    assert "pg_dump" not in wrapper and "pg_restore" not in wrapper
    assert "/usr/bin/dirname" in wrapper
    assert "/usr/bin/env -i" in wrapper
    assert "/usr/bin/python3 -I" in wrapper


def test_valid_external_bundle_is_still_incomplete_and_safe_only(tmp_path: Path) -> None:
    source = make_input(tmp_path)
    gate.validate_bundle(source, RUN_ID, POLICY)
    output = gate.publish(tmp_path / "evidence", RUN_ID, "PASS", [])
    result = json.loads((output / "gate-result.json").read_text(encoding="utf-8"))
    assert result == {
        "schemaVersion": 1,
        "gateId": "backup-restore",
        "runId": RUN_ID,
        "status": "INCOMPLETE",
        "sampleSatisfied": False,
        "readinessAssertionsSatisfied": False,
        "cleanupComplete": False,
        "expressSnapshotUnchanged": False,
        "overallReplacementReady": False,
    }
    assert {entry.name for entry in output.iterdir()} == {"gate-result.json", "result.status"}
    published = b"".join(entry.read_bytes() for entry in output.iterdir())
    assert b"databaseName" not in published and b"keyReference" not in published
    assert stat.S_IMODE(output.stat().st_mode) == 0o500
    assert all(stat.S_IMODE(entry.stat().st_mode) == 0o400 for entry in output.iterdir())
    assert "POLICY_UNFROZEN,CONTROLLED_COLLECTOR_REQUIRED" in (output / "result.status").read_text(
        encoding="utf-8"
    )


def mutate(document: dict[str, Any], case: str) -> None:
    if case == "production-db":
        document["source"]["databaseName"] = "wiseacct_production"
    elif case == "same-db":
        document["restore"] = copy.deepcopy(document["source"])
    elif case == "unencrypted":
        document["encryptedArtifact"]["algorithm"] = "NONE"
    elif case == "plaintext":
        document["plaintext"]["published"] = True
    elif case == "checksum":
        document["encryptedArtifact"]["decryptedRestoreInputSha256"] = HASH_B
    elif case == "raw-key":
        document["encryptedArtifact"]["rawKeyPresent"] = True
    elif case == "url":
        document["encryptedArtifact"]["keyReference"] = "https://kms.invalid/key"
    elif case == "missing-deletion":
        document["cleanup"]["deletionConfirmed"] = False
    elif case == "row-count":
        document["verification"]["rowCounts"][0]["restoreCount"] = 999
    elif case == "empty-db":
        for row in document["verification"]["rowCounts"]:
            row["sourceCount"] = 0
            row["restoreCount"] = 0
    elif case == "empty-sentinel":
        document["verification"]["sentinels"][0]["sourceCount"] = 0
        document["verification"]["sentinels"][0]["restoreCount"] = 0
    elif case == "fixture-hash":
        document["verification"]["fixtureManifestSha256"] = HASH_A
    elif case == "ciphertext-plaintext-same":
        document["encryptedArtifact"]["ciphertextSha256"] = HASH_A
    elif case == "rto-missing":
        del document["timing"]["rtoSeconds"]
    elif case == "express":
        document["expressInvariance"]["after"]["restartCount"] = 1
    elif case == "candidate":
        document["cleanup"]["candidateInventory"] = ["leftover"]
    elif case == "smoke-write":
        document["fastapiSmoke"]["mutations"] = 1
    elif case == "extra-field":
        document["unexpected"] = True
    else:
        raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    [
        "production-db",
        "same-db",
        "unencrypted",
        "plaintext",
        "checksum",
        "raw-key",
        "url",
        "missing-deletion",
        "row-count",
        "empty-db",
        "empty-sentinel",
        "fixture-hash",
        "ciphertext-plaintext-same",
        "rto-missing",
        "express",
        "candidate",
        "smoke-write",
        "extra-field",
    ],
)
def test_adversarial_contract_mutations_fail(tmp_path: Path, case: str) -> None:
    document = evidence()
    mutate(document, case)
    with pytest.raises(gate.Failed):
        validate(document, tmp_path)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("accessToken", "eyJhbGciOiJSUzI1NiJ9.payload.signature"),
        ("email", "person@example.invalid"),
        ("authorization", "Bearer abcdef"),
    ],
)
def test_secret_pii_and_token_material_fail(tmp_path: Path, key: str, value: str) -> None:
    document = evidence()
    document["collector"][key] = value
    with pytest.raises(gate.Failed, match="secret-material"):
        validate(document, tmp_path)


def test_missing_is_incomplete_but_unexpected_is_fail(tmp_path: Path) -> None:
    source = tmp_path / "missing"
    source.mkdir(mode=0o700)
    with pytest.raises(gate.Incomplete):
        gate.validate_bundle(source, RUN_ID, POLICY)
    write_private(source / "unexpected.json", {})
    with pytest.raises(gate.Failed, match="unexpected-files"):
        gate.validate_bundle(source, RUN_ID, POLICY)


@pytest.mark.parametrize(
    ("filename", "mutation"),
    [
        (gate.PROVENANCE_NAME, "missing"),
        (gate.ATTESTATION_NAME, "missing"),
        (gate.PROVENANCE_NAME, "wrong-run"),
        (gate.PROVENANCE_NAME, "wrong-gate"),
        (gate.PROVENANCE_NAME, "bad-attestation-hash"),
        (gate.ATTESTATION_NAME, "image-mismatch"),
    ],
)
def test_provenance_and_collector_attestation_binding(
    tmp_path: Path, filename: str, mutation: str
) -> None:
    source = make_input(tmp_path)
    path = source / filename
    if mutation == "missing":
        path.unlink()
        with pytest.raises(gate.Incomplete):
            gate.validate_bundle(source, RUN_ID, POLICY)
        return
    attachment = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "wrong-run":
        attachment["runId"] = "other-run"
    elif mutation == "wrong-gate":
        attachment["gateId"] = "security"
    elif mutation == "bad-attestation-hash":
        attachment["collectorAttestationSha256"] = HASH_A
    else:
        attachment["fastapiImageId"] = f"sha256:{HASH_A}"
    write_private(path, attachment)
    with pytest.raises(gate.Failed):
        gate.validate_bundle(source, RUN_ID, POLICY)


def test_database_identifier_byte_limit_and_truncation_collision(tmp_path: Path) -> None:
    accepted = "a" * 50 + "_test_" + "b" * 7
    assert len(accepted.encode("ascii")) == 63
    document = evidence()
    document["source"]["databaseName"] = accepted
    accepted_case = tmp_path / "accepted"
    accepted_case.mkdir()
    validate(document, accepted_case)

    too_long = accepted + "c"
    assert len(too_long.encode("ascii")) == 64
    document = evidence()
    document["source"]["databaseName"] = too_long
    length_case = tmp_path / "length"
    length_case.mkdir()
    with pytest.raises(gate.Failed, match="test-database-required"):
        validate(document, length_case)

    document = evidence()
    document["source"]["databaseName"] = accepted
    document["restore"]["databaseName"] = accepted + "z"
    collision_case = tmp_path / "collision"
    collision_case.mkdir()
    with pytest.raises(gate.Failed):
        validate(document, collision_case)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_path_link_and_hardlink_inputs_fail(tmp_path: Path, kind: str) -> None:
    source = make_input(tmp_path)
    path = source / gate.INPUT_NAME
    if kind == "symlink":
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)
    elif kind == "hardlink":
        os.link(path, tmp_path / "outside.json")
    else:
        path.chmod(0o644)
    with pytest.raises(gate.Failed):
        gate.validate_bundle(source, RUN_ID, POLICY)


def test_in_place_metadata_race_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "input.json"
    write_private(path, evidence())
    real_fstat = gate.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> object:
        nonlocal calls
        calls += 1
        result = real_fstat(descriptor)
        if calls == 2:
            values = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
            values["st_ctime_ns"] += 1
            return types.SimpleNamespace(**values)
        return result

    monkeypatch.setattr(gate.os, "fstat", changing_fstat)
    with pytest.raises(gate.Failed, match="changed-input"):
        gate.regular_bytes(path)


def test_collision_and_failed_atomic_publication_leave_no_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "evidence"
    gate.publish(root, RUN_ID, "INCOMPLETE", ["MISSING_EVIDENCE"])
    with pytest.raises(gate.Failed, match="collision"):
        gate.publish(root, RUN_ID, "INCOMPLETE", ["MISSING_EVIDENCE"])
    other = tmp_path / "other"

    def refuse(_source: Path, _target: Path) -> None:
        raise OSError("forced")

    monkeypatch.setattr(gate, "rename_noreplace", refuse)
    with pytest.raises(OSError, match="forced"):
        gate.publish(other, RUN_ID, "FAIL", ["MALFORMED_INPUT"])
    assert list(other.iterdir()) == []


@pytest.mark.parametrize(
    ("unexpected", "exit_code", "status"), [(False, 3, "INCOMPLETE"), (True, 2, "FAIL")]
)
def test_cli_missing_vs_malformed(
    tmp_path: Path, unexpected: bool, exit_code: int, status: str
) -> None:
    source = tmp_path / "input"
    source.mkdir(mode=0o700)
    if unexpected:
        write_private(source / "unexpected", {})
    output = tmp_path / "output"
    completed = subprocess.run(  # noqa: S603 - fixed checked-in gate path
        [
            "/usr/bin/python3",
            "-I",
            str(GATE),
            "--input",
            str(source),
            "--run-id",
            RUN_ID,
            "--evidence-root",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == exit_code
    result = json.loads((output / RUN_ID / "gate-result.json").read_text(encoding="utf-8"))
    assert result["status"] == status
    assert result["gateId"] == "backup-restore"
    assert result["overallReplacementReady"] is False


def test_wrapper_clears_poisoned_command_and_python_environment(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    phase7 = clone / "fastapi-auth-server" / "ops" / "phase7"
    backup_restore = phase7 / "backup_restore"
    backup_restore.mkdir(parents=True)
    copied_wrapper = phase7 / WRAPPER.name
    shutil.copy2(WRAPPER, copied_wrapper)
    for source in (GATE, POLICY, FIXTURE):
        shutil.copy2(source, backup_restore / source.name)
    poisoned = tmp_path / "poisoned"
    poisoned.mkdir()
    marker = tmp_path / "poison-ran"
    fake_dirname = poisoned / "dirname"
    fake_dirname.write_text(f"#!/bin/sh\n: > {marker}\nexit 99\n", encoding="utf-8")
    fake_dirname.chmod(0o755)
    startup = poisoned / "startup.sh"
    startup.write_text(f": > {marker}\n", encoding="utf-8")
    (poisoned / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8"
    )
    source = tmp_path / "missing-input"
    source.mkdir(mode=0o700)
    completed = subprocess.run(  # noqa: S603 - copied fixed checked-in wrapper
        ["/bin/sh", str(copied_wrapper), str(source), "poison-test"],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": str(poisoned),
            "PYTHONPATH": str(poisoned),
            "PYTHONHOME": str(poisoned),
            "ENV": str(startup),
            "BASH_ENV": str(startup),
        },
    )
    assert completed.returncode == 3
    assert not marker.exists()
    result_path = clone / "fastapi-auth-server" / "evidence" / "phase7-backup-restore"
    result = json.loads((result_path / "poison-test" / "gate-result.json").read_text())
    assert result["status"] == "INCOMPLETE"
