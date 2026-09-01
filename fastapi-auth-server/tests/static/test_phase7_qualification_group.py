from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT.parent
EVIDENCE = ROOT / "evidence"
FINALIZER = ROOT / "ops" / "phase7" / "finalize_qualification_group.py"
SCHEMA = ROOT / "ops" / "phase7" / "qualification-group.schema.json"
SPEC = importlib.util.spec_from_file_location("phase7_qualification_group", FINALIZER)
assert SPEC is not None and SPEC.loader is not None
finalizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = finalizer
SPEC.loader.exec_module(finalizer)

HASH_A = "a" * 64
REVISION_A = "1" * 40
IMAGE_A = f"sha256:{'b' * 64}"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def make_bundle(root: Path, gate_id: str) -> dict[str, Any]:
    bundle = root / gate_id
    bundle.mkdir(parents=True)
    cleanup = "".join(
        f"{key}=PASS\n" for key in sorted(finalizer.CLEANUP_KEYS_BY_GATE[gate_id])
    ).encode()
    snapshot = b"stable-express-snapshot\n"
    run_id = f"run-{gate_id}"
    result = {
        "schemaVersion": 1,
        "gateId": gate_id,
        "runId": run_id,
        "status": "PASS",
        "sampleSatisfied": True,
        "readinessAssertionsSatisfied": True,
        "cleanupComplete": True,
        "expressSnapshotUnchanged": True,
        "overallReplacementReady": False,
    }
    result_bytes = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    (bundle / "gate-result.json").write_bytes(result_bytes)
    (bundle / "cleanup.status").write_bytes(cleanup)
    (bundle / "express-before.txt").write_bytes(snapshot)
    (bundle / "express-after.txt").write_bytes(snapshot)
    (bundle / "result.status").write_text("status=PASS\n", encoding="utf-8")
    relative = bundle.relative_to(root).as_posix()
    return {
        "gateId": gate_id,
        "topology": "disposable-local",
        "runId": run_id,
        "evidencePath": relative,
        "evidenceAggregateSha256": finalizer.evidence_aggregate_sha256(bundle),
        "sourceRevision": REVISION_A,
        "applicationTree": HASH_A,
        "schema": HASH_A,
        "lock": HASH_A,
        "config": HASH_A,
        "image": IMAGE_A,
        "status": "PASS",
        "sampleSatisfied": True,
        "readinessAssertionsSatisfied": True,
        "resultEvidencePath": f"{relative}/gate-result.json",
        "resultEvidenceSha256": sha256(result_bytes),
        "cleanupEvidencePath": f"{relative}/cleanup.status",
        "cleanupEvidenceSha256": sha256(cleanup),
        "expressBeforePath": f"{relative}/express-before.txt",
        "expressBeforeSha256": sha256(snapshot),
        "expressAfterPath": f"{relative}/express-after.txt",
        "expressAfterSha256": sha256(snapshot),
    }


def complete_manifest(evidence: Path) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "groupId": "qualification-1",
        "gates": [make_bundle(evidence, gate_id) for gate_id in finalizer.REQUIRED_GATE_IDS],
    }


def finalize_document(tmp_path: Path, document: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    manifest = tmp_path / "manifest.json"
    write_json(manifest, document)
    return cast(tuple[dict[str, Any], bool], finalizer.finalize(manifest, tmp_path / "evidence"))


def test_complete_group_is_only_provisional_ready_for_review(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    result, complete = finalize_document(tmp_path, complete_manifest(evidence))
    assert complete is True
    assert result["status"] == "PROVISIONAL_READY_FOR_REVIEW"
    assert result["overallReplacementReady"] is False
    assert result["reasons"] == []
    assert result["requiredGateIds"] == list(finalizer.REQUIRED_GATE_IDS)


def test_cli_exits_zero_only_for_complete_provisional_group(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = tmp_path / "manifest.json"
    write_json(manifest, complete_manifest(evidence))
    completed = subprocess.run(  # noqa: S603 - fixed repository helper path
        [str(FINALIZER), "--manifest", str(manifest), "--evidence-root", str(evidence)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["status"] == "PROVISIONAL_READY_FOR_REVIEW"


def test_missing_gate_is_incomplete_and_nonzero(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"].pop()
    manifest = tmp_path / "manifest.json"
    write_json(manifest, document)
    completed = subprocess.run(  # noqa: S603 - fixed repository helper path
        [str(FINALIZER), "--manifest", str(manifest), "--evidence-root", str(evidence)],
        check=False,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert result["status"] == "INCOMPLETE"
    assert result["overallReplacementReady"] is False
    assert "missing-gate:local-rollback" in result["reasons"]


@pytest.mark.parametrize("field", ["sourceRevision", "config", "image"])
def test_mixed_provenance_is_incomplete(tmp_path: Path, field: str) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][1][field] = {
        "sourceRevision": "2" * 40,
        "config": "c" * 64,
        "image": f"sha256:{'d' * 64}",
    }[field]
    result, complete = finalize_document(tmp_path, document)
    assert complete is False
    assert result["status"] == "INCOMPLETE"
    assert f"mixed-provenance:{field}" in result["reasons"]


@pytest.mark.parametrize("field", ["sampleSatisfied", "readinessAssertionsSatisfied"])
def test_false_readiness_claim_is_incomplete(tmp_path: Path, field: str) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    gate[field] = False
    result_path = evidence / gate["resultEvidencePath"]
    result_document = json.loads(result_path.read_text(encoding="utf-8"))
    result_document[field] = False
    write_json(result_path, result_document)
    gate["resultEvidenceSha256"] = sha256(result_path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / gate["evidencePath"]
    )
    result, complete = finalize_document(tmp_path, document)
    assert complete is False
    expected = "sample-unsatisfied" if field == "sampleSatisfied" else "readiness-unsatisfied"
    assert f"{expected}:independent-contract" in result["reasons"]


def test_hash_mismatch_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][0]["evidenceAggregateSha256"] = "f" * 64
    with pytest.raises(finalizer.ManifestError, match="aggregate hash mismatch"):
        finalize_document(tmp_path, document)


def test_evidence_aggregate_globally_sorts_encoded_relative_paths(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "a").mkdir(parents=True)
    (bundle / "a" / "z").write_bytes(b"nested")
    (bundle / "a-").write_bytes(b"punctuation")
    records = [
        b"a-\0" + sha256(b"punctuation").encode() + b"\n",
        b"a/z\0" + sha256(b"nested").encode() + b"\n",
    ]
    assert finalizer.evidence_aggregate_sha256(bundle) == sha256(b"".join(records))


def test_path_traversal_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][0]["evidencePath"] = "../outside"
    with pytest.raises(finalizer.ManifestError, match="not confined"):
        finalize_document(tmp_path, document)


def test_symlink_attachment_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    target = evidence / "independent-contract" / "cleanup.status"
    copied = target.with_suffix(".real")
    target.rename(copied)
    target.symlink_to(copied.name)
    with pytest.raises(finalizer.ManifestError, match="symlink"):
        finalize_document(tmp_path, document)


def test_duplicate_gate_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][1]["gateId"] = document["gates"][0]["gateId"]
    with pytest.raises(finalizer.ManifestError, match="duplicate gateId"):
        finalize_document(tmp_path, document)


@pytest.mark.parametrize("scope", ["manifest", "gate"])
def test_extra_fields_are_refused(tmp_path: Path, scope: str) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    if scope == "manifest":
        document["unexpected"] = True
    else:
        document["gates"][0]["unexpected"] = True
    with pytest.raises(finalizer.ManifestError, match="exact approved fields"):
        finalize_document(tmp_path, document)


def test_manifest_without_hashed_gate_result_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    del document["gates"][0]["resultEvidencePath"]
    del document["gates"][0]["resultEvidenceSha256"]
    with pytest.raises(finalizer.ManifestError, match="exact approved fields"):
        finalize_document(tmp_path, document)


def test_boolean_schema_version_is_refused_in_manifest_and_result(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["schemaVersion"] = True
    with pytest.raises(finalizer.ManifestError, match="unsupported schemaVersion"):
        finalize_document(tmp_path, document)

    document = complete_manifest(tmp_path / "other-evidence")
    gate = document["gates"][0]
    result_path = tmp_path / "other-evidence" / gate["resultEvidencePath"]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["schemaVersion"] = True
    write_json(result_path, result)
    gate["resultEvidenceSha256"] = sha256(result_path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        tmp_path / "other-evidence" / gate["evidencePath"]
    )
    manifest = tmp_path / "boolean-result.json"
    write_json(manifest, document)
    with pytest.raises(finalizer.ManifestError, match="violates its exact contract"):
        finalizer.finalize(manifest, tmp_path / "other-evidence")


def test_manifest_claim_cannot_override_hashed_gate_result(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][0]["sampleSatisfied"] = False
    with pytest.raises(finalizer.ManifestError, match="manifest claim does not match"):
        finalize_document(tmp_path, document)


def test_arbitrary_x_pass_cleanup_cannot_complete_group(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    cleanup = evidence / gate["cleanupEvidencePath"]
    cleanup.write_text("x=PASS\n", encoding="utf-8")
    gate["cleanupEvidenceSha256"] = sha256(cleanup.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / gate["evidencePath"]
    )
    with pytest.raises(finalizer.ManifestError, match="cleanup claim does not match"):
        finalize_document(tmp_path, document)


def test_all_failed_results_and_x_pass_cleanup_never_become_ready(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    for gate in document["gates"]:
        gate["status"] = "FAIL"
        cleanup = evidence / gate["cleanupEvidencePath"]
        cleanup.write_text("x=PASS\n", encoding="utf-8")
        gate["cleanupEvidenceSha256"] = sha256(cleanup.read_bytes())
        result_path = evidence / gate["resultEvidencePath"]
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["status"] = "FAIL"
        result["cleanupComplete"] = False
        write_json(result_path, result)
        gate["resultEvidenceSha256"] = sha256(result_path.read_bytes())
        gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
            evidence / gate["evidencePath"]
        )
    result, complete = finalize_document(tmp_path, document)
    assert complete is False
    assert result["status"] == "INCOMPLETE"
    assert result["overallReplacementReady"] is False
    assert all(
        f"gate-not-pass:{gate_id}" in result["reasons"] for gate_id in finalizer.REQUIRED_GATE_IDS
    )
    assert all(
        f"cleanup-not-pass:{gate_id}" in result["reasons"]
        for gate_id in finalizer.REQUIRED_GATE_IDS
    )


def test_cleanup_and_express_invariance_are_required(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    cleanup_document = complete_manifest(evidence)
    cleanup_gate = cleanup_document["gates"][0]
    cleanup_path = evidence / cleanup_gate["cleanupEvidencePath"]
    cleanup_path.write_text("terminateExpress=FAIL\n", encoding="utf-8")
    cleanup_gate["cleanupEvidenceSha256"] = sha256(cleanup_path.read_bytes())
    cleanup_result_path = evidence / cleanup_gate["resultEvidencePath"]
    cleanup_result = json.loads(cleanup_result_path.read_text(encoding="utf-8"))
    cleanup_result["cleanupComplete"] = False
    write_json(cleanup_result_path, cleanup_result)
    cleanup_gate["resultEvidenceSha256"] = sha256(cleanup_result_path.read_bytes())
    cleanup_gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / cleanup_gate["evidencePath"]
    )
    result, complete = finalize_document(tmp_path, cleanup_document)
    assert complete is False
    assert "cleanup-not-pass:independent-contract" in result["reasons"]

    invariance_document = complete_manifest(tmp_path / "other-evidence")
    other_evidence = tmp_path / "other-evidence"
    gate = invariance_document["gates"][0]
    after = other_evidence / gate["expressAfterPath"]
    after.write_text("changed\n", encoding="utf-8")
    gate["expressAfterSha256"] = sha256(after.read_bytes())
    result_path = other_evidence / gate["resultEvidencePath"]
    result_document = json.loads(result_path.read_text(encoding="utf-8"))
    result_document["expressSnapshotUnchanged"] = False
    write_json(result_path, result_document)
    gate["resultEvidenceSha256"] = sha256(result_path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        other_evidence / gate["evidencePath"]
    )
    manifest = tmp_path / "other-manifest.json"
    write_json(manifest, invariance_document)
    result, complete = finalizer.finalize(manifest, other_evidence)
    assert complete is False
    assert "express-invariance-failed:independent-contract" in result["reasons"]


def current_gate(
    evidence: Path,
    gate_id: str,
    bundle_relative: str,
    source_revision: str,
    *,
    sample_satisfied: bool,
) -> dict[str, Any]:
    bundle = evidence / bundle_relative
    cleanup = bundle / "cleanup.status"
    before = bundle / "express-before.txt"
    after = bundle / "express-after.txt"
    return {
        "gateId": gate_id,
        "topology": "recorded-local",
        "runId": bundle.name,
        "evidencePath": bundle_relative,
        "evidenceAggregateSha256": finalizer.evidence_aggregate_sha256(bundle),
        "sourceRevision": source_revision,
        "applicationTree": HASH_A,
        "schema": HASH_A,
        "lock": HASH_A,
        "config": HASH_A,
        "image": IMAGE_A,
        "status": "PASS",
        "sampleSatisfied": sample_satisfied,
        "readinessAssertionsSatisfied": False,
        "resultEvidencePath": (bundle / "gate-result.json").relative_to(evidence).as_posix(),
        "resultEvidenceSha256": sha256((bundle / "gate-result.json").read_bytes()),
        "cleanupEvidencePath": cleanup.relative_to(evidence).as_posix(),
        "cleanupEvidenceSha256": sha256(cleanup.read_bytes()),
        "expressBeforePath": before.relative_to(evidence).as_posix(),
        "expressBeforeSha256": sha256(before.read_bytes()),
        "expressAfterPath": after.relative_to(evidence).as_posix(),
        "expressAfterSha256": sha256(after.read_bytes()),
    }


def test_current_independent_and_shared_evidence_cannot_aggregate(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    independent_relative = "phase7-runtime/20260901t105243_3598166"
    shared_relative = "phase7-shared-runtime/20260901t114832_3911115"
    for gate_id, relative in (
        ("independent-contract", independent_relative),
        ("shared-state-core", shared_relative),
    ):
        target = evidence / relative
        shutil.copytree(EVIDENCE / relative, target)
        target.chmod(0o755)
        result = {
            "schemaVersion": 1,
            "gateId": gate_id,
            "runId": target.name,
            "status": "PASS",
            "sampleSatisfied": False,
            "readinessAssertionsSatisfied": False,
            "cleanupComplete": True,
            "expressSnapshotUnchanged": True,
            "overallReplacementReady": False,
        }
        write_json(target / "gate-result.json", result)
    document = {
        "schemaVersion": 1,
        "groupId": "current-recorded-runs",
        "gates": [
            current_gate(
                evidence,
                "independent-contract",
                independent_relative,
                "19bbdc2ee9ba7a00e3e2c465fb326d9bb476e2b9",
                sample_satisfied=False,
            ),
            current_gate(
                evidence,
                "shared-state-core",
                shared_relative,
                "992b8475212e986e5e64f39927b3b757ba313767",
                sample_satisfied=False,
            ),
        ],
    }
    manifest = tmp_path / "current.json"
    write_json(manifest, document)
    result, complete = finalizer.finalize(manifest, evidence)
    assert complete is False
    assert result["status"] == "INCOMPLETE"
    assert "mixed-provenance:sourceRevision" in result["reasons"]
    assert {reason for reason in result["reasons"] if reason.startswith("missing-gate:")} == {
        "missing-gate:performance",
        "missing-gate:security",
        "missing-gate:chaos",
        "missing-gate:backup-restore",
        "missing-gate:local-rollback",
    }


def test_schema_is_strict_and_lists_exact_required_gates() -> None:
    document = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert document["additionalProperties"] is False
    gate = document["$defs"]["gate"]
    assert gate["additionalProperties"] is False
    assert set(gate["properties"]["gateId"]["enum"]) == set(finalizer.REQUIRED_GATE_IDS)
