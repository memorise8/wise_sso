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
PROVENANCE_SCHEMA = ROOT / "ops" / "phase7" / "qualification-provenance.schema.json"
COLLECTOR_SCHEMA = ROOT / "ops" / "phase7" / "qualification-collector-attestation.schema.json"
SPEC = importlib.util.spec_from_file_location("phase7_qualification_group", FINALIZER)
assert SPEC is not None and SPEC.loader is not None
finalizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = finalizer
SPEC.loader.exec_module(finalizer)

HASH_A = "a" * 64
EXPRESS_IMAGE_A = f"sha256:{'b' * 64}"
FASTAPI_IMAGE_A = f"sha256:{'c' * 64}"
IMAGE_A = EXPRESS_IMAGE_A


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def make_repo(parent: Path, name: str = "repo", marker: str = "fixture") -> Path:
    repo = parent / name
    if repo.exists():
        return repo
    contents = {
        "auth-server/src/app.ts": f"export const app = 'express-{marker}';\n",
        "auth-server/public/app.js": f"console.log('public-{marker}');\n",
        "auth-server/prisma/migrations/0001_init/migration.sql": f"-- migration {marker}\n",
        "fastapi-auth-server/src/wiseacct_sso/main.py": f"app = 'fastapi-{marker}'\n",
        "fastapi-auth-server/README.md": f"# FastAPI {marker}\n",
    }
    for path in (
        *finalizer.EXPRESS_APPLICATION_FILES,
        *finalizer.FASTAPI_APPLICATION_FILES,
        *finalizer.EXPRESS_LOCK_FILES,
        *finalizer.FASTAPI_LOCK_FILES,
        *finalizer.SCHEMA_FILES,
        *finalizer.CONFIG_FILES,
    ):
        contents.setdefault(path, f"tracked input: {path}\n")
    for relative, content in contents.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run([finalizer.GIT, "init", "-q", str(repo)], check=True)  # noqa: S603
    subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "add", "."], check=True
    )
    subprocess.run(  # noqa: S603
        [
            finalizer.GIT,
            "-C",
            str(repo),
            "-c",
            "user.name=Phase7 Test",
            "-c",
            "user.email=phase7@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    return repo


def commit_change(repo: Path, relative: str, content: str) -> None:
    (repo / relative).write_text(content, encoding="utf-8")
    subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "add", relative], check=True
    )
    subprocess.run(  # noqa: S603
        [
            finalizer.GIT,
            "-C",
            str(repo),
            "-c",
            "user.name=Phase7 Test",
            "-c",
            "user.email=phase7@example.invalid",
            "commit",
            "-qm",
            "change",
        ],
        check=True,
    )


def make_bundle(root: Path, gate_id: str, repo_provenance: dict[str, str]) -> dict[str, Any]:
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
    collector_attestation = {
        "schemaVersion": 1,
        "collectorId": "uncontrolled-test-collector",
        "collectorRevision": "4" * 40,
        "collectorTreeObject": "5" * 40,
        "expressImageId": EXPRESS_IMAGE_A,
        "fastapiImageId": FASTAPI_IMAGE_A,
        "status": "UNVERIFIED",
    }
    collector_bytes = json.dumps(
        collector_attestation, sort_keys=True, separators=(",", ":")
    ).encode()
    (bundle / "collector-attestation.json").write_bytes(collector_bytes)
    provenance = {
        "schemaVersion": 2,
        "gateId": gate_id,
        "topology": "disposable-local",
        "runId": run_id,
        **repo_provenance,
        "expressImageId": EXPRESS_IMAGE_A,
        "fastapiImageId": FASTAPI_IMAGE_A,
        "collectorAttestationSha256": sha256(collector_bytes),
    }
    provenance_bytes = json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()
    (bundle / "provenance.json").write_bytes(provenance_bytes)
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
        **{field: provenance[field] for field in finalizer.PROVENANCE_FIELDS - {"schemaVersion"}},
        "status": "PASS",
        "sampleSatisfied": True,
        "readinessAssertionsSatisfied": True,
        "provenanceEvidencePath": f"{relative}/provenance.json",
        "provenanceEvidenceSha256": sha256(provenance_bytes),
        "collectorAttestationEvidencePath": f"{relative}/collector-attestation.json",
        "collectorAttestationEvidenceSha256": sha256(collector_bytes),
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
    repo = make_repo(evidence.parent)
    repo_provenance = finalizer.repository_provenance(repo)
    return {
        "schemaVersion": 2,
        "groupId": "qualification-1",
        "gates": [
            make_bundle(evidence, gate_id, repo_provenance)
            for gate_id in finalizer.REQUIRED_GATE_IDS
        ],
    }


def finalize_document(tmp_path: Path, document: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    manifest = tmp_path / "manifest.json"
    write_json(manifest, document)
    return cast(
        tuple[dict[str, Any], bool],
        finalizer.finalize(manifest, tmp_path / "evidence", tmp_path / "repo"),
    )


def replace_provenance(evidence: Path, gate: dict[str, Any], updates: dict[str, str]) -> None:
    path = evidence / gate["provenanceEvidencePath"]
    provenance = json.loads(path.read_text(encoding="utf-8"))
    provenance.update(updates)
    gate.update(updates)
    write_json(path, provenance)
    gate["provenanceEvidenceSha256"] = sha256(path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / gate["evidencePath"]
    )


def test_otherwise_complete_group_requires_controlled_collector(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    result, complete = finalize_document(tmp_path, complete_manifest(evidence))
    assert complete is False
    assert result["status"] == "INCOMPLETE"
    assert result["overallReplacementReady"] is False
    assert result["reasons"] == ["controlled-collector-required"]
    assert result["requiredGateIds"] == list(finalizer.REQUIRED_GATE_IDS)


def test_cli_is_nonzero_until_controlled_collector_exists(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = tmp_path / "manifest.json"
    write_json(manifest, complete_manifest(evidence))
    completed = subprocess.run(  # noqa: S603 - fixed repository helper path
        [
            str(FINALIZER),
            "--manifest",
            str(manifest),
            "--evidence-root",
            str(evidence),
            "--repo",
            str(tmp_path / "repo"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["status"] == "INCOMPLETE"


def test_missing_gate_is_incomplete_and_nonzero(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"].pop()
    manifest = tmp_path / "manifest.json"
    write_json(manifest, document)
    completed = subprocess.run(  # noqa: S603 - fixed repository helper path
        [
            str(FINALIZER),
            "--manifest",
            str(manifest),
            "--evidence-root",
            str(evidence),
            "--repo",
            str(tmp_path / "repo"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert completed.returncode == 1
    assert result["status"] == "INCOMPLETE"
    assert result["overallReplacementReady"] is False
    assert "missing-gate:local-rollback" in result["reasons"]


@pytest.mark.parametrize("field", ["sourceRevision", "configSha256", "fastapiImageId"])
def test_mixed_provenance_is_incomplete(tmp_path: Path, field: str) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    document["gates"][1][field] = {
        "sourceRevision": "2" * 40,
        "configSha256": "9" * 64,
        "fastapiImageId": f"sha256:{'9' * 64}",
    }[field]
    with pytest.raises(finalizer.ManifestError, match="manifest provenance does not match"):
        finalize_document(tmp_path, document)


def test_mixed_attached_provenance_is_incomplete(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    replace_provenance(evidence, document["gates"][1], {"configSha256": "9" * 64})
    with pytest.raises(finalizer.ManifestError, match="does not match repository"):
        finalize_document(tmp_path, document)


def test_mixed_pair_order_and_image_ids_are_incomplete(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][1]
    replace_provenance(
        evidence,
        gate,
        {
            "expressApplicationTreeSha256": gate["fastapiApplicationTreeSha256"],
            "fastapiApplicationTreeSha256": gate["expressApplicationTreeSha256"],
            "expressImageId": gate["fastapiImageId"],
            "fastapiImageId": gate["expressImageId"],
        },
    )
    with pytest.raises(finalizer.ManifestError, match="does not match repository"):
        finalize_document(tmp_path, document)


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


def test_cleanup_role_cannot_alias_gate_result_path(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    gate["cleanupEvidencePath"] = gate["resultEvidencePath"]
    gate["cleanupEvidenceSha256"] = gate["resultEvidenceSha256"]
    with pytest.raises(finalizer.ManifestError, match="distinct paths"):
        finalize_document(tmp_path, document)


def test_v2_manifest_without_hashed_provenance_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    del document["gates"][0]["provenanceEvidencePath"]
    del document["gates"][0]["provenanceEvidenceSha256"]
    with pytest.raises(finalizer.ManifestError, match="exact approved fields"):
        finalize_document(tmp_path, document)


def test_v2_manifest_without_collector_attachment_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    del document["gates"][0]["collectorAttestationEvidencePath"]
    del document["gates"][0]["collectorAttestationEvidenceSha256"]
    with pytest.raises(finalizer.ManifestError, match="exact approved fields"):
        finalize_document(tmp_path, document)


def test_repo_must_be_absolute_and_clean(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    with pytest.raises(finalizer.ManifestError, match="absolute"):
        finalizer.repository_provenance(Path("repo"))
    (repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(finalizer.ManifestError, match="clean"):
        finalizer.repository_provenance(repo)


def test_git_environment_cannot_redirect_repo_a_to_repo_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_a = make_repo(tmp_path, "repo-a", "a")
    repo_b = make_repo(tmp_path, "repo-b", "b")
    expected_a = finalizer.repository_provenance(repo_a)
    expected_b = finalizer.repository_provenance(repo_b)
    assert expected_a != expected_b
    overrides = {
        "GIT_DIR": str(repo_b / ".git"),
        "GIT_WORK_TREE": str(repo_b),
        "GIT_COMMON_DIR": str(repo_b / ".git"),
        "GIT_OBJECT_DIRECTORY": str(repo_b / ".git" / "objects"),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repo_b / ".git" / "objects"),
        "GIT_INDEX_FILE": str(repo_b / ".git" / "index"),
        "GIT_CONFIG": str(repo_b / ".git" / "config"),
        "GIT_CONFIG_GLOBAL": str(repo_b / ".git" / "config"),
        "GIT_CONFIG_SYSTEM": str(repo_b / ".git" / "config"),
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.worktree",
        "GIT_CONFIG_VALUE_0": str(repo_b),
        "GIT_CEILING_DIRECTORIES": str(tmp_path),
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "0",
    }
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    assert finalizer.repository_provenance(repo_a) == expected_a


def test_git_replace_ref_cannot_redirect_pinned_head_objects(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    commit_a = subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    commit_change(repo, "auth-server/src/app.ts", "export const app = 'replacement-b';\n")
    commit_b = subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "checkout", "--detach", "-q", commit_a],
        check=True,
    )
    subprocess.run(  # noqa: S603
        [finalizer.GIT, "-C", str(repo), "replace", commit_a, commit_b],
        check=True,
    )
    with pytest.raises(finalizer.ManifestError, match="replace refs"):
        finalizer.repository_provenance(repo)


def test_transient_worktree_mutation_does_not_change_head_blob_hashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo(tmp_path)
    expected = finalizer.repository_provenance(repo)
    source = repo / "auth-server" / "src" / "app.ts"
    original_bytes = source.read_bytes()
    original_git = finalizer._git
    status_calls = 0

    def mutate_between_status_checks(
        repo_descriptor: int, git_descriptor: int, *args: str
    ) -> bytes:
        nonlocal status_calls
        is_status = bool(args) and args[0] == "status"
        if is_status:
            status_calls += 1
            if status_calls == 2:
                source.write_bytes(original_bytes)
        result = cast(bytes, original_git(repo_descriptor, git_descriptor, *args))
        if is_status and status_calls == 1:
            source.write_text("transient attacker bytes\n", encoding="utf-8")
        return result

    monkeypatch.setattr(finalizer, "_git", mutate_between_status_checks)
    assert finalizer.repository_provenance(repo) == expected
    assert status_calls == 2


@pytest.mark.parametrize(
    ("relative", "expected_field", "stable_field"),
    [
        (
            "auth-server/public/app.js",
            "expressApplicationTreeSha256",
            "fastapiApplicationTreeSha256",
        ),
        (
            "auth-server/prisma/migrations/0001_init/migration.sql",
            "expressApplicationTreeSha256",
            "fastapiApplicationTreeSha256",
        ),
        (
            "fastapi-auth-server/README.md",
            "fastapiApplicationTreeSha256",
            "expressApplicationTreeSha256",
        ),
    ],
)
def test_every_docker_copy_application_input_changes_its_named_head_hash(
    tmp_path: Path, relative: str, expected_field: str, stable_field: str
) -> None:
    repo = make_repo(tmp_path)
    before = finalizer.repository_provenance(repo)
    commit_change(repo, relative, "committed changed input\n")
    after = finalizer.repository_provenance(repo)
    assert after[expected_field] != before[expected_field]
    assert after[stable_field] == before[stable_field]


@pytest.mark.parametrize("kind", ["linked", "bare"])
def test_linked_or_bare_git_metadata_is_refused(tmp_path: Path, kind: str) -> None:
    if kind == "linked":
        repo = make_repo(tmp_path)
        metadata = tmp_path / "metadata"
        (repo / ".git").rename(metadata)
        (repo / ".git").symlink_to(metadata, target_is_directory=True)
    else:
        repo = tmp_path / "bare"
        subprocess.run(  # noqa: S603
            [finalizer.GIT, "init", "--bare", "-q", str(repo)], check=True
        )
    with pytest.raises(finalizer.ManifestError, match="normal non-linked"):
        finalizer.repository_provenance(repo)


def test_provenance_file_cannot_fabricate_manifest_identity(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    path = evidence / gate["provenanceEvidencePath"]
    provenance = json.loads(path.read_text(encoding="utf-8"))
    provenance["runId"] = "fabricated-run"
    write_json(path, provenance)
    gate["provenanceEvidenceSha256"] = sha256(path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / gate["evidencePath"]
    )
    with pytest.raises(finalizer.ManifestError, match="manifest provenance does not match"):
        finalize_document(tmp_path, document)


def test_fully_consistent_fabricated_provenance_cannot_override_repo(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    fabricated = {
        "sourceRevision": "6" * 40,
        "gitTreeObject": "7" * 40,
        "expressApplicationTreeSha256": "1" * 64,
        "fastapiApplicationTreeSha256": "2" * 64,
        "schemaSha256": "3" * 64,
        "expressLockSha256": "4" * 64,
        "fastapiLockSha256": "5" * 64,
        "configSha256": "6" * 64,
    }
    for gate in document["gates"]:
        replace_provenance(evidence, gate, fabricated)
    with pytest.raises(finalizer.ManifestError, match="does not match repository"):
        finalize_document(tmp_path, document)


def test_global_express_fastapi_swap_cannot_override_named_repo_hashes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    for gate in document["gates"]:
        replace_provenance(
            evidence,
            gate,
            {
                "expressApplicationTreeSha256": gate["fastapiApplicationTreeSha256"],
                "fastapiApplicationTreeSha256": gate["expressApplicationTreeSha256"],
                "expressLockSha256": gate["fastapiLockSha256"],
                "fastapiLockSha256": gate["expressLockSha256"],
                "expressImageId": gate["fastapiImageId"],
                "fastapiImageId": gate["expressImageId"],
            },
        )
    with pytest.raises(finalizer.ManifestError, match="does not match repository"):
        finalize_document(tmp_path, document)


def test_ancestor_swap_cannot_redirect_descriptor_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    original = finalizer._open_relative_directory
    swapped = False

    def swap_after_open(root_descriptor: int, raw: object, label: str) -> int:
        nonlocal swapped
        descriptor = cast(int, original(root_descriptor, raw, label))
        if not swapped:
            moved = tmp_path / "pinned-evidence"
            evidence.rename(moved)
            evidence.symlink_to(moved, target_is_directory=True)
            swapped = True
        return descriptor

    monkeypatch.setattr(finalizer, "_open_relative_directory", swap_after_open)
    result, complete = finalize_document(tmp_path, document)
    assert complete is False
    assert result["reasons"] == ["controlled-collector-required"]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("unexpected", "claim", "exact approved fields"),
        ("schemaVersion", True, "schemaVersion is unsupported"),
        ("configSha256", True, "lowercase SHA-256"),
    ],
)
def test_provenance_extra_fields_and_boolean_types_are_refused(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    path = evidence / gate["provenanceEvidencePath"]
    provenance = json.loads(path.read_text(encoding="utf-8"))
    provenance[field] = value
    write_json(path, provenance)
    gate["provenanceEvidenceSha256"] = sha256(path.read_bytes())
    gate["evidenceAggregateSha256"] = finalizer.evidence_aggregate_sha256(
        evidence / gate["evidencePath"]
    )
    with pytest.raises(finalizer.ManifestError, match=message):
        finalize_document(tmp_path, document)


def test_hardlinked_provenance_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    document = complete_manifest(evidence)
    gate = document["gates"][0]
    provenance = evidence / gate["provenanceEvidencePath"]
    provenance.with_suffix(".hardlink").hardlink_to(provenance)
    with pytest.raises(finalizer.ManifestError, match="single-link regular file"):
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
        finalizer.finalize(manifest, tmp_path / "other-evidence", tmp_path / "repo")


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
    result, complete = finalizer.finalize(manifest, other_evidence, tmp_path / "repo")
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
    result, complete = finalizer.finalize(manifest, evidence, tmp_path / "repo")
    assert complete is False
    assert result["status"] == "INCOMPLETE"
    assert result["gateCount"] == 0
    assert result["reasons"] == ["migration-required:schemaVersion-1"]
    assert all(value is None for value in result["provenanceGroup"].values())


def test_schema_is_strict_and_lists_exact_required_gates() -> None:
    document = json.loads(SCHEMA.read_text(encoding="utf-8"))
    provenance = json.loads(PROVENANCE_SCHEMA.read_text(encoding="utf-8"))
    collector = json.loads(COLLECTOR_SCHEMA.read_text(encoding="utf-8"))
    assert document["properties"]["schemaVersion"]["const"] == 2
    assert document["additionalProperties"] is False
    gate = document["$defs"]["gate"]
    assert gate["additionalProperties"] is False
    assert set(gate["properties"]["gateId"]["enum"]) == set(finalizer.REQUIRED_GATE_IDS)
    assert provenance["properties"]["schemaVersion"]["const"] == 2
    assert provenance["additionalProperties"] is False
    assert set(provenance["required"]) == finalizer.PROVENANCE_FIELDS
    assert set(provenance["properties"]) == finalizer.PROVENANCE_FIELDS
    assert collector["additionalProperties"] is False
    assert set(collector["required"]) == finalizer.COLLECTOR_ATTESTATION_FIELDS
    assert set(collector["properties"]) == finalizer.COLLECTOR_ATTESTATION_FIELDS
