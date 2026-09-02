from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
INTAKE = ROOT / "ops" / "phase7" / "security" / "offline_stager_intake.py"
GATE = ROOT / "ops" / "phase7" / "security" / "security_gate.py"
SCHEMA = ROOT / "ops" / "phase7" / "security" / "online-stager-manifest.schema.json"
WRAPPER = ROOT / "ops" / "phase7" / "run-security-stager-intake.sh"
LOCK = ROOT / "ops" / "phase7" / "security" / "controlled-toolchain-lock.json"


def load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


intake = load(INTAKE, "phase7_security_stager_intake_test")
security_gate = load(GATE, "phase7_security_gate_stager_fixture")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_private(path: Path, data: bytes) -> dict[str, object]:
    path.write_bytes(data)
    path.chmod(0o600)
    return {"path": path.name, "sha256": sha(data), "sizeBytes": len(data)}


def initialize_repo(path: Path) -> tuple[str, str, dict[str, str]]:
    path.mkdir()
    required = set(security_gate.PINNED_FILES.values())
    for exact_paths, prefixes in security_gate.REPOSITORY_INPUT_GROUPS.values():
        required.update(exact_paths)
        for prefix in prefixes:
            required.add(f"{prefix}fixture")
    for relative in required:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(LOCK.read_bytes() if relative == intake.LOCK_RELATIVE else b"fixture\n")
    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["/usr/bin/git", "add", "."], cwd=path, check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-c",
            "user.name=Phase7",
            "-c",
            "user.email=phase7@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=path,
        check=True,
    )
    snapshot = security_gate.repository_snapshot(path)
    return (
        snapshot.provenance["sourceRevision"],
        snapshot.provenance["gitTreeObject"],
        cast(dict[str, str], snapshot.provenance),
    )


def make_bundle(root: Path, repo: Path, run_id: str = "stager-test") -> dict[str, Any]:
    root.mkdir(mode=0o700)
    revision, tree, provenance = initialize_repo(repo)
    counter = 0

    def artifact(label: str, payload: object | None = None) -> dict[str, object]:
        nonlocal counter
        counter += 1
        data = (
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            if payload is not None
            else f"{label}:{counter}\n".encode()
        )
        return write_private(root / f"{counter:02d}-{label}.json", data)

    images = []
    roles = (
        "builder",
        "collector",
        "scanner-gitleaks",
        "scanner-npm-audit",
        "scanner-pip-audit",
        "scanner-ruff",
        "scanner-semgrep",
        "scanner-trivy",
    )
    for index, role in enumerate(roles, start=1):
        digit = format(index, "x")
        digest = f"sha256:{digit * 64}"
        repository = f"registry.example.invalid/wiseacct/{role}"
        signature_raw = artifact(f"{role}-signature-raw")
        signature_descriptor = {
            "schemaVersion": 1,
            "kind": "signature",
            "status": "UNVERIFIED",
            "repository": repository,
            "subjectDigest": digest,
            "rawArtifactSha256": signature_raw["sha256"],
        }
        platform_digit = format(index + 8, "x")[-1]
        config_digit = format(index + 9, "x")[-1]
        platform_digest = f"sha256:{platform_digit * 64}"
        config_digest = f"sha256:{config_digit * 64}"
        archive = artifact(f"{role}-archive")
        attestation_raw = artifact(f"{role}-attestation-raw")
        attestation_descriptor = {
            "schemaVersion": 1,
            "kind": "attestation",
            "status": "UNVERIFIED",
            "repository": repository,
            "subjectDigest": digest,
            "predicateType": "https://slsa.dev/provenance/v1",
            "role": role,
            "archiveSha256": archive["sha256"],
            "platformDigest": platform_digest,
            "configDigest": config_digest,
            "targetPlatform": {"os": "linux", "architecture": "amd64", "variant": None},
            "rawArtifactSha256": attestation_raw["sha256"],
        }
        images.append(
            {
                "role": role,
                "repository": repository,
                "requestedReference": f"{repository}@{digest}",
                "indexDigest": digest,
                "platformDigest": platform_digest,
                "configDigest": config_digest,
                "archive": archive,
                "signatures": [
                    {
                        "status": "UNVERIFIED",
                        "subjectDigest": digest,
                        "rawArtifact": signature_raw,
                        "descriptor": artifact(
                            f"{role}-signature-descriptor", signature_descriptor
                        ),
                    }
                ],
                "attestations": [
                    {
                        "status": "UNVERIFIED",
                        "subjectDigest": digest,
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "rawArtifact": attestation_raw,
                        "descriptor": artifact(
                            f"{role}-attestation-descriptor", attestation_descriptor
                        ),
                    }
                ],
                "fetchedAt": "2026-09-02T00:00:00Z",
            }
        )
    updated = "2026-09-02T00:00:00Z"
    trivy = []
    for index, kind in enumerate(("vulnerability-db", "java-db", "checks-bundle"), start=9):
        digest = f"sha256:{format(index, 'x') * 64}"
        repository = f"registry.example.invalid/aquasecurity/{kind}"
        signature_raw = artifact(f"{kind}-signature-raw")
        signature_descriptor = {
            "schemaVersion": 1,
            "kind": "signature",
            "status": "UNVERIFIED",
            "repository": repository,
            "subjectDigest": digest,
            "rawArtifactSha256": signature_raw["sha256"],
        }
        payload = artifact(kind)
        attestation_raw = artifact(f"{kind}-attestation-raw")
        attestation_descriptor = {
            "schemaVersion": 1,
            "kind": "attestation",
            "status": "UNVERIFIED",
            "repository": repository,
            "subjectDigest": digest,
            "predicateType": "https://slsa.dev/provenance/v1",
            "artifactKind": kind,
            "payloadSha256": payload["sha256"],
            "updatedAt": updated,
            "nextUpdateAt": "2026-09-02T12:00:00Z",
            "rawArtifactSha256": attestation_raw["sha256"],
        }
        trivy.append(
            {
                "kind": kind,
                "repository": repository,
                "manifestDigest": digest,
                "payload": payload,
                "updatedAt": updated,
                "nextUpdateAt": "2026-09-02T12:00:00Z",
                "signatures": [
                    {
                        "status": "UNVERIFIED",
                        "subjectDigest": digest,
                        "rawArtifact": signature_raw,
                        "descriptor": artifact(
                            f"{kind}-signature-descriptor", signature_descriptor
                        ),
                    }
                ],
                "attestations": [
                    {
                        "status": "UNVERIFIED",
                        "subjectDigest": digest,
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "rawArtifact": attestation_raw,
                        "descriptor": artifact(
                            f"{kind}-attestation-descriptor", attestation_descriptor
                        ),
                    }
                ],
            }
        )
    destinations = [
        {"scheme": "https", "host": "registry.example.invalid", "port": 443},
        {"scheme": "https", "host": "pypi.example.invalid", "port": 443},
        {"scheme": "https", "host": "npm.example.invalid", "port": 443},
    ]
    network_raw = artifact("network-evidence-raw")
    network_descriptor = {
        "schemaVersion": 1,
        "kind": "network-observation",
        "status": "STAGED_UNVERIFIED",
        "defaultDeny": True,
        "destinations": destinations,
        "rawArtifactSha256": network_raw["sha256"],
    }
    network = {
        "mode": "default-deny",
        "observationStatus": "STAGED_UNVERIFIED",
        "destinations": destinations,
        "evidence": {
            "rawArtifact": network_raw,
            "descriptor": artifact("network-evidence-descriptor", network_descriptor),
        },
    }
    advisory = []
    for ecosystem, host, lock_field in (
        ("pip", "pypi.example.invalid", "fastapiLockSha256"),
        ("npm", "npm.example.invalid", "expressLockSha256"),
    ):
        producer = "pip-audit" if ecosystem == "pip" else "npm-audit"
        origin = f"https://{host}:443"
        lock_hash = provenance[lock_field]
        request_raw = artifact(f"{ecosystem}-request-raw")
        request_descriptor = {
            "schemaVersion": 1,
            "kind": "advisory-request",
            "ecosystem": ecosystem,
            "producer": producer,
            "serviceOrigin": origin,
            "lockSha256": lock_hash,
            "rawArtifactSha256": request_raw["sha256"],
        }
        response_raw = artifact(f"{ecosystem}-response-raw")
        response_descriptor = {
            "schemaVersion": 1,
            "kind": "advisory-response",
            "status": "STAGED_UNVERIFIED",
            "ecosystem": ecosystem,
            "producer": producer,
            "serviceOrigin": origin,
            "lockSha256": lock_hash,
            "requestRawArtifactSha256": request_raw["sha256"],
            "responseRawArtifactSha256": response_raw["sha256"],
            "observedAt": updated,
        }
        advisory.append(
            {
                "ecosystem": ecosystem,
                "producer": producer,
                "serviceOrigin": origin,
                "lockSha256": lock_hash,
                "request": {
                    "rawArtifact": request_raw,
                    "descriptor": artifact(f"{ecosystem}-request-descriptor", request_descriptor),
                },
                "response": {
                    "rawArtifact": response_raw,
                    "descriptor": artifact(f"{ecosystem}-response-descriptor", response_descriptor),
                },
                "observedAt": updated,
            }
        )
    records = []
    for path in sorted(root.iterdir()):
        data = path.read_bytes()
        records.append(f"{path.name}\0{sha(data)}\0{len(data)}\n".encode())
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "phase7-online-stager-manifest",
        "runId": run_id,
        "status": "STAGED_UNVERIFIED",
        "createdAt": "2026-09-02T00:00:00Z",
        "expiresAt": "2026-09-02T12:00:00Z",
        "sourceRevision": revision,
        "gitTreeObject": tree,
        "toolchainLockSha256": sha(LOCK.read_bytes()),
        "targetPlatform": {"os": "linux", "architecture": "amd64", "variant": None},
        "networkScope": network,
        "images": images,
        "trivyArtifacts": trivy,
        "advisoryReports": advisory,
        "aggregateSha256": sha(b"".join(records)),
    }
    write_private(root / intake.MANIFEST_NAME, (json.dumps(manifest) + "\n").encode())
    return manifest


def write_manifest(bundle: Path, manifest: dict[str, Any]) -> bytes:
    raw = (json.dumps(manifest) + "\n").encode()
    (bundle / intake.MANIFEST_NAME).write_bytes(raw)
    (bundle / intake.MANIFEST_NAME).chmod(0o600)
    return raw


def refresh_aggregate(bundle: Path, manifest: dict[str, Any]) -> None:
    records = []
    for artifact in sorted(path for path in bundle.iterdir() if path.name != intake.MANIFEST_NAME):
        data = artifact.read_bytes()
        records.append(f"{artifact.name}\0{sha(data)}\0{len(data)}\n".encode())
    manifest["aggregateSha256"] = sha(b"".join(records))


def replace_artifact(
    bundle: Path, manifest: dict[str, Any], descriptor: dict[str, Any], payload: object
) -> None:
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = bundle / descriptor["path"]
    path.write_bytes(data)
    path.chmod(0o600)
    descriptor.update(sha256=sha(data), sizeBytes=len(data))
    refresh_aggregate(bundle, manifest)


def validate(bundle: Path, repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    raw = write_manifest(bundle, manifest)
    return cast(
        dict[str, Any],
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        ),
    )


def test_valid_staged_bundle_is_controller_only_incomplete(tmp_path: Path) -> None:
    bundle, repo, evidence = tmp_path / "bundle", tmp_path / "repo", tmp_path / "evidence"
    make_bundle(bundle, repo)
    manifest = intake.validate_manifest(
        (bundle / intake.MANIFEST_NAME).read_bytes(),
        bundle,
        "stager-test",
        repo,
        dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
    )
    assert manifest["status"] == "STAGED_UNVERIFIED"
    raw_paths = (
        manifest["images"][0]["archive"]["path"],
        manifest["images"][0]["signatures"][0]["rawArtifact"]["path"],
        manifest["images"][0]["attestations"][0]["rawArtifact"]["path"],
        manifest["trivyArtifacts"][0]["payload"]["path"],
        manifest["networkScope"]["evidence"]["rawArtifact"]["path"],
        manifest["advisoryReports"][0]["request"]["rawArtifact"]["path"],
        manifest["advisoryReports"][0]["response"]["rawArtifact"]["path"],
    )
    assert all(not (bundle / path).read_bytes().startswith(b"{") for path in raw_paths)
    output = intake.publish(
        evidence,
        "stager-test",
        "INCOMPLETE",
        ["TOOLCHAIN_LOCK_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"],
        True,
    )
    assert {path.name for path in output.iterdir()} == {"gate-result.json", "result.status"}
    result = json.loads((output / "gate-result.json").read_text())
    assert result["intakeValidated"] is True
    assert result["overallReplacementReady"] is False
    assert "PASS" not in (output / "result.status").read_text()


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda manifest: manifest.update(status="VERIFIED"), "identity"),
        (lambda manifest: manifest["networkScope"]["destinations"][0].update(port=80), "https-443"),
        (
            lambda manifest: manifest["advisoryReports"][0].update(lockSha256="a" * 64),
            "lock-binding",
        ),
        (
            lambda manifest: manifest["images"][0]["signatures"][0].update(
                subjectDigest="sha256:" + "f" * 64
            ),
            "subject",
        ),
    ],
)
def test_rejects_untrusted_claims_and_unbound_artifacts(
    tmp_path: Path, mutate: Any, message: str
) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    mutate(manifest)
    raw = (json.dumps(manifest) + "\n").encode()
    (bundle / intake.MANIFEST_NAME).write_bytes(raw)
    with pytest.raises(intake.Failed, match=message):
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


def test_rejects_network_scope_without_default_deny_mode(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["networkScope"]["mode"] = "allowlisted"
    raw = (json.dumps(manifest) + "\n").encode()
    (bundle / intake.MANIFEST_NAME).write_bytes(raw)
    with pytest.raises(intake.Failed, match="default-deny"):
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["targetPlatform"].update(architecture=[]),
        lambda value: value["images"][0].update(role={}),
        lambda value: value["trivyArtifacts"][0].update(kind=[]),
        lambda value: value["advisoryReports"][0].update(ecosystem={}),
        lambda value: value["images"][0]["attestations"][0].update(predicateType=[]),
    ],
)
def test_rejects_unhashable_enum_values_as_malformed(tmp_path: Path, mutate: Any) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    mutate(manifest)
    raw = (json.dumps(manifest) + "\n").encode()
    with pytest.raises(intake.Failed):
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


def test_rejects_non_rfc3339_timestamp_separator(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["createdAt"] = "2026-09-02 00:00:00Z"
    raw = (json.dumps(manifest) + "\n").encode()
    with pytest.raises(intake.Failed, match="timestamp"):
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


def test_rejects_boolean_schema_version(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["schemaVersion"] = True
    with pytest.raises(intake.Failed, match="identity"):
        validate(bundle, repo, manifest)


@pytest.mark.parametrize("field", ["indexDigest", "platformDigest", "configDigest"])
def test_rejects_image_digest_swaps(tmp_path: Path, field: str) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["images"][0][field], manifest["images"][1][field] = (
        manifest["images"][1][field],
        manifest["images"][0][field],
    )
    with pytest.raises(intake.Failed, match=r"(?:role-or-digest|subject|artifact-payload:binding)"):
        validate(bundle, repo, manifest)


def test_rejects_role_and_whole_platform_swaps(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["images"][0]["role"], manifest["images"][1]["role"] = (
        manifest["images"][1]["role"],
        manifest["images"][0]["role"],
    )
    with pytest.raises(intake.Failed, match="artifact-payload:binding"):
        validate(bundle, repo, manifest)
    manifest = make_bundle(tmp_path / "bundle2", tmp_path / "repo2")
    manifest["targetPlatform"] = {"os": "linux", "architecture": "arm64", "variant": "v8"}
    with pytest.raises(intake.Failed, match="artifact-payload:binding"):
        validate(tmp_path / "bundle2", tmp_path / "repo2", manifest)


def test_rejects_invalid_platform_and_duplicate_role(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["targetPlatform"]["variant"] = "v8"
    with pytest.raises(intake.Failed, match="targetPlatform"):
        validate(bundle, repo, manifest)
    manifest = make_bundle(tmp_path / "bundle2", tmp_path / "repo2")
    manifest["images"][1]["role"] = manifest["images"][0]["role"]
    with pytest.raises(intake.Failed, match="role-or-digest"):
        validate(tmp_path / "bundle2", tmp_path / "repo2", manifest)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(createdAt="2026-08-31T00:00:00Z"),
        lambda value: value.update(expiresAt="2026-09-02T00:30:00Z"),
        lambda value: value["images"][0].update(fetchedAt="2026-08-31T00:00:00Z"),
        lambda value: value["trivyArtifacts"][0].update(updatedAt="2026-08-31T00:00:00Z"),
        lambda value: value["trivyArtifacts"][0].update(nextUpdateAt="2026-09-02T00:30:00Z"),
        lambda value: value["advisoryReports"][0].update(observedAt="2026-08-31T00:00:00Z"),
    ],
)
def test_rejects_stale_or_expired_times(tmp_path: Path, mutation: Any) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    mutation(manifest)
    with pytest.raises(intake.Failed, match=r"stale|expired"):
        validate(bundle, repo, manifest)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["advisoryReports"][0].update(producer="npm-audit"),
        lambda value: value["advisoryReports"][0].update(lockSha256="a" * 64),
        lambda value: value["advisoryReports"][0].update(
            request=value["advisoryReports"][1]["request"]
        ),
        lambda value: value["advisoryReports"][0].update(
            response=value["advisoryReports"][1]["response"]
        ),
    ],
)
def test_rejects_advisory_producer_lock_request_response_swaps(
    tmp_path: Path, mutation: Any
) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    mutation(manifest)
    with pytest.raises(intake.Failed, match=r"producer|lock-binding|blob|artifact-payload"):
        validate(bundle, repo, manifest)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["networkScope"]["destinations"][0].update(host="*.invalid"),
        lambda value: value["networkScope"]["destinations"][0].update(scheme="http"),
        lambda value: value["networkScope"]["destinations"][0].update(port=8443),
        lambda value: value["advisoryReports"][0].update(
            serviceOrigin="https://unreported.example.invalid:443"
        ),
    ],
)
def test_rejects_unsafe_or_unreported_network_destinations(tmp_path: Path, mutation: Any) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    mutation(manifest)
    with pytest.raises(intake.Failed, match=r"https-443|undeclared-destination"):
        validate(bundle, repo, manifest)


def test_rejects_hardlinked_or_hash_mismatched_artifact(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    archive = bundle / manifest["images"][0]["archive"]["path"]
    os.link(archive, tmp_path / "alias")
    with pytest.raises(intake.Failed, match="unsafe"):
        intake.validate_manifest(
            (bundle / intake.MANIFEST_NAME).read_bytes(),
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


@pytest.mark.parametrize("case", ["extra", "missing", "symlink", "mode", "size", "hash"])
def test_exact_private_bundle_file_boundary(tmp_path: Path, case: str) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    descriptor = manifest["images"][0]["archive"]
    artifact = bundle / descriptor["path"]
    if case == "extra":
        write_private(bundle / "unexpected", b"unexpected\n")
        expected_error = intake.Failed
    elif case == "missing":
        artifact.unlink()
        expected_error = intake.Incomplete
    elif case == "symlink":
        artifact.unlink()
        artifact.symlink_to(tmp_path / "outside")
        expected_error = intake.Failed
    elif case == "mode":
        artifact.chmod(0o644)
        expected_error = intake.Failed
    elif case == "size":
        descriptor["sizeBytes"] += 1
        expected_error = intake.Failed
    else:
        descriptor["sha256"] = "f" * 64
        expected_error = intake.Failed
    with pytest.raises(expected_error):
        validate(bundle, repo, manifest)


def test_regular_file_toctou_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"original\n")
    artifact.chmod(0o600)
    original_read = intake.os.read
    changed = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        data = cast(bytes, original_read(descriptor, count))
        if data and not changed:
            changed = True
            artifact.write_bytes(b"changed-longer\n")
        return data

    monkeypatch.setattr(intake.os, "read", racing_read)
    with pytest.raises(intake.Failed, match="changed"):
        intake.regular_bytes(artifact)


def test_rejects_forged_signature_payload_even_when_outer_hashes_match(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    signature = manifest["images"][0]["signatures"][0]
    forged = {
        "schemaVersion": 1,
        "kind": "signature",
        "status": "UNVERIFIED",
        "repository": manifest["images"][0]["repository"],
        "subjectDigest": f"sha256:{'f' * 64}",
        "rawArtifactSha256": signature["rawArtifact"]["sha256"],
    }
    data = (json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path = bundle / signature["descriptor"]["path"]
    path.write_bytes(data)
    signature["descriptor"].update(sha256=sha(data), sizeBytes=len(data))
    records = []
    for artifact in sorted(path for path in bundle.iterdir() if path.name != intake.MANIFEST_NAME):
        artifact_data = artifact.read_bytes()
        records.append(f"{artifact.name}\0{sha(artifact_data)}\0{len(artifact_data)}\n".encode())
    manifest["aggregateSha256"] = sha(b"".join(records))
    raw = (json.dumps(manifest) + "\n").encode()
    (bundle / intake.MANIFEST_NAME).write_bytes(raw)
    with pytest.raises(intake.Failed, match="artifact-payload:binding"):
        intake.validate_manifest(
            raw,
            bundle,
            "stager-test",
            repo,
            dt.datetime(2026, 9, 2, 1, tzinfo=dt.UTC),
        )


@pytest.mark.parametrize("artifact_kind", ["attestation", "network"])
def test_rejects_forged_bound_payload_with_recomputed_outer_hashes(
    tmp_path: Path, artifact_kind: str
) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    if artifact_kind == "attestation":
        descriptor = manifest["images"][0]["attestations"][0]["descriptor"]
        payload = json.loads((bundle / descriptor["path"]).read_text())
        payload["configDigest"] = f"sha256:{'f' * 64}"
    else:
        descriptor = manifest["networkScope"]["evidence"]["descriptor"]
        payload = json.loads((bundle / descriptor["path"]).read_text())
        payload["defaultDeny"] = 1
    replace_artifact(bundle, manifest, descriptor, payload)
    with pytest.raises(intake.Failed, match="artifact-payload:binding"):
        validate(bundle, repo, manifest)


@pytest.mark.parametrize("field", ["kind", "payload", "updatedAt", "nextUpdateAt"])
def test_rejects_trivy_material_swaps(tmp_path: Path, field: str) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    if field in {"kind", "payload"}:
        manifest["trivyArtifacts"][0][field], manifest["trivyArtifacts"][1][field] = (
            manifest["trivyArtifacts"][1][field],
            manifest["trivyArtifacts"][0][field],
        )
    elif field == "updatedAt":
        manifest["trivyArtifacts"][0][field] = "2026-09-02T00:30:00Z"
    else:
        manifest["trivyArtifacts"][0][field] = "2026-09-02T13:00:00Z"
    with pytest.raises(intake.Failed, match=r"blob|artifact-payload:binding"):
        validate(bundle, repo, manifest)


def test_rejects_unreported_image_and_trivy_registries(tmp_path: Path) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    manifest["images"][0]["repository"] = "unreported.example.invalid/tool"
    manifest["images"][0]["requestedReference"] = (
        f"unreported.example.invalid/tool@{manifest['images'][0]['indexDigest']}"
    )
    with pytest.raises(intake.Failed, match="undeclared-registry"):
        validate(bundle, repo, manifest)
    manifest = make_bundle(tmp_path / "bundle2", tmp_path / "repo2")
    manifest["trivyArtifacts"][0]["repository"] = "unreported.example.invalid/db"
    with pytest.raises(intake.Failed, match="undeclared-registry"):
        validate(tmp_path / "bundle2", tmp_path / "repo2", manifest)


def test_isolated_valid_intake_ignores_poisoned_environment_and_marker_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, repo = tmp_path / "bundle", tmp_path / "repo"
    manifest = make_bundle(bundle, repo)
    marker = tmp_path / "marker"
    marker_bin = tmp_path / "bin"
    marker_bin.mkdir()
    for name in ("git", "docker", "trivy", "semgrep", "gitleaks"):
        executable = marker_bin / name
        executable.write_text(f"#!/bin/sh\n: > '{marker}'\nexit 99\n")
        executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(marker_bin))
    monkeypatch.setenv("BASH_ENV", str(marker))
    monkeypatch.setenv("PYTHONPATH", str(marker_bin))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(marker))
    assert validate(bundle, repo, manifest)["status"] == "STAGED_UNVERIFIED"
    assert not marker.exists()


def test_missing_input_is_incomplete_and_never_executes_marker(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    marker_bin = tmp_path / "bin"
    marker_bin.mkdir()
    for name in ("git", "docker", "trivy", "semgrep", "gitleaks"):
        executable = marker_bin / name
        executable.write_text(f"#!/bin/sh\n: > '{marker}'\nexit 99\n")
        executable.chmod(0o700)
    result = subprocess.run(  # noqa: S603 - fixed interpreter and test-controlled arguments
        [
            "/usr/bin/python3",
            "-I",
            str(INTAKE),
            "--input",
            str(tmp_path / "missing"),
            "--run-id",
            "missing-test",
            "--repo",
            str(tmp_path / "repo"),
            "--evidence-root",
            str(tmp_path / "evidence"),
        ],
        env={
            "PATH": str(marker_bin),
            "PYTHONPATH": str(marker_bin),
            "GIT_CONFIG_GLOBAL": str(marker),
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3
    assert not marker.exists()
    assert "MISSING_EVIDENCE" in (tmp_path / "evidence/missing-test/result.status").read_text()


def test_wrapper_is_fixed_isolated_and_schema_is_exact() -> None:
    script = WRAPPER.read_text()
    assert "/usr/bin/env -i" in script
    assert "PATH=/usr/bin:/bin" in script
    assert "/usr/bin/python3 -I" in script
    schema = json.loads(SCHEMA.read_text())
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == intake.TOP_FIELDS
    assert schema["properties"]["status"] == {"const": "STAGED_UNVERIFIED"}
    assert stat.S_IMODE(WRAPPER.stat().st_mode) == 0o755
