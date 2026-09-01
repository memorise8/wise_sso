from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "ops" / "phase7" / "security" / "security_gate.py"
SPEC = importlib.util.spec_from_file_location("phase7_security_gate", GATE)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

NOW = dt.datetime(2026, 9, 1, 0, 0, tzinfo=dt.UTC)
NOW_TEXT = "2026-09-01T00:00:00Z"
HASH = "a" * 64
IMAGE = f"sha256:{'b' * 64}"


def dump(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def initialize_repo(path: Path) -> tuple[str, str]:
    path.mkdir()
    (path / "tracked").write_text("committed\n", encoding="utf-8")
    for relative in set(gate.PINNED_FILES.values()):
        pinned = path / relative
        pinned.parent.mkdir(parents=True, exist_ok=True)
        if relative == gate.PINNED_FILES["policySha256"]:
            pinned.write_bytes(dump(gate.EXPECTED_POLICY))
        else:
            pinned.write_text(f"fixture:{relative}\n", encoding="utf-8")
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
    revision = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD^{tree}"],
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return revision, tree


def subject(revision: str, tree: str) -> dict[str, str]:
    return {
        "sourceRevision": revision,
        "applicationTree": tree,
        "imageId": IMAGE,
        "imageConfig": HASH,
        "baseImage": HASH,
    }


def scanner(name: str, scope: str, rule_hash: str = HASH) -> dict[str, str]:
    return {
        "name": name,
        "version": "1.2.3",
        "imageDigest": IMAGE,
        "databaseUpdatedAt": NOW_TEXT,
        "mode": "offline",
        "scope": scope,
        "ruleSha256": rule_hash,
    }


def report(name: str, category: str, revision: str, tree: str, rule_hash: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "scanner": scanner(name, "image" if name == "trivy" else category, rule_hash),
        "subject": subject(revision, tree),
        "findings": [],
    }


def sarif(names: list[str], revision: str, tree: str, rule_hash: str) -> dict[str, Any]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": name, "version": "1.2.3"}},
                "properties": {
                    "databaseUpdatedAt": NOW_TEXT,
                    "imageDigest": IMAGE,
                    "mode": "offline",
                    "scope": (
                        "full-history"
                        if name == "gitleaks"
                        else "filesystem"
                        if name == "trivy"
                        else "source-security"
                    ),
                    "ruleSha256": rule_hash,
                    "subject": subject(revision, tree),
                },
                "results": [],
            }
            for name in names
        ],
    }


def write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def make_input(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    revision, tree = initialize_repo(repo)
    rule_hash = hashlib.sha256((repo / gate.PINNED_FILES["ruleSha256"]).read_bytes()).hexdigest()
    source = tmp_path / "input"
    source.mkdir(mode=0o700)
    blobs: dict[str, bytes] = {}
    for name, (tool, category) in gate.DEPENDENCY_REPORTS.items():
        blobs[name] = dump(report(tool, category, revision, tree, rule_hash))
    for name in gate.IMAGE_REPORTS:
        blobs[name] = dump(report("trivy", "image", revision, tree, rule_hash))
    blobs.update(
        {
            "sast.sarif": dump(sarif(["ruff", "semgrep"], revision, tree, rule_hash)),
            "secrets.sarif": dump(sarif(["gitleaks", "trivy"], revision, tree, rule_hash)),
            "sbom.cdx.json": dump(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
                    "version": 1,
                    "metadata": {
                        "timestamp": NOW_TEXT,
                        "scanner": scanner("trivy", "image", rule_hash),
                        "subject": subject(revision, tree),
                    },
                    "components": [],
                }
            ),
            "licenses.json": dump(
                {
                    "schemaVersion": 1,
                    "scanner": scanner("trivy", "image", rule_hash),
                    "subject": subject(revision, tree),
                    "manualReview": [],
                    "packages": [],
                }
            ),
            "hardening.status": b"".join(
                f"{key}=PASS\n".encode() for key in sorted(gate.HARDENING_KEYS)
            ),
            "negative-tests.xml": (
                f'<testsuite tests="{len(gate.REQUIRED_NEGATIVE_TESTS)}" failures="0" '
                'errors="0" skipped="0">'
                + "".join(
                    f'<testcase classname="phase7-security" name="{name}" time="0.001">'
                    f'<properties><property name="evidenceSha256" value="{HASH}"/>'
                    "</properties></testcase>"
                    for name in sorted(gate.REQUIRED_NEGATIVE_TESTS)
                )
                + "</testsuite>\n"
            ).encode(),
            "negative-tests.status": (
                f"status=PASS\ntests={len(gate.REQUIRED_NEGATIVE_TESTS)}\n"
                "failures=0\nerrors=0\nskipped=0\n"
            ).encode(),
            "sanitization.status": b"status=PASS\nsecretPatterns=0\npiiPatterns=0\nunsafePaths=0\n",
            "cleanup.status": b"".join(
                f"{key}=PASS\n".encode() for key in sorted(gate.CLEANUP_KEYS)
            ),
            "express-before.txt": b"stable-sanitized-snapshot\n",
            "express-after.txt": b"stable-sanitized-snapshot\n",
            "candidate-inventory.json": dump(
                {"schemaVersion": 1, "imageId": IMAGE, "resources": []}
            ),
        }
    )
    for name, data in blobs.items():
        write_private(source / name, data)
    hashes = ",".join(f"{name}:{hashlib.sha256(blobs[name]).hexdigest()}" for name in sorted(blobs))
    provenance = {
        "schemaVersion": "1",
        "runId": "security-test",
        "sourceRevision": revision,
        "applicationTree": tree,
        **{
            key: hashlib.sha256((repo / relative).read_bytes()).hexdigest()
            for key, relative in gate.PINNED_FILES.items()
        },
        "imageId": IMAGE,
        "imageConfig": HASH,
        "baseImage": HASH,
        "scannerImages": json.dumps(
            {name: IMAGE for name in sorted(gate.SCANNER_NAMES)}, separators=(",", ":")
        ),
        "scannerVersions": json.dumps(
            {name: "1.2.3" for name in sorted(gate.SCANNER_NAMES)}, separators=(",", ":")
        ),
        "scannerDatabaseUpdatedAt": NOW_TEXT,
        "network": "disabled",
        "sockets": "none",
        "reportHashes": hashes,
        "expressBeforeSha256": hashlib.sha256(blobs["express-before.txt"]).hexdigest(),
        "expressAfterSha256": hashlib.sha256(blobs["express-after.txt"]).hexdigest(),
        "candidateInventorySha256": hashlib.sha256(blobs["candidate-inventory.json"]).hexdigest(),
        "cleanupInventorySha256": hashlib.sha256(blobs["cleanup.status"]).hexdigest(),
    }
    write_private(
        source / "provenance.txt",
        b"".join(f"{key}={value}\n".encode() for key, value in provenance.items()),
    )
    return source, repo


def refresh_provenance_hashes(source: Path) -> None:
    path = source / "provenance.txt"
    values = gate.parse_pairs(path.read_bytes(), gate.PROVENANCE_KEYS, "provenance")
    values["reportHashes"] = ",".join(
        f"{name}:{hashlib.sha256((source / name).read_bytes()).hexdigest()}"
        for name in sorted(gate.EXPECTED_INPUTS - {"provenance.txt"})
    )
    for key, name in {
        "expressBeforeSha256": "express-before.txt",
        "expressAfterSha256": "express-after.txt",
        "candidateInventorySha256": "candidate-inventory.json",
        "cleanupInventorySha256": "cleanup.status",
    }.items():
        values[key] = hashlib.sha256((source / name).read_bytes()).hexdigest()
    write_private(path, b"".join(f"{key}={value}\n".encode() for key, value in values.items()))


def validate(source: Path, repo: Path) -> None:
    gate.validate_bundle(source, "security-test", repo, NOW)


def set_package_licenses(
    source: Path, license_ids: list[str], manual_review: list[str] | None = None
) -> None:
    purl = "pkg:npm/x@1"
    sbom_path = source / "sbom.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"] = [{"name": "x", "version": "1", "purl": purl, "licenses": license_ids}]
    write_private(sbom_path, dump(sbom))
    license_path = source / "licenses.json"
    licenses = json.loads(license_path.read_text(encoding="utf-8"))
    licenses["manualReview"] = manual_review or []
    licenses["packages"] = [{"name": "x", "version": "1", "purl": purl, "licenses": license_ids}]
    write_private(license_path, dump(licenses))


def test_valid_bundle_publishes_immutable_pass(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    blobs, reasons = gate.validate_bundle(source, "security-test", repo, NOW)
    output = gate.publish(tmp_path / "evidence", "security-test", blobs, "PASS", reasons)
    assert stat.S_IMODE(output.stat().st_mode) == 0o500
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in output.iterdir())
    result = json.loads((output / "gate-result.json").read_text(encoding="utf-8"))
    assert result["status"] == "INCOMPLETE"
    assert result["readinessAssertionsSatisfied"] is False
    assert result["overallReplacementReady"] is False


def test_missing_artifact_is_incomplete(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    (source / "sast.sarif").unlink()
    with pytest.raises(gate.Incomplete, match=r"missing:sast\.sarif"):
        validate(source, repo)


@pytest.mark.parametrize(
    ("unexpected", "exit_code", "status"), [(False, 3, "INCOMPLETE"), (True, 2, "FAIL")]
)
def test_cli_distinguishes_missing_from_malformed(
    tmp_path: Path, unexpected: bool, exit_code: int, status: str
) -> None:
    source = tmp_path / "input"
    source.mkdir(mode=0o700)
    if unexpected:
        write_private(source / "unexpected", b"sanitized\n")
    evidence = tmp_path / "evidence"
    completed = subprocess.run(  # noqa: S603 - fixed repository helper path
        [
            str(GATE),
            "--input",
            str(source),
            "--run-id",
            "security-test",
            "--repo",
            str(tmp_path),
            "--evidence-root",
            str(evidence),
            "--now",
            NOW_TEXT,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == exit_code
    result = json.loads(
        (evidence / "security-test" / "gate-result.json").read_text(encoding="utf-8")
    )
    assert result["status"] == status
    assert result["overallReplacementReady"] is False
    status_text = (evidence / "security-test" / "result.status").read_text(encoding="utf-8")
    assert "reasonCodes=" in status_text
    assert "password" not in status_text.lower()


@pytest.mark.parametrize("mutation", ["extra-field", "stale-database", "subject-mismatch"])
def test_malformed_or_unlinked_report_fails(tmp_path: Path, mutation: str) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-python.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "extra-field":
        document["unexpected"] = True
    elif mutation == "stale-database":
        document["scanner"]["databaseUpdatedAt"] = "2026-08-30T00:00:00Z"
    else:
        document["subject"]["imageId"] = f"sha256:{'c' * 64}"
    write_private(path, dump(document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed):
        validate(source, repo)


def finding(severity: str, domain: str, waiver: object = None) -> dict[str, object]:
    return {
        "id": "CVE-TEST",
        "severity": severity,
        "domain": domain,
        "path": "package-lock.json:package",
        "reachability": "unreachable-build-only",
        "waiver": waiver,
    }


def test_unapproved_high_and_auth_medium_fail(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-node-runtime.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["findings"] = [finding("HIGH", "dependency")]
    write_private(path, dump(document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="unapproved-high"):
        validate(source, repo)
    document["findings"] = [finding("MEDIUM", "auth")]
    write_private(path, dump(document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="blocking-medium"):
        validate(source, repo)


def test_narrow_build_only_high_waiver_is_accepted(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-node-build.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["findings"] = [
        finding(
            "HIGH",
            "dependency",
            {
                "owner": "security-team",
                "rationale": "not shipped",
                "compensatingControl": "production install excludes dev dependencies",
                "expiresAt": "2026-09-20T00:00:00Z",
            },
        )
    ]
    write_private(path, dump(document))
    refresh_provenance_hashes(source)
    validate(source, repo)


@pytest.mark.parametrize("license_id", ["UNKNOWN", "AGPL-3.0", "SSPL-1.0", "BUSL-1.1"])
def test_forbidden_or_unknown_license_fails(tmp_path: Path, license_id: str) -> None:
    source, repo = make_input(tmp_path)
    set_package_licenses(source, [license_id])
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="license:forbidden"):
        validate(source, repo)


def test_gpl_requires_exact_manual_review(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    set_package_licenses(source, ["LGPL-3.0-only"])
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="manual-review:pkg:npm/x@1"):
        validate(source, repo)


@pytest.mark.parametrize("shape", ["missing", "extra", "duplicate", "mismatch"])
def test_sbom_and_license_packages_reconcile_exactly(tmp_path: Path, shape: str) -> None:
    source, repo = make_input(tmp_path)
    set_package_licenses(source, ["MIT"])
    licenses_path = source / "licenses.json"
    licenses = json.loads(licenses_path.read_text(encoding="utf-8"))
    if shape == "missing":
        licenses["packages"] = []
    elif shape == "extra":
        licenses["packages"].append(
            {"name": "y", "version": "1", "purl": "pkg:npm/y@1", "licenses": ["MIT"]}
        )
    elif shape == "duplicate":
        licenses["packages"].append(licenses["packages"][0])
    else:
        licenses["packages"][0]["licenses"] = ["Apache-2.0"]
    write_private(licenses_path, dump(licenses))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="license:"):
        validate(source, repo)


def test_agpl_only_in_sbom_cannot_pass_empty_license_report(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    sbom_path = source / "sbom.cdx.json"
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    sbom["components"] = [
        {"name": "x", "version": "1", "purl": "pkg:npm/x@1", "licenses": ["AGPL-3.0"]}
    ]
    write_private(sbom_path, dump(sbom))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="reconciliation"):
        validate(source, repo)


def test_quoted_json_token_and_email_are_refused_despite_sanitization_pass(
    tmp_path: Path,
) -> None:
    source, repo = make_input(tmp_path)
    write_private(
        source / "express-before.txt",
        b'{"token":"ghp_abcdef123456","email":"person@example.com"}\n',
    )
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="secret-material"):
        validate(source, repo)


def test_camel_case_jwt_and_unicode_escaped_email_are_recursively_refused(
    tmp_path: Path,
) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-python.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["accessToken"] = "eyJhbGciOiJSUzI1NiJ9.payload.signature"
    document["contact"] = "person@example.com"
    write_private(path, json.dumps(document).replace("@", r"\u0040").encode())
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="secret-material"):
        validate(source, repo)


def test_low_gitleaks_finding_is_blocking(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    path = source / "secrets.sarif"
    document = json.loads(path.read_text(encoding="utf-8"))
    gitleaks = next(run for run in document["runs"] if run["tool"]["driver"]["name"] == "gitleaks")
    gitleaks["results"] = [finding("LOW", "secrets")]
    write_private(path, dump(document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="secrets:finding-present"):
        validate(source, repo)


def test_dummy_negative_test_suite_is_refused(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    write_private(
        source / "negative-tests.xml",
        b'<testsuite tests="1" failures="0" errors="0" skipped="0">'
        b'<testcase classname="phase7-security" name="dummy" time="0.001">'
        b'<properties><property name="evidenceSha256" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/></properties></testcase></testsuite>',
    )
    write_private(
        source / "negative-tests.status",
        b"status=PASS\ntests=1\nfailures=0\nerrors=0\nskipped=0\n",
    )
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="negative-tests"):
        validate(source, repo)


def test_empty_exact_name_negative_cases_are_refused(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    cases = "".join(
        f'<testcase classname="phase7-security" name="{name}" time="0.001"/>'
        for name in sorted(gate.REQUIRED_NEGATIVE_TESTS)
    )
    write_private(
        source / "negative-tests.xml",
        (
            f'<testsuite tests="{len(gate.REQUIRED_NEGATIVE_TESTS)}" failures="0" '
            f'errors="0" skipped="0">{cases}</testsuite>'
        ).encode(),
    )
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="required-cases"):
        validate(source, repo)


def test_scanner_report_must_match_pinned_image_digest(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-python.json"
    report_document = json.loads(path.read_text(encoding="utf-8"))
    report_document["scanner"]["imageDigest"] = f"sha256:{'c' * 64}"
    write_private(path, dump(report_document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="scanner:image-identity"):
        validate(source, repo)


def test_scanner_version_type_and_domain_are_canonical(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    path = source / "dependency-python.json"
    report_document = json.loads(path.read_text(encoding="utf-8"))
    report_document["scanner"]["version"] = 123
    write_private(path, dump(report_document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="scanner:identity"):
        validate(source, repo)
    report_document["scanner"]["version"] = "1.2.3"
    report_document["findings"] = [finding("MEDIUM", "AUTH")]
    write_private(path, dump(report_document))
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="finding-domain"):
        validate(source, repo)


def test_policy_content_is_enforced_not_only_hashed() -> None:
    mutated = {**gate.EXPECTED_POLICY, "maximumScannerDatabaseAgeHours": 48}
    with pytest.raises(gate.Failed, match="security-policy:exact-contract"):
        gate.validate_policy(dump(mutated))


def test_reason_codes_never_include_attacker_controlled_finding_id() -> None:
    attacker = gate.Failed("unapproved-high:leak-me@example.com")
    assert gate.reason_code(attacker) == "POLICY_VIOLATION"
    assert "leak" not in gate.reason_code(attacker).lower()


def test_express_snapshot_bytes_must_match(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    write_private(source / "express-after.txt", b"changed-sanitized-snapshot\n")
    refresh_provenance_hashes(source)
    with pytest.raises(gate.Failed, match="express-snapshot:changed"):
        validate(source, repo)


def test_hardlinked_input_is_refused(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    os.link(source / "licenses.json", tmp_path / "outside-license.json")
    with pytest.raises(gate.Failed, match="unsafe-file"):
        validate(source, repo)


def test_in_place_mutation_metadata_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "input"
    write_private(path, b"sanitized\n")
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


def test_failed_rename_removes_private_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "evidence"

    def refuse(_source: Path, _target: Path) -> None:
        raise OSError("forced")

    monkeypatch.setattr(gate, "rename_noreplace", refuse)
    with pytest.raises(OSError, match="forced"):
        gate.publish(evidence, "security-test", {}, "INCOMPLETE", ["MISSING_EVIDENCE"])
    assert list(evidence.iterdir()) == []


def test_incomplete_publication_never_copies_opaque_secret_bytes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    secret = b'{"accessToken":"eyJhbGciOiJSUzI1NiJ9.payload.signature",'
    secret += b'"email":"person\\u0040example.com"}\n'
    output = gate.publish(
        evidence,
        "security-test",
        {"express-before.txt": secret, "express-after.txt": secret},
        "INCOMPLETE",
        ["CONTROLLED_COLLECTOR_REQUIRED"],
    )
    assert {path.name for path in output.iterdir()} == {"result.status", "gate-result.json"}
    published = b"".join(path.read_bytes() for path in output.iterdir())
    assert b"accessToken" not in published
    assert b"eyJ" not in published
    assert b"person" not in published


def test_symlink_bad_permissions_secret_and_extra_file_fail(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    target = source / "negative-tests.xml"
    real = tmp_path / "real.xml"
    target.rename(real)
    target.symlink_to(real)
    with pytest.raises(gate.Failed, match="unsafe-file"):
        validate(source, repo)
    target.unlink()
    real.rename(target)
    target.chmod(0o644)
    with pytest.raises(gate.Failed, match="unsafe-permissions"):
        validate(source, repo)
    target.chmod(0o600)
    write_private(target, b"<testsuite><system-out>password=hunter2</system-out></testsuite>")
    with pytest.raises(gate.Failed, match="secret-material"):
        validate(source, repo)
    write_private(
        target,
        b'<testsuite tests="1" failures="0" errors="0" skipped="0">'
        b'<testcase name="x"/></testsuite>',
    )
    write_private(source / "unexpected.txt", b"x")
    with pytest.raises(gate.Failed, match="unexpected-files"):
        validate(source, repo)


def test_dirty_source_and_publication_collision_fail(tmp_path: Path) -> None:
    source, repo = make_input(tmp_path)
    (repo / "tracked").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(gate.Failed, match="source:dirty"):
        validate(source, repo)
    (repo / "tracked").write_text("committed\n", encoding="utf-8")
    blobs, _ = gate.validate_bundle(source, "security-test", repo, NOW)
    root = tmp_path / "evidence"
    gate.publish(root, "security-test", blobs, "PASS", [])
    with pytest.raises(gate.Failed, match="collision"):
        gate.publish(root, "security-test", blobs, "PASS", [])
