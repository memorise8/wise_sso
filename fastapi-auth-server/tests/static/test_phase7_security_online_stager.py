from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "ops" / "phase7" / "security" / "online_stager.py"
INTAKE = ROOT / "ops" / "phase7" / "security" / "offline_stager_intake.py"
GATE = ROOT / "ops" / "phase7" / "security" / "security_gate.py"
LOCK = ROOT / "ops" / "phase7" / "security" / "controlled-toolchain-lock.json"
SCHEMA = ROOT / "ops" / "phase7" / "security" / "controlled-toolchain-lock.schema.json"
WRAPPER = ROOT / "ops" / "phase7" / "run-security-online-stager.sh"


def load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


controller = load(CONTROLLER, "phase7_online_stager_test")
intake = load(INTAKE, "phase7_online_stager_intake_projection_test")
gate = load(GATE, "phase7_online_stager_gate_fixture")


def initialize_repo(path: Path, lock_bytes: bytes | None = None) -> tuple[str, str]:
    path.mkdir()
    required = set(gate.PINNED_FILES.values())
    for exact_paths, prefixes in gate.REPOSITORY_INPUT_GROUPS.values():
        required.update(exact_paths)
        for prefix in prefixes:
            required.add(f"{prefix}fixture")
    for relative in required:
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            lock_bytes
            if relative == controller.LOCK_RELATIVE and lock_bytes is not None
            else LOCK.read_bytes()
            if relative == controller.LOCK_RELATIVE
            else b"fixture\n"
        )
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
    provenance = gate.repository_snapshot(path).provenance
    return provenance["sourceRevision"], provenance["gitTreeObject"]


def frozen_lock() -> dict[str, Any]:
    lock = copy.deepcopy(gate.TOOLCHAIN_LOCK)
    lock["status"] = "FROZEN"
    lock["bootstrapBinary"] = {"path": "/usr/bin/docker", "sha256": "a" * 64}
    for group in ("images", "scanners"):
        for index, (name, image) in enumerate(lock[group].items(), start=1):
            digit = format((index + (0 if group == "images" else 8)) % 16, "x")
            image.update(
                repository=f"registry.example.invalid/wiseacct/{name}",
                version="1.2.3",
                indexDigest=f"sha256:{digit * 64}",
                platformDigests={
                    "linux/amd64": f"sha256:{'b' * 64}",
                    "linux/arm64/v8": f"sha256:{'c' * 64}",
                },
                configDigests={
                    "linux/amd64": f"sha256:{'d' * 64}",
                    "linux/arm64/v8": f"sha256:{'e' * 64}",
                },
            )
    for artifact in lock["trivyArtifacts"].values():
        artifact.update(
            repository="ghcr.io/aquasecurity/trivy-db",
            version="2.0.0",
            manifestDigest=f"sha256:{'f' * 64}",
            payloadSha256="1" * 64,
        )
    for policies in lock["signaturePolicies"].values():
        for policy in policies.values():
            policy.update(
                issuer="https://token.actions.githubusercontent.com",
                subject="repo:owner/project",
                rekorRequired=True,
            )
    lock["advisoryOrigins"] = {
        "pip": "https://pypi.org:443",
        "npm": "https://registry.npmjs.org:443",
    }
    lock["destinationAllowlist"] = sorted(
        {
            "https://registry.example.invalid:443",
            "https://ghcr.io:443",
            *lock["advisoryOrigins"].values(),
        }
    )
    return cast(dict[str, Any], lock)


def test_checked_in_lock_and_schema_are_exact_unfrozen_contract() -> None:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert gate.type_exact_equal(lock, gate.TOOLCHAIN_LOCK)
    assert controller.validate_lock(lock)["status"] == "UNFROZEN"
    assert schema["additionalProperties"] is False
    assert "signaturePolicies" in schema["required"]
    frozen = schema["allOf"][0]["then"]["properties"]
    unfrozen = schema["allOf"][1]["then"]["properties"]
    assert frozen["destinationAllowlist"]["minItems"] == 1
    assert frozen["bootstrapBinary"]["properties"]["path"] == {"const": "/usr/bin/docker"}
    assert unfrozen["destinationAllowlist"]["maxItems"] == 0
    assert unfrozen["bootstrapBinary"] == {"const": {"path": None, "sha256": None}}


def test_frozen_schema_patterns_match_runtime_repository_and_version_rules() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    frozen_image = schema["$defs"]["frozenImage"]["properties"]
    repository_pattern = re.compile(frozen_image["repository"]["pattern"])
    version_pattern = re.compile(frozen_image["version"]["pattern"])
    assert repository_pattern.fullmatch("x") is not None
    assert controller.REPOSITORY.fullmatch("x") is not None
    assert version_pattern.fullmatch("Latest") is None
    lock = frozen_lock()
    lock["images"]["builder"]["repository"] = "x"
    lock["destinationAllowlist"].append("https://x:443")
    lock["destinationAllowlist"].sort()
    assert controller.validate_lock(lock)["images"]["builder"]["repository"] == "x"
    lock["images"]["builder"]["version"] = "Latest"
    with pytest.raises(controller.Refused):
        controller.validate_lock(lock)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schemaVersion=True),
        lambda value: value["images"]["builder"].update(indexDigest=False),
        lambda value: value["scanners"]["trivy"].update(version="latest"),
        lambda value: value["images"]["collector"].update(repository="repo.example/x:latest"),
        lambda value: value["signaturePolicies"]["images"]["builder"].update(rekorRequired=None),
        lambda value: value.update(destinationAllowlist=[]),
    ],
)
def test_frozen_lock_rejects_type_null_and_mutable_reference_attacks(mutation: Any) -> None:
    lock = frozen_lock()
    mutation(lock)
    with pytest.raises(controller.Refused):
        controller.validate_lock(lock)


def test_frozen_lock_builds_only_declarative_non_executable_subjects() -> None:
    lock = frozen_lock()
    plan = controller.collection_plan(lock, "linux/amd64")
    assert len(plan) == 8
    assert all(subject.platform == "linux/amd64" for subject in plan)
    assert all("@sha256:" in subject.requested_reference for subject in plan)
    assert all(subject.platform_digest.startswith("sha256:") for subject in plan)
    assert all(subject.config_digest.startswith("sha256:") for subject in plan)
    assert all(not hasattr(subject, "argv") for subject in plan)
    assert all(not hasattr(subject, "env") for subject in plan)


@pytest.mark.parametrize("mode", ["check", "collect"])
def test_current_lock_returns_controller_authored_incomplete_and_executes_nothing(
    tmp_path: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    initialize_repo(repo)
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    monkeypatch.setenv("DOCKER_HOST", "tcp://attacker.invalid:2375")
    monkeypatch.setenv("HTTP_PROXY", "http://attacker.invalid")
    result = controller.run(
        mode,
        f"online-{mode}",
        "linux/amd64",
        output_parent,
        repo,
    )
    assert result == 3
    output = output_parent / f"online-{mode}"
    document = json.loads((output / "gate-result.json").read_text(encoding="utf-8"))
    assert document["status"] == "INCOMPLETE"
    assert document["reasonCodes"] == ["TOOLCHAIN_LOCK_UNFROZEN", "CONTROLLED_COLLECTOR_REQUIRED"]
    assert document["preflightValidated"] is True
    assert document["toolchainFrozen"] is False
    assert document["readinessAssertionsSatisfied"] is False
    assert document["overallReplacementReady"] is False
    assert set(output.iterdir()) == {output / "gate-result.json", output / "result.status"}
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in output.iterdir())


@pytest.mark.parametrize("mode", ["check", "collect"])
def test_dirty_repository_is_rejected_before_publication(tmp_path: Path, mode: str) -> None:
    repo = tmp_path / "repo"
    initialize_repo(repo)
    tracked = repo / gate.PINNED_FILES["policySha256"]
    tracked.write_bytes(b"dirty\n")
    output_parent = tmp_path / "output"
    output_parent.mkdir(mode=0o700)
    assert controller.run(mode, f"dirty-{mode}", "linux/amd64", output_parent, repo) == 2
    assert not (output_parent / f"dirty-{mode}").exists()


def test_toolchain_lock_nested_records_are_independent() -> None:
    image_values = list(gate.TOOLCHAIN_LOCK["scanners"].values())
    assert len({id(value) for value in image_values}) == len(image_values)
    assert len({id(value["platformDigests"]) for value in image_values}) == len(image_values)
    policies = [
        policy
        for group in gate.TOOLCHAIN_LOCK["signaturePolicies"].values()
        for policy in group.values()
    ]
    assert len({id(value) for value in policies}) == len(policies)


def test_pass_forge_and_unsafe_output_boundary_are_impossible(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    initialize_repo(repo)
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    assert controller.run("check", "pass-forge", "linux/amd64", unsafe, repo) == 2
    assert not (unsafe / "pass-forge").exists()


def test_frozen_manifest_projection_mismatch_is_rejected() -> None:
    lock = frozen_lock()
    images = []
    for role, image in [*lock["images"].items(), *lock["scanners"].items()]:
        manifest_role = role if role in {"builder", "collector"} else f"scanner-{role}"
        policy_group = "images" if role in {"builder", "collector"} else "scanners"
        policy = lock["signaturePolicies"][policy_group][role]
        images.append(
            {
                "role": manifest_role,
                "repository": image["repository"],
                "requestedReference": f"{image['repository']}@{image['indexDigest']}",
                "indexDigest": image["indexDigest"],
                "platformDigest": image["platformDigests"]["linux/amd64"],
                "configDigest": image["configDigests"]["linux/amd64"],
                "signatures": [
                    {
                        "issuer": policy["issuer"],
                        "identity": policy["subject"],
                        "rekorIncluded": policy["rekorRequired"],
                    }
                ],
            }
        )
    manifest = {
        "targetPlatform": controller.PLATFORMS["linux/amd64"],
        "images": images,
        "trivyArtifacts": [
            {
                "kind": kind,
                "repository": artifact["repository"],
                "manifestDigest": artifact["manifestDigest"],
                "payload": {"sha256": artifact["payloadSha256"]},
                "signatures": [
                    {
                        "issuer": lock["signaturePolicies"]["trivyArtifacts"][kind]["issuer"],
                        "identity": lock["signaturePolicies"]["trivyArtifacts"][kind]["subject"],
                        "rekorIncluded": lock["signaturePolicies"]["trivyArtifacts"][kind][
                            "rekorRequired"
                        ],
                    }
                ],
            }
            for kind, artifact in lock["trivyArtifacts"].items()
        ],
        "advisoryReports": [
            {"ecosystem": ecosystem, "serviceOrigin": origin}
            for ecosystem, origin in lock["advisoryOrigins"].items()
        ],
        "networkScope": {
            "destinations": [
                {
                    "scheme": "https",
                    "host": origin.removeprefix("https://").removesuffix(":443"),
                    "port": 443,
                }
                for origin in lock["destinationAllowlist"]
            ]
        },
    }
    intake.validate_lock_projection(manifest, lock)
    manifest["images"][0]["indexDigest"] = f"sha256:{'0' * 64}"
    with pytest.raises(intake.Failed, match="toolchain-lock:image-projection"):
        intake.validate_lock_projection(manifest, lock)


def test_frozen_manifest_signature_policy_mismatch_is_rejected() -> None:
    lock = frozen_lock()
    manifest = {
        "targetPlatform": controller.PLATFORMS["linux/amd64"],
        "images": [],
        "trivyArtifacts": [],
        "advisoryReports": [
            {"ecosystem": ecosystem, "serviceOrigin": origin}
            for ecosystem, origin in lock["advisoryOrigins"].items()
        ],
        "networkScope": {
            "destinations": [
                {"scheme": "https", "host": origin[8:-4], "port": 443}
                for origin in lock["destinationAllowlist"]
            ]
        },
    }
    for role, image in [*lock["images"].items(), *lock["scanners"].items()]:
        group = "images" if role in {"builder", "collector"} else "scanners"
        policy = lock["signaturePolicies"][group][role]
        manifest["images"].append(
            {
                "role": role if group == "images" else f"scanner-{role}",
                "repository": image["repository"],
                "requestedReference": f"{image['repository']}@{image['indexDigest']}",
                "indexDigest": image["indexDigest"],
                "platformDigest": image["platformDigests"]["linux/amd64"],
                "configDigest": image["configDigests"]["linux/amd64"],
                "signatures": [
                    {
                        "issuer": policy["issuer"],
                        "identity": policy["subject"],
                        "rekorIncluded": True,
                    }
                ],
            }
        )
    for kind, artifact in lock["trivyArtifacts"].items():
        policy = lock["signaturePolicies"]["trivyArtifacts"][kind]
        manifest["trivyArtifacts"].append(
            {
                "kind": kind,
                "repository": artifact["repository"],
                "manifestDigest": artifact["manifestDigest"],
                "payload": {"sha256": artifact["payloadSha256"]},
                "signatures": [
                    {
                        "issuer": policy["issuer"],
                        "identity": policy["subject"],
                        "rekorIncluded": True,
                    }
                ],
            }
        )
    manifest["images"][0]["signatures"][0]["identity"] = "attacker"
    with pytest.raises(intake.Failed, match="signature-policy-projection"):
        intake.validate_lock_projection(manifest, lock)


def test_publication_remains_bound_to_open_parent_during_symlink_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    initialize_repo(repo)
    parent = tmp_path / "output"
    moved = tmp_path / "moved-output"
    attacker = tmp_path / "attacker"
    parent.mkdir(mode=0o700)
    attacker.mkdir(mode=0o700)
    original = controller.rename_noreplace

    def swap(directory_fd: int, source: str, target: str) -> None:
        parent.rename(moved)
        parent.symlink_to(attacker, target_is_directory=True)
        original(directory_fd, source, target)

    monkeypatch.setattr(controller, "rename_noreplace", swap)
    assert controller.run("check", "swap-test", "linux/amd64", parent, repo) == 3
    assert (moved / "swap-test/gate-result.json").is_file()
    assert list(attacker.iterdir()) == []
    parent.unlink()


def test_replaced_staging_name_cannot_publish_forged_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    initialize_repo(repo)
    parent = tmp_path / "output"
    parent.mkdir(mode=0o700)
    original = controller.rename_noreplace
    attacked = False

    def replace_before_rename(directory_fd: int, source: str, target: str) -> None:
        nonlocal attacked
        if not attacked and target == "race-test":
            attacked = True
            os.rename(
                source,
                ".owned-staging-aside",
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.mkdir(source, mode=0o700, dir_fd=directory_fd)
            forged_dir_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory_fd)
            try:
                forged_fd = os.open(
                    "gate-result.json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=forged_dir_fd,
                )
                try:
                    os.write(forged_fd, b'{"status":"PASS"}\n')
                finally:
                    os.close(forged_fd)
            finally:
                os.close(forged_dir_fd)
        original(directory_fd, source, target)

    monkeypatch.setattr(controller, "rename_noreplace", replace_before_rename)
    assert controller.run("check", "race-test", "linux/amd64", parent, repo) == 2
    assert not (parent / "race-test").exists()
    rejected = list(parent.glob(".race-test.rejected.*"))
    assert len(rejected) == 1
    assert (rejected[0] / "gate-result.json").read_text() == '{"status":"PASS"}\n'


def test_wrapper_has_isolated_environment_and_no_network_or_daemon_invocation() -> None:
    text = WRAPPER.read_text(encoding="utf-8")
    assert "/usr/bin/env -i" in text
    assert "/usr/bin/python3 -I" in text
    assert "curl " not in text
    assert "docker " not in text
    assert "sudo " not in text
    assert "eval " not in text
    assert "sh -c" not in text
    assert os.access(WRAPPER, os.X_OK)
