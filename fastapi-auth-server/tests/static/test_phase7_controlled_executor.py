from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

SECURITY = Path(__file__).resolve().parents[2] / "ops/phase7/security"


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


boundary = load("phase7_controlled_executor_boundary_test", SECURITY / "execution_boundary.py")
executor = load("phase7_controlled_executor_test", SECURITY / "controlled_executor.py")
online_stager = load("phase7_controlled_executor_online_stager_test", SECURITY / "online_stager.py")

TRUST_ROOT = b'{"synthetic":"development-only-root"}\n'
VERIFIER = b"""#!/usr/bin/python3
import json
import os
import sys
import time

if any(key in os.environ for key in ("AWS_SECRET_ACCESS_KEY", "REGISTRY_PASSWORD", "TOKEN")):
    raise SystemExit(22)
if len(sys.argv) == 11 and sys.argv[1] == "verify-blob":
    if sys.argv[2] != "--bundle" or sys.argv[4] != "--trusted-root":
        raise SystemExit(24)
    if sys.argv[6] != "--certificate-identity" or sys.argv[8] != "--certificate-oidc-issuer":
        raise SystemExit(25)
    if open(sys.argv[5], "rb").read() != b'{"synthetic":"development-only-root"}\\n':
        raise SystemExit(21)
    json.load(open(sys.argv[3], encoding="utf-8"))
    if not open(sys.argv[10], "rb").read():
        raise SystemExit(26)
    print("Verified OK", file=sys.stderr)
    raise SystemExit(0)
if len(sys.argv) != 3:
    raise SystemExit(20)
if open(sys.argv[1], "rb").read() != b'{"synthetic":"development-only-root"}\\n':
    raise SystemExit(21)
with open(sys.argv[2], encoding="utf-8") as stream:
    document = json.load(stream)
mode = document.pop("mode", "result")
if mode == "timeout":
    time.sleep(30)
elif mode == "fork-close-pipes":
    pid_file = document.pop("pidFile")
    child = os.fork()
    if child == 0:
        os.close(1)
        os.close(2)
        time.sleep(30)
        os._exit(0)
    with open(pid_file, "w", encoding="ascii") as target:
        target.write(str(child))
    print(json.dumps(document, separators=(",", ":")))
elif mode == "stdout-oversize":
    os.write(1, b"x" * 70000)
elif mode == "stderr-oversize":
    os.write(2, b"x" * 70000)
elif mode == "stderr":
    os.write(2, b"unexpected diagnostic")
elif mode == "reject":
    raise SystemExit(23)
else:
    print(json.dumps(document, separators=(",", ":")))
"""

DIGEST = "sha256:" + "a" * 64
IDENTITY = "https://example.invalid/workflow@refs/tags/test"
ISSUER = "https://issuer.example.invalid"


@pytest.fixture
def private_root(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    root = tmp_path_factory.mktemp("controlled-executor")
    root.chmod(0o700)
    (root / boundary.VERIFIER_NAME).write_bytes(VERIFIER)
    (root / boundary.VERIFIER_NAME).chmod(0o500)
    (root / boundary.TRUST_ROOT_NAME).write_bytes(TRUST_ROOT)
    (root / boundary.TRUST_ROOT_NAME).chmod(0o400)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
        daemon.bind(str(root / boundary.DAEMON_SOCKET_NAME))
        (root / boundary.DAEMON_SOCKET_NAME).chmod(0o600)
        yield root


def admit(root: Path) -> Any:
    return boundary.admit_boundary(
        root,
        verifier_sha256=hashlib.sha256(VERIFIER).hexdigest(),
        trust_root_sha256=hashlib.sha256(TRUST_ROOT).hexdigest(),
    )


def expectation(**changes: object) -> Any:
    values = {
        "digest": DIGEST,
        "identity": IDENTITY,
        "issuer": ISSUER,
        "rekor_required": True,
        **changes,
    }
    return executor._DevelopmentExpectation(**values)


def write_input(path: Path, **changes: object) -> Path:
    document = {
        "schemaVersion": 1,
        "digest": DIGEST,
        "identity": IDENTITY,
        "issuer": ISSUER,
        "rekorIncluded": True,
        **changes,
    }
    path.write_text(json.dumps(document))
    return path


def run(root: Path, fixture_input: Path, **kwargs: object) -> Any:
    with admit(root) as lease, lease.snapshot_material() as material:
        return executor._run_development_fixture_verifier(
            material, expectation(), fixture_input, **kwargs
        )


def test_qualification_refuses_before_material_or_process_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Bomb:
        def __getattribute__(self, _name: str) -> object:
            pytest.fail("qualification refusal touched caller material")

    monkeypatch.setattr(
        executor.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("qualification refusal started a process"),
    )
    with pytest.raises(
        executor.ControlledExecutionRefused,
        match="independently-approved-toolchain-required",
    ):
        executor.verify_for_qualification(Bomb(), approved=True, verified=True)


def test_frozen_online_stager_reaches_fail_closed_consumer_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    class FakeExecutor:
        @staticmethod
        def verify_for_qualification(**kwargs: object) -> None:
            calls.append(kwargs)
            raise executor.ControlledExecutionRefused("approval-required")

    class FakeGate:
        TOOLCHAIN_LOCK: ClassVar[dict[str, object]] = {"status": None}

        @staticmethod
        def repository_snapshot(_repo: Path) -> SimpleNamespace:
            return SimpleNamespace(
                pinned_blobs={online_stager.LOCK_RELATIVE: b'{"status":"FROZEN"}'}
            )

        @staticmethod
        def type_exact_equal(_actual: object, _expected: object) -> bool:
            return True

    monkeypatch.setattr(online_stager, "load_security_gate", lambda: FakeGate())
    monkeypatch.setattr(online_stager, "load_controlled_executor", lambda: FakeExecutor())
    monkeypatch.setattr(online_stager, "validate_lock", lambda _lock: {"status": "FROZEN"})
    repo = tmp_path / "repo"
    output = tmp_path / "output"
    repo.mkdir()
    output.mkdir()
    assert online_stager.run("collect", "frozen", "linux/amd64", output, repo) == 2
    assert calls == [{"lock_bytes": b'{"status":"FROZEN"}', "platform": "linux/amd64"}]
    assert list(output.iterdir()) == []


def test_cosign_v3_blob_contract_uses_only_reviewed_exact_flags() -> None:
    policy = executor.CosignV3Policy(identity=IDENTITY, issuer=ISSUER)
    argv = executor.build_cosign_v3_blob_argv(10, 11, 12, 13, policy)
    assert argv == (
        "/proc/self/fd/10",
        "verify-blob",
        "--bundle",
        "/proc/self/fd/12",
        "--trusted-root",
        "/proc/self/fd/11",
        "--certificate-identity",
        IDENTITY,
        "--certificate-oidc-issuer",
        ISSUER,
        "/proc/self/fd/13",
    )
    forbidden = {
        "--offline",
        "--insecure-ignore-tlog",
        "--private-infrastructure",
        "--key",
        "--certificate-identity-regexp",
        "--certificate-oidc-issuer-regexp",
        "--allow-insecure-registry",
        "--check-claims=false",
    }
    assert forbidden.isdisjoint(argv)
    assert executor.COSIGN_V3_COMPATIBILITY_SECURITY_FLOOR == (3, 1, 3)


def test_cosign_v3_image_contract_keeps_claim_checks_and_local_layout() -> None:
    policy = executor.CosignV3Policy(identity=IDENTITY, issuer=ISSUER)
    assert executor.build_cosign_v3_image_argv(10, 11, 12, policy) == (
        "/proc/self/fd/10",
        "verify",
        "--local-image",
        "--trusted-root",
        "/proc/self/fd/11",
        "--certificate-identity",
        IDENTITY,
        "--certificate-oidc-issuer",
        ISSUER,
        "--check-claims=true",
        "--output",
        "json",
        "/proc/self/fd/12",
    )


@pytest.mark.parametrize(
    ("return_code", "stdout", "stderr", "failure"),
    [
        (1, b"", b"", "rejected"),
        (0, b"x" * (executor.MAX_OUTPUT_BYTES + 1), b"", "output-oversize"),
    ],
)
def test_cosign_blob_process_contract_fails_closed(
    return_code: int, stdout: bytes, stderr: bytes, failure: str
) -> None:
    with pytest.raises(executor.ControlledExecutionRefused, match=failure):
        executor.validate_cosign_v3_blob_process_result(return_code, stdout, stderr)


def test_cosign_blob_success_uses_exit_status_and_hashes_diagnostic_streams() -> None:
    stdout = b'{"untrustedDiagnostic":true}\n'
    stderr = b"Verified OK\n"
    observation = executor.validate_cosign_v3_blob_process_result(0, stdout, stderr)
    assert observation.return_code == 0
    assert observation.stdout_sha256 == hashlib.sha256(stdout).hexdigest()
    assert observation.stdout_size == len(stdout)
    assert observation.stderr_sha256 == hashlib.sha256(stderr).hexdigest()
    assert observation.stderr_size == len(stderr)
    assert not hasattr(observation, "verified")
    assert not hasattr(observation, "qualifyingEvidence")


@pytest.mark.parametrize(
    ("descriptor", "policy"),
    [
        (-1, executor.CosignV3Policy(identity=IDENTITY, issuer=ISSUER)),
        (True, executor.CosignV3Policy(identity=IDENTITY, issuer=ISSUER)),
        (10, executor.CosignV3Policy(identity="bad\nidentity", issuer=ISSUER)),
        (10, executor.CosignV3Policy(identity=IDENTITY, issuer="")),
    ],
)
def test_cosign_v3_blob_contract_rejects_invalid_inputs(descriptor: Any, policy: Any) -> None:
    with pytest.raises(executor.ControlledExecutionRefused):
        executor.build_cosign_v3_blob_argv(descriptor, 11, 12, 13, policy)


def test_standard_v03_bundle_pre_admission_rejects_legacy_and_ambiguous_content(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        json.dumps(
            {
                "mediaType": executor.STANDARD_BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"certificate": "synthetic"},
                "messageSignature": {"signature": "synthetic"},
            }
        )
    )
    admission = executor.pre_admit_standard_bundle(bundle)
    assert admission.size == bundle.stat().st_size
    assert admission.sha256 == hashlib.sha256(bundle.read_bytes()).hexdigest()

    bundle.write_text(json.dumps({"base64Signature": "legacy"}))
    with pytest.raises(executor.ControlledExecutionRefused, match=r"standard-v0\.3-required"):
        executor.pre_admit_standard_bundle(bundle)

    bundle.write_text(
        json.dumps(
            {
                "mediaType": executor.STANDARD_BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {},
                "messageSignature": {},
                "dsseEnvelope": {},
            }
        )
    )
    with pytest.raises(executor.ControlledExecutionRefused, match="cosign-bundle:content"):
        executor.pre_admit_standard_bundle(bundle)


def test_blob_digest_is_bound_independently_before_cosign(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"exact local artifact")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    admission = executor.bind_blob_artifact(artifact, digest)
    assert admission.digest == digest
    assert admission.size == len(b"exact local artifact")
    with pytest.raises(executor.ControlledExecutionRefused, match="digest-mismatch"):
        executor.bind_blob_artifact(artifact, "sha256:" + "0" * 64)


def standardized_bundle(path: Path) -> bytes:
    raw = json.dumps(
        {
            "mediaType": executor.STANDARD_BUNDLE_MEDIA_TYPE,
            "verificationMaterial": {"certificate": "synthetic"},
            "messageSignature": {"signature": "synthetic"},
        },
        separators=(",", ":"),
    ).encode()
    path.write_bytes(raw)
    return raw


def test_blob_checkpoint_consumes_same_admitted_fds_and_remains_nonqualifying(
    private_root: Path, tmp_path: Path
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_bytes = standardized_bundle(bundle_path)
    artifact_path = tmp_path / "artifact.bin"
    artifact_bytes = b"exact artifact passed to cosign"
    artifact_path.write_bytes(artifact_bytes)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    calls: list[tuple[tuple[str, ...], tuple[int, ...]]] = []

    class FakeOwnedRunner:
        def run(
            self,
            argv: tuple[str, ...],
            *,
            pass_fds: tuple[int, ...],
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> Any:
            assert timeout_seconds == 1.0
            assert maximum_output_bytes == 1024
            assert os.pread(pass_fds[2], len(bundle_bytes), 0) == bundle_bytes
            assert os.pread(pass_fds[3], len(artifact_bytes), 0) == artifact_bytes
            assert (
                executor.fcntl.fcntl(pass_fds[2], executor._F_GET_SEALS) & executor._REQUIRED_SEALS
                == executor._REQUIRED_SEALS
            )
            assert (
                executor.fcntl.fcntl(pass_fds[3], executor._F_GET_SEALS) & executor._REQUIRED_SEALS
                == executor._REQUIRED_SEALS
            )
            assert argv[3] == f"/proc/self/fd/{pass_fds[2]}"
            assert argv[-1] == f"/proc/self/fd/{pass_fds[3]}"
            calls.append((argv, pass_fds))
            return executor.ProcessCapture(0, b"", b"Verified OK\n")

    with admit(private_root) as lease, lease.snapshot_material() as material:
        observation = executor._run_cosign_v3_blob_checkpoint(
            material,
            executor.CosignV3Policy(IDENTITY, ISSUER),
            bundle_path,
            artifact_path,
            artifact_digest,
            FakeOwnedRunner(),
            timeout_seconds=1.0,
            maximum_output_bytes=1024,
        )
    assert len(calls) == 1
    assert observation.artifact.digest == artifact_digest
    assert observation.bundle.sha256 == hashlib.sha256(bundle_bytes).hexdigest()
    assert observation.process.stderr_sha256 == hashlib.sha256(b"Verified OK\n").hexdigest()
    assert observation.evidence_class == "DEVELOPMENT_ONLY_UNAUTHENTICATED_TOOLCHAIN"
    assert not hasattr(observation, "qualifyingEvidence")


def test_blob_checkpoint_runs_actual_cosign_argv_with_local_fixture_only(
    private_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle_path = tmp_path / "bundle.json"
    standardized_bundle(bundle_path)
    artifact_path = tmp_path / "artifact.bin"
    artifact_bytes = b"local fixture artifact"
    artifact_path.write_bytes(artifact_bytes)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    monkeypatch.setenv("REGISTRY_PASSWORD", "must-not-reach-child")

    with admit(private_root) as lease, lease.snapshot_material() as material:
        observation = executor._run_cosign_v3_blob_checkpoint(
            material,
            executor.CosignV3Policy(IDENTITY, ISSUER),
            bundle_path,
            artifact_path,
            artifact_digest,
            timeout_seconds=1.0,
            maximum_output_bytes=1024,
        )
    assert observation.process.return_code == 0
    assert observation.process.stdout_size == 0
    assert observation.process.stderr_sha256 == hashlib.sha256(b"Verified OK\n").hexdigest()
    assert observation.describe()["evidenceClass"] == ("DEVELOPMENT_ONLY_UNAUTHENTICATED_TOOLCHAIN")


def test_image_checkpoint_refuses_until_full_layout_projection_exists() -> None:
    with pytest.raises(executor.ControlledExecutionRefused, match="layout-projection"):
        executor.run_cosign_v3_image_checkpoint(approved=True)


def test_blob_checkpoint_uses_original_sealed_bytes_during_source_mutation(
    private_root: Path, tmp_path: Path
) -> None:
    bundle_path = tmp_path / "bundle.json"
    standardized_bundle(bundle_path)
    artifact_path = tmp_path / "artifact.bin"
    artifact_bytes = b"original artifact bytes"
    artifact_path.write_bytes(artifact_bytes)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()

    class MutatingRunner:
        def run(
            self,
            _argv: tuple[str, ...],
            *,
            pass_fds: tuple[int, ...],
            **_kwargs: object,
        ) -> Any:
            artifact_path.write_bytes(b"changed artifact bytes!")
            assert os.pread(pass_fds[3], len(artifact_bytes), 0) == artifact_bytes
            return executor.ProcessCapture(0, b"", b"Verified OK\n")

    with admit(private_root) as lease, lease.snapshot_material() as material:
        observation = executor._run_cosign_v3_blob_checkpoint(
            material,
            executor.CosignV3Policy(IDENTITY, ISSUER),
            bundle_path,
            artifact_path,
            artifact_digest,
            MutatingRunner(),
        )
    assert observation.artifact.digest == artifact_digest
    assert artifact_path.read_bytes() == b"changed artifact bytes!"


def test_runner_fd_close_and_reuse_does_not_close_unrelated_descriptor(
    private_root: Path, tmp_path: Path
) -> None:
    bundle_path = tmp_path / "bundle.json"
    standardized_bundle(bundle_path)
    artifact_path = tmp_path / "artifact.bin"
    artifact_bytes = b"artifact"
    artifact_path.write_bytes(artifact_bytes)
    artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    harmless = tmp_path / "harmless.txt"
    harmless.write_bytes(b"must remain open")
    reused: list[int] = []

    class ReusingRunner:
        def run(
            self,
            _argv: tuple[str, ...],
            *,
            pass_fds: tuple[int, ...],
            **_kwargs: object,
        ) -> Any:
            borrowed_bundle_fd = pass_fds[2]
            os.close(borrowed_bundle_fd)
            replacement = os.open(harmless, os.O_RDONLY)
            assert replacement == borrowed_bundle_fd
            reused.append(replacement)
            return executor.ProcessCapture(0, b"", b"Verified OK\n")

    with admit(private_root) as lease, lease.snapshot_material() as material:
        with pytest.raises(
            executor.ControlledExecutionRefused, match="cosign-bundle:changed-sealed"
        ):
            executor._run_cosign_v3_blob_checkpoint(
                material,
                executor.CosignV3Policy(IDENTITY, ISSUER),
                bundle_path,
                artifact_path,
                artifact_digest,
                ReusingRunner(),
            )
    assert len(reused) == 1
    assert os.pread(reused[0], len(b"must remain open"), 0) == b"must remain open"
    os.close(reused[0])


def test_sealed_development_verifier_runs_but_never_qualifies(
    private_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-child")
    observation = run(private_root, write_input(tmp_path / "input.json"))
    description = observation.describe()
    assert description["outcome"] == "SYNTHETIC_VERIFIER_MATCHED"
    assert description["evidenceClass"] == "DEVELOPMENT_ONLY_SYNTHETIC_VERIFIER"
    assert "qualifyingEvidence" not in description
    assert "approved" not in description
    assert "verified" not in description
    assert "B03 bootstrap and independent approval remain required" in description["limitations"]


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("digest", "sha256:" + "b" * 64, "development-output:digest"),
        ("identity", "other-identity", "development-output:identity"),
        ("issuer", "other-issuer", "development-output:issuer"),
        ("rekorIncluded", False, "development-output:rekorIncluded"),
    ],
)
def test_mismatched_verifier_claims_are_refused(
    private_root: Path, tmp_path: Path, field: str, value: object, failure: str
) -> None:
    with pytest.raises(executor.ControlledExecutionRefused, match=failure):
        run(private_root, write_input(tmp_path / "input.json", **{field: value}))


@pytest.mark.parametrize(
    ("mode", "failure"),
    [
        ("timeout", "development-verifier:timeout"),
        ("stdout-oversize", "development-verifier:stdout-oversize"),
        ("stderr-oversize", "development-verifier:stderr-oversize"),
        ("stderr", "development-verifier:stderr"),
        ("reject", "development-verifier:rejected"),
    ],
)
def test_timeout_oversize_and_rejection_are_fail_closed(
    private_root: Path, tmp_path: Path, mode: str, failure: str
) -> None:
    fixture_input = write_input(tmp_path / "input.json", mode=mode)
    with pytest.raises(executor.ControlledExecutionRefused, match=failure):
        run(
            private_root,
            fixture_input,
            timeout_seconds=0.05 if mode == "timeout" else 5.0,
            maximum_output_bytes=100 if "oversize" in mode else executor.MAX_OUTPUT_BYTES,
        )


def process_is_live(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return False
    _, separator, fields = raw.rpartition(") ")
    return bool(separator) and fields.split()[0] != "Z"


def test_successful_leader_exit_drains_same_group_child_that_closed_pipes(
    private_root: Path, tmp_path: Path
) -> None:
    pid_file = tmp_path / "child.pid"
    fixture_input = write_input(
        tmp_path / "input.json",
        mode="fork-close-pipes",
        pidFile=str(pid_file),
    )
    observation = run(private_root, fixture_input, timeout_seconds=2.0)
    child_pid = int(pid_file.read_text(encoding="ascii"))
    assert observation.describe()["outcome"] == "SYNTHETIC_VERIFIER_MATCHED"
    assert not process_is_live(child_pid)


@pytest.mark.parametrize("failure_stage", ["selector-init", "selector-register", "pidfd"])
def test_start_handoff_baseexception_still_drains_started_process(
    private_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    started: list[int] = []
    original_popen = executor.subprocess.Popen

    def recording_popen(*args: object, **kwargs: object) -> Any:
        process = original_popen(*args, **kwargs)
        started.append(process.pid)
        return process

    monkeypatch.setattr(executor.subprocess, "Popen", recording_popen)
    if failure_stage == "selector-init":
        monkeypatch.setattr(
            executor.selectors,
            "DefaultSelector",
            lambda: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
    elif failure_stage == "selector-register":

        class InterruptingSelector:
            def register(self, *_args: object, **_kwargs: object) -> None:
                raise KeyboardInterrupt

            def close(self) -> None:
                pass

        monkeypatch.setattr(executor.selectors, "DefaultSelector", lambda: InterruptingSelector())
    else:
        monkeypatch.setattr(
            executor.os,
            "pidfd_open",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
        )
    with pytest.raises(executor.ControlledExecutionRefused, match="owned-process:lifecycle"):
        run(private_root, write_input(tmp_path / "input.json"), timeout_seconds=1.0)
    assert len(started) == 1
    assert not process_is_live(started[0])


def test_input_symlink_and_oversize_are_refused(private_root: Path, tmp_path: Path) -> None:
    real = write_input(tmp_path / "real.json")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(executor.ControlledExecutionRefused, match="development-input:open"):
        run(private_root, link)

    oversized = tmp_path / "oversized.json"
    with oversized.open("wb") as stream:
        stream.truncate(executor.MAX_INPUT_BYTES + 1)
    with pytest.raises(executor.ControlledExecutionRefused, match="development-input:size"):
        run(private_root, oversized)


@pytest.mark.parametrize(
    "changes",
    [
        {"digest": "bad"},
        {"identity": "identity\nsecret"},
        {"issuer": ""},
        {"rekor_required": False},
    ],
)
def test_invalid_development_expectations_refuse_before_launch(
    private_root: Path, tmp_path: Path, changes: dict[str, object]
) -> None:
    fixture_input = write_input(tmp_path / "input.json")
    with admit(private_root) as lease, lease.snapshot_material() as material:
        with pytest.raises(executor.ControlledExecutionRefused) as error:
            executor._run_development_fixture_verifier(
                material, expectation(**changes), fixture_input
            )
    assert "secret" not in str(error.value)


def test_closed_material_is_refused(private_root: Path, tmp_path: Path) -> None:
    fixture_input = write_input(tmp_path / "input.json")
    with admit(private_root) as lease:
        material = lease.snapshot_material()
        material.close()
        with pytest.raises(executor.ControlledExecutionRefused, match="sealed-material"):
            executor._run_development_fixture_verifier(material, expectation(), fixture_input)


@pytest.mark.parametrize("field", ["status", "verified", "qualifyingEvidence", "approved"])
def test_caller_trust_fields_in_synthetic_output_are_rejected(
    private_root: Path, tmp_path: Path, field: str
) -> None:
    with pytest.raises(executor.ControlledExecutionRefused, match="development-output:fields"):
        run(private_root, write_input(tmp_path / "input.json", **{field: True}))
