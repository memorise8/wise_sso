from __future__ import annotations

import errno
import fcntl
import hashlib
import importlib.util
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/phase7/security/execution_boundary.py"
spec = importlib.util.spec_from_file_location("phase7_sealed_material_test", MODULE)
assert spec is not None and spec.loader is not None
boundary = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = boundary
spec.loader.exec_module(boundary)

VERIFIER = b"synthetic verifier fixture, never executed\n"
TRUST_ROOT = b'{"synthetic":"trust root"}\n'


@pytest.fixture
def private_root(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    root = tmp_path_factory.mktemp("sealed-material")
    root.chmod(0o700)
    (root / boundary.VERIFIER_NAME).write_bytes(VERIFIER)
    (root / boundary.VERIFIER_NAME).chmod(0o500)
    (root / boundary.TRUST_ROOT_NAME).write_bytes(TRUST_ROOT)
    (root / boundary.TRUST_ROOT_NAME).chmod(0o400)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
        daemon.bind(str(root / boundary.DAEMON_SOCKET_NAME))
        (root / boundary.DAEMON_SOCKET_NAME).chmod(0o600)
        yield root


def admit(root: Path, *, verifier: bytes = VERIFIER, trust_root: bytes = TRUST_ROOT) -> Any:
    return boundary.admit_boundary(
        root,
        verifier_sha256=hashlib.sha256(verifier).hexdigest(),
        trust_root_sha256=hashlib.sha256(trust_root).hexdigest(),
    )


def test_snapshot_is_sealed_read_only_material(private_root: Path) -> None:
    required = boundary._REQUIRED_SEALS
    with admit(private_root) as lease, lease.snapshot_material() as material:
        description = material.describe()
        assert description["status"] == "UNVERIFIED"
        assert description["immutableMaterial"] is True
        assert "executionAllowed" not in description
        assert "authorized" not in description
        assert os.read(material.verifier_fd, len(VERIFIER)) == VERIFIER
        assert os.read(material.trust_root_fd, len(TRUST_ROOT)) == TRUST_ROOT
        assert fcntl.fcntl(material.verifier_fd, boundary._F_GET_SEALS) & required == required
        assert fcntl.fcntl(material.trust_root_fd, boundary._F_GET_SEALS) & required == required
        assert os.fstat(material.verifier_fd).st_mode & 0o777 == 0o500
        assert os.fstat(material.trust_root_fd).st_mode & 0o777 == 0o400
        assert not os.get_inheritable(material.verifier_fd)
        assert not os.get_inheritable(material.trust_root_fd)

        for descriptor in (material.verifier_fd, material.trust_root_fd):
            with pytest.raises(OSError) as write_error:
                os.write(descriptor, b"x")
            assert write_error.value.errno == errno.EPERM
            with pytest.raises(OSError) as truncate_error:
                os.ftruncate(descriptor, 0)
            assert truncate_error.value.errno == errno.EPERM


def test_source_mutation_after_snapshot_cannot_change_snapshot(private_root: Path) -> None:
    with admit(private_root) as lease, lease.snapshot_material() as material:
        path = private_root / boundary.VERIFIER_NAME
        path.chmod(0o700)
        path.write_bytes(b"changed after sealed copy")
        path.chmod(0o500)
        assert os.pread(material.verifier_fd, len(VERIFIER), 0) == VERIFIER


def test_snapshot_descriptors_are_read_only_properties(private_root: Path) -> None:
    with admit(private_root) as lease, lease.snapshot_material() as material:
        with pytest.raises((AttributeError, TypeError)):
            material.verifier_fd = -1
        with pytest.raises((AttributeError, TypeError)):
            material.trust_root_fd = -1


def test_snapshot_context_closes_both_descriptors(private_root: Path) -> None:
    with admit(private_root) as lease:
        with lease.snapshot_material() as material:
            verifier_fd = material.verifier_fd
            trust_root_fd = material.trust_root_fd
        for descriptor in (verifier_fd, trust_root_fd):
            with pytest.raises(OSError):
                os.fstat(descriptor)
        with pytest.raises(boundary.BoundaryRefused):
            material.describe()
        material.close()


def test_closed_snapshot_refuses_context_entry(private_root: Path) -> None:
    with admit(private_root) as lease:
        material = lease.snapshot_material()
        material.close()
        with pytest.raises(boundary.BoundaryRefused, match="sealed-material-closed"), material:
            pytest.fail("closed material must not enter")


@pytest.mark.parametrize("access", ["describe", "property", "enter"])
def test_closed_and_reused_fd_is_refused_without_closing_unrelated_file(
    private_root: Path, tmp_path: Path, access: str
) -> None:
    harmless = tmp_path / "harmless.txt"
    harmless.write_bytes(b"unrelated descriptor")
    with admit(private_root) as lease:
        material = lease.snapshot_material()
        verifier_fd = material.verifier_fd
        trust_root_fd = material.trust_root_fd
        os.close(verifier_fd)
        unrelated_fd = os.open(harmless, os.O_RDONLY)
        assert unrelated_fd == verifier_fd
        try:
            with pytest.raises(boundary.BoundaryRefused, match="changed-sealed-verifier"):
                if access == "describe":
                    material.describe()
                elif access == "property":
                    _ = material.verifier_fd
                else:
                    with material:
                        pytest.fail("reused descriptor must not enter")
            assert os.pread(unrelated_fd, 20, 0) == b"unrelated descriptor"
            with pytest.raises(OSError):
                os.fstat(trust_root_fd)
            material.close()
            assert os.pread(unrelated_fd, 20, 0) == b"unrelated descriptor"
        finally:
            os.close(unrelated_fd)


def test_consumer_exception_closes_snapshot_descriptors(private_root: Path) -> None:
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    with admit(private_root) as lease:
        with pytest.raises(RuntimeError, match="consumer failed"), lease.snapshot_material():
            raise RuntimeError("consumer failed")
    assert len(list(descriptors.iterdir())) == before


def test_partial_snapshot_failure_closes_every_memfd(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    real_fcntl = fcntl.fcntl

    def fail_trust_root_seal(fd: int, operation: int, argument: int = 0) -> Any:
        if operation == boundary._F_ADD_SEALS and os.fstat(fd).st_mode & 0o777 == 0o400:
            raise OSError(errno.EPERM, "synthetic sealing failure")
        return real_fcntl(fd, operation, argument)

    monkeypatch.setattr(boundary.fcntl, "fcntl", fail_trust_root_seal)
    with admit(private_root) as lease, pytest.raises(boundary.BoundaryRefused):
        lease.snapshot_material()
    assert len(list(descriptors.iterdir())) == before


def test_modes_are_applied_before_each_memfd_is_sealed(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fcntl = fcntl.fcntl
    modes_at_seal: list[int] = []

    def observe_mode(fd: int, operation: int, argument: int = 0) -> Any:
        if operation == boundary._F_ADD_SEALS:
            modes_at_seal.append(os.fstat(fd).st_mode & 0o777)
        return real_fcntl(fd, operation, argument)

    monkeypatch.setattr(boundary.fcntl, "fcntl", observe_mode)
    with admit(private_root) as lease, lease.snapshot_material():
        pass
    assert modes_at_seal == [0o500, 0o400]


def test_append_immediately_before_sealing_is_rejected(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fcntl = fcntl.fcntl
    appended = False

    def append_before_seal(fd: int, operation: int, argument: int = 0) -> Any:
        nonlocal appended
        if operation == boundary._F_ADD_SEALS and not appended:
            appended = True
            os.write(fd, b"suffix")
        return real_fcntl(fd, operation, argument)

    monkeypatch.setattr(boundary.fcntl, "fcntl", append_before_seal)
    with (
        admit(private_root) as lease,
        pytest.raises(boundary.BoundaryRefused, match="snapshot-verifier"),
    ):
        lease.snapshot_material()
    assert appended


@pytest.mark.parametrize(
    ("attribute", "owner"),
    [
        ("memfd_create", os),
        ("MFD_ALLOW_SEALING", os),
    ],
)
def test_unsupported_kernel_contract_fails_closed(
    private_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
    owner: object,
) -> None:
    monkeypatch.delattr(owner, attribute)
    with (
        admit(private_root) as lease,
        pytest.raises(boundary.BoundaryRefused, match="sealed-material-unavailable"),
    ):
        lease.snapshot_material()


def test_unsupported_memfd_syscall_fails_closed(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(name: str, flags: int) -> int:
        raise OSError(errno.ENOSYS, "synthetic unavailable syscall")

    monkeypatch.setattr(boundary.os, "memfd_create", unavailable)
    with admit(private_root) as lease, pytest.raises(boundary.BoundaryRefused):
        lease.snapshot_material()


def test_non_linux_platform_fails_closed(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(boundary.sys, "platform", "not-linux")
    with (
        admit(private_root) as lease,
        pytest.raises(boundary.BoundaryRefused, match="sealed-material-unavailable"),
    ):
        lease.snapshot_material()


@pytest.mark.parametrize("name", [boundary.VERIFIER_NAME, boundary.TRUST_ROOT_NAME])
def test_source_write_during_copy_is_rejected(
    private_root: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    original_pread = os.pread
    changed = False
    target = private_root / name
    target_identity = (target.stat().st_dev, target.stat().st_ino)

    def mutate_once(descriptor: int, count: int, offset: int) -> bytes:
        nonlocal changed
        data = original_pread(descriptor, count, offset)
        metadata = os.fstat(descriptor)
        if not changed and (metadata.st_dev, metadata.st_ino) == target_identity:
            changed = True
            mode = 0o500 if name == boundary.VERIFIER_NAME else 0o400
            original = VERIFIER if name == boundary.VERIFIER_NAME else TRUST_ROOT
            target.chmod(0o700)
            target.write_bytes(original)
            target.chmod(mode)
        return data

    monkeypatch.setattr(boundary.os, "pread", mutate_once)
    expected_label = "verifier" if name == boundary.VERIFIER_NAME else "trust-root"
    with (
        admit(private_root) as lease,
        pytest.raises(boundary.BoundaryRefused, match=f"changed-{expected_label}"),
    ):
        lease.snapshot_material()
    assert changed


def test_copied_digest_must_equal_reviewed_digest(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_write = os.write
    substituted = False

    def substitute_once(descriptor: int, data: bytes | memoryview) -> int:
        nonlocal substituted
        if not substituted:
            substituted = True
            return original_write(descriptor, b"x" * len(data))
        return original_write(descriptor, data)

    monkeypatch.setattr(boundary.os, "write", substitute_once)
    with (
        admit(private_root) as lease,
        pytest.raises(boundary.BoundaryRefused, match="verifier-sha256"),
    ):
        lease.snapshot_material()


@pytest.mark.parametrize("maximum", [0, -1, True, "1024"])
def test_invalid_snapshot_size_policy_is_rejected(
    private_root: Path, monkeypatch: pytest.MonkeyPatch, maximum: object
) -> None:
    with admit(private_root) as lease:
        monkeypatch.setattr(boundary, "MAX_VERIFIER_BYTES", maximum)
        with pytest.raises(boundary.BoundaryRefused, match="policy:invalid-verifier-maximum"):
            lease.snapshot_material()


def test_oversize_snapshot_is_rejected(private_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with admit(private_root) as lease:
        monkeypatch.setattr(boundary, "MAX_VERIFIER_BYTES", len(VERIFIER) - 1)
        with pytest.raises(boundary.BoundaryRefused, match="oversize-verifier"):
            lease.snapshot_material()


@pytest.mark.parametrize(
    ("name", "mode", "other"),
    [
        (boundary.VERIFIER_NAME, 0o500, TRUST_ROOT),
        (boundary.TRUST_ROOT_NAME, 0o400, VERIFIER),
    ],
)
def test_empty_snapshot_material_is_rejected(
    private_root: Path, name: str, mode: int, other: bytes
) -> None:
    path = private_root / name
    path.chmod(0o600)
    path.write_bytes(b"")
    path.chmod(mode)
    verifier = b"" if name == boundary.VERIFIER_NAME else other
    trust_root = b"" if name == boundary.TRUST_ROOT_NAME else other
    with (
        admit(private_root, verifier=verifier, trust_root=trust_root) as lease,
        pytest.raises(
            boundary.BoundaryRefused, match=f"empty-{'verifier' if mode == 0o500 else 'trust-root'}"
        ),
    ):
        lease.snapshot_material()
