from __future__ import annotations

import hashlib
import importlib.util
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ops/phase7/security/execution_boundary.py"
spec = importlib.util.spec_from_file_location("phase7_execution_boundary_test", MODULE)
assert spec is not None and spec.loader is not None
boundary = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = boundary
spec.loader.exec_module(boundary)

# Synthetic bytes: tests must never execute the verifier or connect to this socket.
VERIFIER = b"synthetic verifier fixture, not an executable\n"
TRUST_ROOT = b'{"synthetic":true}\n'


@pytest.fixture
def private_root(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    root = tmp_path_factory.mktemp("boundary")
    root.chmod(0o700)
    (root / "verifier.bin").write_bytes(VERIFIER)
    (root / "verifier.bin").chmod(0o500)
    (root / "trust-root.json").write_bytes(TRUST_ROOT)
    (root / "trust-root.json").chmod(0o400)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as daemon:
        daemon.bind(str(root / "daemon.sock"))
        (root / "daemon.sock").chmod(0o600)
        yield root


def admit(root: Path) -> Any:
    return boundary.admit_boundary(
        root,
        verifier_sha256=hashlib.sha256(VERIFIER).hexdigest(),
        trust_root_sha256=hashlib.sha256(TRUST_ROOT).hexdigest(),
    )


def test_admission_never_executes_or_connects(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail("admission must not execute or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    with admit(private_root) as lease:
        lease.revalidate()
        description = lease.describe()
        assert description["status"] == "UNVERIFIED"
        assert "executionAllowed" not in description
        assert "argv" not in description
        assert "env" not in description
    with pytest.raises(boundary.BoundaryRefused):
        lease.revalidate()
    lease.close()


@pytest.mark.parametrize(
    ("name", "mode"),
    [(".", 0o755), ("verifier.bin", 0o700), ("trust-root.json", 0o600), ("daemon.sock", 0o660)],
)
def test_unsafe_permissions_are_refused(private_root: Path, name: str, mode: int) -> None:
    (private_root / name).chmod(mode)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json", "daemon.sock"])
def test_child_symlink_is_refused(private_root: Path, name: str) -> None:
    child = private_root / name
    moved = private_root / f"saved-{name}"
    child.rename(moved)
    child.symlink_to(moved)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


def test_symlink_ancestor_is_refused(private_root: Path) -> None:
    alias = private_root.parent / f"alias-{private_root.name}"
    alias.symlink_to(private_root, target_is_directory=True)
    with pytest.raises(boundary.BoundaryRefused):
        admit(alias)


def test_symlink_in_parent_path_is_refused(private_root: Path) -> None:
    alias = private_root.parent / f"parent-alias-{private_root.name}"
    alias.symlink_to(private_root.parent, target_is_directory=True)
    with pytest.raises(boundary.BoundaryRefused):
        admit(alias / private_root.name)


def test_relative_root_is_refused(private_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(private_root.parent)
    with pytest.raises(boundary.BoundaryRefused):
        admit(Path(private_root.name))


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json", "daemon.sock"])
def test_missing_resource_is_refused(private_root: Path, name: str) -> None:
    (private_root / name).unlink()
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


def test_foreign_owner_is_refused(private_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    different_uid = os.geteuid() + 1
    monkeypatch.setattr(os, "geteuid", lambda: different_uid)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json", "daemon.sock"])
def test_hardlinked_material_is_refused(private_root: Path, name: str) -> None:
    os.link(private_root / name, private_root / f"alias-{name}")
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("kind", ["file", "directory", "fifo"])
def test_daemon_must_be_a_socket(private_root: Path, kind: str) -> None:
    path = private_root / "daemon.sock"
    path.unlink()
    if kind == "file":
        path.write_bytes(b"not a socket")
    elif kind == "directory":
        path.mkdir()
    else:
        os.mkfifo(path)
    path.chmod(0o600)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json"])
def test_fifo_material_is_refused_without_blocking(private_root: Path, name: str) -> None:
    path = private_root / name
    mode = path.stat().st_mode & 0o777
    path.unlink()
    os.mkfifo(path, mode)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json"])
def test_digest_mismatch_is_refused(private_root: Path, name: str) -> None:
    path = private_root / name
    mode = path.stat().st_mode & 0o777
    path.chmod(0o600)
    path.write_bytes(b"substituted material")
    path.chmod(mode)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


@pytest.mark.parametrize("digest", [None, True, "", "a" * 63, "A" * 64, "sha256:" + "a" * 64])
def test_unreviewed_or_malformed_hash_is_refused(private_root: Path, digest: Any) -> None:
    with pytest.raises(boundary.BoundaryRefused):
        boundary.admit_boundary(
            private_root,
            verifier_sha256=digest,
            trust_root_sha256=hashlib.sha256(TRUST_ROOT).hexdigest(),
        )


@pytest.mark.parametrize("name", ["verifier.bin", "trust-root.json", "daemon.sock"])
def test_revalidation_detects_name_replacement(private_root: Path, name: str) -> None:
    with admit(private_root) as lease:
        path = private_root / name
        path.rename(private_root / f"original-{name}")
        if name == "daemon.sock":
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as substitute:
                substitute.bind(str(path))
                path.chmod(0o600)
                with pytest.raises(boundary.BoundaryRefused):
                    lease.revalidate()
        else:
            path.write_bytes(VERIFIER if name == "verifier.bin" else TRUST_ROOT)
            path.chmod(0o500 if name == "verifier.bin" else 0o400)
            with pytest.raises(boundary.BoundaryRefused):
                lease.revalidate()


def test_revalidation_detects_directory_replacement(private_root: Path) -> None:
    with admit(private_root) as lease:
        moved = private_root.with_name(f"{private_root.name}-moved")
        private_root.rename(moved)
        private_root.mkdir(mode=0o700)
        with pytest.raises(boundary.BoundaryRefused):
            lease.revalidate()


def test_revalidation_detects_in_place_write_even_after_mode_restore(private_root: Path) -> None:
    with admit(private_root) as lease:
        path = private_root / "verifier.bin"
        path.chmod(0o700)
        path.write_bytes(b"x" * len(VERIFIER))
        path.chmod(0o500)
        with pytest.raises(boundary.BoundaryRefused):
            lease.revalidate()


def test_oversize_material_is_refused(private_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(boundary, "MAX_VERIFIER_BYTES", len(VERIFIER) - 1)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)


def test_mutation_during_hashing_is_refused(
    private_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_read = os.read
    changed = False

    def mutate_once(descriptor: int, count: int) -> bytes:
        nonlocal changed
        data = original_read(descriptor, count)
        if not changed:
            changed = True
            path = private_root / "verifier.bin"
            path.chmod(0o700)
            # Restore identical bytes: content equality must not conceal a write race.
            path.write_bytes(VERIFIER)
            path.chmod(0o500)
        return data

    monkeypatch.setattr(os, "read", mutate_once)
    with pytest.raises(boundary.BoundaryRefused):
        admit(private_root)
    assert changed


def test_failed_admissions_do_not_leak_descriptors(private_root: Path) -> None:
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    for _ in range(20):
        with pytest.raises(boundary.BoundaryRefused):
            boundary.admit_boundary(
                private_root,
                verifier_sha256="0" * 64,
                trust_root_sha256=hashlib.sha256(TRUST_ROOT).hexdigest(),
            )
    assert len(list(descriptors.iterdir())) == before


def test_context_exception_closes_descriptors(private_root: Path) -> None:
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    with pytest.raises(RuntimeError, match="consumer failure"), admit(private_root):
        raise RuntimeError("consumer failure")
    assert len(list(descriptors.iterdir())) == before


def test_failed_context_entry_closes_descriptors(private_root: Path) -> None:
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    lease = admit(private_root)
    (private_root / "daemon.sock").unlink()
    with pytest.raises(boundary.BoundaryRefused), lease:
        pytest.fail("changed boundary must not enter")
    assert len(list(descriptors.iterdir())) == before
