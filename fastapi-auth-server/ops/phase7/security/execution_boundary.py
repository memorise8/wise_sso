"""Admission checks for a future isolated Phase 7 execution boundary.

This module deliberately provides no process, network, Docker, or verifier execution.
It only pins caller-reviewed local inputs and a Unix socket pathname long enough for a
future controller to perform a separate authenticated operation.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Self

VERIFIER_NAME = "verifier.bin"
TRUST_ROOT_NAME = "trust-root.json"
DAEMON_SOCKET_NAME = "daemon.sock"

MAX_ROOT_PATH_BYTES = 4_096
MAX_PATH_COMPONENTS = 64
MAX_VERIFIER_BYTES = 64 * 1024 * 1024
MAX_TRUST_ROOT_BYTES = 8 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
# Values from linux/fcntl.h; Python 3.12 does not expose them on every Linux build.
_F_ADD_SEALS = 1_033
_F_GET_SEALS = 1_034
_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_REQUIRED_SEALS = _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_SEAL
_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


class BoundaryRefused(ValueError):
    """The local execution boundary did not satisfy the admission contract."""


@dataclass(frozen=True, slots=True)
class _PinnedMetadata:
    values: tuple[int, ...]

    @classmethod
    def capture(cls, value: os.stat_result) -> Self:
        return cls(tuple(int(getattr(value, field)) for field in _STABLE_FIELDS))

    def matches(self, value: os.stat_result) -> bool:
        return self.values == tuple(int(getattr(value, field)) for field in _STABLE_FIELDS)

    @property
    def identity(self) -> tuple[int, int]:
        return self.values[0], self.values[1]


def _flags(*, directory: bool = False) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise BoundaryRefused("boundary:nofollow-unavailable")
    result = os.O_RDONLY | nofollow | int(getattr(os, "O_CLOEXEC", 0))
    if directory:
        result |= os.O_DIRECTORY
    return int(result)


def _validated_components(root: Path) -> tuple[str, ...]:
    raw = os.fspath(root)
    if not isinstance(raw, str) or not raw.startswith(os.sep):
        raise BoundaryRefused("boundary:root-path")
    if "\x00" in raw or len(os.fsencode(raw)) > MAX_ROOT_PATH_BYTES:
        raise BoundaryRefused("boundary:root-path")
    normalized = os.path.normpath(raw)
    if raw != normalized or normalized == os.sep:
        raise BoundaryRefused("boundary:root-path")
    components = tuple(part for part in normalized.split(os.sep) if part)
    if not components or len(components) > MAX_PATH_COMPONENTS:
        raise BoundaryRefused("boundary:root-path")
    if any(part in {".", ".."} for part in components):
        raise BoundaryRefused("boundary:root-path")
    return components


def _open_root(root: Path) -> int:
    components = _validated_components(root)
    try:
        descriptor = os.open(os.sep, _flags(directory=True))
    except OSError as exc:
        raise BoundaryRefused("boundary:unsafe-root") from exc
    try:
        for component in components:
            next_descriptor = os.open(component, _flags(directory=True), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except (OSError, ValueError) as exc:
        os.close(descriptor)
        if isinstance(exc, BoundaryRefused):
            raise
        raise BoundaryRefused("boundary:unsafe-root") from exc
    return descriptor


def _require_root(metadata: os.stat_result, uid: int) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise BoundaryRefused("boundary:unsafe-root")


def _open_owned_file(
    root_fd: int,
    name: str,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> tuple[int, _PinnedMetadata]:
    try:
        descriptor = os.open(name, _flags() | os.O_NONBLOCK, dir_fd=root_fd)
        opened = os.fstat(descriptor)
        bound = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        if "descriptor" in locals():
            os.close(descriptor)
        raise BoundaryRefused(f"boundary:unsafe-{name}") from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or opened.st_uid != uid
        or opened.st_gid != gid
        or stat.S_IMODE(opened.st_mode) != mode
        or (opened.st_dev, opened.st_ino) != (bound.st_dev, bound.st_ino)
    ):
        os.close(descriptor)
        raise BoundaryRefused(f"boundary:unsafe-{name}")
    return descriptor, _PinnedMetadata.capture(opened)


def _require_socket(root_fd: int, uid: int, gid: int) -> _PinnedMetadata:
    try:
        metadata = os.stat(DAEMON_SOCKET_NAME, dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        raise BoundaryRefused("boundary:unsafe-daemon-socket") from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise BoundaryRefused("boundary:unsafe-daemon-socket")
    return _PinnedMetadata.capture(metadata)


def _require_maximum(maximum: int, label: str) -> int:
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise BoundaryRefused(f"policy:invalid-{label}-maximum")
    return maximum


def _bounded_sha256(descriptor: int, maximum: int, label: str) -> str:
    maximum = _require_maximum(maximum, label)
    before = os.fstat(descriptor)
    if before.st_size > maximum:
        raise BoundaryRefused(f"boundary:oversize-{label}")
    digest = hashlib.sha256()
    total = 0
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise BoundaryRefused(f"boundary:oversize-{label}")
        digest.update(chunk)
    after = os.fstat(descriptor)
    if not _PinnedMetadata.capture(before).matches(after):
        raise BoundaryRefused(f"boundary:changed-{label}")
    return digest.hexdigest()


def _require_reviewed_hash(value: str, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise BoundaryRefused(f"policy:invalid-{label}-sha256")
    return value


def _memfd_flags() -> int:
    """Return the Linux memfd flags, or fail closed."""
    create = getattr(os, "memfd_create", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    close_on_exec = getattr(os, "MFD_CLOEXEC", None)
    if (
        sys.platform != "linux"
        or create is None
        or not isinstance(allow_sealing, int)
        or not isinstance(close_on_exec, int)
    ):
        raise BoundaryRefused("boundary:sealed-material-unavailable")
    return allow_sealing | close_on_exec


def _write_all(descriptor: int, data: bytes, label: str) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        try:
            count = os.write(descriptor, view[written:])
        except OSError as exc:
            raise BoundaryRefused(f"boundary:snapshot-{label}") from exc
        if count <= 0:
            raise BoundaryRefused(f"boundary:snapshot-{label}")
        written += count


def _sha256_exact_pread(descriptor: int, size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise BoundaryRefused(f"boundary:snapshot-{label}")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _snapshot_descriptor(
    source: int,
    expected_metadata: _PinnedMetadata,
    expected_sha256: str,
    *,
    maximum: int,
    mode: int,
    label: str,
) -> tuple[int, _PinnedMetadata]:
    maximum = _require_maximum(maximum, label)
    flags = _memfd_flags()
    destination = -1
    try:
        before = os.fstat(source)
        if not expected_metadata.matches(before):
            raise BoundaryRefused(f"boundary:changed-{label}")
        if before.st_size <= 0:
            raise BoundaryRefused(f"boundary:empty-{label}")
        if before.st_size > maximum:
            raise BoundaryRefused(f"boundary:oversize-{label}")

        destination = os.memfd_create(f"phase7-{label}", flags)
        os.fchmod(destination, mode)
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            count = min(1024 * 1024, before.st_size - offset)
            chunk = os.pread(source, count, offset)
            if not chunk:
                raise BoundaryRefused(f"boundary:changed-{label}")
            _write_all(destination, chunk, label)
            digest.update(chunk)
            offset += len(chunk)

        after = os.fstat(source)
        if not expected_metadata.matches(after):
            raise BoundaryRefused(f"boundary:changed-{label}")
        if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
            raise BoundaryRefused(f"boundary:{label}-sha256")
        copied = os.fstat(destination)
        if copied.st_size != before.st_size or stat.S_IMODE(copied.st_mode) != mode:
            raise BoundaryRefused(f"boundary:snapshot-{label}")
        fcntl.fcntl(destination, _F_ADD_SEALS, _REQUIRED_SEALS)
        applied = fcntl.fcntl(destination, _F_GET_SEALS)
        if not isinstance(applied, int) or applied & _REQUIRED_SEALS != _REQUIRED_SEALS:
            raise BoundaryRefused(f"boundary:unsealed-{label}")
        sealed = os.fstat(destination)
        if sealed.st_size != before.st_size or stat.S_IMODE(sealed.st_mode) != mode:
            raise BoundaryRefused(f"boundary:snapshot-{label}")
        sealed_sha256 = _sha256_exact_pread(destination, before.st_size, label)
        if not hmac.compare_digest(sealed_sha256, expected_sha256):
            raise BoundaryRefused(f"boundary:{label}-sha256")
        os.lseek(destination, 0, os.SEEK_SET)
        result = destination, _PinnedMetadata.capture(sealed)
        destination = -1
        return result
    except BoundaryRefused:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise BoundaryRefused(f"boundary:snapshot-{label}") from exc
    finally:
        if destination >= 0:
            try:
                os.close(destination)
            except OSError:
                pass


@dataclass(frozen=True, slots=True, repr=False)
class SealedMaterial:
    """Immutable local copies that confer no execution authorization."""

    _verifier_fd: int
    _trust_root_fd: int
    _verifier_metadata: _PinnedMetadata
    _trust_root_metadata: _PinnedMetadata
    _verifier_sha256: str
    _trust_root_sha256: str
    _closed_state: list[bool]

    def __enter__(self) -> Self:
        try:
            self._require_open()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._closed_state[0]:
            raise BoundaryRefused("boundary:sealed-material-closed")
        try:
            self._revalidate_descriptor(self._verifier_fd, self._verifier_metadata, "verifier")
            self._revalidate_descriptor(
                self._trust_root_fd, self._trust_root_metadata, "trust-root"
            )
        except BoundaryRefused:
            self.close()
            raise

    @staticmethod
    def _revalidate_descriptor(descriptor: int, expected: _PinnedMetadata, label: str) -> None:
        try:
            current = os.fstat(descriptor)
            applied = fcntl.fcntl(descriptor, _F_GET_SEALS)
        except OSError as exc:
            raise BoundaryRefused(f"boundary:changed-sealed-{label}") from exc
        if (
            not expected.matches(current)
            or not isinstance(applied, int)
            or applied & _REQUIRED_SEALS != _REQUIRED_SEALS
        ):
            raise BoundaryRefused(f"boundary:changed-sealed-{label}")

    @property
    def verifier_fd(self) -> int:
        self._require_open()
        return self._verifier_fd

    @property
    def trust_root_fd(self) -> int:
        self._require_open()
        return self._trust_root_fd

    def close(self) -> None:
        if self._closed_state[0]:
            return
        self._closed_state[0] = True
        pairs = (
            (self._trust_root_fd, self._trust_root_metadata),
            (self._verifier_fd, self._verifier_metadata),
        )
        for descriptor, expected in pairs:
            try:
                current = os.fstat(descriptor)
            except OSError:
                continue
            if (current.st_dev, current.st_ino) == expected.identity:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def describe(self) -> Mapping[str, object]:
        self._require_open()
        return MappingProxyType(
            {
                "status": "UNVERIFIED",
                "immutableMaterial": True,
                "verifierSha256": self._verifier_sha256,
                "trustRootSha256": self._trust_root_sha256,
                "limitations": (
                    "sealed copies do not authenticate a publisher",
                    "sealed copies do not prove daemon isolation",
                    "no verifier, daemon, process, or network operation was performed",
                ),
            }
        )


@dataclass(frozen=True, slots=True, repr=False)
class BoundaryLease:
    """Pinned, non-executing admission state for the local boundary."""

    _root: Path
    _root_fd: int
    _verifier_fd: int
    _trust_root_fd: int
    _uid: int
    _gid: int
    _root_metadata: _PinnedMetadata
    _verifier_metadata: _PinnedMetadata
    _trust_root_metadata: _PinnedMetadata
    _socket_metadata: _PinnedMetadata
    _verifier_sha256: str
    _trust_root_sha256: str
    _closed_state: list[bool]

    def __enter__(self) -> Self:
        try:
            self.revalidate()
        except Exception:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed_state[0]:
            return
        self._closed_state[0] = True
        for descriptor in (self._trust_root_fd, self._verifier_fd, self._root_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass

    def revalidate(self) -> None:
        """Reject closure, path replacement, or metadata changes since admission."""
        if self._closed_state[0]:
            raise BoundaryRefused("boundary:closed")
        try:
            retained_root = os.fstat(self._root_fd)
            _require_root(retained_root, self._uid)
            if not self._root_metadata.matches(retained_root):
                raise BoundaryRefused("boundary:changed-root")
            rebound_fd = _open_root(self._root)
            try:
                rebound = os.fstat(rebound_fd)
            finally:
                os.close(rebound_fd)
            if not self._root_metadata.matches(rebound):
                raise BoundaryRefused("boundary:changed-root")
            self._revalidate_file(VERIFIER_NAME, self._verifier_fd, self._verifier_metadata, 0o500)
            self._revalidate_file(
                TRUST_ROOT_NAME, self._trust_root_fd, self._trust_root_metadata, 0o400
            )
            socket_metadata = _require_socket(self._root_fd, self._uid, self._gid)
            if socket_metadata.identity != self._socket_metadata.identity or (
                not self._socket_metadata.matches(
                    os.stat(DAEMON_SOCKET_NAME, dir_fd=self._root_fd, follow_symlinks=False)
                )
            ):
                raise BoundaryRefused("boundary:changed-daemon-socket")
        except BoundaryRefused:
            raise
        except OSError as exc:
            raise BoundaryRefused("boundary:changed") from exc

    def _revalidate_file(
        self, name: str, descriptor: int, expected: _PinnedMetadata, mode: int
    ) -> None:
        opened = os.fstat(descriptor)
        bound = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        if (
            not expected.matches(opened)
            or (opened.st_dev, opened.st_ino) != (bound.st_dev, bound.st_ino)
            or not stat.S_ISREG(bound.st_mode)
            or bound.st_nlink != 1
            or bound.st_uid != self._uid
            or bound.st_gid != self._gid
            or stat.S_IMODE(bound.st_mode) != mode
        ):
            raise BoundaryRefused(f"boundary:changed-{name}")

    def describe(self) -> Mapping[str, object]:
        """Describe admission without claiming authenticity, isolation, or execution."""
        self.revalidate()
        return MappingProxyType(
            {
                "status": "UNVERIFIED",
                "verifierName": VERIFIER_NAME,
                "verifierSha256": self._verifier_sha256,
                "trustRootName": TRUST_ROOT_NAME,
                "trustRootSha256": self._trust_root_sha256,
                "daemonSocketName": DAEMON_SOCKET_NAME,
                "descriptorsPinned": True,
                "limitations": (
                    "socket ownership does not prove daemon isolation",
                    "a reviewed local hash does not authenticate a publisher",
                    "no verifier, daemon, process, or network operation was performed",
                ),
            }
        )

    def snapshot_material(self) -> SealedMaterial:
        """Copy reviewed inputs into sealed memfds without executing either input."""
        self.revalidate()
        verifier_fd = -1
        trust_root_fd = -1
        try:
            verifier_fd, verifier_metadata = _snapshot_descriptor(
                self._verifier_fd,
                self._verifier_metadata,
                self._verifier_sha256,
                maximum=MAX_VERIFIER_BYTES,
                mode=0o500,
                label="verifier",
            )
            trust_root_fd, trust_root_metadata = _snapshot_descriptor(
                self._trust_root_fd,
                self._trust_root_metadata,
                self._trust_root_sha256,
                maximum=MAX_TRUST_ROOT_BYTES,
                mode=0o400,
                label="trust-root",
            )
            self.revalidate()
            result = SealedMaterial(
                _verifier_fd=verifier_fd,
                _trust_root_fd=trust_root_fd,
                _verifier_metadata=verifier_metadata,
                _trust_root_metadata=trust_root_metadata,
                _verifier_sha256=self._verifier_sha256,
                _trust_root_sha256=self._trust_root_sha256,
                _closed_state=[False],
            )
            verifier_fd = -1
            trust_root_fd = -1
            return result
        finally:
            for descriptor in (trust_root_fd, verifier_fd):
                if descriptor >= 0:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass


def admit_boundary(
    root: Path,
    *,
    verifier_sha256: str,
    trust_root_sha256: str,
) -> BoundaryLease:
    """Admit reviewed local inputs while retaining their descriptors.

    The expected hashes are caller-supplied policy inputs. Matching them is only a local
    integrity check and must not be treated as publisher authentication.
    """
    reviewed_verifier = _require_reviewed_hash(verifier_sha256, "verifier")
    reviewed_trust_root = _require_reviewed_hash(trust_root_sha256, "trust-root")
    uid = os.geteuid()
    gid = os.getegid()
    root_fd = _open_root(root)
    verifier_fd = -1
    trust_root_fd = -1
    try:
        root_metadata = os.fstat(root_fd)
        _require_root(root_metadata, uid)
        verifier_fd, verifier_metadata = _open_owned_file(
            root_fd, VERIFIER_NAME, mode=0o500, uid=uid, gid=gid
        )
        trust_root_fd, trust_root_metadata = _open_owned_file(
            root_fd, TRUST_ROOT_NAME, mode=0o400, uid=uid, gid=gid
        )
        socket_metadata = _require_socket(root_fd, uid, gid)
        actual_verifier = _bounded_sha256(verifier_fd, MAX_VERIFIER_BYTES, "verifier")
        actual_trust_root = _bounded_sha256(trust_root_fd, MAX_TRUST_ROOT_BYTES, "trust-root")
        if not hmac.compare_digest(actual_verifier, reviewed_verifier):
            raise BoundaryRefused("boundary:verifier-sha256")
        if not hmac.compare_digest(actual_trust_root, reviewed_trust_root):
            raise BoundaryRefused("boundary:trust-root-sha256")
        lease = BoundaryLease(
            _root=root,
            _root_fd=root_fd,
            _verifier_fd=verifier_fd,
            _trust_root_fd=trust_root_fd,
            _uid=uid,
            _gid=gid,
            _root_metadata=_PinnedMetadata.capture(root_metadata),
            _verifier_metadata=verifier_metadata,
            _trust_root_metadata=trust_root_metadata,
            _socket_metadata=socket_metadata,
            _verifier_sha256=actual_verifier,
            _trust_root_sha256=actual_trust_root,
            _closed_state=[False],
        )
        lease.revalidate()
    except Exception:
        for descriptor in (trust_root_fd, verifier_fd, root_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise
    return lease
