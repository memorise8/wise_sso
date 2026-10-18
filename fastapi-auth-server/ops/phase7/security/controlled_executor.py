"""Fail-closed Phase 7 verifier process boundary.

The reviewed Cosign v3 command shapes and bounded pre-admission checks are defined,
but production activation is deliberately absent. B03 must authenticate and
independently approve the verifier, trust root and policy; until then
:func:`verify_for_qualification` refuses before descriptor access or process start.
The private development harness proves bounded execution of sealed descriptors
without making that trust decision.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any, NoReturn, Protocol

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 60.0
STANDARD_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
# Compatibility/security floor only. It does not select or approve the local binary.
COSIGN_V3_COMPATIBILITY_SECURITY_FLOOR = (3, 1, 3)

_F_ADD_SEALS = 1_033
_F_GET_SEALS = 1_034
_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_REQUIRED_SEALS = _F_SEAL_WRITE | _F_SEAL_GROW | _F_SEAL_SHRINK | _F_SEAL_SEAL

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PRINTABLE = re.compile(r"[!-~]{1,2048}")
_DEVELOPMENT_RESULT_FIELDS = frozenset(
    {"schemaVersion", "digest", "identity", "issuer", "rekorIncluded"}
)


class ControlledExecutionRefused(ValueError):
    """Public-safe refusal that never embeds supplied material."""


def _load_b01_lifecycle() -> ModuleType:
    path = Path(__file__).resolve().parent.parent / "collector_runtime.py"
    spec = importlib.util.spec_from_file_location("phase7_controlled_executor_b01", path)
    if spec is None or spec.loader is None:
        raise ControlledExecutionRefused("owned-process:lifecycle-unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        sys.modules.pop(spec.name, None)
        raise ControlledExecutionRefused("owned-process:lifecycle-unavailable") from exc
    return module


@dataclass(frozen=True, slots=True)
class CosignV3Policy:
    """Candidate exact policy values; their approval is outside this module."""

    identity: str
    issuer: str

    def validate(self) -> None:
        for value, label in ((self.identity, "identity"), (self.issuer, "issuer")):
            if not isinstance(value, str) or _PRINTABLE.fullmatch(value) is None:
                raise ControlledExecutionRefused(f"cosign-policy:{label}")


@dataclass(frozen=True, slots=True)
class StandardBundleAdmission:
    """Bounded v0.3 bundle shape observation, not signature authentication."""

    sha256: str
    size: int
    media_type: str = STANDARD_BUNDLE_MEDIA_TYPE


@dataclass(frozen=True, slots=True)
class ArtifactAdmission:
    """Independent local artifact digest binding for a future Cosign call."""

    digest: str
    size: int


@dataclass(frozen=True, slots=True)
class CosignProcessObservation:
    """Bounded diagnostic bytes from a successful Cosign process exit."""

    return_code: int
    stdout_sha256: str
    stdout_size: int
    stderr_sha256: str
    stderr_size: int


@dataclass(frozen=True, slots=True)
class ProcessCapture:
    """Bounded byte capture returned by a B01-owned one-shot process runner."""

    return_code: int
    stdout: bytes
    stderr: bytes


class OwnedProcessRunner(Protocol):
    """B01 lifecycle boundary; ``pass_fds`` are borrowed and must not be closed."""

    def run(
        self,
        argv: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> ProcessCapture: ...


@dataclass(frozen=True, slots=True)
class CosignBlobCheckpointObservation:
    """Same-FD Cosign adapter observation that cannot qualify before B03."""

    artifact: ArtifactAdmission
    bundle: StandardBundleAdmission
    process: CosignProcessObservation
    argv_sha256: str
    evidence_class: str = "DEVELOPMENT_ONLY_UNAUTHENTICATED_TOOLCHAIN"

    def describe(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "evidenceClass": self.evidence_class,
                "artifactDigest": self.artifact.digest,
                "bundleSha256": self.bundle.sha256,
                "argvSha256": self.argv_sha256,
                "stdoutSha256": self.process.stdout_sha256,
                "stderrSha256": self.process.stderr_sha256,
                "limitations": (
                    "B03 authenticated activation is absent",
                    "development process-group ownership cannot contain escaped descendants",
                    "this checkpoint cannot release FROZEN or READY gates",
                ),
            }
        )


@dataclass(slots=True)
class _PinnedRegular:
    descriptor: int
    metadata: os.stat_result
    label: str

    def revalidate(self) -> None:
        try:
            current = os.fstat(self.descriptor)
        except OSError as exc:
            raise ControlledExecutionRefused(f"{self.label}:changed") from exc
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(self.metadata, field) != getattr(current, field) for field in stable):
            raise ControlledExecutionRefused(f"{self.label}:changed")

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor < 0:
            return
        try:
            current = os.fstat(descriptor)
        except OSError:
            return
        if (current.st_dev, current.st_ino) == (self.metadata.st_dev, self.metadata.st_ino):
            os.close(descriptor)


@dataclass(slots=True)
class _SealedSnapshot:
    descriptor: int
    metadata: os.stat_result
    sha256: str
    size: int
    label: str

    def revalidate(self) -> None:
        try:
            current = os.fstat(self.descriptor)
            seals = fcntl.fcntl(self.descriptor, _F_GET_SEALS)
        except OSError as exc:
            raise ControlledExecutionRefused(f"{self.label}:changed-sealed") from exc
        stable = ("st_dev", "st_ino", "st_mode", "st_size")
        if (
            any(getattr(self.metadata, field) != getattr(current, field) for field in stable)
            or not isinstance(seals, int)
            or seals & _REQUIRED_SEALS != _REQUIRED_SEALS
        ):
            raise ControlledExecutionRefused(f"{self.label}:changed-sealed")
        if _pread_sha256(self.descriptor, self.size, self.label) != self.sha256:
            raise ControlledExecutionRefused(f"{self.label}:changed-sealed")

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor < 0:
            return
        try:
            current = os.fstat(descriptor)
        except OSError:
            return
        if (current.st_dev, current.st_ino) == (self.metadata.st_dev, self.metadata.st_ino):
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _DevelopmentExpectation:
    """Synthetic fixture expectation; never a production policy or approval."""

    digest: str
    identity: str
    issuer: str
    rekor_required: bool = True

    def validate(self) -> None:
        if not isinstance(self.digest, str) or _DIGEST.fullmatch(self.digest) is None:
            raise ControlledExecutionRefused("development-policy:digest")
        for value, label in ((self.identity, "identity"), (self.issuer, "issuer")):
            if not isinstance(value, str) or _PRINTABLE.fullmatch(value) is None:
                raise ControlledExecutionRefused(f"development-policy:{label}")
        if self.rekor_required is not True:
            raise ControlledExecutionRefused("development-policy:rekor-required")


@dataclass(frozen=True, slots=True)
class _DevelopmentObservation:
    """Matched synthetic response with a permanently nonqualifying classification."""

    digest: str
    identity: str
    issuer: str
    rekor_included: bool
    evidence_class: str = "DEVELOPMENT_ONLY_SYNTHETIC_VERIFIER"

    def describe(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "outcome": "SYNTHETIC_VERIFIER_MATCHED",
                "digest": self.digest,
                "identity": self.identity,
                "issuer": self.issuer,
                "rekorIncluded": self.rekor_included,
                "evidenceClass": self.evidence_class,
                "limitations": (
                    "synthetic protocol is not the Cosign CLI contract",
                    "sealed bytes do not authenticate their publisher",
                    "B03 bootstrap and independent approval remain required",
                    "this observation cannot release FROZEN or READY gates",
                ),
            }
        )


def verify_for_qualification(*_args: object, **_kwargs: object) -> NoReturn:
    """Refuse before descriptor access or process creation until B03 activation.

    Keeping this stable entrypoint gives the stagers a fail-closed consumer target
    without accepting a caller-provided ``verified``/``approved`` flag.
    """

    raise ControlledExecutionRefused("qualification:independently-approved-toolchain-required")


def _read_regular_bounded(path: Path, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ControlledExecutionRefused(f"{label}:path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ControlledExecutionRefused(f"{label}:nofollow-unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | nofollow | int(getattr(os, "O_CLOEXEC", 0)),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise ControlledExecutionRefused(f"{label}:size-or-type")
        chunks: list[bytes] = []
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                raise ControlledExecutionRefused(f"{label}:changed")
            chunks.append(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ControlledExecutionRefused(f"{label}:changed")
        return b"".join(chunks)
    except ControlledExecutionRefused:
        raise
    except OSError as exc:
        raise ControlledExecutionRefused(f"{label}:open") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_pinned_regular(path: Path, maximum: int, label: str) -> _PinnedRegular:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ControlledExecutionRefused(f"{label}:path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ControlledExecutionRefused(f"{label}:nofollow-unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | nofollow | int(getattr(os, "O_CLOEXEC", 0)),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > maximum
        ):
            raise ControlledExecutionRefused(f"{label}:size-or-type")
        result = _PinnedRegular(descriptor, metadata, label)
        descriptor = -1
        return result
    except ControlledExecutionRefused:
        raise
    except OSError as exc:
        raise ControlledExecutionRefused(f"{label}:open") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _pinned_bytes(pinned: _PinnedRegular) -> bytes:
    pinned.revalidate()
    chunks: list[bytes] = []
    offset = 0
    while offset < pinned.metadata.st_size:
        try:
            chunk = os.pread(
                pinned.descriptor,
                min(1024 * 1024, pinned.metadata.st_size - offset),
                offset,
            )
        except OSError as exc:
            raise ControlledExecutionRefused(f"{pinned.label}:changed") from exc
        if not chunk:
            raise ControlledExecutionRefused(f"{pinned.label}:changed")
        chunks.append(chunk)
        offset += len(chunk)
    pinned.revalidate()
    return b"".join(chunks)


def _pinned_sha256(pinned: _PinnedRegular) -> str:
    pinned.revalidate()
    digest = hashlib.sha256()
    offset = 0
    while offset < pinned.metadata.st_size:
        try:
            chunk = os.pread(
                pinned.descriptor,
                min(1024 * 1024, pinned.metadata.st_size - offset),
                offset,
            )
        except OSError as exc:
            raise ControlledExecutionRefused(f"{pinned.label}:changed") from exc
        if not chunk:
            raise ControlledExecutionRefused(f"{pinned.label}:changed")
        digest.update(chunk)
        offset += len(chunk)
    pinned.revalidate()
    return digest.hexdigest()


def _pread_sha256(descriptor: int, size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        try:
            chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        except OSError as exc:
            raise ControlledExecutionRefused(f"{label}:sealed-read") from exc
        if not chunk:
            raise ControlledExecutionRefused(f"{label}:sealed-read")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def _sealed_snapshot(pinned: _PinnedRegular, expected_sha256: str) -> _SealedSnapshot:
    create = getattr(os, "memfd_create", None)
    allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
    close_on_exec = getattr(os, "MFD_CLOEXEC", None)
    if (
        sys.platform != "linux"
        or create is None
        or not isinstance(allow_sealing, int)
        or not isinstance(close_on_exec, int)
    ):
        raise ControlledExecutionRefused(f"{pinned.label}:sealed-unavailable")
    pinned.revalidate()
    destination = -1
    try:
        destination = os.memfd_create(f"phase7-{pinned.label}", allow_sealing | close_on_exec)
        os.fchmod(destination, 0o400)
        digest = hashlib.sha256()
        offset = 0
        while offset < pinned.metadata.st_size:
            try:
                chunk = os.pread(
                    pinned.descriptor,
                    min(1024 * 1024, pinned.metadata.st_size - offset),
                    offset,
                )
            except OSError as exc:
                raise ControlledExecutionRefused(f"{pinned.label}:snapshot") from exc
            if not chunk:
                raise ControlledExecutionRefused(f"{pinned.label}:snapshot")
            view = memoryview(chunk)
            while view:
                try:
                    written = os.write(destination, view)
                except OSError as exc:
                    raise ControlledExecutionRefused(f"{pinned.label}:snapshot") from exc
                if written <= 0:
                    raise ControlledExecutionRefused(f"{pinned.label}:snapshot")
                view = view[written:]
            digest.update(chunk)
            offset += len(chunk)
        pinned.revalidate()
        if digest.hexdigest() != expected_sha256:
            raise ControlledExecutionRefused(f"{pinned.label}:snapshot-digest")
        fcntl.fcntl(destination, _F_ADD_SEALS, _REQUIRED_SEALS)
        metadata = os.fstat(destination)
        result = _SealedSnapshot(
            descriptor=destination,
            metadata=metadata,
            sha256=expected_sha256,
            size=pinned.metadata.st_size,
            label=pinned.label,
        )
        result.revalidate()
        destination = -1
        return result
    except ControlledExecutionRefused:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise ControlledExecutionRefused(f"{pinned.label}:snapshot") from exc
    finally:
        if destination >= 0:
            os.close(destination)


def _standard_bundle(raw: bytes) -> StandardBundleAdmission:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ControlledExecutionRefused("cosign-bundle:json") from exc
    if not isinstance(document, dict):
        raise ControlledExecutionRefused("cosign-bundle:shape")
    if document.get("mediaType") != STANDARD_BUNDLE_MEDIA_TYPE:
        raise ControlledExecutionRefused("cosign-bundle:standard-v0.3-required")
    if not isinstance(document.get("verificationMaterial"), dict):
        raise ControlledExecutionRefused("cosign-bundle:verification-material")
    content = {name for name in ("messageSignature", "dsseEnvelope") if name in document}
    if len(content) != 1 or not isinstance(document[next(iter(content))], dict):
        raise ControlledExecutionRefused("cosign-bundle:content")
    return StandardBundleAdmission(hashlib.sha256(raw).hexdigest(), len(raw))


def pre_admit_standard_bundle(path: Path) -> StandardBundleAdmission:
    """Reject legacy LocalSignedPayload JSON before any future Cosign execution."""

    raw = _read_regular_bounded(path, MAX_INPUT_BYTES, "cosign-bundle")
    return _standard_bundle(raw)


def bind_blob_artifact(
    path: Path, expected_digest: str, *, maximum_bytes: int = MAX_ARTIFACT_BYTES
) -> ArtifactAdmission:
    """Hash the exact local blob independently of Cosign's signed claim checks."""

    if not isinstance(expected_digest, str) or _DIGEST.fullmatch(expected_digest) is None:
        raise ControlledExecutionRefused("cosign-artifact:digest")
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or not 0 < maximum_bytes <= MAX_ARTIFACT_BYTES
    ):
        raise ControlledExecutionRefused("cosign-artifact:maximum")
    actual_sha256, size = _hash_regular_bounded(path, maximum_bytes, "cosign-artifact")
    actual = "sha256:" + actual_sha256
    if actual != expected_digest:
        raise ControlledExecutionRefused("cosign-artifact:digest-mismatch")
    return ArtifactAdmission(actual, size)


def _hash_regular_bounded(path: Path, maximum: int, label: str) -> tuple[str, int]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ControlledExecutionRefused(f"{label}:path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ControlledExecutionRefused(f"{label}:nofollow-unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | nofollow | int(getattr(os, "O_CLOEXEC", 0)),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise ControlledExecutionRefused(f"{label}:size-or-type")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                raise ControlledExecutionRefused(f"{label}:changed")
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ControlledExecutionRefused(f"{label}:changed")
        return digest.hexdigest(), before.st_size
    except ControlledExecutionRefused:
        raise
    except OSError as exc:
        raise ControlledExecutionRefused(f"{label}:open") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_cosign_v3_blob_argv(
    verifier_fd: int,
    trust_root_fd: int,
    bundle_fd: int,
    artifact_fd: int,
    policy: CosignV3Policy,
) -> tuple[str, ...]:
    """Build the reviewed Cosign v3 verify-blob FD contract without executing it."""

    descriptors = (verifier_fd, trust_root_fd, bundle_fd, artifact_fd)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in descriptors
    ):
        raise ControlledExecutionRefused("cosign-contract:descriptor")
    if not isinstance(policy, CosignV3Policy):
        raise ControlledExecutionRefused("cosign-policy:type")
    policy.validate()
    executable = f"/proc/self/fd/{verifier_fd}"
    return (
        executable,
        "verify-blob",
        "--bundle",
        f"/proc/self/fd/{bundle_fd}",
        "--trusted-root",
        f"/proc/self/fd/{trust_root_fd}",
        "--certificate-identity",
        policy.identity,
        "--certificate-oidc-issuer",
        policy.issuer,
        f"/proc/self/fd/{artifact_fd}",
    )


def build_cosign_v3_image_argv(
    verifier_fd: int,
    trust_root_fd: int,
    local_layout_fd: int,
    policy: CosignV3Policy,
) -> tuple[str, ...]:
    """Build the reviewed air-gapped image argv without executing or approving it."""

    descriptors = (verifier_fd, trust_root_fd, local_layout_fd)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in descriptors
    ):
        raise ControlledExecutionRefused("cosign-contract:descriptor")
    if not isinstance(policy, CosignV3Policy):
        raise ControlledExecutionRefused("cosign-policy:type")
    policy.validate()
    executable = f"/proc/self/fd/{verifier_fd}"
    return (
        executable,
        "verify",
        "--local-image",
        "--trusted-root",
        f"/proc/self/fd/{trust_root_fd}",
        "--certificate-identity",
        policy.identity,
        "--certificate-oidc-issuer",
        policy.issuer,
        "--check-claims=true",
        "--output",
        "json",
        f"/proc/self/fd/{local_layout_fd}",
    )


def run_cosign_v3_image_checkpoint(*_args: object, **_kwargs: object) -> NoReturn:
    """Refuse images until index/platform/config and local-layout binding exists."""

    raise ControlledExecutionRefused("cosign-image:layout-projection-not-implemented")


def validate_cosign_v3_blob_process_result(
    return_code: int, stdout: bytes, stderr: bytes
) -> CosignProcessObservation:
    """Use exit success as verdict; retain bounded output only as hashed diagnostics."""

    if type(return_code) is not int or return_code != 0:
        raise ControlledExecutionRefused("cosign-process:rejected")
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise ControlledExecutionRefused("cosign-process:output-type")
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        raise ControlledExecutionRefused("cosign-process:output-oversize")
    return CosignProcessObservation(
        return_code=return_code,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_size=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stderr_size=len(stderr),
    )


def _run_cosign_v3_blob_checkpoint(
    material: Any,
    policy: CosignV3Policy,
    bundle_path: Path,
    artifact_path: Path,
    expected_artifact_digest: str,
    runner: OwnedProcessRunner | None = None,
    *,
    timeout_seconds: float = 10.0,
    maximum_output_bytes: int = MAX_OUTPUT_BYTES,
) -> CosignBlobCheckpointObservation:
    """Use the same admitted FDs for a B01-owned, still nonqualifying Cosign call.

    This adapter is deliberately separate from :func:`verify_for_qualification`.
    A fake or development runner can exercise it, but cannot create qualifying
    evidence; B03 must later supply the authenticated activation and live B01 runner.
    """

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise ControlledExecutionRefused("cosign-policy:timeout")
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or not 0 < maximum_output_bytes <= MAX_OUTPUT_BYTES
    ):
        raise ControlledExecutionRefused("cosign-policy:output-maximum")
    if not isinstance(policy, CosignV3Policy):
        raise ControlledExecutionRefused("cosign-policy:type")
    policy.validate()
    if (
        not isinstance(expected_artifact_digest, str)
        or _DIGEST.fullmatch(expected_artifact_digest) is None
    ):
        raise ControlledExecutionRefused("cosign-artifact:digest")
    try:
        description = material.describe()
        verifier_fd = material.verifier_fd
        trust_root_fd = material.trust_root_fd
    except Exception as exc:
        raise ControlledExecutionRefused("boundary:sealed-material") from exc
    if (
        description.get("status") != "UNVERIFIED"
        or description.get("immutableMaterial") is not True
    ):
        raise ControlledExecutionRefused("boundary:sealed-material")

    bundle = _open_pinned_regular(bundle_path, MAX_INPUT_BYTES, "cosign-bundle")
    artifact: _PinnedRegular | None = None
    sealed_bundle: _SealedSnapshot | None = None
    sealed_artifact: _SealedSnapshot | None = None
    try:
        artifact = _open_pinned_regular(artifact_path, MAX_ARTIFACT_BYTES, "cosign-artifact")
        bundle_admission = _standard_bundle(_pinned_bytes(bundle))
        artifact_sha256 = _pinned_sha256(artifact)
        actual_artifact_digest = "sha256:" + artifact_sha256
        if actual_artifact_digest != expected_artifact_digest:
            raise ControlledExecutionRefused("cosign-artifact:digest-mismatch")
        artifact_admission = ArtifactAdmission(
            digest=actual_artifact_digest,
            size=artifact.metadata.st_size,
        )
        sealed_bundle = _sealed_snapshot(bundle, bundle_admission.sha256)
        sealed_artifact = _sealed_snapshot(artifact, artifact_sha256)
        argv = build_cosign_v3_blob_argv(
            verifier_fd,
            trust_root_fd,
            sealed_bundle.descriptor,
            sealed_artifact.descriptor,
            policy,
        )
        # Revalidate every immutable descriptor immediately before handing it to B01.
        sealed_bundle.revalidate()
        sealed_artifact.revalidate()
        if material.verifier_fd != verifier_fd or material.trust_root_fd != trust_root_fd:
            raise ControlledExecutionRefused("boundary:sealed-material")
        try:
            active_runner: OwnedProcessRunner = (
                runner if runner is not None else _DevelopmentOwnedProcessRunner()
            )
            capture = active_runner.run(
                argv,
                pass_fds=(
                    verifier_fd,
                    trust_root_fd,
                    sealed_bundle.descriptor,
                    sealed_artifact.descriptor,
                ),
                timeout_seconds=float(timeout_seconds),
                maximum_output_bytes=maximum_output_bytes,
            )
        except ControlledExecutionRefused:
            raise
        except Exception as exc:
            raise ControlledExecutionRefused("cosign-process:runner") from exc
        # The result applies only if the exact same sealed inputs survived the call.
        sealed_bundle.revalidate()
        sealed_artifact.revalidate()
        if material.verifier_fd != verifier_fd or material.trust_root_fd != trust_root_fd:
            raise ControlledExecutionRefused("boundary:sealed-material")
        if not isinstance(capture, ProcessCapture):
            raise ControlledExecutionRefused("cosign-process:capture")
        process = validate_cosign_v3_blob_process_result(
            capture.return_code, capture.stdout, capture.stderr
        )
        argv_sha256 = hashlib.sha256(b"\0".join(value.encode() for value in argv)).hexdigest()
        return CosignBlobCheckpointObservation(
            artifact=artifact_admission,
            bundle=bundle_admission,
            process=process,
            argv_sha256=argv_sha256,
        )
    finally:
        if sealed_artifact is not None:
            sealed_artifact.close()
        if sealed_bundle is not None:
            sealed_bundle.close()
        if artifact is not None:
            artifact.close()
        bundle.close()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ControlledExecutionRefused("development-output:duplicate-field")
        result[key] = value
    return result


def _open_bounded_file(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ControlledExecutionRefused("development-input:path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ControlledExecutionRefused("development-input:nofollow-unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | nofollow | int(getattr(os, "O_CLOEXEC", 0)),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_INPUT_BYTES
        ):
            raise ControlledExecutionRefused("development-input:size")
        return descriptor
    except ControlledExecutionRefused:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ControlledExecutionRefused("development-input:open") from exc


def _collect_pipe_bytes(
    process: subprocess.Popen[bytes], deadline: float, maximum: int, label: str
) -> tuple[bytes, bytes]:
    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        raise ControlledExecutionRefused(f"{label}:pipes")
    selector: selectors.BaseSelector | None = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ, "stdout")
        selector.register(stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControlledExecutionRefused(f"{label}:timeout")
            events = selector.select(remaining)
            if not events:
                raise ControlledExecutionRefused(f"{label}:timeout")
            for key, _mask in events:
                chunk = os.read(key.fd, min(65_536, maximum + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    raise ControlledExecutionRefused(f"{label}:{key.data}-oversize")
    finally:
        if selector is not None:
            selector.close()
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


class _DevelopmentOwnedProcessRunner:
    """One-shot mechanics reusing B01's reviewed unreaped-leader PG drain."""

    def __init__(self, label: str = "cosign-process") -> None:
        self._label = label

    def run(
        self,
        argv: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> ProcessCapture:
        if not argv or argv[0] != f"/proc/self/fd/{pass_fds[0]}":
            raise ControlledExecutionRefused("cosign-process:argv")
        lifecycle = _load_b01_lifecycle()
        pidfd_open = getattr(os, "pidfd_open", None)
        if pidfd_open is None:
            raise ControlledExecutionRefused("owned-process:pidfd-unavailable")
        process: subprocess.Popen[bytes] | None = None
        pidfd = -1
        drained = False
        deadline = time.monotonic() + timeout_seconds
        drain_timeout = min(2.0, max(0.05, timeout_seconds))
        try:
            try:
                process = subprocess.Popen(  # noqa: S603
                    argv,
                    executable=argv[0],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    close_fds=True,
                    pass_fds=pass_fds,
                    env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    start_new_session=True,
                )
            except OSError as exc:
                raise ControlledExecutionRefused("cosign-process:launch") from exc
            try:
                pidfd = pidfd_open(process.pid, 0)
            except BaseException:
                lifecycle._terminate_before_pidfd(process, drain_timeout)
                drained = True
                raise
            stdout, stderr = _collect_pipe_bytes(
                process, deadline, maximum_output_bytes, self._label
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not lifecycle._wait_for_exit(pidfd, remaining):
                raise ControlledExecutionRefused(f"{self._label}:timeout")
            # Keep the exited leader unreaped until B01 has signaled and drained its PG.
            lifecycle._terminate_process_group(process, pidfd, drain_timeout)
            drained = True
            if process.returncode is None:
                raise ControlledExecutionRefused("owned-process:leader-reap-failed")
            return ProcessCapture(process.returncode, stdout, stderr)
        except ControlledExecutionRefused:
            raise
        except BaseException as exc:
            raise ControlledExecutionRefused("owned-process:lifecycle") from exc
        finally:
            if process is not None:
                if not drained:
                    try:
                        if pidfd >= 0:
                            lifecycle._terminate_process_group(process, pidfd, drain_timeout)
                        else:
                            lifecycle._terminate_before_pidfd(process, drain_timeout)
                    except BaseException as exc:
                        raise ControlledExecutionRefused("owned-process:cleanup") from exc
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            if pidfd >= 0:
                try:
                    os.close(pidfd)
                except OSError:
                    pass


def _validate_development_result(
    raw: bytes, expected: _DevelopmentExpectation
) -> _DevelopmentObservation:
    if not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise ControlledExecutionRefused("development-output:size")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ControlledExecutionRefused("development-output:json") from exc
    if not isinstance(document, dict) or set(document) != _DEVELOPMENT_RESULT_FIELDS:
        raise ControlledExecutionRefused("development-output:fields")
    if document.get("schemaVersion") != 1:
        raise ControlledExecutionRefused("development-output:version")
    checks = (
        ("digest", expected.digest),
        ("identity", expected.identity),
        ("issuer", expected.issuer),
        ("rekorIncluded", expected.rekor_required),
    )
    for field, value in checks:
        if document.get(field) != value:
            raise ControlledExecutionRefused(f"development-output:{field}")
    return _DevelopmentObservation(
        digest=expected.digest,
        identity=expected.identity,
        issuer=expected.issuer,
        rekor_included=True,
    )


def _run_development_fixture_verifier(
    material: Any,
    expected: _DevelopmentExpectation,
    fixture_input: Path,
    *,
    timeout_seconds: float = 10.0,
    maximum_output_bytes: int = MAX_OUTPUT_BYTES,
) -> _DevelopmentObservation:
    """Exercise a synthetic FD protocol and return only nonqualifying evidence.

    The synthetic executable receives positional ``/proc/self/fd`` references for
    the sealed trust root and bounded fixture input. This protocol must never be
    used as the eventual Cosign adapter.
    """

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
    ):
        raise ControlledExecutionRefused("development-policy:timeout")
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or not 0 < maximum_output_bytes <= MAX_OUTPUT_BYTES
    ):
        raise ControlledExecutionRefused("development-policy:output-maximum")
    if not isinstance(expected, _DevelopmentExpectation):
        raise ControlledExecutionRefused("development-policy:type")
    expected.validate()
    try:
        description = material.describe()
        verifier_fd = material.verifier_fd
        trust_root_fd = material.trust_root_fd
    except Exception as exc:
        raise ControlledExecutionRefused("boundary:sealed-material") from exc
    if (
        description.get("status") != "UNVERIFIED"
        or description.get("immutableMaterial") is not True
    ):
        raise ControlledExecutionRefused("boundary:sealed-material")

    input_fd = _open_bounded_file(fixture_input)
    executable = f"/proc/self/fd/{verifier_fd}"
    argv = (executable, f"/proc/self/fd/{trust_root_fd}", f"/proc/self/fd/{input_fd}")
    try:
        capture = _DevelopmentOwnedProcessRunner("development-verifier").run(
            argv,
            pass_fds=(verifier_fd, trust_root_fd, input_fd),
            timeout_seconds=float(timeout_seconds),
            maximum_output_bytes=maximum_output_bytes,
        )
    finally:
        os.close(input_fd)
    if capture.return_code != 0:
        raise ControlledExecutionRefused("development-verifier:rejected")
    stdout, stderr = capture.stdout, capture.stderr
    if stderr:
        raise ControlledExecutionRefused("development-verifier:stderr")
    return _validate_development_result(stdout, expected)
