"""Launcher-owned private pipe consumer for test-only OAuth invocation records."""

from __future__ import annotations

import json
import math
import os
import selectors
import stat
import time
from dataclasses import dataclass
from typing import Final, Literal, Self

Runtime = Literal["express", "fastapi"]
MAX_RECORDS: Final = 16
MAX_RECORD_BYTES: Final = 512
MAX_STREAM_BYTES: Final = MAX_RECORDS * MAX_RECORD_BYTES
_FIELDS: Final = {
    "schemaVersion",
    "runId",
    "runtime",
    "source",
    "provider",
    "operation",
    "sequence",
}


class PrivateProviderRecordError(RuntimeError):
    """The private record channel or its exact binding is invalid."""


@dataclass(frozen=True, slots=True)
class ChildRecordBinding:
    fd: int
    environment: dict[str, str]


@dataclass(frozen=True, slots=True)
class _DescriptorIdentity:
    device: int
    inode: int
    mode: int
    owner: int


def _identity(fd: int) -> _DescriptorIdentity:
    details = os.fstat(fd)
    return _DescriptorIdentity(
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
    )


def _validate_run_id(run_id: str) -> None:
    if not 8 <= len(run_id) <= 64 or any(
        not (character.isascii() and (character.isalnum() or character in "._-"))
        for character in run_id
    ):
        raise PrivateProviderRecordError("runId is outside the private record scope")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise PrivateProviderRecordError(
                "private provider record contains duplicate fields"
            )
        result[name] = value
    return result


class PrivateProviderRecordChannel:
    """Own one nonblocking anonymous pipe and destructively consume its records once."""

    def __init__(self, *, run_id: str, runtime: Runtime) -> None:
        _validate_run_id(run_id)
        if runtime not in {"express", "fastapi"}:
            raise PrivateProviderRecordError(
                "runtime is outside the private record scope"
            )
        if not hasattr(os, "pipe2"):
            raise PrivateProviderRecordError("private record pipe2 support is required")
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            read_identity = _identity(read_fd)
            write_identity = _identity(write_fd)
        except BaseException:
            for descriptor in (read_fd, write_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise
        self._run_id = run_id
        self._runtime = runtime
        self._read_fd: int | None = read_fd
        self._write_fd: int | None = write_fd
        self._read_identity = read_identity
        self._write_identity = write_identity
        self._binding_issued = False
        self._handed_off = False
        self._consumed = False

    def child_binding(self) -> ChildRecordBinding:
        if self._handed_off or self._write_fd is None:
            raise PrivateProviderRecordError(
                "private record write descriptor was already handed off"
            )
        self._require_identity(self._write_fd, self._write_identity, "write")
        if self._binding_issued:
            raise PrivateProviderRecordError(
                "private record child binding was already issued"
            )
        self._binding_issued = True
        return ChildRecordBinding(
            fd=self._write_fd,
            environment={
                "WISEACCT_TEST_PROVIDER_RECORD_FD": str(self._write_fd),
                "WISEACCT_TEST_PROVIDER_RUN_ID": self._run_id,
                "WISEACCT_TEST_PROVIDER_RUNTIME": self._runtime,
            },
        )

    def handoff(self) -> None:
        if self._handed_off or self._write_fd is None:
            raise PrivateProviderRecordError(
                "private record write descriptor was already handed off"
            )
        if not self._binding_issued:
            raise PrivateProviderRecordError(
                "private record child binding was not issued"
            )
        self._require_identity(self._write_fd, self._write_identity, "write")
        descriptor = self._write_fd
        self._write_fd = None
        self._handed_off = True
        self._close_if_owned(descriptor, self._write_identity)

    def consume(self, *, timeout_seconds: float = 5.0) -> dict[str, object]:
        if self._consumed:
            raise PrivateProviderRecordError(
                "private provider records were already consumed"
            )
        if not self._handed_off:
            raise PrivateProviderRecordError(
                "private record write descriptor is still launcher-owned"
            )
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise PrivateProviderRecordError(
                "record timeout must be positive and finite"
            )
        if self._read_fd is None:
            raise PrivateProviderRecordError(
                "private record read descriptor is unavailable"
            )
        self._consumed = True
        descriptor = self._read_fd
        self._read_fd = None
        self._require_identity(descriptor, self._read_identity, "read")
        try:
            payload = self._read_all(descriptor, timeout_seconds)
        finally:
            self._close_if_owned(descriptor, self._read_identity)
        records = self._parse(payload)
        return {
            "source": "launcher-owned-private-provider-record-pipe-v1",
            "consumed": True,
            "records": records,
        }

    def close(self) -> None:
        if self._write_fd is not None:
            descriptor = self._write_fd
            self._write_fd = None
            self._close_if_owned(descriptor, self._write_identity)
        if self._read_fd is not None:
            descriptor = self._read_fd
            self._read_fd = None
            self._close_if_owned(descriptor, self._read_identity)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _read_all(self, descriptor: int, timeout_seconds: float) -> bytes:
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PrivateProviderRecordError(
                        "private record pipe did not reach EOF"
                    )
                if not selector.select(remaining):
                    raise PrivateProviderRecordError(
                        "private record pipe did not reach EOF"
                    )
                try:
                    chunk = os.read(
                        descriptor, min(4096, MAX_STREAM_BYTES + 1 - len(output))
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    return bytes(output)
                output.extend(chunk)
                if len(output) > MAX_STREAM_BYTES:
                    raise PrivateProviderRecordError(
                        "private provider record stream is too large"
                    )

    def _parse(self, payload: bytes) -> list[dict[str, object]]:
        if not payload or not payload.endswith(b"\n"):
            raise PrivateProviderRecordError(
                "private provider record stream is incomplete"
            )
        lines = payload.splitlines()
        if not 1 <= len(lines) <= MAX_RECORDS:
            raise PrivateProviderRecordError("private provider record count is invalid")
        records: list[dict[str, object]] = []
        for sequence, line in enumerate(lines, start=1):
            if len(line) + 1 > MAX_RECORD_BYTES:
                raise PrivateProviderRecordError("private provider record is too large")
            try:
                record = json.loads(line, object_pairs_hook=_unique_json_object)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PrivateProviderRecordError(
                    "private provider record is invalid JSON"
                ) from error
            if not isinstance(record, dict) or set(record) != _FIELDS:
                raise PrivateProviderRecordError(
                    "private provider record fields are not exact"
                )
            if (
                type(record["schemaVersion"]) is not int
                or record["schemaVersion"] != 1
                or record["runId"] != self._run_id
                or record["runtime"] != self._runtime
                or record["source"] != "provider-transport"
                or not isinstance(record["provider"], str)
                or record["provider"] not in {"google", "naver", "kakao"}
                or not isinstance(record["operation"], str)
                or record["operation"] not in {"token", "user-info"}
                or type(record["sequence"]) is not int
                or record["sequence"] != sequence
            ):
                raise PrivateProviderRecordError(
                    "private provider record binding does not match"
                )
            records.append(record)
        return records

    @staticmethod
    def _require_identity(
        descriptor: int, expected: _DescriptorIdentity, label: str
    ) -> None:
        try:
            actual = _identity(descriptor)
        except OSError as error:
            raise PrivateProviderRecordError(
                f"private record {label} descriptor is unavailable"
            ) from error
        if (
            actual != expected
            or not stat.S_ISFIFO(actual.mode)
            or actual.owner != os.getuid()
        ):
            raise PrivateProviderRecordError(
                f"private record {label} descriptor identity changed"
            )

    @staticmethod
    def _close_if_owned(descriptor: int, expected: _DescriptorIdentity) -> None:
        try:
            if _identity(descriptor) == expected:
                os.close(descriptor)
        except OSError:
            return
