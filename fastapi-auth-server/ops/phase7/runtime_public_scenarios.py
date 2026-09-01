#!/usr/bin/env python3
"""Create and validate a private Phase 7 public scenario runtime derivative."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, cast


class InvalidScenario(ValueError):
    """The runtime scenario is not the exact approved JWKS derivative."""


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def read_example_jwk(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise InvalidScenario(f"invalid environment example line {line_number}")
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    try:
        document: Any = json.loads(values["JWT_ACCESS_PUBLIC_JWK"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise InvalidScenario("synthetic example must contain one valid public JWK") from exc
    if not isinstance(document, dict) or set(document) != {"kty", "use", "alg", "kid", "n", "e"}:
        raise InvalidScenario("synthetic public JWK has an unexpected structure")
    if any(not isinstance(value, str) or not value for value in document.values()):
        raise InvalidScenario("synthetic public JWK values must be non-empty strings")
    if document["kty"] != "RSA" or document["use"] != "sig" or document["alg"] != "RS256":
        raise InvalidScenario("synthetic public JWK must be an RSA RS256 signing key")
    return cast(dict[str, str], document)


def read_document(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        document: Any = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidScenario(f"{label} must contain valid JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("scenarios"), list):
        raise InvalidScenario(f"{label} must contain a scenarios array")
    return document


def derive(source: dict[str, Any], jwk: dict[str, str]) -> dict[str, Any]:
    derived = json.loads(json.dumps(source))
    matches = [
        item
        for item in derived["scenarios"]
        if isinstance(item, dict) and item.get("id") == "public.jwks"
    ]
    if len(matches) != 1:
        raise InvalidScenario("committed corpus must contain exactly one public.jwks scenario")
    try:
        keys = matches[0]["expect"]["json"]["keys"]
    except (KeyError, TypeError) as exc:
        raise InvalidScenario("public.jwks must contain an expected keys array") from exc
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        raise InvalidScenario("public.jwks must expect exactly one JWK")
    matches[0]["expect"]["json"]["keys"] = [jwk]
    return cast(dict[str, Any], derived)


def encoded(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()


def open_private(path: Path) -> bytes:
    if not path.is_absolute():
        raise InvalidScenario("runtime public scenario path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InvalidScenario("runtime public scenario must be an existing non-link file") from exc
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise InvalidScenario(
                "runtime public scenario must be a regular file with exact mode 0600"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


def write_exclusive(path: Path, payload: bytes) -> None:
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise InvalidScenario("runtime public scenario output must use an absolute non-link parent")
    parent_stat = path.parent.stat()
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_IMODE(parent_stat.st_mode) != 0o700:
        raise InvalidScenario("runtime public scenario output parent must have exact mode 0700")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise InvalidScenario("runtime public scenario write did not complete")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise InvalidScenario("runtime public scenario creation did not preserve mode 0600")


def validate_exact(payload: bytes, *, source: Path, example: Path) -> tuple[bytes, str]:
    source_payload = source.read_bytes()
    source_document = read_document(source_payload, label="committed public corpus")
    jwk = read_example_jwk(example)
    expected = encoded(derive(source_document, jwk))
    actual = encoded(read_document(payload, label="runtime public scenario"))
    if actual != expected:
        raise InvalidScenario(
            "runtime public scenario may replace only the public.jwks expected JWK"
        )
    jwk_hash = sha256(json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode())
    return expected, jwk_hash


def create(args: argparse.Namespace) -> int:
    payload, _ = validate_exact(
        encoded(
            derive(
                read_document(args.source.read_bytes(), label="committed public corpus"),
                read_example_jwk(args.example),
            )
        ),
        source=args.source,
        example=args.example,
    )
    write_exclusive(args.output, payload)
    return 0


def snapshot(args: argparse.Namespace) -> int:
    resolved = args.input.resolve()
    if resolved.is_relative_to(args.repo.resolve()) or resolved.is_relative_to(
        args.evidence.resolve()
    ):
        raise InvalidScenario("runtime public scenario must live outside repository and evidence")
    payload = open_private(args.input)
    normalized, jwk_hash = validate_exact(payload, source=args.source, example=args.example)
    write_exclusive(args.output, normalized)
    print(f"runtimePublicScenarioSha256={sha256(normalized)}")
    print(f"runtimePublicJwkSha256={jwk_hash}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    for command in ("create", "snapshot"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--source", type=Path, required=True)
        sub.add_argument("--example", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
        if command == "snapshot":
            sub.add_argument("--input", type=Path, required=True)
            sub.add_argument("--repo", type=Path, required=True)
            sub.add_argument("--evidence", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return create(args) if args.command == "create" else snapshot(args)
    except (InvalidScenario, OSError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    raise SystemExit(main())
