"""G01a byte-preserving, UNAUTHENTICATED collector statement protocol.

Parsing and binding checks are not signature verification. This module deliberately
does not expose a qualifying result; G01b must authenticate the exact payload bytes
and detached bundle using the independently approved B02/B03 trust material.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

MAX_DOCUMENT_BYTES = 65536
GATE_IDS = frozenset(
    {
        "independent-contract",
        "shared-state-core",
        "security",
        "performance",
        "backup-restore",
        "chaos",
        "local-rollback",
    }
)
ID_FIELDS = frozenset({"groupId", "runId", "collectorId", "topology"})
REVISION_FIELDS = frozenset(
    {"sourceRevision", "gitTreeObject", "collectorRevision", "collectorTreeObject"}
)
IMAGE_FIELDS = frozenset({"expressImageId", "fastapiImageId", "collectorImageId"})
DIGEST_FIELDS = frozenset(
    {
        "collectorConfigSha256",
        "inputAggregateSha256",
        "outputAggregateSha256",
        "verifierSha256",
        "trustRootSha256",
        "policySha256",
    }
)
TIME_FIELDS = frozenset({"startedAtUnixMs", "finishedAtUnixMs"})
IDENTITY_FIELDS = frozenset({"signerIdentity", "oidcIssuer"})
STATEMENT_FIELDS = (
    ID_FIELDS
    | REVISION_FIELDS
    | IMAGE_FIELDS
    | DIGEST_FIELDS
    | TIME_FIELDS
    | IDENTITY_FIELDS
    | {"schemaVersion", "gateId", "platform"}
)
ENVELOPE_FIELDS = frozenset(
    {"schemaVersion", "payloadSha256", "signatureBundleSha256", "rekorEntrySha256"}
)
PRE_ATTESTATION_ROLES = {
    "input": frozenset({"execution-context.json", "gate-inputs.json"}),
    "output": frozenset(
        {
            "observations.json",
            "checks.json",
            "cleanup.json",
            "express-before.json",
            "express-after.json",
        }
    ),
}
POST_ATTESTATION_FIELDS = frozenset(
    {
        "collectorAttestationSha256",
        "collectorAttestationEvidenceSha256",
        "provenanceEvidenceSha256",
        "evidenceAggregateSha256",
        "inputAggregateSha256",
        "outputAggregateSha256",
        "payloadSha256",
        "signatureBundleSha256",
        "rekorEntrySha256",
    }
)


class AttestationError(ValueError):
    """Public-safe protocol or binding failure; never includes supplied values."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttestationError("duplicate JSON field")
        result[key] = value
    return result


def _decode(raw: bytes, fields: frozenset[str]) -> dict[str, Any]:
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise AttestationError("document size invalid")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise AttestationError("document encoding invalid") from exc
    if not isinstance(document, dict) or set(document) != fields:
        raise AttestationError("document fields invalid")
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 2:
        raise AttestationError("document version invalid")
    return document


def _match(value: Any, pattern: str) -> None:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise AttestationError("document field format invalid")


@dataclass(frozen=True)
class UnauthenticatedStatement:
    """Original signed-payload candidate bytes, with no assertion of authenticity."""

    payload: bytes
    fields: Mapping[str, Any]

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def parse_statement(raw: bytes) -> UnauthenticatedStatement:
    """Validate the v2 statement shape without accepting a caller trust flag."""
    document = _decode(raw, frozenset(STATEMENT_FIELDS))
    if not isinstance(document["gateId"], str) or document["gateId"] not in GATE_IDS:
        raise AttestationError("gate invalid")
    if document["platform"] not in ("linux/amd64", "linux/arm64"):
        raise AttestationError("platform invalid")
    for field in ID_FIELDS:
        _match(document[field], r"[a-z0-9][a-z0-9._-]{0,127}")
    for field in REVISION_FIELDS:
        _match(document[field], r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
    for field in IMAGE_FIELDS:
        _match(document[field], r"sha256:[0-9a-f]{64}")
    for field in DIGEST_FIELDS:
        _match(document[field], r"[0-9a-f]{64}")
    for field in TIME_FIELDS:
        if type(document[field]) is not int or not 0 < document[field] < 2**63:
            raise AttestationError("timestamp invalid")
    if document["finishedAtUnixMs"] < document["startedAtUnixMs"]:
        raise AttestationError("timestamp order invalid")
    for field in IDENTITY_FIELDS:
        _match(document[field], r"[!-~]{1,2048}")
    return UnauthenticatedStatement(raw, MappingProxyType(document))


def check_expected_bindings(statement: UnauthenticatedStatement, expected_payload: bytes) -> None:
    """Compare every field to independently collected expectations, not to evidence.

    This is a necessary consistency check, never an authentication decision. The
    caller must not derive expectations from the untrusted statement itself.
    """
    expected = parse_statement(expected_payload)
    if statement.fields != expected.fields:
        raise AttestationError("statement binding mismatch")


def check_detached_material(
    statement: UnauthenticatedStatement,
    envelope: bytes,
    signature_bundle: bytes,
    rekor_entry: bytes,
) -> None:
    """Check detached byte digests only; forged matching material still is untrusted.

    The envelope is outside the signed statement to avoid a bundle/payload hash
    cycle. B02 must verify signatures, identity, inclusion and policy independently.
    """
    document = _decode(envelope, ENVELOPE_FIELDS)
    for field in ENVELOPE_FIELDS - {"schemaVersion"}:
        _match(document[field], r"[0-9a-f]{64}")
    if not signature_bundle or not rekor_entry:
        raise AttestationError("detached material missing")
    actual = {
        "schemaVersion": 2,
        "payloadSha256": statement.payload_sha256,
        "signatureBundleSha256": hashlib.sha256(signature_bundle).hexdigest(),
        "rekorEntrySha256": hashlib.sha256(rekor_entry).hexdigest(),
    }
    if document != actual:
        raise AttestationError("detached material binding mismatch")


def pre_attestation_aggregate(kind: str, records: Mapping[str, bytes]) -> str:
    """Hash the exact v1 pre-sign inventory, never the final evidence bundle.

    Producers freeze these JSON byte records before signing. The fixed role set
    excludes provenance, statements, envelopes and downstream group wrappers;
    reserved reference fields are forbidden even inside an allowed role record.
    This function does no file discovery or authenticity/sample/secret validation.
    """
    if kind not in PRE_ATTESTATION_ROLES or set(records) != PRE_ATTESTATION_ROLES[kind]:
        raise AttestationError("pre-attestation inventory invalid")
    digest = hashlib.sha256(f"wiseacct:collector-pre-attestation:v1:{kind}\n".encode())
    for role in sorted(records):
        raw = records[role]
        if not raw or len(raw) > 64 * 1024 * 1024:
            raise AttestationError("pre-attestation record size invalid")
        try:
            document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise AttestationError("pre-attestation JSON invalid") from exc
        pending = [document]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                if POST_ATTESTATION_FIELDS.intersection(item):
                    raise AttestationError("post-attestation reference in pre-attestation record")
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, float) and not math.isfinite(item):
                raise AttestationError("nonfinite pre-attestation value")
        digest.update(role.encode() + b"\0" + hashlib.sha256(raw).hexdigest().encode() + b"\n")
    return digest.hexdigest()
