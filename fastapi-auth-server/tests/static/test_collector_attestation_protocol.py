"""G01a format/binding regressions; none of these tests authenticate evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "ops/phase7/collector_attestation.py"
SPEC = importlib.util.spec_from_file_location("collector_attestation_protocol", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PROTOCOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROTOCOL
SPEC.loader.exec_module(PROTOCOL)


def statement() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "gateId": "security",
        "topology": "independent",
        "groupId": "group-1",
        "runId": "run-1",
        "collectorId": "controlled-collector",
        "sourceRevision": "a" * 40,
        "gitTreeObject": "b" * 40,
        "collectorRevision": "c" * 40,
        "collectorTreeObject": "d" * 40,
        "expressImageId": "sha256:" + "a" * 64,
        "fastapiImageId": "sha256:" + "b" * 64,
        "collectorImageId": "sha256:" + "c" * 64,
        "collectorConfigSha256": "d" * 64,
        "inputAggregateSha256": "e" * 64,
        "outputAggregateSha256": "f" * 64,
        "platform": "linux/amd64",
        "startedAtUnixMs": 1000,
        "finishedAtUnixMs": 2000,
        "verifierSha256": "1" * 64,
        "trustRootSha256": "2" * 64,
        "policySha256": "3" * 64,
        "signerIdentity": "https://example.invalid/workflow@refs/tags/test",
        "oidcIssuer": "https://issuer.example.invalid",
    }


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def test_schema_and_parser_field_inventory_agree() -> None:
    schema = json.loads(
        MODULE_PATH.with_name("qualification-collector-statement-v2.schema.json").read_text()
    )
    assert set(schema["required"]) == PROTOCOL.STATEMENT_FIELDS
    assert set(schema["properties"]) == PROTOCOL.STATEMENT_FIELDS
    assert set(schema["properties"]["gateId"]["enum"]) == PROTOCOL.GATE_IDS
    assert schema["additionalProperties"] is False


def test_original_bytes_preserved_and_fields_immutable() -> None:
    raw = json.dumps(statement(), indent=2).encode()
    parsed = PROTOCOL.parse_statement(raw)
    assert parsed.payload == raw
    assert parsed.payload_sha256 == hashlib.sha256(raw).hexdigest()
    assert parsed.payload_sha256 != hashlib.sha256(encode(statement())).hexdigest()
    with pytest.raises(TypeError):
        parsed.fields["runId"] = "tampered"
    assert not hasattr(parsed, "verified")
    assert not hasattr(parsed, "qualifyingEvidence")
    PROTOCOL.check_expected_bindings(parsed, encode(statement()))


@pytest.mark.parametrize("field", sorted(PROTOCOL.STATEMENT_FIELDS))
def test_missing_fields_rejected(field: str) -> None:
    value = statement()
    del value[field]
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.parse_statement(encode(value))


@pytest.mark.parametrize("field", sorted(PROTOCOL.STATEMENT_FIELDS))
def test_each_binding_mutation_rejected(field: str) -> None:
    value = statement()
    if field == "schemaVersion":
        value[field] = 1
    elif field == "gateId":
        value[field] = "chaos"
    elif field == "platform":
        value[field] = "linux/arm64"
    elif field in PROTOCOL.TIME_FIELDS:
        value[field] += 1
    elif field in PROTOCOL.IMAGE_FIELDS:
        value[field] = "sha256:" + "9" * 64
    elif field in PROTOCOL.DIGEST_FIELDS or field in PROTOCOL.REVISION_FIELDS:
        value[field] = "9" * len(value[field])
    else:
        value[field] += "-changed"
    with pytest.raises(PROTOCOL.AttestationError):
        parsed = PROTOCOL.parse_statement(encode(value))
        PROTOCOL.check_expected_bindings(parsed, encode(statement()))


@pytest.mark.parametrize("value", [None, [], {}, True, 1, float("nan")])
@pytest.mark.parametrize("field", sorted(PROTOCOL.STATEMENT_FIELDS))
def test_wrong_types_fail_closed(field: str, value: Any) -> None:
    data = statement()
    data[field] = value
    # Positive integers are valid timestamps; they still must match expectations.
    with pytest.raises(PROTOCOL.AttestationError):
        parsed = PROTOCOL.parse_statement(encode(data))
        PROTOCOL.check_expected_bindings(parsed, encode(statement()))


@pytest.mark.parametrize("field", ["status", "verified", "qualifyingEvidence", "signatureValid"])
def test_caller_trust_flags_rejected(field: str) -> None:
    data = statement()
    data[field] = "VERIFIED"
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.parse_statement(encode(data))


@pytest.mark.parametrize("raw", [b"", b"\xff", b"[]", b"null", b"{" * 5000, b" " * 65537])
def test_invalid_documents_rejected(raw: bytes) -> None:
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.parse_statement(raw)


def test_duplicate_field_rejected() -> None:
    raw = encode(statement())
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.parse_statement(b'{"runId":"other",' + raw[1:])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sourceRevision", "a" * 41),
        ("runId", "../escape"),
        ("platform", "host"),
        ("startedAtUnixMs", 0),
        ("finishedAtUnixMs", 2**63),
        ("finishedAtUnixMs", 999),
        ("signerIdentity", "identity\nsecret"),
        ("oidcIssuer", ""),
        ("signerIdentity", "a" * 2049),
    ],
)
def test_invalid_values_rejected_without_leaking_values(field: str, value: Any) -> None:
    data = statement()
    data[field] = value
    with pytest.raises(PROTOCOL.AttestationError) as error:
        PROTOCOL.parse_statement(encode(data))
    assert "secret" not in str(error.value)


def material(parsed: Any, bundle: bytes, rekor: bytes) -> bytes:
    return encode(
        {
            "schemaVersion": 2,
            "payloadSha256": parsed.payload_sha256,
            "signatureBundleSha256": hashlib.sha256(bundle).hexdigest(),
            "rekorEntrySha256": hashlib.sha256(rekor).hexdigest(),
        }
    )


def test_detached_hashes_do_not_imply_authentication() -> None:
    parsed = PROTOCOL.parse_statement(encode(statement()))
    bundle, rekor = b"forged bundle", b"forged entry"
    # Even forged bytes can match their hashes: this API returns no trust decision.
    assert (
        PROTOCOL.check_detached_material(parsed, material(parsed, bundle, rekor), bundle, rekor)
        is None
    )


@pytest.mark.parametrize("target", ["payload", "bundle", "rekor", "empty-bundle", "empty-rekor"])
def test_detached_tampering_rejected(target: str) -> None:
    parsed = PROTOCOL.parse_statement(encode(statement()))
    bundle, rekor = b"bundle", b"entry"
    envelope = material(parsed, bundle, rekor)
    if target == "payload":
        changed = statement()
        changed["runId"] = "changed"
        parsed = PROTOCOL.parse_statement(encode(changed))
    elif target == "bundle":
        bundle += b"changed"
    elif target == "rekor":
        rekor += b"changed"
    elif target == "empty-bundle":
        bundle = b""
    else:
        rekor = b""
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.check_detached_material(parsed, envelope, bundle, rekor)


def test_pre_attestation_inventory_encoding_and_order() -> None:
    for kind, roles in PROTOCOL.PRE_ATTESTATION_ROLES.items():
        records = {role: encode({"observation": role}) for role in roles}
        encoded_records = f"wiseacct:collector-pre-attestation:v1:{kind}\n".encode()
        for role in sorted(records):
            encoded_records += (
                role.encode() + b"\0" + hashlib.sha256(records[role]).hexdigest().encode() + b"\n"
            )
        actual = PROTOCOL.pre_attestation_aggregate(kind, records)
        assert actual == hashlib.sha256(encoded_records).hexdigest()
        assert actual == PROTOCOL.pre_attestation_aggregate(
            kind, dict(reversed(list(records.items())))
        )
        for role in roles:
            changed = {**records, role: encode({"changed": True})}
            assert PROTOCOL.pre_attestation_aggregate(kind, changed) != actual


@pytest.mark.parametrize(
    "wrapper",
    [
        "provenance.json",
        "statement.json",
        "envelope.json",
        "bundle.json",
        "rekor.json",
        "group.json",
    ],
)
def test_post_attestation_wrapper_roles_rejected(wrapper: str) -> None:
    records = dict.fromkeys(PROTOCOL.PRE_ATTESTATION_ROLES["output"], b"{}")
    records[wrapper] = encode({"collectorAttestationSha256": "a" * 64})
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.pre_attestation_aggregate("output", records)


@pytest.mark.parametrize("field", sorted(PROTOCOL.POST_ATTESTATION_FIELDS))
def test_disguised_circular_provenance_rejected(field: str) -> None:
    records = dict.fromkeys(PROTOCOL.PRE_ATTESTATION_ROLES["output"], b"{}")
    records["observations.json"] = encode({"nested": [{field: "a" * 64}]})
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.pre_attestation_aggregate("output", records)


@pytest.mark.parametrize("raw", [b"", b"invalid", b'{"x":1,"x":2}', b'{"x":NaN}'])
def test_invalid_pre_attestation_records_rejected(raw: bytes) -> None:
    records = dict.fromkeys(PROTOCOL.PRE_ATTESTATION_ROLES["input"], b"{}")
    records["gate-inputs.json"] = raw
    with pytest.raises(PROTOCOL.AttestationError):
        PROTOCOL.pre_attestation_aggregate("input", records)


def test_pre_attestation_missing_roles_rejected() -> None:
    for kind in PROTOCOL.PRE_ATTESTATION_ROLES:
        with pytest.raises(PROTOCOL.AttestationError):
            PROTOCOL.pre_attestation_aggregate(kind, {})
