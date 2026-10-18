# G01a collector statement interface

Development protocol only. Existing v1 producers/finalizer remain unchanged and
nonqualifying. This interface does **not** complete G01 or authenticate a gate.

`collector_attestation.parse_statement(payload_bytes)` returns an explicitly
`UnauthenticatedStatement`. The schema is `qualification-collector-statement-v2.schema.json`.
The Python parser additionally rejects duplicate fields, nonfinite values, reversed
timestamps, malformed types and documents above 64 KiB. Raw payload bytes are
preserved: the verifier must authenticate these bytes, not a reserialized object.

All seven producers use the same 24 fields. `groupId/runId/gateId/topology` scope the run;
source/tree and collector revision/tree identify the code; all three immutable image
IDs, collector configuration, input/output aggregates bind the execution; platform
and timestamps describe its observations. Verifier/root/policy digests and exact
signer identity/issuer bind the independently approved verification policy.

Before signing, freeze the exact v1 pre-attestation inventories. All gates normalize
their raw development records to these roles before invoking `pre_attestation_aggregate`:

- Input: `execution-context.json`, `gate-inputs.json`.
- Output: `observations.json`, `checks.json`, `cleanup.json`, `express-before.json`,
  `express-after.json`.

Each is a JSON byte record (at most 64 MiB). Input execution context must record all
source/tree/schema/lock/config/image observations and inventory policy, independently
collected before signing. Output observations carry the gate-specific raw results.
Missing/extra roles, duplicate JSON keys and nonfinite values are refused. Roles are
sorted lexically; each record encodes `role + NUL + lowercase SHA256(bytes) + LF`.
The aggregate hashes the ASCII prefix `wiseacct:collector-pre-attestation:v1:input\n`
or `wiseacct:collector-pre-attestation:v1:output\n` followed by those sorted records.
No reserialization of the supplied JSON bytes occurs.

**This is not the existing final bundle aggregate.** Statement, envelope, signature
bundle, Rekor entry, provenance and every downstream wrapper referencing any of
them are excluded. Reserved post-attestation reference fields are refused recursively
even inside allowed roles. Producers must never disguise downstream wrappers as raw
observations. The final evidence bundle can contain and hash these artifacts only
after the pre-attestation records and signed statement have been frozen, preserving
the DAG: raw records → statement → detached material/provenance → final bundle/group.
G01b must compare *all* statement fields to observations from the trusted orchestrator.
Never derive expected bindings from the statement itself.
`check_expected_bindings` checks consistency only and returns no trust decision.

Detached envelope fields are exactly `schemaVersion:2`, `payloadSha256`,
`signatureBundleSha256`, `rekorEntrySha256`. It is not inside the signed payload.
`check_detached_material` binds those exact byte strings, **not** their authenticity:
matching hashes of forged material still pass this consistency check. B02/B03 must
independently authenticate the bundle, signature, exact identity/issuer, trust root,
Rekor inclusion/freshness and executable provenance before G01b permits any result.
No `VERIFIED`, `PASS` or caller boolean is accepted as a trust field.

Integration prerequisites: authenticated B02 verifier, approved B03 trust material,
producer migration for all seven gates and consumer/finalizer negative tests.
Until then do not replace the finalizer's fail-closed v1 path or promote evidence.
