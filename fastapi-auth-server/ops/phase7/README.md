# Phase 7 qualification runner

This directory contains a provisional, local-only qualification orchestrator.
It does not start services, change ingress, contact providers, or approve a
cutover. The caller must provide two already-running loopback HTTP origins, a
shared `_test_` PostgreSQL database through Python and Node connection URLs, and
an isolated Redis database from 1 through 15.

The runner requires a clean Git commit before it creates an immutable
`evidence/phase7/<run-id>/` directory. It executes only the public, read-only
contract differential first and records canonical JSONL with sanitized
run/source/scenario provenance. Stateful fixtures and guard scenarios are not
part of this initial gate and are explicitly recorded as `NOT_RUN`.
Performance, security, chaos, backup/restore, and local
rollback are deliberate fail-closed placeholders: each records `SKIP` and the
overall command exits 3 (`INCOMPLETE`) until those gates are implemented.

Required environment variables:

- `WISEACCT_PHASE7_BASELINE_URL`
- `WISEACCT_PHASE7_CANDIDATE_URL`
- `WISEACCT_PHASE7_DATABASE_URL`
- `WISEACCT_PHASE7_NODE_DATABASE_URL`
- `WISEACCT_PHASE7_REDIS_URL`

`WISEACCT_PHASE7_RUN_ID` is optional and must contain only lowercase ASCII
letters, digits, dots, underscores, or hyphens. Connection credentials are
validated but never written to evidence.
