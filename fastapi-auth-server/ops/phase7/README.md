# Phase 7 qualification runner

This provisional runner qualifies two **already-running**, isolated loopback
runtimes. It never starts services, changes ingress, contacts providers, or
approves a cutover. Express and FastAPI must use separate test PostgreSQL
endpoints and distinct non-zero Redis database tuples. The FastAPI Python and
Node database URLs must resolve to the same FastAPI test endpoint.

The independent contract gate runs `public.json`, then `guards.json`, then
`fixtures.json`, stopping at the first failure. Both runtime adapters, their
private configs, and explicit `express`/`fastapi` preflight names are passed to
every suite. Each suite produces deterministic JSONL plus a status containing
the scenario/result hashes and counts. A successful contract gate records
`passedGate=independent-contract`, but the overall result remains `INCOMPLETE`
while performance, security, chaos, backup/restore, and local rollback are
fail-closed placeholders. The current scenario corpus is not yet the complete
Phase 7 replacement sample, so this gate alone cannot establish replacement
readiness.

Required environment variables:

- `WISEACCT_PHASE7_BASELINE_URL` — isolated Express loopback origin.
- `WISEACCT_PHASE7_CANDIDATE_URL` — distinct isolated FastAPI loopback origin.
- `WISEACCT_PHASE7_EXPRESS_DATABASE_URL` — Node PostgreSQL URL for the Express
  test database, using a non-default port.
- `WISEACCT_PHASE7_FASTAPI_DATABASE_URL` — `postgresql+asyncpg` URL for the
  FastAPI test database, using a non-default port.
- `WISEACCT_PHASE7_FASTAPI_NODE_DATABASE_URL` — Node/psql-compatible URL for
  that exact same FastAPI database endpoint.
- `WISEACCT_PHASE7_EXPRESS_REDIS_URL` — isolated Redis tuple with DB 1–15 and a
  non-default port.
- `WISEACCT_PHASE7_FASTAPI_REDIS_URL` — a distinct isolated Redis tuple with DB
  1–15 and a non-default port.
- `WISEACCT_PHASE7_EXPRESS_ADAPTER_CONFIG` — Express adapter JSON path.
- `WISEACCT_PHASE7_FASTAPI_ADAPTER_CONFIG` — FastAPI adapter JSON path.

`WISEACCT_PHASE7_RUN_ID` is optional and accepts only lowercase ASCII letters,
digits, dots, underscores, or hyphens.

Both adapter config paths must be absolute, point directly to non-symlink regular files,
have exact mode `0600`, and live outside the repository/evidence tree. They use
the environment object documented in `contracts/adapters/README.md`; their
database and Redis URLs must exactly match the corresponding values above.
The FastAPI config also requires `CONTRACT_FASTAPI_RUNTIME=1`. Only the
documented `CONTRACT_*` keys are accepted; process-control and ambient database
keys are rejected. Each config is opened once and copied into a private `/tmp`
snapshot used for the whole run. Config paths, contents, credentials, and config
hashes are never written to Phase 7 evidence.

Both adapter preflights run once before the first HTTP suite. Their sanitized
outcomes are recorded separately. Both are attempted even if one fails, and a
failure leaves all three suites at `NOT_RUN`.

The runner requires a clean committed worktree before creating the immutable
`evidence/phase7/<run-id>/` directory. An independent contract success followed
by placeholder gates exits 3 to report honest `INCOMPLETE` status.
