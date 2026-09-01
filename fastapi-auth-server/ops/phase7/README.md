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

The disposable launcher derives a private runtime-only copy of `public.json`
for its committed synthetic signer. Only the expected JWK in the single
`public.jwks` scenario may differ. The qualification runner reopens that input
as a non-link regular file with exact mode `0600`, verifies the complete
derivation against the committed corpus and `.env.example`, snapshots it into
its private directory, and records only scenario/JWK hashes in provenance.
The checked-in public corpus remains unchanged.

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

## Disposable independent runtime launcher

`ops/run-phase7-independent-integration.sh` is the guarded local entry point
that supplies those already-running runtimes. It requires a clean committed
worktree and zero pre-existing resources from the candidate Compose project.
It takes the repository integration lock, snapshots the current Express
containers' identity, restart count, state, health, and start time, and then
starts only the existing guarded FastAPI development Compose stack.

For each run it creates two separately named test databases and two DML-only
login roles after applying the committed Prisma migrations. Express and
FastAPI run as host processes on distinct loopback ports and use Redis logical
databases 13 and 14 respectively. Both receive the same access signer, issuer,
generated refresh secret, and client policy. The signer and base policy come
from the committed synthetic `.env.example`; the issuer is pinned to the
contract corpus compatibility value. The launcher adds only the loopback contract-fixture client;
OAuth providers remain disabled and mail remains in development capture mode.
Private runtime environments and adapter configs live in a mode-0700 `mktemp`
directory, and each config has mode 0600.

Candidate container, network, and volume inspection is tri-state: every Docker
query must succeed before the result can be `EMPTY`; query failure is distinct
from both `EMPTY` and `PRESENT`. HTTP readiness is accepted only after the
launched process ID is also proven to own the expected TCP LISTEN socket.

The qualification runner verifies the inherited integration-lock descriptor.
Exit 3 is accepted only when the immutable qualification result contains both
`status=INCOMPLETE` and `passedGate=independent-contract`. This means the
independent contract gate passed; it does not waive the downstream Phase 7
gates or approve replacement.

On every exit the launcher stops both host runtimes, drops the two exact test
databases and roles, clears only Redis databases 13 and 14, removes the guarded
candidate Compose resources, and compares the Express before/after snapshots.
Only after cleanup does it publish sanitized, immutable evidence under
`evidence/phase7-runtime/<run-id>/`, including the qualification run ID and
evidence hash. Runtime log bodies, adapter configs, URLs, and credentials stay
in the temporary directory and are deleted rather than published.
Publication refuses collisions, validates a complete sanitized read-only
bundle, and uses a no-replace atomic directory rename. A `PASS` bundle is
rejected unless cleanup, Express stability, and zero-candidate invariants are
all proven.

The runtime bundle includes `cleanup.status`, with a sanitized result for each
runtime termination, database and role drop, Redis probe/clear, candidate
Compose down, Express snapshot, candidate-resource inspection, and private
temporary-directory removal. This makes an aggregate cleanup failure
attributable without publishing credentials or runtime log bodies. A child
that has already exited is reaped successfully; ownership mismatches and a
process that remains alive after TERM/KILL still fail cleanup.
The Redis probe is accepted as benignly absent only for the exact paired result
`exit 1` plus `ABSENT`. `UNUSABLE`, an output/exit mismatch, or a probe error is
recorded separately and blocks PASS before the guarded Compose teardown.
For a full successful launcher run, every cleanup key must be `PASS`, including
the Redis probe and both logical-database clears; `NOT_REQUIRED` is never enough
for an overall runtime `PASS`. Aggregate cleanup, Express snapshot, candidate
resource, and private-temp fields are cross-checked against their corresponding
step values before publication.

Expected connection-refused messages during readiness polling are written only
to the private temporary directory. The console receives one non-sensitive
timeout error only if readiness is never established.

Express is started through a Phase 7-only Node launcher that injects
`127.0.0.1` when the unchanged application calls `listen(port, callback)` and
rejects an explicit wildcard or non-loopback host. The socket proof checks both
the owning PID's socket inode and the `/proc` TCP local address; wildcard
listeners cannot satisfy readiness.

Before final evidence publication, the sanitized Express snapshots are copied
to sibling staging and the private `/tmp/wiseacct-phase7-runtime.*` directory
containing credentials and log bodies is removed and verified absent. Failure
to remove it forces `status=FAIL`, `privateTempRemoved=false`, and a non-zero
launcher exit. `PASS` publication requires `privateTempRemoved=true`.

This launcher is intentionally local and provisional. It does not alter
production routing or configuration, call real OAuth/mail providers, perform a
mixed-runtime canary, or approve a cutover.
