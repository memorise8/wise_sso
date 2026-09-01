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

## Disposable shared-state core gate

`ops/run-phase7-shared-integration.sh` is a separate opt-in launcher for the
`shared-state-core-v1` concurrent-ingress/shared-state smoke gate; the verified
independent launcher is left unchanged. Both loopback runtimes use one
disposable test database through two distinct DML roles and share Redis logical
database 13. They receive the same synthetic signer, refresh secret, issuer,
and client policy. Prisma migrations run once before the restricted runtime
roles are used.

The launcher reuses the integration lock, production Express before/after
snapshot, candidate-resource tri-state check, exact PID LISTEN proof, and
fail-closed cleanup pattern. Cleanup is limited to the launched children, the
generated shared test database and roles, Redis DB 13, and the guarded candidate
Compose project. No production routing, database, Redis, configuration, or
credential is changed.

`ops/phase7/run-shared-state-core-gate.sh` validates and privately snapshots
both 0600 adapter configs, runs both adapter preflights, then invokes
`contracts/bin/shared_state.py` with the canonical shared fixture adapter. A
pass requires exactly 100 JSONL trial rows, zero mismatches, stable source
hashes, sanitized immutable evidence, complete cleanup, an unchanged production
Express snapshot, and zero remaining candidate resources. Runtime evidence is
atomically published without replacement under
`evidence/phase7-shared-runtime/<run-id>/`.

Exactly 70 rows belong to the seven schedules that prove mixed-runtime HTTP
request-lifetime overlap. The remaining 30 rows are sequential cross-runtime or
alternating-ingress checks and are not counted as concurrent overlap evidence.

This incremental result always records `fullPhase7SampleSatisfied=false` and
`overallReplacementReady=false`; it does not satisfy the full Phase 7 sample or
the performance, security, chaos, backup/restore, rollback, refreeze, or cutover
gates. It also does not prove deterministic database critical-section ordering,
linearizability, or exhaustive race coverage; those claims require separately
instrumented concurrency evidence and the approved full sample.

## Qualification run-group finalizer

`ops/phase7/finalize_qualification_group.py` is a local, read-only aggregation
gate. It does not run a service, use Docker, contact production, or approve a
replacement. Its input follows `ops/phase7/qualification-group.schema.json` and
must name exactly these seven gate IDs once each:

- `independent-contract`
- `shared-state-core`
- `performance`
- `security`
- `chaos`
- `backup-restore`
- `local-rollback`

Every gate entry pins its topology and run ID, evidence-relative directory and
deterministic aggregate SHA-256, source revision, application-tree/schema/lock/
config identifiers, immutable image digest, status, sample/readiness assertions,
cleanup evidence, and Express before/after evidence. Objects have exact fields;
unknown fields and gate IDs are rejected. The manifest and every attached input
must be regular non-symlink files, and every path is confined below the explicit
repository evidence root. The evidence aggregate is SHA-256 over sorted records
of `relative-path`, a NUL byte, the file SHA-256, and a newline.

The manifest's status, sample, and readiness values are not authoritative by
themselves. Each entry must also attach a hashed `gate-result.json` inside that
same evidence bundle. That document has the exact fields `schemaVersion`,
`gateId`, `runId`, `status`, `sampleSatisfied`,
`readinessAssertionsSatisfied`, `cleanupComplete`,
`expressSnapshotUnchanged`, and `overallReplacementReady`; no extras are
accepted. Its identity and claims must match the manifest, its cleanup claim
must match the attached cleanup file, and its Express claim must match the
attached snapshot bytes. The result document must keep
`overallReplacementReady=false`.

Cleanup is also an exact gate contract, not an arbitrary list of passing labels.
The independent and shared-state gates use their launcher-specific step sets.
The five downstream gates use exactly `runtimeCleanup`, `databaseCleanup`,
`redisCleanup`, `candidateResources`, `expressSnapshot`, and
`privateTempRemove`. Missing, duplicate, or extra cleanup steps—including a
fabricated `x=PASS`—cannot satisfy the finalizer.

Run it from `fastapi-auth-server` with a separately prepared manifest:

```sh
./ops/phase7/finalize_qualification_group.py \
  --manifest /absolute/path/to/private-run-group.json \
  --evidence-root ./evidence
```

Exit `0` means only `status=PROVISIONAL_READY_FOR_REVIEW`: all seven gates say
`PASS`, all sample and readiness assertions are true, every cleanup step passes,
each Express snapshot pair is byte-identical, all attachment/aggregate hashes
match, and the shared source/tree/schema/lock/config/image provenance group is
identical. Even then the output deliberately keeps
`overallReplacementReady=false`; human review, refreeze, and an independently
authorized cutover decision remain outside this tool.

Exit `1` emits a sanitized `status=INCOMPLETE` result for an otherwise valid
group that has missing/non-passing gates, false assertions, failed cleanup or
Express invariance, or mixed provenance. Exit `2` refuses malformed, unsafe, or
hash-mismatched input. The currently recorded independent and shared-state runs
cannot form a group: their source revisions differ, their full sample/readiness
assertions remain false, and performance, security, chaos, backup/restore, and
local rollback evidence is absent.

## Security evidence gate

`ops/phase7/run-security-gate.sh ABSOLUTE_SANITIZED_INPUT_DIR RUN_ID` validates
externally generated, offline security evidence; it does not install or run
scanners, start Docker, or access the network. The input directory must be a
non-link absolute directory with mode `0700`. It must contain exactly mode-0600
regular non-link files named `provenance.txt`, the three
`dependency-{python,node-runtime,node-build}.json` reports, `sast.sarif`,
`secrets.sarif`, `image-{vulns,high-critical,misconfig}.json`,
`sbom.cdx.json`, `licenses.json`, `hardening.status`, `negative-tests.xml`,
`negative-tests.status`, `sanitization.status`, and `cleanup.status`.
The exact set also includes `express-before.txt`, `express-after.txt`, and
`candidate-inventory.json`. Files must be single-link and owned by the caller;
the controller checks stable inode, size, owner, link count, mtime, and ctime
while copying them through descriptors into a private snapshot before parsing.

Provenance is an exact key/value contract that pins the run, committed HEAD and
tree, runner/policy/rule/lock/Dockerfile hashes, exact image ID/config/base
digest, scanner identities/versions/database time, disabled network and absent
sockets, plus every report hash. Reports repeat the exact source and image
subject. Every report also repeats the digest-pinned scanner image, exact
declared version, and common database timestamp. Scanner identities are fixed to pip-audit and npm audit for dependency
groups, Ruff plus pinned Semgrep rules for SAST, full-history Gitleaks plus Trivy
filesystem scanning for secrets, and offline Trivy for the exact image. Scanner
databases must be no more than 24 hours old.

The checked-in policy is parsed as an exact document in addition to being
hashed. CycloneDX components and the license report must join one-to-one by
package URL with identical names, versions, and non-empty license sets; missing,
extra, or duplicate packages/licenses fail. Sanitization is independently
enforced over every published byte for credential keys and token prefixes,
authorization/Bearer values, PEM material, URLs, and email-shaped PII. The
negative-test JUnit suite must contain the exact required security case IDs;
counts or a generic passing testcase are insufficient. The pinned Semgrep rules
are a bounded source-pattern supplement only: their presence and clean report
do not independently prove redirect or JWT correctness, which remains covered
by the exact negative-test manifest and other gate evidence.

The gate rejects unapproved Critical or High findings and Medium findings in
auth, crypto, redirect, or network-reachable domains. Only an unreachable
Node build-only High may carry an exact owner, rationale, compensating control,
and expiry no more than 30 days away; broad ignores and Critical waivers are not
accepted. Unknown/unlicensed, AGPL, SSPL, BUSL, Commons Clause, and
noncommercial licenses fail. GPL/LGPL coordinates require an exact manual
review record. Hardening must prove non-root execution, a read-only root
filesystem, all capabilities dropped, no-new-privileges, and tmpfs. Negative
tests, sanitization, and every downstream cleanup key must pass.
Express before/after snapshots must be byte-identical and separately hashed in
provenance. The exact empty candidate inventory and cleanup inventory are also
hash-bound; cleanup labels alone cannot establish these claims.

Missing required evidence exits `3` as `INCOMPLETE`; malformed, unsafe, stale,
unlinked, policy-violating, dirty-source, or colliding input exits `2` as
`FAIL`. The external-artifact controller currently keeps even a fully validated
bundle at `INCOMPLETE` with `CONTROLLED_COLLECTOR_REQUIRED`: opaque caller-authored
runtime snapshots and JUnit cannot authenticate execution. A future controlled,
pinned launcher must produce structured subject-bound Express/runtime evidence
and a source/tree/image-bound negative-test attestation before `PASS` can be
enabled. Evidence is atomically published without replacement beneath
`evidence/phase7-security/<run-id>/`. Published directories
and files are read-only. Every result, including `PASS`, records
`overallReplacementReady=false`; this gate never authorizes replacement.
While this controlled-collector requirement remains active, published bundles
contain only controller-generated `result.status` and `gate-result.json`;
caller-authored reports, snapshots, XML, and text are validated privately but
are never republished.
Publication fsyncs every staged file, the staging directory, the renamed
evidence root, and a newly created root's parent. FAIL/INCOMPLETE status retains
only bounded sanitized reason codes.
